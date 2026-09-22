//! The OpenAI-compatible HTTP surface.

use crate::backend::SealedClient;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::TryStreamExt;
use ppq_tee::PrivateModel;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

/// Chat requests carry whole conversations, and sometimes images, so axum's
/// 2 MiB default is too small. The sealed client holds the body in memory
/// regardless, so this is a cap on memory per request, not a streaming limit.
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

/// What `owned_by` says for every model: they are all PPQ's.
const MODEL_OWNER: &str = "ppq";

pub fn router<C: SealedClient>(client: Arc<C>) -> Router {
    Router::new()
        .route("/v1/models", get(list_models::<C>))
        // Model ids carry a slash (`private/glm-5-2`), so the capture must
        // span the remaining path segments, not one.
        .route("/v1/models/{*id}", get(get_model::<C>))
        .route("/v1/chat/completions", post(chat_completions::<C>))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(client)
}

/// An OpenAI model object. `created` is `0`: PPQ's catalogue carries no
/// creation time and the field is required by the schema. The last three
/// fields are extensions clients ignore.
#[derive(Serialize)]
struct Model {
    id: String,
    object: &'static str,
    created: u64,
    owned_by: &'static str,
    name: String,
    context_length: u32,
    pricing: Pricing,
}

#[derive(Serialize)]
struct Pricing {
    input_per_1m_tokens: f64,
    output_per_1m_tokens: f64,
    currency: String,
}

impl From<PrivateModel> for Model {
    fn from(m: PrivateModel) -> Self {
        Self {
            id: m.id,
            object: "model",
            created: 0,
            owned_by: MODEL_OWNER,
            name: m.name,
            context_length: m.context_length,
            pricing: Pricing {
                input_per_1m_tokens: m.pricing.input_per_1m,
                output_per_1m_tokens: m.pricing.output_per_1m,
                currency: m.pricing.currency,
            },
        }
    }
}

#[derive(Serialize)]
struct ModelList {
    object: &'static str,
    data: Vec<Model>,
}

async fn list_models<C: SealedClient>(
    State(client): State<Arc<C>>,
) -> Result<Json<ModelList>, ApiError> {
    let data = client
        .list_models()
        .await?
        .into_iter()
        .map(Model::from)
        .collect();
    Ok(Json(ModelList {
        object: "list",
        data,
    }))
}

async fn get_model<C: SealedClient>(
    State(client): State<Arc<C>>,
    Path(id): Path<String>,
) -> Result<Json<Model>, ApiError> {
    client
        .list_models()
        .await?
        .into_iter()
        .find(|m| m.id == id)
        .map(|m| Json(Model::from(m)))
        .ok_or_else(|| ApiError::not_found(format!("The model '{id}' does not exist")))
}

async fn chat_completions<C: SealedClient>(
    State(client): State<Arc<C>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let body: Value = serde_json::from_slice(&body)
        .map_err(|e| ApiError::invalid_request(format!("request body is not valid JSON: {e}")))?;
    let Some(obj) = body.as_object() else {
        return Err(ApiError::invalid_request(
            "request body must be a JSON object",
        ));
    };
    let Some(model) = obj.get("model").and_then(Value::as_str) else {
        return Err(ApiError::invalid_request(
            "you must provide a model parameter",
        ));
    };
    let stream = match obj.get("stream") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(ApiError::invalid_request("'stream' must be a boolean")),
    };
    tracing::info!(model, stream, "chat completion");

    if !stream {
        return Ok(Json(client.chat_completion(body).await?).into_response());
    }

    let sse = client.chat_completion_stream(body).await?;
    // A mid-stream failure ends the body early. hyper then aborts the
    // connection, so the client sees a truncated stream rather than a
    // well-formed one that silently lost its tail.
    let sse = sse.map_err(|e| {
        tracing::warn!(error = %e, "sealed stream aborted");
        std::io::Error::other(e)
    });
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        ],
        Body::from_stream(sse),
    )
        .into_response())
}

/// An error in OpenAI's `{"error": {...}}` shape, or an authenticated enclave
/// error body relayed as-is.
#[derive(Debug)]
pub enum ApiError {
    Shaped {
        status: StatusCode,
        kind: &'static str,
        code: Option<&'static str>,
        message: String,
    },
    /// The enclave's own error response: already OpenAI-shaped, and the only
    /// error body that is enclave-authenticated, so it passes through intact.
    Enclave { status: StatusCode, body: String },
}

impl ApiError {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self::Shaped {
            status: StatusCode::BAD_REQUEST,
            kind: "invalid_request_error",
            code: None,
            message: message.into(),
        }
    }

    fn not_found(message: String) -> Self {
        Self::Shaped {
            status: StatusCode::NOT_FOUND,
            kind: "invalid_request_error",
            code: Some("model_not_found"),
            message,
        }
    }
}

impl From<ppq_tee::Error> for ApiError {
    fn from(err: ppq_tee::Error) -> Self {
        use ppq_tee::Error;
        let shaped = |status, kind, code, message| Self::Shaped {
            status,
            kind,
            code,
            message,
        };
        match err {
            Error::Enclave { status, body } => match StatusCode::from_u16(status) {
                Ok(status) => Self::Enclave { status, body },
                Err(_) => shaped(
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    Some("enclave_error"),
                    format!("enclave returned unusable HTTP status {status}: {body}"),
                ),
            },
            Error::UnauthenticatedUpstream { status, body } => shaped(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                Some("unauthenticated_upstream"),
                format!("request was rejected before reaching the enclave (HTTP {status}; unauthenticated diagnostics): {body}"),
            ),
            Error::Http(e) => shaped(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                Some("transport"),
                format!("transport failure talking to the enclave: {e}"),
            ),
            Error::Ehbp(e) => shaped(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                Some("ehbp_protocol"),
                format!("sealed channel protocol error: {e}"),
            ),
            Error::Json(e) => shaped(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                Some("malformed_response"),
                format!("enclave response was not valid JSON: {e}"),
            ),
            Error::Attestation(e) => shaped(
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream_error",
                Some("attestation_failed"),
                format!("the enclave could not be verified: {e}"),
            ),
            Error::InvalidModelId(id) => Self::invalid_request(format!("model id cannot be sent: {id:?}")),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Shaped {
                status,
                kind,
                code,
                message,
            } => {
                let body = json!({ "error": { "message": message, "type": kind, "param": null, "code": code } });
                (status, Json(body)).into_response()
            }
            Self::Enclave { status, body } => match serde_json::from_str::<Value>(&body) {
                Ok(v) => (status, Json(v)).into_response(),
                // Not JSON after all: wrap it so the client still gets the
                // documented shape.
                Err(_) => (
                    status,
                    Json(json!({ "error": { "message": body, "type": "upstream_error", "param": null, "code": "enclave_error" } })),
                )
                    .into_response(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SseStream;
    use axum::http::Request;
    use futures::StreamExt;
    use http_body_util::BodyExt;
    use ppq_tee::Error;
    use std::sync::Mutex;
    use tower::ServiceExt;

    #[derive(Default)]
    struct Fake {
        models: Vec<PrivateModel>,
        /// Consumed by the next completion call, streaming or not.
        fail_with: Mutex<Option<Error>>,
        /// What the fake saw as the request body.
        seen: Mutex<Option<Value>>,
    }

    impl Fake {
        fn take_failure(&self) -> Option<Error> {
            self.fail_with.lock().unwrap().take()
        }
    }

    impl SealedClient for Fake {
        async fn list_models(&self) -> ppq_tee::Result<Vec<PrivateModel>> {
            match self.take_failure() {
                Some(e) => Err(e),
                None => Ok(self.models.clone()),
            }
        }
        async fn chat_completion(&self, body: Value) -> ppq_tee::Result<Value> {
            *self.seen.lock().unwrap() = Some(body);
            match self.take_failure() {
                Some(e) => Err(e),
                None => {
                    Ok(json!({ "id": "cmpl-1", "choices": [{ "message": { "content": "hi" } }] }))
                }
            }
        }
        async fn chat_completion_stream(&self, body: Value) -> ppq_tee::Result<SseStream> {
            *self.seen.lock().unwrap() = Some(body);
            if let Some(e) = self.take_failure() {
                return Err(e);
            }
            let chunks = [
                "data: {\"a\":1}\n\n",
                "data: {\"b\":2}\n\n",
                "data: [DONE]\n\n",
            ]
            .map(|s| Ok(Bytes::from_static(s.as_bytes())));
            Ok(futures::stream::iter(chunks).boxed())
        }
    }

    fn glm() -> PrivateModel {
        PrivateModel {
            id: "private/glm-5-2".into(),
            name: "GLM 5.2 (Private via TEE)".into(),
            context_length: 384_000,
            pricing: ppq_tee::Pricing {
                input_per_1m: 1.5,
                output_per_1m: 3.0,
                currency: "USD".into(),
            },
        }
    }

    fn app(fake: Fake) -> (Router, Arc<Fake>) {
        let fake = Arc::new(fake);
        (router(Arc::clone(&fake)), fake)
    }

    async fn send(app: Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Bytes) {
        let resp = app.oneshot(req).await.expect("infallible service");
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        (status, headers, body)
    }

    fn get_req(path: &str) -> Request<Body> {
        Request::get(path).body(Body::empty()).unwrap()
    }

    fn post_json(path: &str, body: &str) -> Request<Body> {
        Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn error_of(body: &Bytes) -> Value {
        serde_json::from_slice::<Value>(body).expect("error body is JSON")["error"].clone()
    }

    #[tokio::test]
    async fn lists_models_in_openai_shape() {
        let (app, _) = app(Fake {
            models: vec![glm()],
            ..Default::default()
        });
        let (status, headers, body) = send(app, get_req("/v1/models")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["object"], "list");
        assert_eq!(v["data"][0]["id"], "private/glm-5-2");
        assert_eq!(v["data"][0]["object"], "model");
        assert_eq!(v["data"][0]["owned_by"], MODEL_OWNER);
        assert!(
            v["data"][0]["created"].is_u64(),
            "created is required by the schema"
        );
        assert_eq!(v["data"][0]["context_length"], 384_000);
        assert_eq!(v["data"][0]["pricing"]["output_per_1m_tokens"], 3.0);
    }

    #[tokio::test]
    async fn retrieves_one_model_or_404s() {
        let (app, _) = app(Fake {
            models: vec![glm()],
            ..Default::default()
        });
        let (status, _, body) = send(app.clone(), get_req("/v1/models/private/glm-5-2")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["id"],
            "private/glm-5-2"
        );

        let (status, _, body) = send(app, get_req("/v1/models/private/nope")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(error_of(&body)["code"], "model_not_found");
    }

    #[tokio::test]
    async fn relays_a_non_streaming_completion() {
        let (app, fake) = app(Fake::default());
        let req = r#"{"model":"private/glm-5-2","messages":[{"role":"user","content":"hi"}]}"#;
        let (status, headers, body) = send(app, post_json("/v1/chat/completions", req)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["id"],
            "cmpl-1"
        );
        let seen = fake
            .seen
            .lock()
            .unwrap()
            .clone()
            .expect("client was called");
        assert_eq!(
            seen["model"], "private/glm-5-2",
            "body is passed through untouched"
        );
        assert_eq!(seen["messages"][0]["content"], "hi");
    }

    #[tokio::test]
    async fn streams_sse_bytes_as_they_come() {
        let (app, _) = app(Fake::default());
        let req = r#"{"model":"private/glm-5-2","messages":[],"stream":true}"#;
        let (status, headers, body) = send(app, post_json("/v1/chat/completions", req)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "text/event-stream");
        assert_eq!(headers[header::CACHE_CONTROL], "no-cache");
        assert_eq!(
            &body[..],
            b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\ndata: [DONE]\n\n"
        );
    }

    #[tokio::test]
    async fn rejects_requests_without_a_model() {
        let (app, fake) = app(Fake::default());
        for body in [
            r#"{"messages":[]}"#,
            r#"{"model":7}"#,
            r#"[1,2]"#,
            "not json",
            r#"{"model":"x","stream":"yes"}"#,
        ] {
            let (status, _, resp) =
                send(app.clone(), post_json("/v1/chat/completions", body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "body {body:?}");
            assert_eq!(
                error_of(&resp)["type"],
                "invalid_request_error",
                "body {body:?}"
            );
        }
        assert!(
            fake.seen.lock().unwrap().is_none(),
            "nothing reached the sealed client"
        );
    }

    #[tokio::test]
    async fn relays_an_authenticated_enclave_error_verbatim() {
        let (app, _) = app(Fake {
            fail_with: Mutex::new(Some(Error::Enclave {
                status: 429,
                body: r#"{"error":{"message":"rate limited","type":"rate_limit_error","code":"rate_limit"}}"#.into(),
            })),
            ..Default::default()
        });
        let req = r#"{"model":"private/glm-5-2","messages":[],"stream":true}"#;
        let (status, headers, body) = send(app, post_json("/v1/chat/completions", req)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            headers[header::CONTENT_TYPE],
            "application/json",
            "not an SSE stream"
        );
        assert_eq!(error_of(&body)["code"], "rate_limit");
    }

    #[tokio::test]
    async fn wraps_a_non_json_enclave_error() {
        let (app, _) = app(Fake {
            fail_with: Mutex::new(Some(Error::Enclave {
                status: 500,
                body: "<html>oops</html>".into(),
            })),
            ..Default::default()
        });
        let (status, _, body) =
            send(app, post_json("/v1/chat/completions", r#"{"model":"m"}"#)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error_of(&body)["message"], "<html>oops</html>");
    }

    #[tokio::test]
    async fn maps_each_error_kind_to_a_status() {
        let cases: Vec<(Error, StatusCode, &str)> = vec![
            (
                Error::UnauthenticatedUpstream {
                    status: 401,
                    body: "bad key".into(),
                },
                StatusCode::BAD_GATEWAY,
                "unauthenticated_upstream",
            ),
            (
                Error::Ehbp("nonce".into()),
                StatusCode::BAD_GATEWAY,
                "ehbp_protocol",
            ),
            (
                Error::Attestation("rekor".into()),
                StatusCode::SERVICE_UNAVAILABLE,
                "attestation_failed",
            ),
            (
                Error::InvalidModelId("a\nb".into()),
                StatusCode::BAD_REQUEST,
                "null",
            ),
        ];
        for (err, want_status, want_code) in cases {
            let desc = err.to_string();
            let (app, _) = app(Fake {
                fail_with: Mutex::new(Some(err)),
                ..Default::default()
            });
            let (status, _, body) = send(app, get_req("/v1/models")).await;
            assert_eq!(status, want_status, "{desc}");
            let e = error_of(&body);
            assert_eq!(e["code"].as_str().unwrap_or("null"), want_code, "{desc}");
            assert!(
                e["message"]
                    .as_str()
                    .unwrap()
                    .contains(&desc.split(':').next_back().unwrap().trim()[..3]),
                "{desc}"
            );
        }
    }
}
