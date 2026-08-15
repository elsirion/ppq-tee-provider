//! `rig-core` integration.
//!
//! `rig-core` is generic over its HTTP backend, so the EHBP channel plugs in
//! as that backend and rig's OpenAI-compatible machinery — message
//! conversion, tool calls, SSE streaming, telemetry — runs unchanged on top of
//! it. Nothing here re-derives a wire format; the only PPQ-specific pieces are
//! where a request body gets sealed and which id goes in the body versus the
//! header.
//!
//! The sealing itself lives in [`crate::client`] and is shared verbatim with
//! `PpqClient`'s own JSON API, so the two transports cannot drift apart on
//! encryption or on any of the fail-closed checks.

use crate::client::{open_body, open_stream, routing_headers, seal_and_send};
use crate::{Error, PpqClient, Result};
use bytes::Bytes;
use futures::StreamExt;
use rig_core::client::{self, DebugExt, Nothing, Provider, ProviderBuilder};
use rig_core::completion::CompletionError;
use rig_core::http_client::{self, HttpClientExt, LazyBody, MultipartForm, StreamingResponse};
use rig_core::providers::openai::{self, completion::OpenAICompatibleProvider};
use std::future::Future;
use std::sync::Arc;

/// Where the enclave's OpenAI-compatible API lives, relative to the PPQ base
/// URL. rig appends `/chat/completions` to it.
pub const RIG_BASE_PATH: &str = "/private/v1";

/// An HTTP backend whose request bodies are HPKE-sealed to the attested
/// enclave and whose response bodies are opened from EHBP frames.
///
/// Everything rig sends through this type is encrypted end-to-end to the key
/// the hardware proved. There is no plaintext path: a backend with no attested
/// client refuses to send at all.
#[derive(Clone, Debug, Default)]
pub struct EhbpHttp {
    /// `None` only in the `Default` value rig's `CompletionModel` bound
    /// (`H: Default`) forces us to have. A defaulted backend has no
    /// attestation and nothing to seal to, so it fails closed on every
    /// request rather than degrading to plaintext.
    ///
    /// Behind an `Arc` because `HttpClientExt::send` returns a
    /// `Future + 'static`, which cannot borrow `&self`.
    inner: Option<Arc<PpqClient>>,
}

impl EhbpHttp {
    /// A backend bound to an already-attested client.
    pub fn new(client: PpqClient) -> Self {
        Self {
            inner: Some(Arc::new(client)),
        }
    }

    fn attested(&self) -> http_client::Result<Arc<PpqClient>> {
        self.inner.clone().ok_or_else(|| {
            instance(Error::Attestation(
                "this EHBP backend is not attested to any enclave and will not send".into(),
            ))
        })
    }
}

/// Seal one rig-built request and hand back the still-encrypted response.
///
/// Only POSTs go through: a GET would carry the bearer token to the enclave
/// with no sealed body at all, and rig only ever GETs on `VerifyClient`, which
/// this transport deliberately does not support.
async fn send_sealed(
    client: Arc<PpqClient>,
    parts: http::request::Parts,
    body: Bytes,
) -> Result<(crate::ehbp::stream::FrameDecoder, reqwest::Response)> {
    if parts.method != http::Method::POST {
        return Err(Error::Ehbp(format!(
            "the sealed transport only carries POST, not {}",
            parts.method
        )));
    }

    // rig's default header map (set up in `PpqClient::completion_model`)
    // carries the routing headers; rig adds `Content-Type`, and its SSE source
    // adds `Accept`. They are forwarded as-is — `seal_and_send` then overwrites
    // the ones it owns, so nothing here can displace or duplicate the auth,
    // content-type or encapsulated-key headers.
    let mut headers = reqwest::header::HeaderMap::with_capacity(parts.headers.len());
    for (name, value) in parts.headers.iter() {
        headers.append(name.clone(), value.clone());
    }

    seal_and_send(&client, &parts.uri.to_string(), &body, headers).await
}

/// Map a transport failure into rig's error type without blurring the line
/// between what the enclave said and what an intermediary said.
///
/// [`Error::Enclave`] is authenticated enclave output, so it becomes
/// `InvalidStatusCodeWithMessage`, which rig surfaces through
/// `CompletionError::provider_response_status()`/`_body()` as a genuine
/// provider response. Everything else — including
/// [`Error::UnauthenticatedUpstream`], whose body is attacker-forgeable —
/// becomes `Error::Instance`, which rig reports as a rig-side transport
/// diagnostic with no provider response attached. A caller reading
/// `provider_response_body()` therefore never sees a forged CDN error page
/// dressed up as a model response.
fn to_http_error(error: Error) -> http_client::Error {
    match error {
        Error::Enclave { status, body } => match http::StatusCode::from_u16(status) {
            Ok(status) => http_client::Error::InvalidStatusCodeWithMessage(status, body),
            Err(_) => instance(Error::Enclave { status, body }),
        },
        other => instance(other),
    }
}

fn instance(error: Error) -> http_client::Error {
    http_client::Error::Instance(Box::new(error))
}

impl HttpClientExt for EhbpHttp {
    fn send<T, U>(
        &self,
        req: http::Request<T>,
    ) -> impl Future<Output = http_client::Result<http::Response<LazyBody<U>>>> + Send + 'static
    where
        T: Into<Bytes> + Send,
        U: From<Bytes> + Send + 'static,
    {
        let client = self.attested();
        let (parts, body) = req.into_parts();
        let body: Bytes = body.into();

        async move {
            let client = client?;
            let (decoder, response) = send_sealed(client, parts, body)
                .await
                .map_err(to_http_error)?;
            let status = response.status();
            let plaintext = open_body(decoder, response).await.map_err(to_http_error)?;

            // Only the status survives from the outer response: every header
            // an intermediary could have written is unauthenticated, and rig
            // reads nothing but the status and the body here.
            http::Response::builder()
                .status(status)
                .body(Box::pin(async move { Ok(U::from(Bytes::from(plaintext))) }) as LazyBody<U>)
                .map_err(http_client::Error::Protocol)
        }
    }

    fn send_multipart<U>(
        &self,
        _req: http::Request<MultipartForm>,
    ) -> impl Future<Output = http_client::Result<http::Response<LazyBody<U>>>> + Send + 'static
    where
        U: From<Bytes> + Send + 'static,
    {
        // EHBP seals one byte stream; there is no multipart framing for it,
        // and the enclave serves no multipart endpoint. Refuse rather than
        // send an unsealed form.
        std::future::ready(Err(instance(Error::Ehbp(
            "multipart requests are not carried over the sealed transport".into(),
        ))))
    }

    fn send_streaming<T>(
        &self,
        req: http::Request<T>,
    ) -> impl Future<Output = http_client::Result<StreamingResponse>> + Send
    where
        T: Into<Bytes> + Send,
    {
        let client = self.attested();
        let (parts, body) = req.into_parts();
        let body: Bytes = body.into();

        async move {
            let client = client?;
            let (decoder, response) = send_sealed(client, parts, body)
                .await
                .map_err(to_http_error)?;
            let status = response.status();
            let plaintext = open_stream(decoder, response)
                .await
                .map_err(to_http_error)?;

            // The decrypted body is what the SSE parser has to read, and it is
            // SSE by construction: rig only streams a `"stream": true` request,
            // and this is the plaintext the enclave produced for it. The
            // ciphertext's own content type describes the EHBP frames around
            // it, not the events inside, so it is not forwarded.
            http::Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, "text/event-stream")
                .body(
                    Box::pin(plaintext.map(|chunk| chunk.map_err(to_http_error)))
                        as http_client::sse::BoxedStream,
                )
                .map_err(http_client::Error::Protocol)
        }
    }
}

/// How PPQ's enclave differs from stock OpenAI chat completions.
#[derive(Debug, Clone, Copy, Default)]
pub struct PpqExt;

/// Builds [`PpqExt`]. Exists because rig's `Provider` trait requires a
/// builder; it carries no configuration of its own, since everything the
/// transport needs already lives in the attested [`PpqClient`].
#[derive(Debug, Clone, Copy, Default)]
pub struct PpqExtBuilder;

impl Provider for PpqExt {
    type Builder = PpqExtBuilder;

    /// rig's `VerifyClient` GETs this path to check credentials. It cannot
    /// work here — the sealed transport carries POSTs only — and it does not
    /// need to: the key is proven by attestation before a client exists, and
    /// by the first sealed request after that.
    const VERIFY_PATH: &'static str = "/models";
}

impl DebugExt for PpqExt {}

impl ProviderBuilder for PpqExtBuilder {
    type Extension<H>
        = PpqExt
    where
        H: HttpClientExt;

    /// The bearer token stays in [`PpqClient`], which is the only thing that
    /// ever talks to the network. Handing rig a copy would put it in a header
    /// map this crate does not control, for no gain.
    type ApiKey = Nothing;

    /// Only a fallback: [`PpqClient::completion_model`] always overrides this
    /// with the attested client's own base URL.
    const BASE_URL: &'static str = "https://api.ppq.ai/private/v1";

    fn build<H>(
        _builder: &client::ClientBuilder<Self, Self::ApiKey, H>,
    ) -> http_client::Result<PpqExt>
    where
        H: HttpClientExt,
    {
        Ok(PpqExt)
    }
}

impl OpenAICompatibleProvider for PpqExt {
    const PROVIDER_NAME: &'static str = "ppq-private";

    // PPQ's catalogue omits `supported_parameters` for its `e2e` models, which
    // reads as "tools unsupported". That is an artefact of the field being
    // absent, not a statement about the enclave: it does emit tool calls, and
    // the reference client drives `private/glm-5-2` almost entirely through
    // them. Deriving these from the catalogue would silently disable tool
    // calling and structured output for every model, so they are stated here
    // and the catalogue is never consulted for capabilities.
    const SUPPORTS_TOOLS: bool = true;
    const SUPPORTS_RESPONSE_FORMAT: bool = true;

    type StreamingUsage = openai::Usage;
    type Response = openai::CompletionResponse;

    fn prepare_request(
        &self,
        request: &mut openai::completion::CompletionRequest,
    ) -> std::result::Result<(), CompletionError> {
        // The `X-Private-Model` header carries the user-facing id; the body
        // carries the enclave-internal one. Proven against the live enclave in
        // Task 11 — swapping them fails.
        request.model = crate::enclave_model_id(&request.model).to_string();
        Ok(())
    }
}

/// A `rig-core` chat-completions model served by the attested enclave.
pub type PpqCompletionModel = openai::completion::GenericCompletionModel<PpqExt, EhbpHttp>;

impl PpqClient {
    /// A `rig-core` completion model for `id` (e.g. `private/glm-5-2`).
    ///
    /// The id is not validated against the catalogue: that would put a network
    /// round-trip on a hot path, the catalogue is unauthenticated discovery
    /// metadata, and the attested enclave is the authority on what it serves.
    /// It is only checked for being a legal header value, so a malformed id
    /// fails here instead of panicking or reaching the wire.
    pub fn completion_model(&self, id: &str) -> Result<PpqCompletionModel> {
        let client = rig_core::client::Client::<PpqExt>::builder()
            .api_key(Nothing)
            .base_url(format!("{}{}", self.base_url, RIG_BASE_PATH))
            .http_client(EhbpHttp::new(self.clone()))
            .http_headers(routing_headers(id)?)
            .build()
            .map_err(|e| Error::Ehbp(format!("could not build the rig client: {e}")))?;

        Ok(PpqCompletionModel::new(client, id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use futures::StreamExt;
    use rig_core::completion::{
        CompletionModel as _, CompletionRequest as CoreRequest, ToolDefinition,
    };
    use rig_core::message::Message;
    use rig_core::providers::openai::completion::OpenAICompatibleProvider;
    use rig_core::streaming::StreamedAssistantContent;
    use rig_core::OneOrMany;
    use std::sync::{Arc, Mutex};

    fn core_request(tools: Vec<ToolDefinition>) -> CoreRequest {
        CoreRequest {
            model: None,
            preamble: Some("You are concise.".to_string()),
            chat_history: OneOrMany::one(Message::user("ping")),
            documents: vec![],
            tools,
            temperature: None,
            max_tokens: Some(64),
            tool_choice: None,
            additional_params: None,
            output_schema: None,
            record_telemetry_content: false,
        }
    }

    fn a_tool() -> ToolDefinition {
        ToolDefinition {
            name: "ping".to_string(),
            description: "Pings.".to_string(),
            parameters: serde_json::json!({"type": "object", "properties": {}}),
        }
    }

    #[test]
    fn strips_the_private_prefix_from_the_request_body() {
        let mut req = openai::completion::CompletionRequest {
            model: "private/glm-5-2".to_string(),
            messages: vec![],
            tools: vec![],
            tool_choice: None,
            temperature: None,
            max_tokens: None,
            additional_params: None,
        };
        PpqExt.prepare_request(&mut req).unwrap();
        assert_eq!(
            req.model, "glm-5-2",
            "the enclave expects the unprefixed id in the body"
        );
    }

    /// PPQ's catalogue omits `supported_parameters` for e2e models, which
    /// reads as "no tools". It is wrong: the enclave does emit tool calls.
    /// Asserted in a `const` block so a regression cannot even build — these
    /// are compile-time constants, and `completes_a_prompt_through_the_sealed_transport`
    /// is what proves the flag actually reaches the wire.
    #[test]
    fn advertises_tool_support() {
        const { assert!(PpqExt::SUPPORTS_TOOLS) };
        const { assert!(PpqExt::SUPPORTS_RESPONSE_FORMAT) };
    }

    /// The rig client's base URL is derived from the attested client's, so the
    /// `ProviderBuilder` default only ever shows up in a client nobody built
    /// through `completion_model`. Pin it anyway: a drift between the two
    /// would be invisible until a request went to the wrong path.
    #[test]
    fn the_provider_default_base_url_matches_the_attested_default() {
        assert_eq!(
            <PpqExtBuilder as rig_core::client::ProviderBuilder>::BASE_URL,
            format!("{}{}", crate::client::DEFAULT_BASE_URL, RIG_BASE_PATH)
        );
    }

    /// rig routes to `{base}/chat/completions` itself. If that ever stopped
    /// landing on the endpoint `PpqClient`'s own JSON API posts to, requests
    /// would go somewhere the enclave does not serve.
    #[test]
    fn rig_routes_to_the_same_endpoint_as_the_json_api() {
        assert_eq!(
            format!("{RIG_BASE_PATH}/chat/completions"),
            crate::client::CHAT_COMPLETIONS_PATH
        );
    }

    #[tokio::test]
    async fn completes_a_prompt_through_the_sealed_transport() {
        let (sk, pk) = keypair();
        let seen = Arc::new(Mutex::new(None));
        let seen_body = Arc::clone(&seen);
        let (base, recorded) =
            serve(move |req| {
                let (plaintext, sealed) = enclave(
                &sk,
                req,
                &[br#"{"id":"c1","model":"glm-5-2","choices":[{"index":0,"#,
                  br#""message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}]}"#],
            );
                *seen_body.lock().unwrap() = Some(plaintext);
                http_response(200, &[nonce_header()], &sealed)
            })
            .await;

        let model = client_for(&base, pk)
            .completion_model("private/glm-5-2")
            .unwrap();
        let response = model
            .completion(core_request(vec![a_tool()]))
            .await
            .unwrap();
        assert!(
            format!("{:?}", response.choice).contains("pong"),
            "got: {:?}",
            response.choice
        );

        // The enclave-internal id goes in the body, the user-facing one in the
        // header — the same split `chat_completion` uses.
        let sent = seen.lock().unwrap().clone().unwrap();
        assert_eq!(sent["model"], "glm-5-2");
        assert_eq!(
            sent["messages"][0]["role"], "system",
            "rig's own message conversion is what builds the body: {sent}"
        );
        assert_eq!(
            sent["tools"][0]["function"]["name"], "ping",
            "SUPPORTS_TOOLS must put the tool on the wire: {sent}"
        );

        let req = recorded.lock().unwrap().take().unwrap();
        // rig builds this URL itself, from the base URL `completion_model`
        // gave it. It has to land on the endpoint the enclave actually serves.
        assert_eq!(
            req.request_line,
            format!("POST {} HTTP/1.1", crate::client::CHAT_COMPLETIONS_PATH)
        );
        assert_eq!(req.header("x-private-model"), "private/glm-5-2");
        assert_eq!(req.header("x-query-source"), "api");
        assert_eq!(req.header("authorization"), "Bearer sk-test");
        // rig puts a `Content-Type` on the request too. It must replace ours,
        // not stack with it: two `Content-Type` headers is a malformed request.
        assert_eq!(req.header("content-type"), "application/json");
        assert_eq!(req.header("transfer-encoding"), "chunked");
        assert!(!req.headers.contains_key("content-length"));
    }

    /// A reasoning model answers with `content: null` alongside its tool
    /// calls. That must round-trip, not parse-fail.
    #[tokio::test]
    async fn a_null_content_tool_call_response_parses() {
        let (sk, pk) = keypair();
        let (base, _) = serve(move |req| {
            let (_, sealed) = enclave(
                &sk,
                req,
                &[br#"{"id":"c1","model":"glm-5-2","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"ping","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#],
            );
            http_response(200, &[nonce_header()], &sealed)
        })
        .await;

        let response = client_for(&base, pk)
            .completion_model("private/glm-5-2")
            .unwrap()
            .completion(core_request(vec![a_tool()]))
            .await
            .unwrap();
        assert!(
            response
                .choice
                .iter()
                .any(|c| matches!(c, rig_core::completion::AssistantContent::ToolCall(_))),
            "got: {:?}",
            response.choice
        );
    }

    #[tokio::test]
    async fn streams_a_completion_through_the_sealed_transport() {
        let (sk, pk) = keypair();
        let (base, _) = serve(move |req| {
            let (_, sealed) = enclave(
                &sk,
                req,
                &[
                    b"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"po\"}}]}\n\n",
                    b"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"ng\"}}]}\n\n",
                    b"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":null,\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"ping\",\"arguments\":\"{}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
                    b"data: [DONE]\n\n",
                ],
            );
            http_response(200, &[nonce_header()], &sealed)
        })
        .await;

        let mut stream = client_for(&base, pk)
            .completion_model("private/glm-5-2")
            .unwrap()
            .stream(core_request(vec![a_tool()]))
            .await
            .expect("the stream opens");

        let mut text = String::new();
        let mut tool_calls = Vec::new();
        while let Some(item) = stream.next().await {
            match item.expect("every stream item decrypts") {
                StreamedAssistantContent::Text(t) => text.push_str(&t.text),
                StreamedAssistantContent::ToolCall { tool_call, .. } => tool_calls.push(tool_call),
                _ => {}
            }
        }
        assert_eq!(text, "pong", "rig's SSE parser drives the decrypted stream");
        assert_eq!(tool_calls.len(), 1, "got: {tool_calls:?}");
        assert_eq!(tool_calls[0].function.name, "ping");
    }

    /// A sealed non-2xx authenticates: it *is* enclave output, so its status
    /// and body must reach the caller as a genuine provider response.
    #[tokio::test]
    async fn a_sealed_enclave_error_keeps_its_status_and_body() {
        let (sk, pk) = keypair();
        let (base, _) = serve(move |req| {
            let (_, sealed) = enclave(&sk, req, &[br#"{"error":{"message":"rate limited"}}"#]);
            http_response(429, &[nonce_header()], &sealed)
        })
        .await;

        let error = client_for(&base, pk)
            .completion_model("private/glm-5-2")
            .unwrap()
            .completion(core_request(vec![]))
            .await
            .expect_err("a sealed 429 is not a completion");
        assert_eq!(
            error.provider_response_status(),
            Some(http::StatusCode::TOO_MANY_REQUESTS)
        );
        assert!(
            error
                .provider_response_body()
                .is_some_and(|b| b.contains("rate limited")),
            "got: {error}"
        );
    }

    /// A non-2xx that never carried a response nonce never reached the
    /// enclave, so its body is attacker-forgeable. It must not be handed to a
    /// caller as a provider response — otherwise a CDN error page reads as
    /// something the model said.
    #[tokio::test]
    async fn an_unauthenticated_upstream_error_is_not_a_provider_response() {
        let (_, pk) = keypair();
        let (base, _) = serve(|_| {
            http_response(
                502,
                &[],
                br#"{"error":{"message":"forged by the intermediary"}}"#,
            )
        })
        .await;

        let error = client_for(&base, pk)
            .completion_model("private/glm-5-2")
            .unwrap()
            .completion(core_request(vec![]))
            .await
            .expect_err("an unattested error page is not enclave output");
        assert_eq!(error.provider_response_status(), None, "got: {error}");
        assert_eq!(error.provider_response_body(), None, "got: {error}");
        assert!(
            error.to_string().contains("unauthenticated upstream"),
            "the caller has to be able to tell why: {error}"
        );
    }

    /// `rig`'s `CompletionModel` bound requires `H: Default`, so a defaulted
    /// backend exists whether we want one or not. It has no attestation and
    /// no key to seal to, so it must refuse rather than fall back to plaintext.
    #[tokio::test]
    async fn the_default_backend_refuses_to_send() {
        use rig_core::http_client::HttpClientExt;

        let request = http::Request::post("https://api.ppq.ai/private/v1/chat/completions")
            .body(Vec::new())
            .unwrap();
        // The `Ok` type holds a boxed future, which is not `Debug`.
        let Err(error) =
            HttpClientExt::send::<_, bytes::Bytes>(&EhbpHttp::default(), request).await
        else {
            panic!("an unattested backend must never send");
        };
        assert!(error.to_string().contains("not attested"), "got: {error}");
    }

    /// Everything on this transport is a sealed POST. A GET would carry the
    /// bearer token with no sealed body at all, so it is refused rather than
    /// silently sent in the clear — `VerifyClient` is the only rig surface
    /// that tries one.
    #[tokio::test]
    async fn refuses_a_request_that_is_not_a_post() {
        use rig_core::http_client::HttpClientExt;

        let (_, pk) = keypair();
        let client = EhbpHttp::new(client_for("https://api.ppq.ai", pk));
        let request = http::Request::get("https://api.ppq.ai/private/v1/models")
            .body(Vec::new())
            .unwrap();
        let Err(error) = HttpClientExt::send::<_, bytes::Bytes>(&client, request).await else {
            panic!("only sealed POSTs go over this transport");
        };
        assert!(error.to_string().contains("GET"), "got: {error}");
    }

    /// `PpqClient` redacts its API key in `Debug`; the rig backend wraps one,
    /// and rig's own `Client` prints its backend. The redaction has to survive
    /// both wrappers or a `tracing::debug!(?model)` leaks the bearer token.
    #[test]
    fn debug_on_the_rig_backend_still_redacts_the_api_key() {
        let (_, pk) = keypair();
        let mut inner = client_for("http://127.0.0.1:1", pk);
        inner.api_key = "sk-super-secret-do-not-leak".to_string();

        let out = format!("{:?}", EhbpHttp::new(inner));
        assert!(!out.contains("sk-super-secret"), "api key leaked: {out}");
        assert!(out.contains("redacted"), "got: {out}");
    }

    #[tokio::test]
    async fn rejects_a_model_id_that_cannot_be_a_header_value() {
        let (_, pk) = keypair();
        // `PpqCompletionModel` is not `Debug`, so `expect_err` is unavailable.
        let Err(error) =
            client_for("https://api.ppq.ai", pk).completion_model("private/glm\r\nX-Injected: yes")
        else {
            panic!("a header-injecting model id must not build a model");
        };
        assert!(matches!(error, crate::Error::InvalidModelId(_)));
    }
}
