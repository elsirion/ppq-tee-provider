//! The attested client: attest once, then seal every request to the key the
//! hardware proved.

use crate::attest::{self, Attestation, TrustPolicy};
use crate::ehbp::{keyconfig, open::FrameOpener, seal, stream::FrameDecoder};
use crate::models::{self, PrivateModel};
use crate::{Error, Result};
use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt};

pub const DEFAULT_BASE_URL: &str = "https://api.ppq.ai";

/// How long to wait for the TCP+TLS handshake before giving up.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a single read on the socket may stall before giving up.
///
/// This resets after every successful read, so it bounds *stalls*, not total
/// duration — a long but steadily-trickling SSE stream never trips it.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Cap on an error body pulled from an untrusted or semi-trusted response, so
/// a hostile or misbehaving peer cannot inflate a single error message
/// without bound.
const MAX_ERROR_BODY_BYTES: usize = 4096;

/// Truncate `body` to `MAX_ERROR_BODY_BYTES`, noting it in the string when it
/// happens, so nothing downstream mistakes the cut text for the whole body.
pub(crate) fn cap_body(mut body: String) -> String {
    if body.len() <= MAX_ERROR_BODY_BYTES {
        return body;
    }
    let mut cut = MAX_ERROR_BODY_BYTES;
    while !body.is_char_boundary(cut) {
        cut -= 1;
    }
    body.truncate(cut);
    body.push_str(&format!("... (truncated to {MAX_ERROR_BODY_BYTES} bytes)"));
    body
}

#[derive(Clone)]
pub struct PpqClient {
    pub(crate) http: reqwest::Client,
    pub(crate) base_url: String,
    pub(crate) api_key: String,
    pub(crate) attestation: Attestation,
}

/// Hand-written to redact `api_key` — `PpqClient` is public and a leaked
/// bearer token in a `dbg!` or `tracing::debug!(?client)` is a real
/// vulnerability, not a hypothetical one.
impl std::fmt::Debug for PpqClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PpqClient")
            .field("http", &self.http)
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .field("attestation", &self.attestation)
            .finish()
    }
}

#[derive(Default)]
pub struct PpqClientBuilder {
    api_key: Option<String>,
    base_url: Option<String>,
    trust_policy: Option<TrustPolicy>,
}

/// Hand-written for the same reason as `PpqClient`'s: `api_key` must never
/// appear in a formatted output, even before the client is built.
impl std::fmt::Debug for PpqClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PpqClientBuilder")
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("base_url", &self.base_url)
            .field("trust_policy", &self.trust_policy)
            .finish()
    }
}

impl PpqClient {
    pub fn builder() -> PpqClientBuilder {
        PpqClientBuilder::default()
    }

    /// What the hardware proved about the enclave at construction time.
    pub fn attestation(&self) -> &Attestation {
        &self.attestation
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// TEE-backed models from PPQ's catalogue.
    ///
    /// This is served by PPQ's *plaintext* API, not from inside the enclave,
    /// so it is unauthenticated discovery metadata — never a trust input.
    /// Nothing here is verified: the response is an ordinary TLS-protected
    /// HTTP body from `api.ppq.ai` with no attestation behind it, and PPQ (or
    /// anyone who can terminate that TLS) can put anything in it. The security
    /// guarantee comes from attestation alone and is independent of what this
    /// returns; request model ids are never validated against it, and an
    /// unknown id is simply rejected by the enclave. In particular, do not
    /// infer model capabilities from these entries — `e2e` entries omit
    /// `supported_parameters` entirely.
    pub async fn list_models(&self) -> Result<Vec<PrivateModel>> {
        let body = self
            .http
            .get(format!("{}/v1/models", self.base_url))
            .bearer_auth(&self.api_key)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        models::parse_private(&body)
    }

    /// Send one OpenAI-format chat completion through the sealed channel.
    ///
    /// The returned value is the enclave's decrypted body. A sealed non-2xx
    /// (e.g. a rate-limit error the enclave itself produced) still
    /// authenticates — it *is* enclave output — but is surfaced as
    /// `Err(Error::Enclave)` rather than `Ok`, so a caller cannot mistake a
    /// rate-limit or payment error for a completion. Only responses that
    /// never carried an `Ehbp-Response-Nonce` become `Error::UnauthenticatedUpstream`.
    pub async fn chat_completion(&self, mut body: serde_json::Value) -> Result<serde_json::Value> {
        let model = self.take_model(&mut body)?;
        let (decoder, response) = self.send_sealed(&body, &model).await?;
        Ok(serde_json::from_slice(
            &open_body(decoder, response).await?,
        )?)
    }

    /// Stream one OpenAI-format chat completion; yields decrypted SSE bytes.
    ///
    /// See [`open_stream`] for how a sealed non-2xx and a truncated stream are
    /// handled — neither can be mistaken for a completed one.
    pub async fn chat_completion_stream(
        &self,
        mut body: serde_json::Value,
    ) -> Result<impl Stream<Item = Result<Bytes>>> {
        let model = self.take_model(&mut body)?;
        body["stream"] = serde_json::Value::Bool(true);
        let (decoder, response) = self.send_sealed(&body, &model).await?;
        open_stream(decoder, response).await
    }

    /// Rewrite `model` to the enclave-internal id and return the user-facing one.
    fn take_model(&self, body: &mut serde_json::Value) -> Result<String> {
        let obj = body
            .as_object_mut()
            .ok_or_else(|| Error::Ehbp("request body is not a JSON object".into()))?;
        let user_facing = obj
            .get("model")
            .and_then(|m| m.as_str())
            .ok_or_else(|| Error::Ehbp("request has no model".into()))?
            .to_string();
        obj.insert(
            "model".to_string(),
            serde_json::Value::String(models::enclave_model_id(&user_facing).to_string()),
        );
        Ok(user_facing)
    }

    async fn send_sealed(
        &self,
        body: &serde_json::Value,
        model: &str,
    ) -> Result<(FrameDecoder, reqwest::Response)> {
        seal_and_send(
            self,
            &format!("{}{}", self.base_url, CHAT_COMPLETIONS_PATH),
            &serde_json::to_vec(body)?,
            routing_headers(model)?,
        )
        .await
    }
}

/// The enclave's chat-completions endpoint, relative to the base URL. The
/// `rig` transport reaches the same URL by way of rig's own routing, so this
/// constant is what the two paths are checked against each other on.
pub(crate) const CHAT_COMPLETIONS_PATH: &str = "/private/v1/chat/completions";

/// The two non-EHBP headers the enclave's front end routes on: which model to
/// dispatch to (user-facing id, `private/` prefix intact) and where the query
/// came from.
pub(crate) fn routing_headers(model: &str) -> Result<reqwest::header::HeaderMap> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "x-private-model",
        reqwest::header::HeaderValue::from_str(model)
            .map_err(|_| Error::InvalidModelId(model.to_string()))?,
    );
    headers.insert(
        "x-query-source",
        reqwest::header::HeaderValue::from_static("api"),
    );
    Ok(headers)
}

/// Seal `plaintext` to the attested enclave key and POST it to `url`.
///
/// The single place a request body is encrypted. Both `PpqClient`'s JSON API
/// and the `rig` transport go through here, so the two cannot drift on
/// sealing, on the chunked framing EHBP requires, or on any of the fail-closed
/// checks that decide whether a response is enclave output at all.
///
/// `extra_headers` carries whatever the caller needs to route the request; the
/// auth, content-type and EHBP headers are then `insert`ed over it, so a
/// caller can never displace them — and, just as importantly, can never end up
/// sending a second copy of one alongside ours.
pub(crate) async fn seal_and_send(
    client: &PpqClient,
    url: &str,
    plaintext: &[u8],
    mut headers: reqwest::header::HeaderMap,
) -> Result<(FrameDecoder, reqwest::Response)> {
    // The bearer token and the sealed body only ever go to the origin we
    // attested. `starts_with` on the bare base URL would also accept
    // `https://api.ppq.ai.example.com/...`, so the boundary has to be a path
    // separator.
    let base = client.base_url.trim_end_matches('/');
    if !url.starts_with(base) || !url[base.len()..].starts_with('/') {
        return Err(Error::Ehbp(format!(
            "refusing to seal a request to {url}, which is outside the attested origin {base}"
        )));
    }

    let sealed = seal::seal(&client.attestation.hpke_public_key, plaintext)?;

    // EHBP requires chunked transfer encoding with no `Content-Length`.
    // `.body(Vec<u8>)` sets `Content-Length` and sends no `Transfer-Encoding`
    // — see `sends_the_sealed_body_chunked_without_a_content_length` — so the
    // body goes out as a single-item stream instead, which makes `reqwest`
    // frame it as chunked. (Measured 2026-08-15: the live enclave happens to
    // accept a `Content-Length` body as well, but the spec is explicit and a
    // streaming request body could not carry one anyway.)
    let one_chunk = futures::stream::iter([Ok::<Bytes, std::io::Error>(Bytes::from(sealed.body))]);
    let sealed_body = reqwest::Body::wrap_stream(one_chunk);

    // `insert`, not `RequestBuilder::header` — that one *appends*, so a caller
    // who already set `Content-Type` (rig's client does) would put two of them
    // on the wire.
    let mut bearer = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", client.api_key))
        .map_err(|_| Error::Attestation("API key is not a valid header value".into()))?;
    bearer.set_sensitive(true);
    headers.insert(reqwest::header::AUTHORIZATION, bearer);
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        "ehbp-encapsulated-key",
        reqwest::header::HeaderValue::from_str(&hex::encode(sealed.enc))
            .expect("hex is a valid header value"),
    );

    let response = client
        .http
        .post(url)
        .headers(headers)
        .body(sealed_body)
        .send()
        .await?;

    let status = response.status();
    let nonce_hex = response
        .headers()
        .get("ehbp-response-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let Some(nonce_hex) = nonce_hex else {
        // Missing nonce on 2xx is a body-substitution attack surface: an
        // on-path attacker strips the header and supplies plaintext. Fail
        // closed. On non-2xx it usually means an intermediary rejected the
        // request before the enclave saw it — surface it as explicitly
        // unauthenticated so callers cannot mistake it for enclave output.
        let body = response.text().await.unwrap_or_default();
        return Err(if status.is_success() {
            Error::Ehbp("2xx response without Ehbp-Response-Nonce".into())
        } else {
            Error::UnauthenticatedUpstream {
                status: status.as_u16(),
                body: cap_body(body),
            }
        });
    };

    let nonce = hex::decode(&nonce_hex)
        .map_err(|e| Error::Ehbp(format!("response nonce is not hex: {e}")))?;
    let opener: FrameOpener = sealed.session.opener(&nonce)?;
    Ok((FrameDecoder::new(opener), response))
}

/// Decrypt a sealed response in full.
///
/// A sealed body authenticates whatever its status line says, so a non-2xx
/// *is* enclave output — but it must never come back as `Ok`, or a caller
/// doing `resp["choices"][0]` on a rate-limit error would silently read
/// `Value::Null` instead of noticing the failure.
pub(crate) async fn open_body(
    mut decoder: FrameDecoder,
    response: reqwest::Response,
) -> Result<Vec<u8>> {
    let status = response.status();
    let mut out = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        out.extend(decoder.push(&chunk?)?);
    }
    decoder.finish()?;
    if !status.is_success() {
        return Err(Error::Enclave {
            status: status.as_u16(),
            body: cap_body(String::from_utf8_lossy(&out).into_owned()),
        });
    }
    Ok(out)
}

/// Decrypt a sealed response incrementally.
///
/// A sealed non-2xx never produces a stream: the status is checked before any
/// stream is built and the decrypted body is returned as `Err(Error::Enclave)`
/// instead. Yielding that body as a stream item would hand a consumer
/// expecting SSE a single chunk of error JSON with no signal that it isn't a
/// completion.
///
/// On the 2xx path the stream ends after its first error: the decoder is
/// poisoned by any failure, so continuing past one could only produce more
/// errors. A transport EOF that leaves a partial frame is itself an error —
/// the final item — so a truncated stream can never be mistaken for a complete
/// one.
pub(crate) async fn open_stream(
    mut decoder: FrameDecoder,
    response: reqwest::Response,
) -> Result<impl Stream<Item = Result<Bytes>>> {
    let status = response.status();
    let mut inner = response.bytes_stream();

    if !status.is_success() {
        let mut out = Vec::new();
        while let Some(chunk) = inner.next().await {
            out.extend(decoder.push(&chunk?)?);
        }
        decoder.finish()?;
        return Err(Error::Enclave {
            status: status.as_u16(),
            body: cap_body(String::from_utf8_lossy(&out).into_owned()),
        });
    }

    let stream = futures::stream::unfold(Some((decoder, inner)), |state| async move {
        let (mut decoder, mut inner) = state?;
        match inner.next().await {
            Some(Ok(chunk)) => match decoder.push(&chunk) {
                Ok(plain) => Some((Ok(Bytes::from(plain)), Some((decoder, inner)))),
                Err(e) => Some((Err(e), None)),
            },
            Some(Err(e)) => Some((Err(Error::Http(e)), None)),
            // Transport EOF: only a clean frame boundary ends the stream
            // successfully.
            None => match decoder.finish() {
                Ok(()) => None,
                Err(e) => Some((Err(e), None)),
            },
        }
    });

    // A transport chunk that completes no frame yields no plaintext; don't
    // surface those as empty items.
    Ok(stream.try_filter(|plain| futures::future::ready(!plain.is_empty())))
}

impl PpqClientBuilder {
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    pub fn trust_policy(mut self, policy: TrustPolicy) -> Self {
        self.trust_policy = Some(policy);
        self
    }

    /// Attest the enclave, then build a client bound to the attested key.
    ///
    /// This is the only place attestation happens; every request afterwards is
    /// sealed to the key proven here.
    pub async fn build(self) -> Result<PpqClient> {
        let api_key = self
            .api_key
            .ok_or_else(|| Error::Attestation("no API key configured".into()))?;
        let base_url = self
            .base_url
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let policy = self.trust_policy.unwrap_or_default();

        // `connect_timeout` bounds the handshake; `read_timeout` bounds a
        // stalled socket read and resets on every successful one, so it
        // cannot cut off a long-running but actively-streaming completion —
        // only a genuinely stuck enclave or CDN. Deliberately no total
        // `.timeout()`: that applies from connect until the body finishes,
        // which would kill a legitimately long SSE stream.
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build()?;

        // Attestation goes through the same client, so a stalled attestation
        // endpoint cannot hang `build()` — the one call every user makes.
        let attestation = attest::attest(&http, &base_url, &policy).await?;

        // Cross-check the advertised key config against the attested key. A
        // mismatch means the endpoint is serving a key the hardware never
        // vouched for.
        let advertised = http
            .get(format!("{base_url}/private/.well-known/hpke-keys"))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let config = keyconfig::parse(&advertised)?;
        if config.public_key != attestation.hpke_public_key {
            return Err(Error::Attestation(
                "advertised HPKE key does not match the attested key".into(),
            ));
        }

        Ok(PpqClient {
            http,
            base_url,
            api_key,
            attestation,
        })
    }
}

/// Offline end-to-end tests against an in-process EHBP server.
///
/// These exercise the parts of the request/response path that no unit test
/// below the client can reach: the wire framing of the outgoing request
/// (chunked, no `Content-Length`), the header set, the model-id split between
/// body and header, and every fail-closed branch of response handling.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn round_trips_a_completion_through_the_sealed_channel() {
        let (sk, pk) = keypair();
        let seen = Arc::new(Mutex::new(None));
        let seen_body = Arc::clone(&seen);
        let (base, recorded) = serve(move |req| {
            let (plaintext, sealed) = enclave(
                &sk,
                req,
                &[br#"{"choices":[{"message":"#, br#"{"content":"pong"}}]}"#],
            );
            *seen_body.lock().unwrap() = Some(plaintext);
            http_response(200, &[nonce_header()], &sealed)
        })
        .await;

        let out = client_for(&base, pk)
            .chat_completion(serde_json::json!({
                "model": "private/glm-5-2",
                "messages": [{"role": "user", "content": "ping"}],
            }))
            .await
            .expect("round trip succeeds");
        assert_eq!(out["choices"][0]["message"]["content"], "pong");

        // The enclave-internal id goes in the body, the user-facing one in the
        // header. Swapping them fails against the real enclave.
        let plaintext = seen.lock().unwrap().clone().unwrap();
        assert_eq!(plaintext["model"], "glm-5-2");
        let req = recorded.lock().unwrap().take().unwrap();
        assert_eq!(req.header("x-private-model"), "private/glm-5-2");
        assert_eq!(req.header("authorization"), "Bearer sk-test");
        assert_eq!(req.header("content-type"), "application/json");
        assert_eq!(req.header("x-query-source"), "api");
    }

    #[tokio::test]
    async fn sends_the_sealed_body_chunked_without_a_content_length() {
        let (sk, pk) = keypair();
        let (base, recorded) = serve(move |req| {
            let (_, sealed) = enclave(&sk, req, &[b"{}"]);
            http_response(200, &[nonce_header()], &sealed)
        })
        .await;

        client_for(&base, pk)
            .chat_completion(serde_json::json!({"model": "private/x"}))
            .await
            .unwrap();

        let req = recorded.lock().unwrap().take().unwrap();
        assert_eq!(
            req.header("transfer-encoding"),
            "chunked",
            "EHBP requires chunked transfer encoding"
        );
        assert!(
            !req.headers.contains_key("content-length"),
            "EHBP forbids Content-Length on a sealed request"
        );
    }

    #[tokio::test]
    async fn rejects_a_2xx_without_a_response_nonce() {
        let (_, pk) = keypair();
        let (base, _) = serve(|_| http_response(200, &[], br#"{"choices":["plaintext"]}"#)).await;

        let err = client_for(&base, pk)
            .chat_completion(serde_json::json!({"model": "private/x"}))
            .await
            .expect_err("a 2xx without the nonce must never yield a body");
        assert!(
            err.to_string().contains("without Ehbp-Response-Nonce"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn surfaces_a_non_2xx_without_a_nonce_as_unauthenticated() {
        let (_, pk) = keypair();
        let (base, _) = serve(|_| http_response(502, &[], b"<html>cdn error page</html>")).await;

        let err = client_for(&base, pk)
            .chat_completion(serde_json::json!({"model": "private/x"}))
            .await
            .expect_err("a plaintext error page is not enclave output");
        match err {
            Error::UnauthenticatedUpstream { status, body } => {
                assert_eq!(status, 502);
                assert!(body.contains("cdn error page"));
            }
            other => panic!("wrong variant: {other}"),
        }
    }

    #[tokio::test]
    async fn decrypts_a_sealed_non_2xx_but_surfaces_it_as_an_error() {
        // A sealed body authenticates: it *is* enclave output, whatever the
        // status line says. But a non-2xx status means the enclave itself
        // said no, so it must not come back as `Ok` — a caller doing
        // `resp["choices"][0]` on a rate-limit error would silently read
        // `Value::Null` instead of noticing the failure.
        let (sk, pk) = keypair();
        let (base, _) = serve(move |req| {
            let (_, sealed) = enclave(&sk, req, &[br#"{"error":{"message":"rate limited"}}"#]);
            http_response(429, &[nonce_header()], &sealed)
        })
        .await;

        let err = client_for(&base, pk)
            .chat_completion(serde_json::json!({"model": "private/x"}))
            .await
            .expect_err("a sealed non-2xx must not come back as Ok");
        match err {
            Error::Enclave { status, body } => {
                assert_eq!(status, 429);
                assert!(body.contains("rate limited"), "got: {body}");
            }
            other => panic!("wrong variant: {other}"),
        }
    }

    #[tokio::test]
    async fn decrypts_a_sealed_non_2xx_stream_but_surfaces_it_as_an_error() {
        // Same as above but for the streaming entry point: a sealed non-2xx
        // must never come back as a stream whose sole item is the decrypted
        // error body — that reads to a consumer as if it were SSE content.
        let (sk, pk) = keypair();
        let (base, _) = serve(move |req| {
            let (_, sealed) = enclave(&sk, req, &[br#"{"error":{"message":"payment required"}}"#]);
            http_response(402, &[nonce_header()], &sealed)
        })
        .await;

        // `expect_err` needs `T: Debug`, and the `Ok` type here is an opaque
        // stream, so match manually rather than requiring `Debug` on it.
        let err = match client_for(&base, pk)
            .chat_completion_stream(serde_json::json!({"model": "private/x"}))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("a sealed non-2xx must not yield a stream"),
        };
        match err {
            Error::Enclave { status, body } => {
                assert_eq!(status, 402);
                assert!(body.contains("payment required"), "got: {body}");
            }
            other => panic!("wrong variant: {other}"),
        }
    }

    #[tokio::test]
    async fn rejects_a_response_that_does_not_authenticate() {
        let (sk, pk) = keypair();
        let (base, _) = serve(move |req| {
            let (_, mut sealed) = enclave(&sk, req, &[b"{\"ok\":true}"]);
            sealed[6] ^= 0xFF;
            http_response(200, &[nonce_header()], &sealed)
        })
        .await;

        assert!(client_for(&base, pk)
            .chat_completion(serde_json::json!({"model": "private/x"}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn streams_decrypted_frames_in_order() {
        let (sk, pk) = keypair();
        let seen = Arc::new(Mutex::new(None));
        let seen_body = Arc::clone(&seen);
        let (base, _) = serve(move |req| {
            let (plaintext, sealed) = enclave(
                &sk,
                req,
                &[b"data: one\n\n", b"data: two\n\n", b"data: [DONE]\n\n"],
            );
            *seen_body.lock().unwrap() = Some(plaintext);
            http_response(200, &[nonce_header()], &sealed)
        })
        .await;

        let stream = client_for(&base, pk)
            .chat_completion_stream(serde_json::json!({"model": "private/glm-5-2"}))
            .await
            .unwrap();
        futures::pin_mut!(stream);
        let mut sse = String::new();
        while let Some(chunk) = stream.next().await {
            sse.push_str(std::str::from_utf8(&chunk.unwrap()).unwrap());
        }
        assert_eq!(sse, "data: one\n\ndata: two\n\ndata: [DONE]\n\n");
        assert_eq!(
            seen.lock().unwrap().clone().unwrap()["stream"],
            serde_json::Value::Bool(true),
            "streaming requests ask the enclave to stream"
        );
    }

    #[tokio::test]
    async fn a_truncated_stream_ends_in_an_error() {
        let (sk, pk) = keypair();
        let (base, _) = serve(move |req| {
            let (_, sealed) = enclave(&sk, req, &[b"data: one\n\n", b"data: [DONE]\n\n"]);
            // Cut the final frame short: transport EOF mid-frame must not look
            // like a completed stream.
            let cut = sealed.len() - 5;
            http_response(200, &[nonce_header()], &sealed[..cut])
        })
        .await;

        let stream = client_for(&base, pk)
            .chat_completion_stream(serde_json::json!({"model": "private/x"}))
            .await
            .unwrap();
        futures::pin_mut!(stream);
        let mut items = Vec::new();
        while let Some(item) = stream.next().await {
            items.push(item);
        }
        assert!(
            items.last().expect("at least one item").is_err(),
            "a truncated stream must end in an error"
        );
    }

    #[tokio::test]
    async fn rejects_a_body_without_a_model() {
        let (_, pk) = keypair();
        let c = client_for("http://127.0.0.1:1", pk);
        assert!(c
            .chat_completion(serde_json::json!({"messages": []}))
            .await
            .is_err());
        assert!(c
            .chat_completion(serde_json::json!("not an object"))
            .await
            .is_err());
    }

    /// `seal_and_send` takes a URL because the `rig` transport gets one from
    /// rig's own routing rather than building it here. A URL off the attested
    /// origin would carry the bearer token — and a body sealed to the enclave
    /// key — somewhere the hardware never vouched for, so it is refused. The
    /// look-alike host is the case a bare `starts_with` would let through.
    #[tokio::test]
    async fn refuses_to_seal_a_request_outside_the_attested_origin() {
        let (_, pk) = keypair();
        let client = client_for("https://api.ppq.ai", pk);

        for url in [
            "https://api.ppq.ai.attacker.example/private/v1/chat/completions",
            "https://attacker.example/private/v1/chat/completions",
        ] {
            let err = seal_and_send(&client, url, b"{}", Default::default())
                .await
                .map(|_| ())
                .expect_err("only the attested origin may receive a sealed request");
            assert!(
                err.to_string().contains("outside the attested origin"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn debug_redacts_the_api_key_on_the_client() {
        let secret = "sk-super-secret-do-not-leak";
        let (_, pk) = keypair();
        let mut client = client_for("http://127.0.0.1:1", pk);
        client.api_key = secret.to_string();

        let out = format!("{client:?}");
        assert!(!out.contains(secret), "api key leaked into Debug: {out}");
        assert!(out.contains("redacted"), "got: {out}");
        // Other fields stay visible; they are useful for debugging.
        assert!(out.contains("127.0.0.1:1"), "got: {out}");
    }

    #[test]
    fn debug_redacts_the_api_key_on_the_builder() {
        let secret = "sk-super-secret-do-not-leak";
        let builder = PpqClient::builder()
            .api_key(secret)
            .base_url("http://127.0.0.1:1");

        let out = format!("{builder:?}");
        assert!(!out.contains(secret), "api key leaked into Debug: {out}");
        assert!(out.contains("redacted"), "got: {out}");
        assert!(out.contains("127.0.0.1:1"), "got: {out}");
    }
}
