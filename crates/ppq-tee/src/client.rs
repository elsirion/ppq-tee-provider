//! The attested client: attest once, then seal every request to the key the
//! hardware proved.

use crate::attest::{self, Attestation, TrustPolicy};
use crate::ehbp::{keyconfig, open::FrameOpener, seal, stream::FrameDecoder};
use crate::models::{self, PrivateModel};
use crate::{Error, Result};
use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt};

pub const DEFAULT_BASE_URL: &str = "https://api.ppq.ai";

#[derive(Debug, Clone)]
pub struct PpqClient {
    pub(crate) http: reqwest::Client,
    pub(crate) base_url: String,
    pub(crate) api_key: String,
    pub(crate) attestation: Attestation,
}

#[derive(Debug, Default)]
pub struct PpqClientBuilder {
    api_key: Option<String>,
    base_url: Option<String>,
    trust_policy: Option<TrustPolicy>,
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
    /// (e.g. a rate-limit error the enclave itself produced) is returned the
    /// same way: it authenticated, so it *is* enclave output. Only responses
    /// that never carried an `Ehbp-Response-Nonce` are errors here.
    pub async fn chat_completion(&self, mut body: serde_json::Value) -> Result<serde_json::Value> {
        let model = self.take_model(&mut body)?;
        let (mut decoder, response) = self.send_sealed(&body, &model).await?;
        let mut out = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            out.extend(decoder.push(&chunk?)?);
        }
        decoder.finish()?;
        Ok(serde_json::from_slice(&out)?)
    }

    /// Stream one OpenAI-format chat completion; yields decrypted SSE bytes.
    ///
    /// The stream ends after its first error: the decoder is poisoned by any
    /// failure, so continuing past one could only produce more errors. A
    /// transport EOF that leaves a partial frame is itself an error — the
    /// final item — so a truncated stream can never be mistaken for a
    /// complete one.
    pub async fn chat_completion_stream(
        &self,
        mut body: serde_json::Value,
    ) -> Result<impl Stream<Item = Result<Bytes>>> {
        let model = self.take_model(&mut body)?;
        body["stream"] = serde_json::Value::Bool(true);
        let (decoder, response) = self.send_sealed(&body, &model).await?;

        let stream = futures::stream::unfold(
            Some((decoder, response.bytes_stream())),
            |state| async move {
                let (mut decoder, mut inner) = state?;
                match inner.next().await {
                    Some(Ok(chunk)) => match decoder.push(&chunk) {
                        Ok(plain) => Some((Ok(Bytes::from(plain)), Some((decoder, inner)))),
                        Err(e) => Some((Err(e), None)),
                    },
                    Some(Err(e)) => Some((Err(Error::Http(e)), None)),
                    // Transport EOF: only a clean frame boundary ends the
                    // stream successfully.
                    None => match decoder.finish() {
                        Ok(()) => None,
                        Err(e) => Some((Err(e), None)),
                    },
                }
            },
        );

        // A transport chunk that completes no frame yields no plaintext;
        // don't surface those as empty items.
        Ok(stream.try_filter(|plain| futures::future::ready(!plain.is_empty())))
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
        let plaintext = serde_json::to_vec(body)?;
        let sealed = seal::seal(&self.attestation.hpke_public_key, &plaintext)?;

        // EHBP requires chunked transfer encoding with no `Content-Length`.
        // `.body(Vec<u8>)` sets `Content-Length` and sends no
        // `Transfer-Encoding` — see
        // `sends_the_sealed_body_chunked_without_a_content_length` — so the
        // body goes out as a single-item stream instead, which makes `reqwest`
        // frame it as chunked. (Measured 2026-08-15: the live enclave happens
        // to accept a `Content-Length` body as well, but the spec is explicit
        // and a streaming request body could not carry one anyway.)
        let one_chunk =
            futures::stream::iter([Ok::<Bytes, std::io::Error>(Bytes::from(sealed.body))]);
        let sealed_body = reqwest::Body::wrap_stream(one_chunk);

        let response = self
            .http
            .post(format!("{}/private/v1/chat/completions", self.base_url))
            .bearer_auth(&self.api_key)
            .header("Content-Type", "application/json")
            .header("Ehbp-Encapsulated-Key", hex::encode(sealed.enc))
            .header("X-Private-Model", model)
            .header("x-query-source", "api")
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
                    body,
                }
            });
        };

        let nonce = hex::decode(&nonce_hex)
            .map_err(|e| Error::Ehbp(format!("response nonce is not hex: {e}")))?;
        let opener: FrameOpener = sealed.session.opener(&nonce)?;
        Ok((FrameDecoder::new(opener), response))
    }
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

        let attestation = attest::attest(&base_url, &policy).await?;

        // Cross-check the advertised key config against the attested key. A
        // mismatch means the endpoint is serving a key the hardware never
        // vouched for.
        let advertised = reqwest::get(format!("{base_url}/private/.well-known/hpke-keys"))
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
            http: reqwest::Client::new(),
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
    use crate::ehbp::open::{FrameSealer, RESPONSE_EXPORT_LABEL};
    use hpke::{
        aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as _, OpModeR,
        Serializable,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    type ServerKey = <X25519HkdfSha256 as hpke::Kem>::PrivateKey;

    /// The response nonce our fake enclave always uses.
    const NONCE: [u8; 32] = [0x11; 32];

    /// A request as it arrived on the wire.
    struct Recorded {
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    impl Recorded {
        fn header(&self, name: &str) -> &str {
            self.headers
                .get(name)
                .map(String::as_str)
                .unwrap_or_else(|| panic!("missing header {name}: {:?}", self.headers))
        }
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    async fn fill_at_least(sock: &mut TcpStream, buf: &mut Vec<u8>, want: usize) {
        while buf.len() < want {
            let mut tmp = [0u8; 4096];
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0, "unexpected EOF while reading the request");
            buf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn read_chunked(sock: &mut TcpStream, rest: &mut Vec<u8>) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let line_end = loop {
                if let Some(p) = find(rest, b"\r\n") {
                    break p;
                }
                let want = rest.len() + 1;
                fill_at_least(sock, rest, want).await;
            };
            let size = usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).unwrap(), 16)
                .expect("chunk size is hex");
            fill_at_least(sock, rest, line_end + 2 + size + 2).await;
            out.extend_from_slice(&rest[line_end + 2..line_end + 2 + size]);
            rest.drain(..line_end + 2 + size + 2);
            if size == 0 {
                return out;
            }
        }
    }

    async fn read_request(sock: &mut TcpStream) -> Recorded {
        let mut buf = Vec::new();
        let head_end = loop {
            if let Some(p) = find(&buf, b"\r\n\r\n") {
                break p + 4;
            }
            let want = buf.len() + 1;
            fill_at_least(sock, &mut buf, want).await;
        };
        let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
        let mut headers = HashMap::new();
        for line in head.lines().skip(1) {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        let mut rest = buf[head_end..].to_vec();

        let chunked = headers
            .get("transfer-encoding")
            .is_some_and(|v| v.contains("chunked"));
        let body = if chunked {
            read_chunked(sock, &mut rest).await
        } else {
            let len: usize = headers
                .get("content-length")
                .map(|v| v.parse().unwrap())
                .unwrap_or(0);
            fill_at_least(sock, &mut rest, len).await;
            rest.truncate(len);
            rest
        };
        Recorded { headers, body }
    }

    /// Serve exactly one request from `127.0.0.1`, then close the connection.
    ///
    /// `handler` returns the raw response bytes, so a test can send a
    /// deliberately malformed or truncated one. The recorded request is handed
    /// back through the returned handle for the test to assert on.
    async fn serve<F>(handler: F) -> (String, Arc<Mutex<Option<Recorded>>>)
    where
        F: FnOnce(&Recorded) -> Vec<u8> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let recorded = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&recorded);

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let request = read_request(&mut sock).await;
            let response = handler(&request);
            *sink.lock().unwrap() = Some(request);
            sock.write_all(&response).await.unwrap();
            // Body framed by close, so a truncated body stays truncated.
            sock.shutdown().await.unwrap();
        });

        (base, recorded)
    }

    /// A response whose body is delimited by connection close.
    fn http_response(status: u16, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n").into_bytes();
        for (k, v) in headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(body);
        out
    }

    fn keypair() -> (ServerKey, [u8; 32]) {
        let (sk, pk) = X25519HkdfSha256::gen_keypair();
        let pk_bytes: [u8; 32] = pk.to_bytes().as_slice().try_into().unwrap();
        (sk, pk_bytes)
    }

    /// The enclave half: open the sealed request, then seal `parts` back.
    ///
    /// Built on `hpke::setup_receiver` rather than on any client code, so a
    /// passing round trip means the client's derivation agrees with an
    /// independent implementation of RFC 9180.
    fn enclave(
        sk: &ServerKey,
        request: &Recorded,
        parts: &[&[u8]],
    ) -> (serde_json::Value, Vec<u8>) {
        let enc_bytes: [u8; 32] = hex::decode(request.header("ehbp-encapsulated-key"))
            .expect("encapsulated key is hex")
            .try_into()
            .expect("encapsulated key is 32 bytes");
        let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&enc_bytes).unwrap();
        let mut ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            sk,
            &enc,
            seal::REQUEST_INFO,
        )
        .unwrap();

        let mut plaintext = Vec::new();
        let mut rest = &request.body[..];
        while rest.len() >= 4 {
            let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            rest = &rest[4..];
            plaintext.extend(ctx.open(&rest[..n], b"").expect("request authenticates"));
            rest = &rest[n..];
        }

        let mut secret = [0u8; 32];
        ctx.export(RESPONSE_EXPORT_LABEL, &mut secret).unwrap();
        let mut sealer = FrameSealer::new(&secret, &enc_bytes, &NONCE).unwrap();
        let mut body = Vec::new();
        for p in parts {
            body.extend(sealer.seal_frame(p).unwrap());
        }
        (
            serde_json::from_slice(&plaintext).expect("request body is JSON"),
            body,
        )
    }

    fn client_for(base: &str, hpke_public_key: [u8; 32]) -> PpqClient {
        PpqClient {
            http: reqwest::Client::new(),
            base_url: base.to_string(),
            api_key: "sk-test".to_string(),
            attestation: Attestation {
                hpke_public_key,
                tls_key_fingerprint: [0u8; 32],
                measurement: [0u8; 48],
                domain: "test.invalid".to_string(),
            },
        }
    }

    fn nonce_header() -> (&'static str, String) {
        ("Ehbp-Response-Nonce", hex::encode(NONCE))
    }

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
    async fn decrypts_a_sealed_non_2xx() {
        // A sealed body authenticated: it *is* enclave output, whatever the
        // status line says.
        let (sk, pk) = keypair();
        let (base, _) = serve(move |req| {
            let (_, sealed) = enclave(&sk, req, &[br#"{"error":{"message":"rate limited"}}"#]);
            http_response(429, &[nonce_header()], &sealed)
        })
        .await;

        let out = client_for(&base, pk)
            .chat_completion(serde_json::json!({"model": "private/x"}))
            .await
            .unwrap();
        assert_eq!(out["error"]["message"], "rate limited");
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
}
