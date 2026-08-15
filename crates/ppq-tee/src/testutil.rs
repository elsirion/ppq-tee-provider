//! An in-process EHBP enclave for tests.
//!
//! The server half is built on `hpke::setup_receiver` and this crate's
//! `FrameSealer`, not on the client code under test, so a passing round trip
//! means the client's derivation agrees with an independent implementation of
//! RFC 9180 rather than merely agreeing with itself.
//!
//! Shared by `client.rs` and `rig.rs`: both need a real sealed conversation to
//! assert against, and a second hand-rolled copy of this harness would be free
//! to drift from the protocol the first one speaks.

use crate::attest::Attestation;
use crate::ehbp::open::{FrameSealer, RESPONSE_EXPORT_LABEL};
use crate::ehbp::seal;
use crate::PpqClient;
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as _, OpModeR,
    Serializable,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub type ServerKey = <X25519HkdfSha256 as hpke::Kem>::PrivateKey;

/// The response nonce our fake enclave always uses.
pub const NONCE: [u8; 32] = [0x11; 32];

/// A request as it arrived on the wire.
pub struct Recorded {
    /// The request line, e.g. `POST /private/v1/chat/completions HTTP/1.1`.
    pub request_line: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Recorded {
    pub fn header(&self, name: &str) -> &str {
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
    let request_line = head.lines().next().unwrap_or_default().to_string();
    let mut headers: HashMap<String, String> = HashMap::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            // Repeated header names are joined rather than overwritten, so a
            // test asserting on a header value also catches an accidentally
            // duplicated one — `reqwest`'s `RequestBuilder::header` appends.
            headers
                .entry(k.trim().to_ascii_lowercase())
                .and_modify(|existing| {
                    existing.push_str(", ");
                    existing.push_str(v.trim());
                })
                .or_insert_with(|| v.trim().to_string());
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
    Recorded {
        request_line,
        headers,
        body,
    }
}

/// Serve exactly one request from `127.0.0.1`, then close the connection.
///
/// `handler` returns the raw response bytes, so a test can send a deliberately
/// malformed or truncated one. The recorded request is handed back through the
/// returned handle for the test to assert on.
pub async fn serve<F>(handler: F) -> (String, Arc<Mutex<Option<Recorded>>>)
where
    F: Fn(&Recorded) -> Vec<u8> + Send + 'static,
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
pub fn http_response(status: u16, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n").into_bytes();
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

pub fn keypair() -> (ServerKey, [u8; 32]) {
    let (sk, pk) = X25519HkdfSha256::gen_keypair();
    let pk_bytes: [u8; 32] = pk.to_bytes().as_slice().try_into().unwrap();
    (sk, pk_bytes)
}

/// The enclave half: open the sealed request, then seal `parts` back.
///
/// Returns the request body it decrypted (always JSON on this API) alongside
/// the sealed response bytes.
pub fn enclave(
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

/// A client already "attested" to `hpke_public_key`, pointed at `base`.
pub fn client_for(base: &str, hpke_public_key: [u8; 32]) -> PpqClient {
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

pub fn nonce_header() -> (&'static str, String) {
    ("Ehbp-Response-Nonce", hex::encode(NONCE))
}
