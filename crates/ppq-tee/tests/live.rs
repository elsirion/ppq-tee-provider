//! Live tests against api.ppq.ai. Ignored by default: they need network access
//! and spend credit on the configured key.
//!
//! Run with: PPQ_API_KEY=sk-... cargo test -p ppq-tee --test live -- --ignored
//!
//! These are the only tests where the other half of EHBP is the real enclave
//! rather than our own code, so they are what actually pins the protocol
//! constants (`"ehbp request"`, `"ehbp response"`, the `enc ‖ response_nonce`
//! HKDF salt, and the big-endian per-frame sequence). A decryption failure
//! here is a protocol bug, not a configuration problem.

use futures::StreamExt;
use ppq_tee::PpqClient;

fn key() -> String {
    std::env::var("PPQ_API_KEY").expect("set PPQ_API_KEY to run live tests")
}

async fn client() -> PpqClient {
    PpqClient::builder()
        .api_key(key())
        .build()
        .await
        .expect("attestation succeeds against the live enclave")
}

#[tokio::test]
#[ignore]
async fn attests_the_live_enclave() {
    let c = client().await;
    // The attestation check is `client()` itself: `build()` returns `Err`
    // unless the hardware report chained to AMD and matched the signed build
    // attestation. `domain` is *not* part of that — it is echoed verbatim from
    // the bundle JSON (see `Attestation::domain`), so this is a smoke check
    // that we reached the deployment we expected, not an attestation check.
    assert_eq!(c.attestation().domain, "inference.tinfoil.sh");
    assert_ne!(c.attestation().hpke_public_key, [0u8; 32]);
}

#[tokio::test]
#[ignore]
async fn lists_private_models() {
    let models = client().await.list_models().await.unwrap();
    assert!(!models.is_empty(), "PPQ serves at least one e2e model");
    assert!(models.iter().all(|m| m.id.starts_with("private/")));
}

#[tokio::test]
#[ignore]
async fn completes_a_prompt() {
    let resp = client()
        .await
        .chat_completion(serde_json::json!({
            "model": "private/glm-5-2",
            "messages": [{"role": "user", "content": "Reply with exactly: pong"}],
            // glm-5-2 is a reasoning model: it spends tokens on a `reasoning`
            // field before it emits any `content`, so too small a budget
            // returns `finish_reason: "length"` with `content: null`. The
            // budget has to clear the reasoning, or this asserts nothing about
            // the completion.
            "max_tokens": 512,
        }))
        .await
        .unwrap();
    // The enclave echoes the id it was actually given, which is the
    // enclave-internal one — the `private/` prefix belongs in the header only.
    assert_eq!(resp["model"], "glm-5-2");
    let text = resp["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_else(|| panic!("no completion in: {resp}"));
    assert!(text.to_lowercase().contains("pong"), "got: {text}");
}

#[tokio::test]
#[ignore]
async fn streams_a_prompt() {
    let stream = client()
        .await
        .chat_completion_stream(serde_json::json!({
            "model": "private/glm-5-2",
            "messages": [{"role": "user", "content": "Count: 1 2 3"}],
            "max_tokens": 32,
        }))
        .await
        .unwrap();
    futures::pin_mut!(stream);

    let mut sse = String::new();
    while let Some(chunk) = stream.next().await {
        sse.push_str(std::str::from_utf8(&chunk.unwrap()).unwrap());
    }
    assert!(sse.contains("data:"), "decrypted stream is SSE: {sse}");
    assert!(sse.contains("[DONE]"), "stream reached its terminal event");
}

#[tokio::test]
#[ignore]
async fn rejects_a_tampered_trust_policy() {
    use ppq_tee::attest::TrustPolicy;
    let result = PpqClient::builder()
        .api_key(key())
        .trust_policy(TrustPolicy {
            signer_repository: "attacker/evil".into(),
            ..TrustPolicy::default()
        })
        .build()
        .await;
    assert!(result.is_err(), "a wrong signer repo must fail attestation");
}
