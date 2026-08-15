# ppq-tee

A Rust library that talks to [PPQ.AI](https://ppq.ai)'s TEE-backed ("private")
inference models over a hardware-attested, end-to-end-encrypted channel —
**in-process**. No local proxy, no subprocess. It reimplements the behaviour
of the TypeScript
[`PayPerQ/ppq-private-mode-proxy`](https://github.com/PayPerQ/ppq-private-mode-proxy)
as a library.

Attestation runs once, at `PpqClient` construction. Every completion after
that is HPKE-sealed inside your own process before it reaches the network.

## The guarantee

PPQ's servers see request and response **bodies** as ciphertext only. HTTP
headers are not covered — the `Authorization` bearer token, the model id
(`X-Private-Model`) and request timing stay visible to PPQ and to anything on
the network path. What is sealed is every request body, to a public key the
client verifies belongs to a specific, currently-running enclave — not to
PPQ's word for it. That verification chains through three independent layers:

1. A **sigstore DSSE build attestation** (Fulcio-issued certificate, logged
   in Rekor, signed by GitHub Actions in
   `tinfoilsh/confidential-model-router`) states the SEV-SNP measurement the
   enclave image is supposed to have.
2. An **AMD SEV-SNP attestation report**, signed by a VCEK chaining to an
   embedded AMD root, proves the currently-running enclave actually has that
   measurement.
3. The report's `report_data[32..64]` is the enclave's HPKE public key —
   hardware-attested, not asserted by PPQ's API.

Request and response bodies are then sealed to that key using
[EHBP](https://github.com/tinfoilsh/encrypted-http-body-protocol) (RFC 9180
HPKE: X25519-HKDF-SHA256 / HKDF-SHA256 / AES-256-GCM). See
[Security model](#security-model) below for what this does *not* cover.

Live-verified against `api.ppq.ai` on 2026-08-15: enclave
`inference.tinfoil.sh`, measurement prefix `6d657b353726893e`.

## Quickstart

```rust
use ppq_tee::PpqClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Attests the enclave once, here. Every request after this is sealed to
    // the key that attestation proved.
    let ppq = PpqClient::builder()
        .api_key(std::env::var("PPQ_API_KEY")?)
        .build()
        .await?;

    let resp = ppq
        .chat_completion(serde_json::json!({
            "model": "private/glm-5-2",
            "messages": [{"role": "user", "content": "Name three prime numbers."}],
            "max_tokens": 512,
        }))
        .await?;

    println!("{}", resp["choices"][0]["message"]["content"]);
    Ok(())
}
```

`PpqClient::chat_completion_stream` returns a `Stream` of decrypted SSE
bytes for streaming completions. `PpqClient::list_models` returns the
TEE-backed (`privacyLevel == "e2e"`) subset of PPQ's catalogue — see
[Security model](#security-model) for why that call is not itself a trust
input.

## rig integration

Enable the `rig` feature to get a
[`rig-core`](https://crates.io/crates/rig-core) `CompletionModel`:

```toml
ppq-tee = { version = "...", features = ["rig"] }
```

`PpqClient::completion_model(id)` builds a `PpqCompletionModel`, an ordinary
`rig_core::completion::CompletionModel` backed by the sealed EHBP transport.
Driving it directly (this is what `examples/rig_agent.rs` does):

```rust
use rig_core::completion::CompletionModel;

let ppq = PpqClient::builder().api_key(api_key).build().await?;
let model = ppq.completion_model("private/glm-5-2")?;

let response = model
    .completion_request("Name three prime numbers.")
    .preamble("You are concise.".to_string())
    .max_tokens(512)
    .send()
    .await?;
```

As of `rig-core` 0.41, `Agent`/`AgentBuilder` moved out of `rig-core` into
the separate `rig-agent` crate — `ppq-tee` does not depend on it. Since
`PpqCompletionModel` already implements `rig_core::completion::CompletionModel`,
which is exactly what `rig_agent::AgentBuilder::new` accepts, wrapping it in
an agent is one dependency away:

```toml
rig-agent = "..."
```

```rust
// `prompt` is a trait method, so the trait has to be in scope.
use rig_agent::completion::Prompt;

let agent = rig_agent::agent::AgentBuilder::new(
    ppq.completion_model("private/glm-5-2")?
)
.preamble("You are concise.")
.build();

println!("{}", agent.prompt("Name three prime numbers.").await?);
```

Run the example with:

```bash
PPQ_API_KEY=sk-... cargo run -p ppq-tee --features rig --example rig_agent
```

## Running tests

```bash
# Offline suite: pinned attestation fixtures, EHBP round-trips against an
# in-process server, negative attestation tests. No network access needed.
cargo test --all-features

# The `test-server` feature exposes the EHBP server-half primitives
# (`FrameSealer`) used to build that in-process server; it is off by default
# because a client build has no business sealing responses.
cargo test -p ppq-tee --features test-server

# Live tests: real attestation and completions against api.ppq.ai. Ignored
# by default because they need network access and spend API credit.
PPQ_API_KEY=sk-... cargo test -p ppq-tee --test live -- --ignored
```

## Security model

What is protected, and what is not:

- **Bodies are encrypted; HTTP headers are not.** The `Authorization`
  bearer token, the model id (`X-Private-Model`), and request timing are
  visible to PPQ and anything on the network path to it. Only the JSON
  request/response bodies are opaque.
- **The model catalogue (`GET /v1/models`) is not a trust input.** It is
  served by PPQ's plaintext API, not from inside the enclave, so it is
  unauthenticated discovery metadata — never used to decide what's safe to
  send. A model id is merely relayed to the attested enclave, which rejects
  anything it doesn't serve; the security guarantee comes entirely from
  attestation and is independent of the catalogue.
- **Freshness rests on the sigstore layer, not the hardware report.** The
  SEV-SNP report's `report_data` carries the enclave's own keys, not a
  client-supplied nonce, so a replayed *genuine* report still verifies as
  genuine. A malicious server could otherwise replay any attestation
  `tinfoilsh/confidential-model-router` has ever signed — including an older
  release with a known-bad measurement. Freshness is instead enforced by
  `TrustPolicy::max_attestation_age` (default 90 days) against the Rekor
  entry's `integratedTime`. This is inherent to Tinfoil's attestation
  design, not a defect in this crate.
- **`attestation().domain` is server-reported, not attested.** It is echoed
  verbatim from the attestation bundle's JSON and nothing binds it to the
  enclave, so a malicious PPQ could serve a genuine attestation for a real
  Tinfoil enclave under any domain string it liked. Confidentiality does not
  depend on it — bodies are sealed to the *attested* HPKE key — but it is not
  evidence of which deployment answered. Binding it would mean checking the
  SHA-256 of the `enclaveCert` SubjectPublicKeyInfo against the report's
  `tls_key_fingerprint`, then that certificate's SAN against `domain`;
  neither check is implemented.
- **AMD certificate validity periods are not checked.** Documented on
  `verify_chain`: AMD's ARKs run to 2047 and VCEKs are not revoked or rotated
  per-boot, so an expiry check would add no security here while making a
  committed test fixture rot. Separately — and not covered by that doc block
  — AMD's CRL endpoint is never consulted; this crate makes no revocation
  query at all.
- **Turin (AMD family 1Ah) attestations are refused outright.** The
  `TCB_VERSION` field layout differs from Milan/Genoa (family 19h) in a way
  this crate does not know how to parse, and it will not guess.
- **The AMD root certificates are vendored, not fetched live.** They come
  from `virtee/sev` rather than AMD's Key Distribution Service (which was
  unreachable from the environment this crate was built in); provenance,
  SHA-256 digests, and an independent cross-check against Tinfoil's own
  JavaScript verifier are recorded in
  `crates/ppq-tee/testdata/amd/PROVENANCE.md`.

## Design

The full design — attestation pipeline, EHBP wire format, trust policy
rationale — is in
[`docs/superpowers/specs/2026-08-15-ppq-tee-in-process-provider-design.md`](docs/superpowers/specs/2026-08-15-ppq-tee-in-process-provider-design.md).
