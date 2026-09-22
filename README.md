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

Live-verified against `api.ppq.ai` on 2026-09-22: enclave
`inference.tinfoil.sh`, measurement prefix `5d5c37d9ba597467`. The
measurement changes with every Tinfoil redeploy; see the proxy section for
how a long-running process keeps up.

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
            "model": "private/glm-5-3-flash",
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
let model = ppq.completion_model("private/glm-5-3-flash")?;

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
    ppq.completion_model("private/glm-5-3-flash")?
)
.preamble("You are concise.")
.build();

println!("{}", agent.prompt("Name three prime numbers.").await?);
```

Run the example with:

```bash
PPQ_API_KEY=sk-... cargo run -p ppq-tee --features rig --example rig_agent
```

## Local OpenAI-compatible proxy

`crates/ppq-tee-proxy` wraps the library in a small daemon that speaks the
OpenAI HTTP API on localhost, so any OpenAI-compatible client (the openai
SDKs, aider, Open WebUI, `llm`, editor plugins) can use the TEE models by
pointing its base URL at the proxy. The proxy holds the PPQ API key; every
chat completion goes out sealed to the attested enclave key.

| Method | Path | Behaviour |
| --- | --- | --- |
| `GET` | `/v1/models` | The TEE-backed models as an OpenAI list object. |
| `GET` | `/v1/models/{id}` | One model object, or an OpenAI-format 404. |
| `POST` | `/v1/chat/completions` | Sealed and relayed; `"stream": true` yields `text/event-stream`. |

`GET /v1/models` is the OpenAI API's own model-discovery endpoint, so
clients find the models without configuration. Each entry carries the
standard `id`/`object`/`created`/`owned_by` fields plus `name`,
`context_length` and `pricing` as extensions; `created` is `0` because PPQ's
catalogue has no creation time. As with the library, the list is discovery
metadata and not a trust input.

Run it ad hoc:

```bash
PPQ_API_KEY=sk-... nix run github:elsirion/ppq-tee-provider
# or, from a checkout: PPQ_API_KEY=sk-... nix run .
curl http://127.0.0.1:8090/v1/models
OPENAI_BASE_URL=http://127.0.0.1:8090/v1 OPENAI_API_KEY=unused aider --model openai/private/glm-5-3-flash
```

Or deploy it as a NixOS service. The key file is read through systemd's
credential mechanism, so it can be root-only and must not be in the Nix
store:

```nix
{
  inputs.ppq-tee-proxy.url = "github:elsirion/ppq-tee-provider";

  outputs = { nixpkgs, ppq-tee-proxy, ... }: {
    nixosConfigurations.laptop = nixpkgs.lib.nixosSystem {
      modules = [
        ppq-tee-proxy.nixosModules.default
        {
          services.ppq-tee-proxy = {
            enable = true;
            apiKeyFile = "/run/secrets/ppq-api-key"; # e.g. from sops-nix or agenix
            # listenAddress = "127.0.0.1"; port = 8090; reattestAfter = "1h";
          };
        }
      ];
    };
  };
}
```

Flags (each also an environment variable): `--listen` (`PPQ_PROXY_LISTEN`,
default `127.0.0.1:8090`), `--api-key-file` (`PPQ_API_KEY_FILE`; or the key
itself in `PPQ_API_KEY`), `--base-url` (`PPQ_BASE_URL`), `--reattest-after`
(`PPQ_REATTEST_AFTER`, default `1h`).

What the proxy adds on top of the library, and what it does not:

- **It re-attests.** The library binds a client to one attested key for its
  lifetime; the enclave key changes whenever Tinfoil redeploys. The proxy
  attests at startup, again once the attestation is `--reattest-after` old,
  and immediately (at most once per 30 s) when a request fails in a way the
  enclave did not authenticate. A failed request is retried once after
  re-attestation; an authenticated enclave error is relayed as-is and never
  retried.
- **Errors keep OpenAI's shape.** An enclave-authenticated error (rate limit,
  unknown model) is passed through with its status. Anything that never
  reached the enclave — a rejection by PPQ's front end, a transport or
  protocol failure — is a `502` whose message says so; a failed
  re-attestation is a `503`. Nothing unauthenticated is ever presented as a
  completion.
- **It has no client authentication.** Whoever can reach the listening
  socket can spend the API key, which is why it binds to loopback by
  default. Put your own auth in front if you expose it further.
- **Same header caveat as the library.** The bearer token and model id are
  still visible to PPQ; only bodies are sealed.

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
- **`attestation().domain` is not attested.** The string is echoed from the
  attestation bundle's JSON. With `TrustPolicy::check_enclave_certificate` on
  — the default — verification does check that the SHA-256 of the
  `enclaveCert` SubjectPublicKeyInfo equals the report's `tls_key_fingerprint`
  (`report_data[0..32]`), and then that the same certificate's subjectAltName
  covers `domain` under RFC 6125 rules (case-insensitive, wildcards only as a
  whole leftmost label matching exactly one label and never over a single-label
  suffix like `*.com`, `dNSName` entries only, no Common Name fallback). That
  proves the presented certificate carries the attested public key and that it
  says it covers the claimed name.

  It does **not** prove the certificate was issued by anyone: nothing verifies
  its signature. An attacker holding a genuine bundle can rebuild the
  certificate around that same, byte-identical SubjectPublicKeyInfo, give it
  any subjectAltName it likes, leave the signature bits garbage, and pass both
  checks. `report_data[0..32]` binds *key → hardware*; the CA's issuance
  signature is what would bind *name → key*, and it is not checked. So treat
  `domain` as a misconfiguration and smoke-test guard — it catches a server
  that got its own certificate wrong, since the comparison is between the
  bundle's `domain` and the bundle's own certificate (self-consistency, not
  attestation) — never as a verification result or a basis for policy. It
  does *not* catch a client pointed at a genuine-but-wrong deployment: that
  bundle is internally self-consistent and passes. A caller who needs that
  must compare `attestation().domain` against the domain it expected itself.
  Making it trustworthy would mean verifying the certificate chains
  to a WebPKI root; that is not done because the bundle ships only the leaf (no
  intermediate) and that leaf rotates roughly every 90 days. Confidentiality
  never depended on any of it — bodies are sealed to the *attested* HPKE key.
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
