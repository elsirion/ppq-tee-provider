# PPQ TEE in-process LLM provider — design

**Date:** 2026-08-15
**Status:** approved, ready for implementation planning

## 1. Goal

Provide a Rust library that talks to PPQ.AI's TEE-backed ("private") inference
models over a verified, end-to-end-encrypted channel — **in-process**, with no
localhost proxy and no subprocess.

This reimplements the behaviour of
[`PayPerQ/ppq-private-mode-proxy`](https://github.com/PayPerQ/ppq-private-mode-proxy)
(TypeScript, runs an HTTP proxy on port 8787) as a library. Attestation runs
once when the client is constructed; every completion afterwards is HPKE-sealed
inside the caller's own process.

The resulting type must be usable as a `rig-core` LLM provider.

### Non-goals

- No HTTP proxy server, no `/v1/messages` Anthropic dialect, no status page.
  Those exist in the reference implementation only because it is a proxy.
- No support for PPQ's non-TEE (`anon`, `zdr`) models. Those need no encryption
  layer and are already served by rig's stock OpenAI-compatible providers
  pointed at `api.ppq.ai`.

## 2. Background: how the PPQ private channel works

Verified live against `api.ppq.ai` on 2026-08-15. Four layers:

1. **Attestation bundle** — `GET https://api.ppq.ai/private/attestation` returns
   JSON containing a sigstore DSSE bundle, a gzipped AMD SEV-SNP attestation
   report, the AMD VCEK certificate, and the enclave's TLS certificate.
2. **Sigstore layer** — a DSSE in-toto statement, signed by a short-lived Fulcio
   certificate issued to a GitHub Actions OIDC identity and logged in Rekor. Its
   predicate (`https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1`) carries the
   expected `snp_measurement` for the enclave image.
3. **SEV-SNP layer** — the attestation report proves the running enclave has that
   measurement, signed by a VCEK chaining to AMD's root. The report's 64-byte
   `report_data` field carries the enclave's public keys.
4. **EHBP** — [Encrypted HTTP Body Protocol](https://github.com/tinfoilsh/encrypted-http-body-protocol),
   HPKE (RFC 9180) sealing of HTTP bodies using the attested public key. Headers
   stay cleartext so PPQ can route and bill; bodies are opaque to PPQ.

Tinfoil publishes SDKs in Go, JavaScript, Python and Swift. **There is no Rust
SDK**, and no crate implements EHBP. Layers 2–4 are therefore a genuine port.

## 3. Workspace layout

`rig-core` is behind a cargo feature so its release churn cannot break the
crypto layer, and so non-rig callers need not pull it in.

```
ppq-tee-proxy/
├── flake.nix / flake.lock / .envrc
├── Cargo.toml                    # workspace
├── crates/ppq-tee/
│   ├── Cargo.toml                # default = []; feature "rig" -> rig-core 0.41
│   ├── src/
│   │   ├── lib.rs
│   │   ├── attest/
│   │   │   ├── mod.rs            # verify_bundle() orchestration
│   │   │   ├── bundle.rs         # fetch + deserialize
│   │   │   ├── sigstore.rs       # DSSE, Fulcio chain, Rekor, identity policy
│   │   │   ├── policy.rs         # TrustPolicy
│   │   │   └── snp/
│   │   │       ├── report.rs     # 0x4A0 struct parse
│   │   │       ├── vcek.rs       # VCEK -> ASK -> ARK, embedded AMD roots
│   │   │       └── verify.rs     # signature + measurement + guest policy
│   │   ├── ehbp/
│   │   │   ├── keyconfig.rs      # RFC 9458 key_config parse
│   │   │   ├── seal.rs           # request sealing + chunk framing
│   │   │   ├── open.rs           # response key derivation + opening
│   │   │   └── stream.rs         # incremental frame decryptor
│   │   ├── client.rs             # PpqClient
│   │   ├── models.rs             # catalogue discovery
│   │   └── rig.rs                # #[cfg(feature = "rig")]
│   └── testdata/                 # pinned attestation bundle + key config
└── crates/xtask/                 # cargo xtask capture-fixtures
```

## 4. Attestation verification

`PpqClient::builder().api_key(k).build().await?` runs the following once. Every
step fails closed; there is no "warn and continue" path.

### 4.1 Pipeline

1. `GET {base}/private/attestation` → bundle.
2. **Sigstore verification**
   - Build the Fulcio certificate chain against an **embedded** sigstore trusted
     root (checked into the repo, overridable via `TrustPolicy`). Runtime TUF
     refresh is deliberately out of scope.
   - Assert the certificate's identity via its GitHub Actions X.509 extensions:
     `GitHubWorkflowRepository == tinfoilsh/confidential-model-router` (OID
     1.3.6.1.4.1.57264.1.5) and `OIDCIssuer ==
     https://token.actions.githubusercontent.com` (OID 1.3.6.1.4.1.57264.1.1),
     combined with `AllOf`. See §4.4 for why this is not pinned on the SAN.
   - Verify the Rekor entry: signed entry timestamp against the log key from the
     trusted root, inclusion proof to the checkpoint root hash, checkpoint
     signature, and that `canonicalizedBody` hashes to the DSSE envelope.
   - Verify the DSSE signature over `PAE(payloadType, payload)` with the
     certificate's public key.
   - Parse the in-toto predicate to obtain the expected `snp_measurement`.
3. **SEV-SNP verification**
   - Base64-decode and gunzip the report body; parse the 0x4A0-byte structure.
   - Verify the ECDSA-P384 signature over bytes `[0x000..0x2A0]` with the VCEK
     public key. AMD encodes `r`/`s` little-endian; convert before verifying.
   - Chain VCEK → ASK → ARK against embedded AMD root certificates.
   - Policy checks: `measurement == snp_measurement`, debug disabled in the guest
     policy, `VMPL == 0`, and reported TCB not rolled back below committed TCB.
4. Extract from `report_data`: bytes `[0..32]` = TLS public key fingerprint,
   bytes `[32..64]` = **HPKE public key**.
5. `GET {base}/private/.well-known/hpke-keys` (content-type
   `application/ohttp-keys`), parse the first `key_config`, and assert its public
   key equals the attested one. A mismatch is a hard error. The **attested** key
   is what gets used; the advertised config supplies only the suite parameters.

### 4.2 Verification time must come from Rekor

Fulcio certificates are valid for ten minutes. The live bundle captured on
2026-08-15 carries a certificate valid `2026-08-13T22:57:35Z` →
`2026-08-13T23:07:35Z` — already long expired, yet the attestation is entirely
valid.

Certificate validity is therefore checked against the Rekor entry's
`integratedTime`, per standard sigstore practice — never against `now()`.

The `sigstore` crate already does exactly this internally
(`bundle/verify/verifier.rs` compares the cert's `not_before`/`not_after`
against `log_entry.integrated_time`), so no clock needs threading through that
layer. The useful consequence is that a captured fixture verifies
deterministically forever, rather than going stale ten minutes after capture.

Verification is run with the crate's `offline` mode so no Rekor round-trip is
needed; the bundle's own inclusion proof is the evidence.

### 4.3 Trust policy

```rust
pub struct TrustPolicy {
    pub sigstore_trusted_root: ManualTrustRoot<'static>, // embedded default
    pub signer_repository: String,   // "tinfoilsh/confidential-model-router"
    pub oidc_issuer: String,         // "https://token.actions.githubusercontent.com"
    pub amd_roots: Vec<Certificate>, // embedded Milan/Genoa/Turin
    pub require_debug_disabled: bool,// default true
}
```

Defaults encode the values above. Callers pinning a different Tinfoil deployment
override `signer_repository`.

### 4.4 Pin the repository, not the SAN

The obvious anchor is the certificate's SAN URI, but the live value is

```
https://github.com/tinfoilsh/confidential-model-router/.github/workflows/tinfoil-release-publish.yml@refs/tags/v0.0.141
```

— it embeds the **release tag**, and `sigstore`'s `Identity` policy matches the
SAN by exact string. Pinning it would make verification fail on every Tinfoil
release until this crate shipped a new constant.

Pinning `GitHubWorkflowRepository` + `OIDCIssuer` instead gives the same trust
anchor — only that repository's GitHub Actions can produce a passing bundle —
while surviving routine releases. The workflow ref is deliberately *not* pinned;
if that granularity is ever wanted, `GitHubWorkflowRef` can be added to the
`AllOf` at the cost of a constant bump per release.

## 5. EHBP transport

Suite: X25519-HKDF-SHA256 KEM, HKDF-SHA256 KDF, AES-256-GCM AEAD. AAD is empty
throughout.

**Request.** `SetupBaseS(attested_key, info = "ehbp request")` yields `enc` and a
sender context. Set `Ehbp-Encapsulated-Key: hex(enc)`, use chunked transfer
encoding, and omit `Content-Length`. The body is framed as repeating
`u32be len ‖ ciphertext`, where `len` counts ciphertext bytes only. One sealer is
established per body and reused for every chunk.

**Response.**

```
secret = ctx.export("ehbp response", 32)
prk    = HKDF-Extract(salt = enc ‖ response_nonce, ikm = secret)
key    = HKDF-Expand(prk, "key",   32)
base   = HKDF-Expand(prk, "nonce", 12)
```

`response_nonce` is 32 bytes, read from the `Ehbp-Response-Nonce` header. Chunk
`i` (zero-indexed) is opened with `base XOR i`, where `i` is a **big-endian u64
XORed into the last 8 bytes** of the 12-byte base — confirmed against the Go
reference implementation (`identity/derive.go`), as the spec prose alone is
ambiguous here.

**Failure handling.** Fail closed:

- `Ehbp-Response-Nonce` missing on a 2xx response → hard error. No plaintext
  fallback; that would permit body substitution by stripping the header.
- `Ehbp-Response-Nonce` missing on a non-2xx response → surfaced as a distinctly
  typed `UnauthenticatedUpstreamError` variant. These come from intermediaries
  that never reached the enclave, and callers must not be able to confuse one
  with enclave output.
- The streaming decryptor emits a frame's plaintext only after that frame
  authenticates, and rejects an EOF that leaves a partial length prefix or
  partial frame.

## 6. PPQ request shape

`POST {base}/private/v1/chat/completions`, OpenAI chat-completions body.

| Header | Value |
|---|---|
| `Authorization` | `Bearer <PPQ API key>` |
| `X-Private-Model` | user-facing id, e.g. `private/glm-5-2` |
| `x-query-source` | `api` |
| `X-Tool-Id` | optional creator-payout id |

The body's `model` field carries the **enclave-internal** id — the user-facing id
with the `private/` prefix stripped. This is a mechanical rule that holds for
every model; the reference implementation's lookup table was redundant.

## 7. Model discovery

`GET https://api.ppq.ai/v1/models` returns PPQ's full catalogue (346 models as of
2026-08-15) with a `privacyLevel` field taking values `anon`, `zdr` or `e2e`.
The TEE models are exactly those tagged `e2e`, all `owned_by: "Tinfoil"`.

```rust
pub struct PrivateModel {
    pub id: String,            // "private/glm-5-2"
    pub name: String,          // "GLM 5.2 (Private via TEE)"
    pub context_length: u32,
    pub pricing: Pricing,      // input/output per 1M tokens, USD
}

impl PpqClient {
    /// TEE-backed models from PPQ's catalogue (privacyLevel == "e2e").
    pub async fn list_models(&self) -> Result<Vec<PrivateModel>>;
}
```

No model list is hardcoded. `completion_model(id)` accepts any `&str` and does
**not** validate against the catalogue: that would put a network round-trip on a
hot path, and the attested enclave is the authority on what it will serve.

### 7.1 The catalogue is not a trust input

`/v1/models` is served by PPQ's plaintext API, not from inside the enclave. It is
unauthenticated discovery metadata. This is not a weakness — the model id is
merely relayed to the attested enclave, which rejects anything it does not serve.
The security guarantee comes entirely from §4 and is independent of the
catalogue. This must be documented on `list_models` so nobody later mistakes
"PPQ says this model is `e2e`" for a security property.

### 7.2 Do not infer capabilities from `supported_parameters`

The `e2e` entries **omit** `supported_parameters` entirely, whereas `anon`/`zdr`
entries populate it. A naive read makes every private model look like it supports
neither tools nor structured output.

That is wrong: the reference implementation's README states that `glm-5-2`,
`gpt-oss-120b`, `llama3-3-70b` and `kimi-k3` all emit tool calls correctly
through the enclave, and recommends `private/glm-5-2` for Claude Code precisely
because it is tool-call driven.

`SUPPORTS_TOOLS` and `SUPPORTS_RESPONSE_FORMAT` are therefore set statically to
`true` in the rig extension, never derived from this field. Deriving them would
silently disable tool calling for every model.

## 8. rig-core integration

`rig-core` 0.41 is generic over its HTTP backend via the `HttpClientExt` trait,
and exposes `GenericCompletionModel<Ext, H>` plus an `OpenAICompatibleProvider`
extension trait. Since the enclave speaks OpenAI chat-completions, the EHBP
channel plugs in as `H` and all of rig's message conversion, tool-call handling
and SSE streaming come for free.

```rust
impl HttpClientExt for EhbpHttp { /* send, send_streaming via the sealed channel */ }

pub struct PpqExt;
impl OpenAICompatibleProvider for PpqExt {
    const PROVIDER_NAME: &'static str = "ppq-private";
    const SUPPORTS_TOOLS: bool = true;            // see §7.2
    const SUPPORTS_RESPONSE_FORMAT: bool = true;  // see §7.2
    type StreamingUsage = openai::Usage;
    type Response = openai::CompletionResponse;
    fn prepare_request(&self, req: &mut openai::completion::CompletionRequest)
        -> Result<(), CompletionError> { /* strip `private/` from req.model */ }
}

pub type PpqCompletionModel = GenericCompletionModel<PpqExt, EhbpHttp>;
```

`PpqClient::completion_model(id)` builds a rig `Client` whose base URL is
`https://api.ppq.ai/private/v1` and whose default header map carries
`X-Private-Model: <id>` and `x-query-source: api`. rig's `Client` holds an
`Arc<HeaderMap>` applied to outgoing requests, so the per-model header is set
declaratively — no inspecting request bodies to recover the model name.

Usage:

```rust
let ppq = PpqClient::builder().api_key(key).build().await?;   // attests here
let agent = rig::agent::AgentBuilder::new(
    ppq.completion_model("private/glm-5-2")
).build();
```

Core additionally exposes a rig-free escape hatch:

```rust
impl PpqClient {
    pub async fn chat_completion(&self, body: serde_json::Value) -> Result<serde_json::Value>;
    pub async fn chat_completion_stream(&self, body: serde_json::Value)
        -> Result<impl Stream<Item = Result<Bytes>>>;
}
```

### 8.1 Note on `HttpClientExt`

`HttpClientExt::send` returns `impl Future + 'static`, so the implementation
cannot borrow `&self` into the returned future. `EhbpHttp` holds its state in an
`Arc<Inner>` and clones it into each future.

## 9. Testing

Pinned fixtures plus an injectable clock, with live tests gated behind
`#[ignore]`.

**Fixtures.** `testdata/` holds a captured attestation bundle and key config.
Because the sigstore layer anchors on the bundle's own `integratedTime` (§4.2),
these verify deterministically and offline with no clock injection.
`cargo xtask capture-fixtures` refreshes them when PPQ redeploys.

**Negative attestation tests** — each must be rejected:

- flipped byte in the SNP measurement
- corrupted DSSE signature
- `TrustPolicy` naming a different `signer_repository`
- truncated SNP report
- substituted VCEK certificate
- tampered Rekor inclusion proof

**EHBP tests.** Round-trip against an in-process server implementing the server
half of EHBP. This is also what pins down the chunk framing and the `base XOR i`
nonce layout. Cases: multi-chunk streams, zero-length chunks, AEAD tampering,
stripped `Ehbp-Response-Nonce` on 200, truncated final frame, and a non-2xx
plaintext passthrough asserting it surfaces as `UnauthenticatedUpstreamError`.
HPKE primitives are additionally checked against RFC 9180 test vectors.

**Live tests** (`#[ignore]`, require `PPQ_API_KEY`): full attestation against
`api.ppq.ai`, one non-streaming completion, one streaming completion, and
`list_models` returning a non-empty `e2e` set.

## 10. Nix

`flake.nix` using `rust-overlay`, providing a devShell with the stable toolchain
plus `rust-analyzer`, `clippy`, `rustfmt`, `cargo-nextest` and `pkg-config`. TLS
is `rustls` throughout, so **no OpenSSL** in the shell or the dependency tree.
`.envrc` for direnv users.

## 11. Risks

- ~~The `sigstore` 0.14 crate is the main unknown.~~ **Resolved during
  planning.** The crate fits: `bundle::verify::Verifier` handles DSSE bundles
  natively (signing over PAE bytes), checks cert expiry against Rekor's
  `integrated_time` (§4.2), supports `offline` verification, exposes
  `ManualTrustRoot` for an embedded root with no TUF fetch, and provides
  `GitHubWorkflowRepository` / `OIDCIssuer` / `AllOf` policies (§4.3). Use it
  with `default-features = false` plus `bundle`, `sigstore-trust-root` and
  `rustls-tls` to keep OpenSSL out (§10).
- AMD ARK/ASK roots must be embedded per product line (Milan, Genoa, Turin) and
  selected from the report's CPU family. The VCEK ships inside the bundle, so no
  AMD KDS round-trip is needed at verification time.
- Tinfoil may rotate the signing repo or workflow path; that surfaces as an
  identity-policy failure with a clear error, fixed by updating `TrustPolicy`.
- rig-core is pre-1.0 and its `HttpClientExt` / `OpenAICompatibleProvider` traits
  may shift between minor versions. Confining the coupling to `rig.rs` behind a
  feature flag keeps the blast radius to one file.
