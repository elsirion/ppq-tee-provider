# PPQ TEE In-Process LLM Provider — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rust library that talks to PPQ.AI's TEE-backed models over a hardware-attested, end-to-end-encrypted channel in-process, usable as a `rig-core` provider.

**Architecture:** Three layers. An *attestation verifier* (sigstore DSSE → expected measurement; AMD SEV-SNP report → running measurement + attested HPKE public key) runs once at client construction. An *EHBP transport* HPKE-seals every HTTP body to that attested key. A *rig provider*, behind a cargo feature, plugs the transport into `rig-core`'s `HttpClientExt` so rig's OpenAI-compatible machinery handles messages, tools and streaming.

**Tech Stack:** Rust 2021, tokio, reqwest (rustls), `sigstore` 0.14, `hpke` 0.14, `x509-cert`, `p384`, `hkdf`, `aes-gcm`, `rig-core` 0.41 (optional), Nix flake with rust-overlay.

**Spec:** `docs/superpowers/specs/2026-08-15-ppq-tee-in-process-provider-design.md`

## Global Constraints

- **No OpenSSL anywhere.** All TLS is rustls. Every dependency that offers a TLS
  backend feature must be declared `default-features = false` with the rustls
  feature selected explicitly.
- **Fail closed.** No verification or decryption path may fall back to
  "warn and continue". Every failure returns an `Err`.
- **`rig-core` is optional.** It appears only under `#[cfg(feature = "rig")]` and
  only in `src/rig.rs`. `cargo check` with default features must not build it.
- Base URL default: `https://api.ppq.ai`. Attestation: `{base}/private/attestation`.
  Inference: `{base}/private/v1/chat/completions`. Catalogue: `{base}/v1/models`.
  HPKE keys: `{base}/private/.well-known/hpke-keys`.
- Signer repository pinned to `tinfoilsh/confidential-model-router`; OIDC issuer
  pinned to `https://token.actions.githubusercontent.com`. Never pin the SAN.
- Dev API key for live tests: `sk-...`, read from `PPQ_API_KEY`.
  Never commit it.
- Every task ends with a commit. Run `cargo clippy --all-targets -- -D warnings`
  before each commit; it is part of the definition of done.

---

## File Structure

| File | Responsibility |
|---|---|
| `flake.nix`, `.envrc` | Nix devshell: toolchain, no OpenSSL |
| `Cargo.toml` | Workspace manifest |
| `crates/ppq-tee/src/lib.rs` | Public re-exports, crate error type |
| `crates/ppq-tee/src/attest/bundle.rs` | Bundle JSON types + fetch |
| `crates/ppq-tee/src/attest/policy.rs` | `TrustPolicy`, embedded roots |
| `crates/ppq-tee/src/attest/sigstore.rs` | DSSE/Rekor verification → expected measurement |
| `crates/ppq-tee/src/attest/snp/report.rs` | 0x4A0 report parsing |
| `crates/ppq-tee/src/attest/snp/vcek.rs` | VCEK→ASK→ARK chain |
| `crates/ppq-tee/src/attest/snp/verify.rs` | Report signature + policy checks |
| `crates/ppq-tee/src/attest/mod.rs` | `verify_bundle` orchestration |
| `crates/ppq-tee/src/ehbp/keyconfig.rs` | RFC 9458 key_config parsing |
| `crates/ppq-tee/src/ehbp/seal.rs` | Request sealing + chunk framing |
| `crates/ppq-tee/src/ehbp/open.rs` | Response key derivation + opening |
| `crates/ppq-tee/src/ehbp/stream.rs` | Incremental frame decryptor |
| `crates/ppq-tee/src/client.rs` | `PpqClient`, builder, send/stream |
| `crates/ppq-tee/src/models.rs` | Catalogue discovery |
| `crates/ppq-tee/src/rig.rs` | `HttpClientExt` + `OpenAICompatibleProvider` |
| `crates/xtask/src/main.rs` | `capture-fixtures` |

---

### Task 1: Workspace and Nix devshell

**Files:**
- Create: `flake.nix`, `.envrc`, `.gitignore`, `Cargo.toml`,
  `crates/ppq-tee/Cargo.toml`, `crates/ppq-tee/src/lib.rs`

**Interfaces:**
- Consumes: nothing
- Produces: crate `ppq-tee` with `pub enum Error` and `pub type Result<T>`

- [ ] **Step 1: Write `flake.nix`**

```nix
{
  description = "PPQ TEE in-process LLM provider";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        toolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };
      in {
        devShells.default = pkgs.mkShell {
          packages = [ toolchain pkgs.cargo-nextest pkgs.pkg-config ];
          # rustls only: no openssl in the shell, so an accidental
          # native-tls dependency fails the build instead of silently working.
          shellHook = ''
            echo "ppq-tee dev shell — $(rustc --version)"
          '';
        };
      });
}
```

- [ ] **Step 2: Write `.envrc` and `.gitignore`**

`.envrc`:
```
use flake
```

`.gitignore`:
```
/target
/result
.direnv/
```

- [ ] **Step 3: Write the workspace and crate manifests**

`Cargo.toml`:
```toml
[workspace]
members = ["crates/ppq-tee", "crates/xtask"]
resolver = "2"

[workspace.package]
edition = "2021"
license = "MIT"
rust-version = "1.82"
```

`crates/ppq-tee/Cargo.toml`:
```toml
[package]
name = "ppq-tee"
version = "0.1.0"
edition.workspace = true
license.workspace = true
description = "Attested, end-to-end encrypted in-process client for PPQ.AI TEE models"

[features]
default = []
rig = ["dep:rig-core"]

[dependencies]
thiserror = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hex = "0.4"
base64 = "0.22"
bytes = "1"
futures = "0.3"
tokio = { version = "1", features = ["rt", "macros"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json", "stream"] }
rig-core = { version = "0.41", optional = true }

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

`crates/xtask/Cargo.toml`:
```toml
[package]
name = "xtask"
version = "0.0.0"
edition.workspace = true
publish = false

[dependencies]
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "blocking"] }
serde_json = "1"
```

- [ ] **Step 4: Write `crates/ppq-tee/src/lib.rs`**

```rust
//! Attested, end-to-end encrypted in-process client for PPQ.AI TEE models.

pub mod attest;
pub mod ehbp;

/// Every failure mode in this crate. There are no warn-and-continue paths.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("attestation failed: {0}")]
    Attestation(String),
    #[error("ehbp protocol error: {0}")]
    Ehbp(String),
    /// A non-2xx response that arrived without `Ehbp-Response-Nonce`, i.e. it
    /// never reached the enclave. The body is attacker-forgeable diagnostics
    /// and must never be treated as enclave output.
    #[error("unauthenticated upstream error (HTTP {status}): {body}")]
    UnauthenticatedUpstream { status: u16, body: String },
}

pub type Result<T> = std::result::Result<T, Error>;
```

Create `crates/ppq-tee/src/attest/mod.rs` and `crates/ppq-tee/src/ehbp/mod.rs`
each containing only `// filled in by later tasks` for now.

Create `crates/xtask/src/main.rs` with `fn main() {}`.

- [ ] **Step 5: Verify the shell and build**

Run: `nix develop -c cargo build --workspace`
Expected: builds clean, no OpenSSL in the dependency tree.

Run: `nix develop -c cargo tree -p ppq-tee | grep -i openssl`
Expected: no output (exit code 1 from grep). If anything matches, a dependency
pulled native-tls and must be pinned to rustls.

- [ ] **Step 6: Commit**

```bash
git add flake.nix flake.lock .envrc .gitignore Cargo.toml Cargo.lock crates/
git commit -m "feat: rust workspace with nix devshell, rustls only"
```

---

### Task 2: Attestation bundle types and fixture capture

**Files:**
- Create: `crates/ppq-tee/src/attest/bundle.rs`, `crates/xtask/src/main.rs`,
  `crates/ppq-tee/testdata/attestation-bundle.json`,
  `crates/ppq-tee/testdata/hpke-keys.bin`
- Modify: `crates/ppq-tee/src/attest/mod.rs`

**Interfaces:**
- Consumes: `crate::{Error, Result}` from Task 1
- Produces:
  - `pub struct AttestationBundle { domain: String, enclave_attestation_report: EnclaveReport, digest: String, sigstore_bundle: serde_json::Value, vcek: String, enclave_cert: String }`
  - `pub struct EnclaveReport { format: String, body: String }`
  - `pub fn parse(json: &str) -> Result<AttestationBundle>`
  - `pub fn decode_report_body(b: &str) -> Result<Vec<u8>>` — base64 then gzip
  - `pub async fn fetch(base: &str) -> Result<AttestationBundle>`

- [ ] **Step 1: Capture the fixtures**

Add to `crates/xtask/src/main.rs`:

```rust
use std::{fs, path::Path};

fn main() {
    let base = std::env::var("PPQ_API_BASE")
        .unwrap_or_else(|_| "https://api.ppq.ai".to_string());
    let out = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ppq-tee/testdata");
    fs::create_dir_all(&out).expect("create testdata");

    let client = reqwest::blocking::Client::new();

    let bundle = client
        .get(format!("{base}/private/attestation"))
        .send().expect("fetch attestation")
        .text().expect("attestation body");
    // Pretty-print so fixture diffs are readable when PPQ redeploys.
    let parsed: serde_json::Value =
        serde_json::from_str(&bundle).expect("attestation is json");
    fs::write(
        out.join("attestation-bundle.json"),
        serde_json::to_string_pretty(&parsed).unwrap(),
    ).expect("write bundle");

    let keys = client
        .get(format!("{base}/private/.well-known/hpke-keys"))
        .send().expect("fetch hpke keys")
        .bytes().expect("hpke body");
    fs::write(out.join("hpke-keys.bin"), &keys).expect("write keys");

    println!("captured {} byte bundle, {} byte key config", bundle.len(), keys.len());
}
```

Run: `nix develop -c cargo run -p xtask`
Expected: `captured <N> byte bundle, 41 byte key config`

- [ ] **Step 2: Write the failing test**

`crates/ppq-tee/src/attest/bundle.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../testdata/attestation-bundle.json");

    #[test]
    fn parses_the_live_bundle() {
        let b = parse(FIXTURE).expect("fixture parses");
        assert_eq!(b.domain, "inference.tinfoil.sh");
        assert_eq!(
            b.enclave_attestation_report.format,
            "https://tinfoil.sh/predicate/sev-snp-guest/v2"
        );
        assert_eq!(b.digest.len(), 64, "digest is hex sha256");
        assert!(!b.vcek.is_empty());
        assert!(b.enclave_cert.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn decodes_report_body_to_a_full_report() {
        let b = parse(FIXTURE).unwrap();
        let raw = decode_report_body(&b.enclave_attestation_report.body).unwrap();
        assert_eq!(raw.len(), 0x4A0, "SEV-SNP reports are 0x4A0 bytes");
    }

    #[test]
    fn rejects_truncated_report_body() {
        assert!(decode_report_body("not-base64!!").is_err());
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `nix develop -c cargo test -p ppq-tee bundle`
Expected: FAIL — `parse` and `decode_report_body` are not defined.

- [ ] **Step 4: Implement**

Add `flate2 = "1"` to `crates/ppq-tee/Cargo.toml` dependencies, then write the
implementation above the test module in `bundle.rs`:

```rust
use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::io::Read;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationBundle {
    pub domain: String,
    pub enclave_attestation_report: EnclaveReport,
    /// Hex sha256 of `tinfoil-deployment.json`, the DSSE subject.
    pub digest: String,
    /// Passed to the `sigstore` crate verbatim.
    pub sigstore_bundle: serde_json::Value,
    /// Base64 DER of the AMD VCEK certificate.
    pub vcek: String,
    /// PEM of the enclave's TLS certificate.
    pub enclave_cert: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveReport {
    pub format: String,
    /// Base64 of a gzip stream containing the raw 0x4A0-byte report.
    pub body: String,
}

pub fn parse(json: &str) -> Result<AttestationBundle> {
    Ok(serde_json::from_str(json)?)
}

/// Base64-decode then gunzip the report body.
pub fn decode_report_body(body: &str) -> Result<Vec<u8>> {
    let gz = STANDARD
        .decode(body)
        .map_err(|e| Error::Attestation(format!("report body is not base64: {e}")))?;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .map_err(|e| Error::Attestation(format!("report body is not gzip: {e}")))?;
    Ok(out)
}

pub async fn fetch(base: &str) -> Result<AttestationBundle> {
    let body = reqwest::get(format!("{base}/private/attestation"))
        .await?
        .error_for_status()?
        .text()
        .await?;
    parse(&body)
}
```

Set `crates/ppq-tee/src/attest/mod.rs` to `pub mod bundle;`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `nix develop -c cargo test -p ppq-tee bundle`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/ppq-tee/src/attest crates/ppq-tee/testdata crates/xtask Cargo.lock crates/ppq-tee/Cargo.toml
git commit -m "feat: attestation bundle types and fixture capture"
```

---

### Task 3: Trust policy

**Files:**
- Create: `crates/ppq-tee/src/attest/policy.rs`,
  `crates/ppq-tee/testdata/sigstore-trusted-root.json`
- Modify: `crates/ppq-tee/src/attest/mod.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces:
  - `pub struct TrustPolicy { pub signer_repository: String, pub oidc_issuer: String, pub require_debug_disabled: bool }`
  - `impl Default for TrustPolicy`
  - `pub const SIGSTORE_TRUSTED_ROOT: &str` — embedded JSON
  - `pub fn amd_root(product: AmdProduct) -> &'static [u8]` — embedded ARK/ASK PEM
  - `pub enum AmdProduct { Milan, Genoa, Turin }`

- [ ] **Step 1: Download the embedded roots**

```bash
curl -sL https://tuf-repo-cdn.sigstore.dev/targets/trusted_root.json \
  -o crates/ppq-tee/testdata/sigstore-trusted-root.json
mkdir -p crates/ppq-tee/testdata/amd
for p in Milan Genoa Turin; do
  curl -sL "https://kdsintf.amd.com/vcek/v1/$p/cert_chain" \
    -o "crates/ppq-tee/testdata/amd/$p.pem"
done
wc -c crates/ppq-tee/testdata/sigstore-trusted-root.json crates/ppq-tee/testdata/amd/*.pem
```

Expected: all files non-empty. Each AMD `cert_chain` is ASK followed by ARK in PEM.

- [ ] **Step 2: Write the failing test**

`crates/ppq-tee/src/attest/policy.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pins_the_tinfoil_router_repo() {
        let p = TrustPolicy::default();
        assert_eq!(p.signer_repository, "tinfoilsh/confidential-model-router");
        assert_eq!(p.oidc_issuer, "https://token.actions.githubusercontent.com");
        assert!(p.require_debug_disabled);
    }

    #[test]
    fn embedded_roots_are_present() {
        assert!(SIGSTORE_TRUSTED_ROOT.contains("tlogs"));
        for p in [AmdProduct::Milan, AmdProduct::Genoa, AmdProduct::Turin] {
            assert!(
                amd_root(p).starts_with(b"-----BEGIN CERTIFICATE-----"),
                "{p:?} chain is PEM",
            );
        }
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `nix develop -c cargo test -p ppq-tee policy`
Expected: FAIL — `TrustPolicy` not defined.

- [ ] **Step 4: Implement**

```rust
/// What the verifier requires of an attestation before trusting it.
///
/// The signer identity is pinned on the certificate's GitHub Actions
/// *repository* extension rather than its SAN. The SAN embeds the release tag
/// (`...@refs/tags/v0.0.141`) and `sigstore`'s `Identity` policy matches it
/// exactly, so pinning the SAN would fail on every Tinfoil release.
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    pub signer_repository: String,
    pub oidc_issuer: String,
    pub require_debug_disabled: bool,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            signer_repository: "tinfoilsh/confidential-model-router".to_string(),
            oidc_issuer: "https://token.actions.githubusercontent.com".to_string(),
            require_debug_disabled: true,
        }
    }
}

pub const SIGSTORE_TRUSTED_ROOT: &str =
    include_str!("../../testdata/sigstore-trusted-root.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdProduct {
    Milan,
    Genoa,
    Turin,
}

/// ASK+ARK chain for a product line, as PEM.
pub fn amd_root(product: AmdProduct) -> &'static [u8] {
    match product {
        AmdProduct::Milan => include_bytes!("../../testdata/amd/Milan.pem"),
        AmdProduct::Genoa => include_bytes!("../../testdata/amd/Genoa.pem"),
        AmdProduct::Turin => include_bytes!("../../testdata/amd/Turin.pem"),
    }
}
```

Add `pub mod policy;` to `attest/mod.rs`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `nix develop -c cargo test -p ppq-tee policy`
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/ppq-tee/src/attest/policy.rs crates/ppq-tee/testdata
git commit -m "feat: trust policy with embedded sigstore and AMD roots"
```

---

### Task 4: Sigstore layer — expected measurement

**Files:**
- Create: `crates/ppq-tee/src/attest/sigstore.rs`
- Modify: `crates/ppq-tee/src/attest/mod.rs`, `crates/ppq-tee/Cargo.toml`

**Interfaces:**
- Consumes: `bundle::AttestationBundle`, `policy::{TrustPolicy, SIGSTORE_TRUSTED_ROOT}`
- Produces:
  - `pub struct DeploymentPredicate { pub snp_measurement: Vec<u8> }`
  - `pub fn verify(bundle: &AttestationBundle, policy: &TrustPolicy) -> Result<DeploymentPredicate>`

- [ ] **Step 1: Add the dependency**

In `crates/ppq-tee/Cargo.toml`:

```toml
sigstore = { version = "0.14", default-features = false, features = ["bundle", "sigstore-trust-root", "rustls-tls"] }
```

- [ ] **Step 2: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::bundle;

    const FIXTURE: &str = include_str!("../../testdata/attestation-bundle.json");

    fn fixture() -> bundle::AttestationBundle {
        bundle::parse(FIXTURE).unwrap()
    }

    #[test]
    fn extracts_the_expected_measurement() {
        let p = verify(&fixture(), &TrustPolicy::default()).expect("verifies");
        assert_eq!(p.snp_measurement.len(), 48, "SNP measurements are 48 bytes");
    }

    #[test]
    fn rejects_a_different_signer_repository() {
        let policy = TrustPolicy {
            signer_repository: "attacker/evil-router".to_string(),
            ..TrustPolicy::default()
        };
        assert!(verify(&fixture(), &policy).is_err());
    }

    #[test]
    fn rejects_a_corrupted_dsse_signature() {
        let mut b = fixture();
        let sig = b.sigstore_bundle["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str().unwrap().to_string();
        // Flip one base64 character to invalidate the signature.
        let tampered = format!("{}A{}", &sig[..10], &sig[11..]);
        b.sigstore_bundle["dsseEnvelope"]["signatures"][0]["sig"] =
            serde_json::Value::String(tampered);
        assert!(verify(&b, &TrustPolicy::default()).is_err());
    }

    #[test]
    fn rejects_a_tampered_subject_digest() {
        let mut b = fixture();
        b.digest = "0".repeat(64);
        assert!(verify(&b, &TrustPolicy::default()).is_err());
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `nix develop -c cargo test -p ppq-tee sigstore`
Expected: FAIL — `verify` not defined.

- [ ] **Step 4: Implement**

```rust
use crate::attest::bundle::AttestationBundle;
use crate::attest::policy::{TrustPolicy, SIGSTORE_TRUSTED_ROOT};
use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use sigstore::bundle::verify::{
    policy::{AllOf, GitHubWorkflowRepository, OIDCIssuer, SingleX509ExtPolicy, VerificationPolicy},
    Verifier,
};
use sigstore::trust::ManualTrustRoot;

/// The subset of Tinfoil's in-toto predicate this crate consumes.
#[derive(Debug, Clone)]
pub struct DeploymentPredicate {
    /// Expected SEV-SNP launch measurement, 48 bytes.
    pub snp_measurement: Vec<u8>,
}

/// Verify the sigstore bundle and return the deployment it attests to.
///
/// Runs in offline mode: the bundle's own Rekor inclusion proof is the
/// evidence, so no network call is made. Certificate expiry is checked by the
/// `sigstore` crate against the Rekor `integratedTime`, not against `now()` —
/// Fulcio certs live ten minutes, so a wall-clock check would reject every
/// valid attestation older than that.
pub fn verify(
    bundle: &AttestationBundle,
    policy: &TrustPolicy,
) -> Result<DeploymentPredicate> {
    let root: ManualTrustRoot<'static> = serde_json::from_str(SIGSTORE_TRUSTED_ROOT)
        .map_err(|e| Error::Attestation(format!("embedded trusted root is invalid: {e}")))?;
    let verifier = Verifier::new(root)
        .map_err(|e| Error::Attestation(format!("verifier setup failed: {e}")))?;

    let id_policy = AllOf::new([
        &OIDCIssuer::new(&policy.oidc_issuer) as &dyn VerificationPolicy,
        &GitHubWorkflowRepository::new(&policy.signer_repository),
    ])
    .ok_or_else(|| Error::Attestation("empty identity policy".into()))?;

    let parsed: sigstore::bundle::models::Bundle =
        serde_json::from_value(bundle.sigstore_bundle.clone())?;

    let digest = hex::decode(&bundle.digest)
        .map_err(|e| Error::Attestation(format!("bundle digest is not hex: {e}")))?;

    verifier
        .verify_digest(&digest, parsed, &id_policy, /* offline */ true)
        .map_err(|e| Error::Attestation(format!("sigstore verification failed: {e}")))?;

    // Only now is the DSSE payload trustworthy.
    let payload_b64 = bundle.sigstore_bundle["dsseEnvelope"]["payload"]
        .as_str()
        .ok_or_else(|| Error::Attestation("bundle has no dsse payload".into()))?;
    let payload = STANDARD
        .decode(payload_b64)
        .map_err(|e| Error::Attestation(format!("dsse payload is not base64: {e}")))?;
    let stmt: serde_json::Value = serde_json::from_slice(&payload)?;

    // The signature covers the statement; the statement's subject digest must
    // be the one we just verified, or an attacker could pair a valid signature
    // with an unrelated deployment.
    let subject_digest = stmt["subject"][0]["digest"]["sha256"]
        .as_str()
        .ok_or_else(|| Error::Attestation("statement has no subject digest".into()))?;
    if subject_digest != bundle.digest {
        return Err(Error::Attestation(format!(
            "statement subject {subject_digest} does not match bundle digest {}",
            bundle.digest
        )));
    }

    let m = stmt["predicate"]["snp_measurement"]
        .as_str()
        .ok_or_else(|| Error::Attestation("predicate has no snp_measurement".into()))?;
    let snp_measurement = hex::decode(m)
        .map_err(|e| Error::Attestation(format!("snp_measurement is not hex: {e}")))?;
    if snp_measurement.len() != 48 {
        return Err(Error::Attestation(format!(
            "snp_measurement is {} bytes, want 48",
            snp_measurement.len()
        )));
    }

    Ok(DeploymentPredicate { snp_measurement })
}
```

Add `pub mod sigstore;` to `attest/mod.rs`.

> If `verify_digest`'s exact signature differs from the above (argument order or
> the bundle type), adapt the call — the crate is the authority. Do not work
> around a verification failure by relaxing the policy or skipping a check.

- [ ] **Step 5: Run tests to verify they pass**

Run: `nix develop -c cargo test -p ppq-tee sigstore`
Expected: 4 passed. In particular all three negative tests must return `Err`.

- [ ] **Step 6: Commit**

```bash
git add crates/ppq-tee/src/attest/sigstore.rs crates/ppq-tee/src/attest/mod.rs crates/ppq-tee/Cargo.toml Cargo.lock
git commit -m "feat: verify sigstore bundle to obtain expected SNP measurement"
```

---

### Task 5: SEV-SNP report parsing

**Files:**
- Create: `crates/ppq-tee/src/attest/snp/mod.rs`, `crates/ppq-tee/src/attest/snp/report.rs`
- Modify: `crates/ppq-tee/src/attest/mod.rs`

**Interfaces:**
- Consumes: `bundle::decode_report_body`
- Produces:
  - `pub struct Report { pub version: u32, pub policy: u64, pub vmpl: u32, pub report_data: [u8; 64], pub measurement: [u8; 48], pub chip_id: [u8; 64], pub reported_tcb: u64, pub committed_tcb: u64, pub signed_data: Vec<u8>, pub signature_r: [u8; 48], pub signature_s: [u8; 48] }`
  - `pub fn parse(raw: &[u8]) -> Result<Report>`
  - `impl Report { pub fn debug_enabled(&self) -> bool; pub fn tls_key_fingerprint(&self) -> [u8; 32]; pub fn hpke_public_key(&self) -> [u8; 32] }`

- [ ] **Step 1: Write the failing test**

`crates/ppq-tee/src/attest/snp/report.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::bundle;

    const FIXTURE: &str = include_str!("../../../testdata/attestation-bundle.json");

    fn raw() -> Vec<u8> {
        let b = bundle::parse(FIXTURE).unwrap();
        bundle::decode_report_body(&b.enclave_attestation_report.body).unwrap()
    }

    #[test]
    fn parses_the_live_report() {
        let r = parse(&raw()).expect("parses");
        assert!(r.version >= 2, "supported report versions are 2 and up");
        assert_eq!(r.vmpl, 0, "enclave runs at VMPL 0");
        assert_eq!(r.signed_data.len(), 0x2A0);
        assert!(!r.debug_enabled(), "production enclave has debug disabled");
    }

    #[test]
    fn splits_report_data_into_tls_and_hpke_keys() {
        let r = parse(&raw()).unwrap();
        // report_data[0..32] = TLS pubkey fingerprint, [32..64] = HPKE pubkey.
        assert_eq!(r.tls_key_fingerprint(), r.report_data[..32]);
        assert_eq!(r.hpke_public_key(), r.report_data[32..]);
        assert_ne!(r.hpke_public_key(), [0u8; 32], "HPKE key is populated");
    }

    #[test]
    fn rejects_a_truncated_report() {
        let mut short = raw();
        short.truncate(0x400);
        assert!(parse(&short).is_err());
    }

    #[test]
    fn rejects_an_oversized_report() {
        let mut long = raw();
        long.push(0);
        assert!(parse(&long).is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c cargo test -p ppq-tee snp::report`
Expected: FAIL — `parse` not defined.

- [ ] **Step 3: Implement**

Offsets are from the AMD SEV-SNP ABI, cross-checked against Tinfoil's
`packages/verifier/src/sev/report.ts`. All scalars are little-endian.

```rust
use crate::{Error, Result};

pub const REPORT_SIZE: usize = 0x4A0;
pub const SIGNATURE_OFFSET: usize = 0x2A0;
/// Guest policy bit 19 enables debug. It must be clear in production.
const POLICY_DEBUG_BIT: u64 = 1 << 19;

#[derive(Debug, Clone)]
pub struct Report {
    pub version: u32,
    pub policy: u64,
    pub vmpl: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub chip_id: [u8; 64],
    pub reported_tcb: u64,
    pub committed_tcb: u64,
    /// Bytes `[0..0x2A0]` — exactly what the VCEK signature covers.
    pub signed_data: Vec<u8>,
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// AMD stores each signature scalar as 72 little-endian bytes; P-384 needs 48
/// big-endian. Take the low 48 bytes and reverse.
fn scalar_at(b: &[u8], off: usize) -> [u8; 48] {
    let mut s = [0u8; 48];
    s.copy_from_slice(&b[off..off + 48]);
    s.reverse();
    s
}

pub fn parse(raw: &[u8]) -> Result<Report> {
    if raw.len() != REPORT_SIZE {
        return Err(Error::Attestation(format!(
            "report is {} bytes, want {REPORT_SIZE}",
            raw.len()
        )));
    }

    let version = u32_at(raw, 0x00);
    if version < 2 {
        return Err(Error::Attestation(format!(
            "unsupported report version {version}, want 2 or higher"
        )));
    }

    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(&raw[0x50..0x90]);
    let mut measurement = [0u8; 48];
    measurement.copy_from_slice(&raw[0x90..0xC0]);
    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(&raw[0x1A0..0x1E0]);

    Ok(Report {
        version,
        policy: u64_at(raw, 0x08),
        vmpl: u32_at(raw, 0x30),
        report_data,
        measurement,
        chip_id,
        reported_tcb: u64_at(raw, 0x180),
        committed_tcb: u64_at(raw, 0x1E0),
        signed_data: raw[..SIGNATURE_OFFSET].to_vec(),
        signature_r: scalar_at(raw, SIGNATURE_OFFSET),
        signature_s: scalar_at(raw, SIGNATURE_OFFSET + 72),
    })
}

impl Report {
    pub fn debug_enabled(&self) -> bool {
        self.policy & POLICY_DEBUG_BIT != 0
    }

    /// SHA-256 fingerprint of the enclave's TLS public key.
    pub fn tls_key_fingerprint(&self) -> [u8; 32] {
        self.report_data[..32].try_into().unwrap()
    }

    /// The enclave's X25519 HPKE public key — the EHBP trust anchor.
    pub fn hpke_public_key(&self) -> [u8; 32] {
        self.report_data[32..].try_into().unwrap()
    }
}
```

`crates/ppq-tee/src/attest/snp/mod.rs`:
```rust
pub mod report;
```

Add `pub mod snp;` to `attest/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c cargo test -p ppq-tee snp::report`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ppq-tee/src/attest/snp crates/ppq-tee/src/attest/mod.rs
git commit -m "feat: parse SEV-SNP attestation reports"
```

---

### Task 6: VCEK chain and report signature

**Files:**
- Create: `crates/ppq-tee/src/attest/snp/vcek.rs`, `crates/ppq-tee/src/attest/snp/verify.rs`
- Modify: `crates/ppq-tee/src/attest/snp/mod.rs`, `crates/ppq-tee/Cargo.toml`

**Interfaces:**
- Consumes: `report::Report`, `policy::{TrustPolicy, AmdProduct, amd_root}`
- Produces:
  - `pub fn verify_chain(vcek_der: &[u8], product: AmdProduct) -> Result<VcekKey>`
  - `pub struct VcekKey(p384::ecdsa::VerifyingKey)`
  - `pub fn verify_report(report: &Report, vcek: &VcekKey, expected_measurement: &[u8], policy: &TrustPolicy) -> Result<()>`

- [ ] **Step 1: Add dependencies**

```toml
p384 = { version = "0.13", features = ["ecdsa"] }
sha2 = "0.10"
x509-cert = { version = "0.2", features = ["pem"] }
const-oid = "0.9"
```

- [ ] **Step 2: Write the failing test**

`crates/ppq-tee/src/attest/snp/verify.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{bundle, policy::{AmdProduct, TrustPolicy}, sigstore, snp::{report, vcek}};
    use base64::{engine::general_purpose::STANDARD, Engine};

    const FIXTURE: &str = include_str!("../../../testdata/attestation-bundle.json");

    fn parts() -> (report::Report, vcek::VcekKey, Vec<u8>) {
        let b = bundle::parse(FIXTURE).unwrap();
        let raw = bundle::decode_report_body(&b.enclave_attestation_report.body).unwrap();
        let r = report::parse(&raw).unwrap();
        let der = STANDARD.decode(&b.vcek).unwrap();
        let k = vcek::verify_chain(&der, AmdProduct::Milan)
            .or_else(|_| vcek::verify_chain(&der, AmdProduct::Genoa))
            .or_else(|_| vcek::verify_chain(&der, AmdProduct::Turin))
            .expect("VCEK chains to an AMD root");
        let m = sigstore::verify(&b, &TrustPolicy::default()).unwrap().snp_measurement;
        (r, k, m)
    }

    #[test]
    fn accepts_the_live_report() {
        let (r, k, m) = parts();
        verify_report(&r, &k, &m, &TrustPolicy::default()).expect("verifies");
    }

    #[test]
    fn rejects_a_flipped_measurement_byte() {
        let (mut r, k, m) = parts();
        r.measurement[0] ^= 0x01;
        assert!(verify_report(&r, &k, &m, &TrustPolicy::default()).is_err());
    }

    #[test]
    fn rejects_a_measurement_mismatching_the_deployment() {
        let (r, k, _) = parts();
        let wrong = vec![0u8; 48];
        assert!(verify_report(&r, &k, &wrong, &TrustPolicy::default()).is_err());
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let (mut r, k, m) = parts();
        r.signature_r[0] ^= 0xFF;
        assert!(verify_report(&r, &k, &m, &TrustPolicy::default()).is_err());
    }

    #[test]
    fn rejects_debug_enabled_guests() {
        let (mut r, k, m) = parts();
        r.policy |= 1 << 19;
        // Signature check would also fail, so assert the policy check
        // independently of it.
        assert!(r.debug_enabled());
        assert!(verify_report(&r, &k, &m, &TrustPolicy::default()).is_err());
    }
}
```

`crates/ppq-tee/src/attest/snp/vcek.rs` test:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{bundle, policy::AmdProduct};
    use base64::{engine::general_purpose::STANDARD, Engine};

    const FIXTURE: &str = include_str!("../../../testdata/attestation-bundle.json");

    #[test]
    fn rejects_a_garbage_certificate() {
        assert!(verify_chain(&[0u8; 16], AmdProduct::Milan).is_err());
    }

    #[test]
    fn rejects_a_vcek_from_the_wrong_product_line() {
        let b = bundle::parse(FIXTURE).unwrap();
        let der = STANDARD.decode(&b.vcek).unwrap();
        let ok = [AmdProduct::Milan, AmdProduct::Genoa, AmdProduct::Turin]
            .iter()
            .filter(|p| verify_chain(&der, **p).is_ok())
            .count();
        assert_eq!(ok, 1, "VCEK chains to exactly one product line");
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `nix develop -c cargo test -p ppq-tee snp::verify snp::vcek`
Expected: FAIL — `verify_chain` and `verify_report` not defined.

- [ ] **Step 4: Implement `vcek.rs`**

```rust
use crate::attest::policy::{amd_root, AmdProduct};
use crate::{Error, Result};
use p384::ecdsa::VerifyingKey;
use x509_cert::{der::Decode, Certificate};

/// The VCEK's public key, once the chain to an AMD root has been checked.
pub struct VcekKey(pub(crate) VerifyingKey);

/// Verify VCEK -> ASK -> ARK against the embedded root for `product`.
///
/// The VCEK ships inside the attestation bundle, so no AMD KDS round-trip is
/// needed at verification time.
pub fn verify_chain(vcek_der: &[u8], product: AmdProduct) -> Result<VcekKey> {
    let vcek = Certificate::from_der(vcek_der)
        .map_err(|e| Error::Attestation(format!("VCEK is not a DER certificate: {e}")))?;

    let chain_pem = amd_root(product);
    let chain = Certificate::load_pem_chain(chain_pem)
        .map_err(|e| Error::Attestation(format!("embedded AMD chain is invalid: {e}")))?;
    let ask = chain
        .first()
        .ok_or_else(|| Error::Attestation("AMD chain is empty".into()))?;
    let ark = chain
        .get(1)
        .ok_or_else(|| Error::Attestation("AMD chain has no root".into()))?;

    // ARK is self-signed; ASK is signed by ARK; VCEK is signed by ASK.
    verify_signed_by(ark, ark)?;
    verify_signed_by(ask, ark)?;
    verify_signed_by(&vcek, ask)?;

    let key = VerifyingKey::from_sec1_bytes(
        vcek.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| Error::Attestation("VCEK public key is not aligned".into()))?,
    )
    .map_err(|e| Error::Attestation(format!("VCEK public key is not P-384: {e}")))?;

    Ok(VcekKey(key))
}

/// Check that `cert`'s signature verifies under `issuer`'s public key.
///
/// AMD's ARK/ASK use RSA-PSS-4096 and the VCEK uses ECDSA-P384, so dispatch on
/// the signature algorithm rather than assuming one.
fn verify_signed_by(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    use x509_cert::der::Encode;

    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::Attestation(format!("cannot re-encode tbsCertificate: {e}")))?;
    let sig = cert
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Attestation("signature is not aligned".into()))?;
    let spki = &issuer.tbs_certificate.subject_public_key_info;

    match cert.signature_algorithm.oid.to_string().as_str() {
        // ecdsa-with-SHA384
        "1.2.840.10045.4.3.3" => {
            use p384::ecdsa::{signature::Verifier, DerSignature};
            let key = VerifyingKey::from_sec1_bytes(
                spki.subject_public_key
                    .as_bytes()
                    .ok_or_else(|| Error::Attestation("issuer key is not aligned".into()))?,
            )
            .map_err(|e| Error::Attestation(format!("issuer key is not P-384: {e}")))?;
            let sig = DerSignature::try_from(sig)
                .map_err(|e| Error::Attestation(format!("bad ECDSA signature: {e}")))?;
            key.verify(&tbs, &sig)
                .map_err(|e| Error::Attestation(format!("certificate signature invalid: {e}")))
        }
        // id-RSASSA-PSS
        "1.2.840.113549.1.1.10" => {
            use rsa::{pkcs8::DecodePublicKey, pss::Pss, RsaPublicKey};
            use x509_cert::der::Encode as _;
            let key = RsaPublicKey::from_public_key_der(
                &spki.to_der().map_err(|e| {
                    Error::Attestation(format!("cannot re-encode issuer SPKI: {e}"))
                })?,
            )
            .map_err(|e| Error::Attestation(format!("issuer key is not RSA: {e}")))?;
            let digest = <sha2::Sha384 as sha2::Digest>::digest(&tbs);
            key.verify(Pss::new::<sha2::Sha384>(), &digest, sig)
                .map_err(|e| Error::Attestation(format!("certificate signature invalid: {e}")))
        }
        other => Err(Error::Attestation(format!(
            "unsupported certificate signature algorithm {other}"
        ))),
    }
}
```

Add `rsa = { version = "0.9", features = ["sha2"] }` to the manifest.

- [ ] **Step 5: Implement `verify.rs`**

```rust
use crate::attest::policy::TrustPolicy;
use crate::attest::snp::{report::Report, vcek::VcekKey};
use crate::{Error, Result};

/// Check that a report is genuine, matches the attested deployment, and
/// describes a guest we are willing to trust.
pub fn verify_report(
    report: &Report,
    vcek: &VcekKey,
    expected_measurement: &[u8],
    policy: &TrustPolicy,
) -> Result<()> {
    use p384::ecdsa::{signature::Verifier, Signature};

    if report.measurement.as_slice() != expected_measurement {
        return Err(Error::Attestation(format!(
            "enclave measurement {} does not match attested deployment {}",
            hex::encode(report.measurement),
            hex::encode(expected_measurement),
        )));
    }

    if policy.require_debug_disabled && report.debug_enabled() {
        return Err(Error::Attestation(
            "guest policy allows debug; enclave memory could be inspected".into(),
        ));
    }

    if report.vmpl != 0 {
        return Err(Error::Attestation(format!(
            "report is from VMPL {}, want 0",
            report.vmpl
        )));
    }

    // A reported TCB below the committed TCB means the platform was rolled
    // back to firmware with known vulnerabilities.
    if report.reported_tcb < report.committed_tcb {
        return Err(Error::Attestation(format!(
            "reported TCB {:#x} is below committed TCB {:#x}",
            report.reported_tcb, report.committed_tcb
        )));
    }

    let sig = Signature::from_scalars(report.signature_r, report.signature_s)
        .map_err(|e| Error::Attestation(format!("malformed report signature: {e}")))?;
    vcek.0
        .verify(&report.signed_data, &sig)
        .map_err(|e| Error::Attestation(format!("report signature invalid: {e}")))?;

    Ok(())
}
```

Update `snp/mod.rs`:
```rust
pub mod report;
pub mod vcek;
pub mod verify;
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `nix develop -c cargo test -p ppq-tee snp`
Expected: all pass, including the four rejection tests.

- [ ] **Step 7: Commit**

```bash
git add crates/ppq-tee/src/attest/snp crates/ppq-tee/Cargo.toml Cargo.lock
git commit -m "feat: verify SEV-SNP report signature and VCEK chain"
```

---

### Task 7: Attestation orchestration

**Files:**
- Modify: `crates/ppq-tee/src/attest/mod.rs`

**Interfaces:**
- Consumes: everything from Tasks 2–6
- Produces:
  - `pub struct Attestation { pub hpke_public_key: [u8; 32], pub tls_key_fingerprint: [u8; 32], pub measurement: [u8; 48], pub domain: String }`
  - `pub fn verify_bundle(bundle: &AttestationBundle, policy: &TrustPolicy) -> Result<Attestation>`
  - `pub async fn attest(base: &str, policy: &TrustPolicy) -> Result<Attestation>`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../testdata/attestation-bundle.json");
    const KEYS: &[u8] = include_bytes!("../../testdata/hpke-keys.bin");

    #[test]
    fn verifies_the_live_bundle_end_to_end() {
        let b = bundle::parse(FIXTURE).unwrap();
        let a = verify_bundle(&b, &TrustPolicy::default()).expect("verifies");
        assert_eq!(a.domain, "inference.tinfoil.sh");
        assert_ne!(a.hpke_public_key, [0u8; 32]);
    }

    #[test]
    fn attested_key_matches_the_advertised_key_config() {
        let b = bundle::parse(FIXTURE).unwrap();
        let a = verify_bundle(&b, &TrustPolicy::default()).unwrap();
        // key_config layout: key_id(1) kem_id(2) public_key(32) ...
        assert_eq!(&KEYS[3..35], &a.hpke_public_key[..],
            "the enclave advertises exactly the key it attested to");
    }

    #[test]
    fn rejects_a_bundle_whose_report_does_not_match_its_deployment() {
        let mut b = bundle::parse(FIXTURE).unwrap();
        // Point at a valid-looking but different measurement.
        b.digest = "0".repeat(64);
        assert!(verify_bundle(&b, &TrustPolicy::default()).is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c cargo test -p ppq-tee attest::tests`
Expected: FAIL — `verify_bundle` not defined.

- [ ] **Step 3: Implement**

```rust
pub mod bundle;
pub mod policy;
pub mod sigstore;
pub mod snp;

pub use bundle::AttestationBundle;
pub use policy::{AmdProduct, TrustPolicy};

use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

/// What a successful verification establishes about the enclave.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// The enclave's X25519 HPKE public key. Everything EHBP seals goes here.
    pub hpke_public_key: [u8; 32],
    pub tls_key_fingerprint: [u8; 32],
    pub measurement: [u8; 48],
    pub domain: String,
}

/// Verify a bundle offline and extract the enclave's attested keys.
pub fn verify_bundle(
    bundle: &AttestationBundle,
    policy: &TrustPolicy,
) -> Result<Attestation> {
    // 1. What *should* be running, per the signed build attestation.
    let deployment = sigstore::verify(bundle, policy)?;

    // 2. What *is* running, per the hardware.
    let raw = bundle::decode_report_body(&bundle.enclave_attestation_report.body)?;
    let report = snp::report::parse(&raw)?;

    let vcek_der = STANDARD
        .decode(&bundle.vcek)
        .map_err(|e| Error::Attestation(format!("VCEK is not base64: {e}")))?;
    let vcek = [AmdProduct::Milan, AmdProduct::Genoa, AmdProduct::Turin]
        .into_iter()
        .find_map(|p| snp::vcek::verify_chain(&vcek_der, p).ok())
        .ok_or_else(|| {
            Error::Attestation("VCEK does not chain to any known AMD root".into())
        })?;

    // 3. Tie them together.
    snp::verify::verify_report(&report, &vcek, &deployment.snp_measurement, policy)?;

    Ok(Attestation {
        hpke_public_key: report.hpke_public_key(),
        tls_key_fingerprint: report.tls_key_fingerprint(),
        measurement: report.measurement,
        domain: bundle.domain.clone(),
    })
}

/// Fetch and verify the live attestation for `base`.
pub async fn attest(base: &str, policy: &TrustPolicy) -> Result<Attestation> {
    let b = bundle::fetch(base).await?;
    verify_bundle(&b, policy)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c cargo test -p ppq-tee attest`
Expected: all attest tests pass. The `attested_key_matches_the_advertised_key_config`
test is the important one — it proves the hardware-attested key is the same key
the endpoint serves.

- [ ] **Step 5: Commit**

```bash
git add crates/ppq-tee/src/attest/mod.rs
git commit -m "feat: end-to-end attestation verification"
```

---

### Task 8: EHBP key config parsing

**Files:**
- Create: `crates/ppq-tee/src/ehbp/keyconfig.rs`, `crates/ppq-tee/src/ehbp/mod.rs`

**Interfaces:**
- Consumes: `crate::{Error, Result}`
- Produces:
  - `pub struct KeyConfig { pub key_id: u8, pub kem_id: u16, pub public_key: [u8; 32], pub kdf_id: u16, pub aead_id: u16 }`
  - `pub fn parse(raw: &[u8]) -> Result<KeyConfig>`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: &[u8] = include_bytes!("../../testdata/hpke-keys.bin");

    #[test]
    fn parses_the_live_key_config() {
        let c = parse(KEYS).expect("parses");
        assert_eq!(c.key_id, 0);
        assert_eq!(c.kem_id, 0x0020, "X25519-HKDF-SHA256");
        assert_eq!(c.kdf_id, 0x0001, "HKDF-SHA256");
        assert_eq!(c.aead_id, 0x0002, "AES-256-GCM");
    }

    #[test]
    fn rejects_a_truncated_config() {
        assert!(parse(&KEYS[..10]).is_err());
    }

    #[test]
    fn rejects_an_unsupported_kem() {
        let mut bad = KEYS.to_vec();
        bad[1] = 0x00; // corrupt kem_id
        bad[2] = 0x10;
        assert!(parse(&bad).is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c cargo test -p ppq-tee keyconfig`
Expected: FAIL — `parse` not defined.

- [ ] **Step 3: Implement**

```rust
use crate::{Error, Result};

pub const KEM_X25519_HKDF_SHA256: u16 = 0x0020;
pub const KDF_HKDF_SHA256: u16 = 0x0001;
pub const AEAD_AES_256_GCM: u16 = 0x0002;

/// An RFC 9458 §3 `key_config`, as served from `/.well-known/hpke-keys`.
///
/// Layout: `key_id(1) ‖ kem_id(2) ‖ public_key(Npk) ‖ cipher_suites_len(2) ‖
/// (kdf_id(2) ‖ aead_id(2))*`
#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub key_id: u8,
    pub kem_id: u16,
    pub public_key: [u8; 32],
    pub kdf_id: u16,
    pub aead_id: u16,
}

pub fn parse(raw: &[u8]) -> Result<KeyConfig> {
    // 1 + 2 + 32 + 2 + 4
    if raw.len() < 41 {
        return Err(Error::Ehbp(format!(
            "key config is {} bytes, want at least 41",
            raw.len()
        )));
    }
    let key_id = raw[0];
    let kem_id = u16::from_be_bytes([raw[1], raw[2]]);
    if kem_id != KEM_X25519_HKDF_SHA256 {
        return Err(Error::Ehbp(format!("unsupported KEM {kem_id:#06x}")));
    }
    let public_key: [u8; 32] = raw[3..35].try_into().unwrap();

    let suites_len = u16::from_be_bytes([raw[35], raw[36]]) as usize;
    if suites_len < 4 || raw.len() < 37 + suites_len {
        return Err(Error::Ehbp("truncated cipher suite list".into()));
    }
    // Take the first suite; this implementation emits exactly one.
    let kdf_id = u16::from_be_bytes([raw[37], raw[38]]);
    let aead_id = u16::from_be_bytes([raw[39], raw[40]]);
    if kdf_id != KDF_HKDF_SHA256 || aead_id != AEAD_AES_256_GCM {
        return Err(Error::Ehbp(format!(
            "unsupported suite kdf={kdf_id:#06x} aead={aead_id:#06x}"
        )));
    }

    Ok(KeyConfig { key_id, kem_id, public_key, kdf_id, aead_id })
}
```

`crates/ppq-tee/src/ehbp/mod.rs`:
```rust
pub mod keyconfig;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c cargo test -p ppq-tee keyconfig`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ppq-tee/src/ehbp
git commit -m "feat: parse RFC 9458 HPKE key configs"
```

---

### Task 9: EHBP sealing and opening

**Files:**
- Create: `crates/ppq-tee/src/ehbp/seal.rs`, `crates/ppq-tee/src/ehbp/open.rs`
- Modify: `crates/ppq-tee/src/ehbp/mod.rs`, `crates/ppq-tee/Cargo.toml`

**Interfaces:**
- Consumes: `keyconfig::KeyConfig`
- Produces:
  - `pub struct SealedRequest { pub enc: [u8; 32], pub body: Vec<u8>, pub session: ResponseSession }`
  - `pub fn seal(public_key: &[u8; 32], plaintext: &[u8]) -> Result<SealedRequest>`
  - `pub struct ResponseSession { exported_secret: [u8; 32], enc: [u8; 32] }`
  - `impl ResponseSession { pub fn opener(&self, response_nonce: &[u8]) -> Result<FrameOpener> }`
  - `pub struct FrameOpener` with `pub fn open_frame(&mut self, ct: &[u8]) -> Result<Vec<u8>>`
  - `pub fn frame(ciphertext: &[u8]) -> Vec<u8>` — prepend the u32be length

- [ ] **Step 1: Add dependencies**

```toml
hpke = { version = "0.14", default-features = false, features = ["x25519", "alloc"] }
hkdf = "0.12"
aes-gcm = "0.10"
rand = "0.8"
```

- [ ] **Step 2: Write the failing test**

`crates/ppq-tee/src/ehbp/open.rs` — a round-trip against a locally generated
keypair, playing both client and server:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ehbp::seal;

    /// Server half: given the client's `enc` and the server private key,
    /// derive the same response keys and seal a body.
    fn server_respond(
        sk: &<hpke::kem::X25519HkdfSha256 as hpke::Kem>::PrivateKey,
        enc_bytes: &[u8; 32],
        request_ct_frames: &[u8],
        response: &[u8],
    ) -> (Vec<u8>, [u8; 32]) {
        use hpke::{aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, OpModeR};
        let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(enc_bytes).unwrap();
        let mut ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base, sk, &enc, seal::REQUEST_INFO,
        ).unwrap();

        // Open every request frame so the AEAD sequence matches the client's.
        let mut rest = request_ct_frames;
        while rest.len() >= 4 {
            let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            rest = &rest[4..];
            if n > 0 { ctx.open(&rest[..n], b"").unwrap(); }
            rest = &rest[n..];
        }

        let mut secret = [0u8; 32];
        ctx.export(super::RESPONSE_EXPORT_LABEL, &mut secret).unwrap();
        let response_nonce = [7u8; 32];
        let mut sealer = FrameSealer::new(&secret, enc_bytes, &response_nonce).unwrap();
        (sealer.seal_frame(response).unwrap(), response_nonce)
    }

    #[test]
    fn round_trips_a_response_through_the_derived_keys() {
        use hpke::Kem as _;
        let mut rng = rand::thread_rng();
        let (sk, pk) = hpke::kem::X25519HkdfSha256::gen_keypair(&mut rng);
        let pk_bytes: [u8; 32] = {
            use hpke::Serializable;
            pk.to_bytes().as_slice().try_into().unwrap()
        };

        let sealed = seal::seal(&pk_bytes, b"{\"model\":\"glm-5-2\"}").unwrap();
        let (frames, nonce) =
            server_respond(&sk, &sealed.enc, &sealed.body, b"hello from the enclave");

        let mut opener = sealed.session.opener(&nonce).unwrap();
        let n = u32::from_be_bytes(frames[..4].try_into().unwrap()) as usize;
        let plain = opener.open_frame(&frames[4..4 + n]).unwrap();
        assert_eq!(plain, b"hello from the enclave");
    }

    #[test]
    fn rejects_a_tampered_frame() {
        use hpke::Kem as _;
        let mut rng = rand::thread_rng();
        let (sk, pk) = hpke::kem::X25519HkdfSha256::gen_keypair(&mut rng);
        let pk_bytes: [u8; 32] = {
            use hpke::Serializable;
            pk.to_bytes().as_slice().try_into().unwrap()
        };

        let sealed = seal::seal(&pk_bytes, b"x").unwrap();
        let (mut frames, nonce) = server_respond(&sk, &sealed.enc, &sealed.body, b"secret");
        frames[6] ^= 0xFF;

        let mut opener = sealed.session.opener(&nonce).unwrap();
        let n = u32::from_be_bytes(frames[..4].try_into().unwrap()) as usize;
        assert!(opener.open_frame(&frames[4..4 + n]).is_err());
    }

    #[test]
    fn rejects_a_wrong_response_nonce() {
        use hpke::Kem as _;
        let mut rng = rand::thread_rng();
        let (sk, pk) = hpke::kem::X25519HkdfSha256::gen_keypair(&mut rng);
        let pk_bytes: [u8; 32] = {
            use hpke::Serializable;
            pk.to_bytes().as_slice().try_into().unwrap()
        };

        let sealed = seal::seal(&pk_bytes, b"x").unwrap();
        let (frames, _) = server_respond(&sk, &sealed.enc, &sealed.body, b"secret");

        let mut opener = sealed.session.opener(&[9u8; 32]).unwrap();
        let n = u32::from_be_bytes(frames[..4].try_into().unwrap()) as usize;
        assert!(opener.open_frame(&frames[4..4 + n]).is_err());
    }

    #[test]
    fn frame_sequence_advances_per_frame() {
        // Two frames sealed under the same key must produce different
        // ciphertexts for identical plaintext, or the nonce is being reused.
        let secret = [1u8; 32];
        let enc = [2u8; 32];
        let nonce = [3u8; 32];
        let mut s = FrameSealer::new(&secret, &enc, &nonce).unwrap();
        let a = s.seal_frame(b"same").unwrap();
        let b = s.seal_frame(b"same").unwrap();
        assert_ne!(a, b, "frame nonces must not repeat");
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `nix develop -c cargo test -p ppq-tee ehbp::open`
Expected: FAIL — `seal` and `FrameOpener` not defined.

- [ ] **Step 4: Implement `seal.rs`**

```rust
use crate::ehbp::open::ResponseSession;
use crate::{Error, Result};
use hpke::{aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, OpModeS, Serializable};

/// HPKE `info` for the request context, per the EHBP spec.
pub const REQUEST_INFO: &[u8] = b"ehbp request";

pub struct SealedRequest {
    /// Goes in the `Ehbp-Encapsulated-Key` header, hex-encoded.
    pub enc: [u8; 32],
    /// Length-prefixed ciphertext frames, ready to send as the body.
    pub body: Vec<u8>,
    /// Retained so the response can be decrypted.
    pub session: ResponseSession,
}

/// Prepend the 4-byte big-endian ciphertext length required by EHBP framing.
pub fn frame(ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ciphertext.len());
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

/// HPKE-seal a request body to the enclave's attested public key.
///
/// The whole body is sent as a single frame: request bodies are small JSON
/// documents, and one frame keeps the sealer's sequence trivially in step with
/// the server's opener.
pub fn seal(public_key: &[u8; 32], plaintext: &[u8]) -> Result<SealedRequest> {
    let pk = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(public_key)
        .map_err(|e| Error::Ehbp(format!("bad enclave public key: {e}")))?;

    let mut rng = rand::thread_rng();
    let (enc, mut ctx) = hpke::setup_sender::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base, &pk, REQUEST_INFO, &mut rng,
    )
    .map_err(|e| Error::Ehbp(format!("HPKE setup failed: {e}")))?;

    let ct = ctx
        .seal(plaintext, b"")
        .map_err(|e| Error::Ehbp(format!("sealing request failed: {e}")))?;

    let mut exported_secret = [0u8; 32];
    ctx.export(crate::ehbp::open::RESPONSE_EXPORT_LABEL, &mut exported_secret)
        .map_err(|e| Error::Ehbp(format!("HPKE export failed: {e}")))?;

    let enc_bytes: [u8; 32] = enc
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| Error::Ehbp("encapsulated key is not 32 bytes".into()))?;

    Ok(SealedRequest {
        enc: enc_bytes,
        body: frame(&ct),
        session: ResponseSession::new(exported_secret, enc_bytes),
    })
}
```

- [ ] **Step 5: Implement `open.rs`**

```rust
use crate::{Error, Result};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// HPKE export label for response keys, per the EHBP spec.
pub const RESPONSE_EXPORT_LABEL: &[u8] = b"ehbp response";

/// Everything needed to decrypt one response, retained from the request.
#[derive(Debug, Clone)]
pub struct ResponseSession {
    exported_secret: [u8; 32],
    enc: [u8; 32],
}

impl ResponseSession {
    pub fn new(exported_secret: [u8; 32], enc: [u8; 32]) -> Self {
        Self { exported_secret, enc }
    }

    /// Derive the response AEAD from this session and the server's nonce.
    pub fn opener(&self, response_nonce: &[u8]) -> Result<FrameOpener> {
        let (key, base) = derive(&self.exported_secret, &self.enc, response_nonce)?;
        Ok(FrameOpener { cipher: Aes256Gcm::new(&key), base, seq: 0 })
    }
}

/// `prk = Extract(salt = enc ‖ response_nonce, ikm = secret)`, then
/// `key = Expand(prk, "key", 32)` and `nonce = Expand(prk, "nonce", 12)`.
fn derive(
    secret: &[u8; 32],
    enc: &[u8; 32],
    response_nonce: &[u8],
) -> Result<(Key<Aes256Gcm>, [u8; 12])> {
    if response_nonce.len() != 32 {
        return Err(Error::Ehbp(format!(
            "response nonce is {} bytes, want 32",
            response_nonce.len()
        )));
    }
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(enc);
    salt.extend_from_slice(response_nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut key = [0u8; 32];
    hk.expand(b"key", &mut key)
        .map_err(|e| Error::Ehbp(format!("key expansion failed: {e}")))?;
    let mut base = [0u8; 12];
    hk.expand(b"nonce", &mut base)
        .map_err(|e| Error::Ehbp(format!("nonce expansion failed: {e}")))?;

    Ok((*Key::<Aes256Gcm>::from_slice(&key), base))
}

/// Per-frame nonce: `base XOR seq`, with `seq` as a big-endian u64 in the
/// **last 8 bytes** of the 12-byte base. Confirmed against the Go reference
/// (`identity/derive.go`); the written spec is ambiguous on the placement.
fn frame_nonce(base: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *base;
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        n[4 + i] ^= b;
    }
    n
}

/// Opens response frames in order. Never emits plaintext for a frame that
/// failed authentication.
pub struct FrameOpener {
    cipher: Aes256Gcm,
    base: [u8; 12],
    seq: u64,
}

impl FrameOpener {
    pub fn open_frame(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = frame_nonce(&self.base, self.seq);
        let plain = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| Error::Ehbp("response frame failed authentication".into()))?;
        // Advance only after a frame authenticates, so a rejected frame cannot
        // desynchronise the sequence.
        self.seq += 1;
        Ok(plain)
    }
}

/// The server half of the response AEAD. Test-only in this crate, but kept
/// beside the opener so the two derivations cannot drift apart.
pub struct FrameSealer {
    cipher: Aes256Gcm,
    base: [u8; 12],
    seq: u64,
}

impl FrameSealer {
    pub fn new(secret: &[u8; 32], enc: &[u8; 32], response_nonce: &[u8]) -> Result<Self> {
        let (key, base) = derive(secret, enc, response_nonce)?;
        Ok(Self { cipher: Aes256Gcm::new(&key), base, seq: 0 })
    }

    pub fn seal_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = frame_nonce(&self.base, self.seq);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| Error::Ehbp("sealing response frame failed".into()))?;
        self.seq += 1;
        Ok(crate::ehbp::seal::frame(&ct))
    }
}
```

Update `ehbp/mod.rs`:
```rust
pub mod keyconfig;
pub mod open;
pub mod seal;
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `nix develop -c cargo test -p ppq-tee ehbp`
Expected: all pass, including the three rejection tests.

- [ ] **Step 7: Commit**

```bash
git add crates/ppq-tee/src/ehbp crates/ppq-tee/Cargo.toml Cargo.lock
git commit -m "feat: EHBP request sealing and response opening"
```

---

### Task 10: Incremental frame decryptor

**Files:**
- Create: `crates/ppq-tee/src/ehbp/stream.rs`
- Modify: `crates/ppq-tee/src/ehbp/mod.rs`

**Interfaces:**
- Consumes: `open::FrameOpener`
- Produces:
  - `pub struct FrameDecoder { opener: FrameOpener, buf: Vec<u8> }`
  - `impl FrameDecoder { pub fn new(opener: FrameOpener) -> Self; pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>>; pub fn finish(self) -> Result<()> }`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ehbp::open::{FrameSealer, ResponseSession};

    fn pair() -> (FrameSealer, FrameDecoder) {
        let secret = [4u8; 32];
        let enc = [5u8; 32];
        let nonce = [6u8; 32];
        let sealer = FrameSealer::new(&secret, &enc, &nonce).unwrap();
        let session = ResponseSession::new(secret, enc);
        (sealer, FrameDecoder::new(session.opener(&nonce).unwrap()))
    }

    #[test]
    fn decodes_frames_split_across_arbitrary_chunk_boundaries() {
        let (mut s, mut d) = pair();
        let mut wire = s.seal_frame(b"data: one\n\n").unwrap();
        wire.extend(s.seal_frame(b"data: two\n\n").unwrap());

        // Feed one byte at a time — the worst case for framing bugs.
        let mut out = Vec::new();
        for b in &wire {
            out.extend(d.push(&[*b]).unwrap());
        }
        assert_eq!(out, b"data: one\n\ndata: two\n\n");
        d.finish().unwrap();
    }

    #[test]
    fn skips_zero_length_frames() {
        let (mut s, mut d) = pair();
        let mut wire = vec![0, 0, 0, 0]; // empty write from the application
        wire.extend(s.seal_frame(b"payload").unwrap());
        assert_eq!(d.push(&wire).unwrap(), b"payload");
    }

    #[test]
    fn rejects_eof_with_a_partial_length_prefix() {
        let (_, mut d) = pair();
        d.push(&[0, 0]).unwrap();
        assert!(d.finish().is_err());
    }

    #[test]
    fn rejects_eof_with_an_incomplete_frame() {
        let (mut s, mut d) = pair();
        let wire = s.seal_frame(b"truncated").unwrap();
        d.push(&wire[..wire.len() - 3]).unwrap();
        assert!(d.finish().is_err());
    }

    #[test]
    fn emits_nothing_for_an_unauthenticated_frame() {
        let (mut s, mut d) = pair();
        let mut wire = s.seal_frame(b"tampered").unwrap();
        wire[8] ^= 0xFF;
        assert!(d.push(&wire).is_err(), "must not emit unauthenticated bytes");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c cargo test -p ppq-tee ehbp::stream`
Expected: FAIL — `FrameDecoder` not defined.

- [ ] **Step 3: Implement**

```rust
use crate::ehbp::open::FrameOpener;
use crate::{Error, Result};

/// Reassembles EHBP frames from a byte stream that may split them anywhere.
///
/// A frame's plaintext is emitted only after that whole frame authenticates,
/// so a caller never sees bytes the enclave did not sign for.
pub struct FrameDecoder {
    opener: FrameOpener,
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new(opener: FrameOpener) -> Self {
        Self { opener, buf: Vec::new() }
    }

    /// Feed transport bytes; returns whatever plaintext became available.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();

        loop {
            if self.buf.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
            if self.buf.len() < 4 + len {
                break;
            }
            let frame: Vec<u8> = self.buf.drain(..4 + len).skip(4).collect();
            // Zero-length frames come from empty application writes; the spec
            // says receivers ignore them without advancing the sequence.
            if len == 0 {
                continue;
            }
            out.extend(self.opener.open_frame(&frame)?);
        }

        Ok(out)
    }

    /// Assert the stream ended on a frame boundary.
    ///
    /// Transport EOF alone does not prove the application response is
    /// complete, but a partial frame proves it is *not*.
    pub fn finish(self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Ehbp(format!(
                "stream ended mid-frame with {} bytes buffered",
                self.buf.len()
            )))
        }
    }
}
```

Add `pub mod stream;` to `ehbp/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop -c cargo test -p ppq-tee ehbp::stream`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ppq-tee/src/ehbp/stream.rs crates/ppq-tee/src/ehbp/mod.rs
git commit -m "feat: incremental EHBP frame decryptor"
```

---

### Task 11: PpqClient and model discovery

**Files:**
- Create: `crates/ppq-tee/src/client.rs`, `crates/ppq-tee/src/models.rs`,
  `crates/ppq-tee/tests/live.rs`
- Modify: `crates/ppq-tee/src/lib.rs`

**Interfaces:**
- Consumes: `attest::{attest, Attestation, TrustPolicy}`, `ehbp::{seal, stream, keyconfig}`
- Produces:
  - `pub struct PpqClient`, `pub struct PpqClientBuilder`
  - `PpqClientBuilder::{api_key, base_url, trust_policy, build}`
  - `PpqClient::{attestation, chat_completion, chat_completion_stream, list_models, enclave_model_id}`
  - `pub struct PrivateModel { pub id, pub name, pub context_length, pub pricing }`
  - `pub struct Pricing { pub input_per_1m: f64, pub output_per_1m: f64, pub currency: String }`

- [ ] **Step 1: Write `models.rs` with its test**

```rust
use crate::{Error, Result};
use serde::Deserialize;

/// A TEE-backed model from PPQ's catalogue.
#[derive(Debug, Clone)]
pub struct PrivateModel {
    /// User-facing id, e.g. `private/glm-5-2`.
    pub id: String,
    pub name: String,
    pub context_length: u32,
    pub pricing: Pricing,
}

#[derive(Debug, Clone)]
pub struct Pricing {
    pub input_per_1m: f64,
    pub output_per_1m: f64,
    pub currency: String,
}

#[derive(Deserialize)]
struct Catalogue {
    data: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    context_length: u32,
    #[serde(rename = "privacyLevel", default)]
    privacy_level: String,
    #[serde(default)]
    pricing: Option<RawPricing>,
}

#[derive(Deserialize)]
struct RawPricing {
    #[serde(default)]
    currency: String,
    #[serde(rename = "input_per_1M_tokens", default)]
    input: f64,
    #[serde(rename = "output_per_1M_tokens", default)]
    output: f64,
}

/// Keep only the end-to-end encrypted (TEE) models.
pub fn parse_private(json: &str) -> Result<Vec<PrivateModel>> {
    let c: Catalogue = serde_json::from_str(json)?;
    Ok(c.data
        .into_iter()
        .filter(|e| e.privacy_level == "e2e")
        .map(|e| {
            let p = e.pricing.unwrap_or(RawPricing {
                currency: "USD".into(),
                input: 0.0,
                output: 0.0,
            });
            PrivateModel {
                id: e.id,
                name: e.name,
                context_length: e.context_length,
                pricing: Pricing {
                    input_per_1m: p.input,
                    output_per_1m: p.output,
                    currency: p.currency,
                },
            }
        })
        .collect())
}

/// Strip the `private/` prefix to get the id the enclave expects in the body.
///
/// This is a mechanical rule that holds for every TEE model; there is
/// deliberately no lookup table to drift out of date.
pub fn enclave_model_id(id: &str) -> &str {
    id.strip_prefix("private/").unwrap_or(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_e2e_models() {
        let json = r#"{"data":[
            {"id":"gemini-3.7-flash","privacyLevel":"anon","context_length":1},
            {"id":"z-ai/glm-5.2","privacyLevel":"zdr","context_length":2},
            {"id":"private/glm-5-2","name":"GLM 5.2 (Private via TEE)",
             "privacyLevel":"e2e","context_length":384000,
             "pricing":{"currency":"USD","input_per_1M_tokens":1.5,"output_per_1M_tokens":3.0}}
        ]}"#;
        let m = parse_private(json).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].id, "private/glm-5-2");
        assert_eq!(m[0].context_length, 384000);
        assert_eq!(m[0].pricing.output_per_1m, 3.0);
    }

    #[test]
    fn tolerates_e2e_entries_without_pricing() {
        let json = r#"{"data":[{"id":"private/x","privacyLevel":"e2e"}]}"#;
        assert_eq!(parse_private(json).unwrap().len(), 1);
    }

    #[test]
    fn strips_the_private_prefix() {
        assert_eq!(enclave_model_id("private/glm-5-2"), "glm-5-2");
        assert_eq!(enclave_model_id("private/kimi-k3"), "kimi-k3");
        assert_eq!(enclave_model_id("glm-5-2"), "glm-5-2");
    }
}
```

- [ ] **Step 2: Run the models tests**

Run: `nix develop -c cargo test -p ppq-tee models`
Expected: FAIL first (module not declared), then add `pub mod models;` to
`lib.rs` and re-run — 3 passed.

- [ ] **Step 3: Write `client.rs`**

```rust
use crate::attest::{self, Attestation, TrustPolicy};
use crate::ehbp::{keyconfig, open::FrameOpener, seal, stream::FrameDecoder};
use crate::models::{self, PrivateModel};
use crate::{Error, Result};
use bytes::Bytes;
use futures::{Stream, StreamExt};

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
    /// so it is unauthenticated discovery metadata — never a trust input. The
    /// security guarantee comes from attestation and is independent of what
    /// this returns; an unknown model id is simply rejected by the enclave.
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
    pub async fn chat_completion(
        &self,
        mut body: serde_json::Value,
    ) -> Result<serde_json::Value> {
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
    pub async fn chat_completion_stream(
        &self,
        mut body: serde_json::Value,
    ) -> Result<impl Stream<Item = Result<Bytes>>> {
        body["stream"] = serde_json::Value::Bool(true);
        let model = self.take_model(&mut body)?;
        let (decoder, response) = self.send_sealed(&body, &model).await?;

        Ok(futures::stream::unfold(
            (decoder, response.bytes_stream()),
            |(mut decoder, mut inner)| async move {
                match inner.next().await {
                    Some(Ok(chunk)) => match decoder.push(&chunk) {
                        Ok(plain) => Some((Ok(Bytes::from(plain)), (decoder, inner))),
                        Err(e) => Some((Err(e), (decoder, inner))),
                    },
                    Some(Err(e)) => Some((Err(Error::Http(e)), (decoder, inner))),
                    None => None,
                }
            },
        ))
    }

    /// Rewrite `model` to the enclave-internal id and return the user-facing one.
    fn take_model(&self, body: &mut serde_json::Value) -> Result<String> {
        let user_facing = body["model"]
            .as_str()
            .ok_or_else(|| Error::Ehbp("request has no model".into()))?
            .to_string();
        body["model"] =
            serde_json::Value::String(models::enclave_model_id(&user_facing).to_string());
        Ok(user_facing)
    }

    async fn send_sealed(
        &self,
        body: &serde_json::Value,
        model: &str,
    ) -> Result<(FrameDecoder, reqwest::Response)> {
        let plaintext = serde_json::to_vec(body)?;
        let sealed = seal::seal(&self.attestation.hpke_public_key, &plaintext)?;

        let response = self
            .http
            .post(format!("{}/private/v1/chat/completions", self.base_url))
            .bearer_auth(&self.api_key)
            .header("Content-Type", "application/json")
            .header("Ehbp-Encapsulated-Key", hex::encode(sealed.enc))
            .header("X-Private-Model", model)
            .header("x-query-source", "api")
            .body(sealed.body)
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
                Error::UnauthenticatedUpstream { status: status.as_u16(), body }
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
        let base_url = self.base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
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
```

Add to `lib.rs`:
```rust
pub mod client;
pub mod models;

pub use client::{PpqClient, PpqClientBuilder};
pub use models::{PrivateModel, Pricing};
```

- [ ] **Step 4: Write the live integration tests**

`crates/ppq-tee/tests/live.rs`:

```rust
//! Live tests against api.ppq.ai. Ignored by default: they need network access
//! and spend credit on the configured key.
//!
//! Run with: PPQ_API_KEY=sk-... cargo test -p ppq-tee --test live -- --ignored

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
            "max_tokens": 16,
        }))
        .await
        .unwrap();
    let text = resp["choices"][0]["message"]["content"].as_str().unwrap();
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
```

- [ ] **Step 5: Run the offline tests, then the live ones**

Run: `nix develop -c cargo test -p ppq-tee`
Expected: all offline tests pass; live tests reported as ignored.

Run: `PPQ_API_KEY=$PPQ_API_KEY nix develop -c cargo test -p ppq-tee --test live -- --ignored`
Expected: 5 passed. This is the first end-to-end proof: attestation, sealing,
decryption and streaming all working against the real enclave.

- [ ] **Step 6: Commit**

```bash
git add crates/ppq-tee/src/client.rs crates/ppq-tee/src/models.rs crates/ppq-tee/src/lib.rs crates/ppq-tee/tests
git commit -m "feat: PpqClient with attested sealed transport and model discovery"
```

---

### Task 12: rig-core provider

**Files:**
- Create: `crates/ppq-tee/src/rig.rs`, `crates/ppq-tee/examples/rig_agent.rs`
- Modify: `crates/ppq-tee/src/lib.rs`, `crates/ppq-tee/Cargo.toml`

**Interfaces:**
- Consumes: `PpqClient`
- Produces:
  - `pub struct EhbpHttp` implementing `rig_core::http_client::HttpClientExt`
  - `pub struct PpqExt` implementing `rig_core::providers::openai::completion::OpenAICompatibleProvider`
  - `pub type PpqCompletionModel`
  - `impl PpqClient { pub fn completion_model(&self, id: &str) -> PpqCompletionModel }`

- [ ] **Step 1: Add the feature wiring**

In `crates/ppq-tee/Cargo.toml` the `rig` feature and optional `rig-core` are
already declared from Task 1. Add to `lib.rs`:

```rust
#[cfg(feature = "rig")]
pub mod rig;
```

- [ ] **Step 2: Write the failing test**

At the bottom of `crates/ppq-tee/src/rig.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_the_private_prefix_from_the_request_body() {
        use rig_core::providers::openai::completion::{
            CompletionRequest as OaiRequest, OpenAICompatibleProvider,
        };
        let mut req = OaiRequest {
            model: "private/glm-5-2".to_string(),
            ..Default::default()
        };
        PpqExt.prepare_request(&mut req).unwrap();
        assert_eq!(
            req.model, "glm-5-2",
            "the enclave expects the unprefixed id in the body"
        );
    }

    #[test]
    fn advertises_tool_support() {
        use rig_core::providers::openai::completion::OpenAICompatibleProvider;
        // PPQ's catalogue omits `supported_parameters` for e2e models, which
        // reads as "no tools". It is wrong: the enclave does emit tool calls.
        assert!(PpqExt::SUPPORTS_TOOLS);
        assert!(PpqExt::SUPPORTS_RESPONSE_FORMAT);
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `nix develop -c cargo test -p ppq-tee --features rig rig::`
Expected: FAIL — `PpqExt` not defined.

- [ ] **Step 4: Implement**

```rust
//! `rig-core` integration.
//!
//! `rig-core` is generic over its HTTP backend, so the EHBP channel plugs in as
//! that backend and rig's OpenAI-compatible machinery handles message
//! conversion, tool calls and SSE streaming unchanged. Nothing here re-derives
//! wire formats.

use crate::PpqClient;
use rig_core::http_client::{HttpClientExt, LazyBody, Result as HttpResult, StreamingResponse};
use rig_core::providers::openai::{self, completion::OpenAICompatibleProvider};
use std::sync::Arc;

/// An HTTP backend whose bodies are HPKE-sealed to the attested enclave.
#[derive(Clone)]
pub struct EhbpHttp {
    // `HttpClientExt::send` returns `impl Future + 'static`, so the future
    // cannot borrow `&self`; hold shared state behind an Arc and clone it in.
    inner: Arc<PpqClient>,
}

impl EhbpHttp {
    pub fn new(client: PpqClient) -> Self {
        Self { inner: Arc::new(client) }
    }
}

impl HttpClientExt for EhbpHttp {
    fn send<T, U>(
        &self,
        req: http::Request<T>,
    ) -> impl std::future::Future<Output = HttpResult<http::Response<LazyBody<U>>>> + Send + 'static
    where
        T: Into<bytes::Bytes> + Send,
        U: From<bytes::Bytes> + Send + 'static,
    {
        let inner = self.inner.clone();
        async move { crate::rig::send_sealed(inner, req).await }
    }

    fn send_streaming<T>(
        &self,
        req: http::Request<T>,
    ) -> impl std::future::Future<Output = HttpResult<StreamingResponse>> + Send
    where
        T: Into<bytes::Bytes> + Send,
    {
        let inner = self.inner.clone();
        async move { crate::rig::send_sealed_streaming(inner, req).await }
    }
}

/// Provider extension describing how PPQ's enclave differs from stock OpenAI.
#[derive(Debug, Clone, Copy, Default)]
pub struct PpqExt;

impl OpenAICompatibleProvider for PpqExt {
    const PROVIDER_NAME: &'static str = "ppq-private";

    // PPQ's catalogue omits `supported_parameters` for e2e models, which would
    // read as "tools unsupported". That is an artefact of the field being
    // absent: the enclave does emit tool calls, and Claude Code drives
    // private/glm-5-2 entirely through them. Deriving these from the catalogue
    // would silently disable tool calling for every model.
    const SUPPORTS_TOOLS: bool = true;
    const SUPPORTS_RESPONSE_FORMAT: bool = true;

    type StreamingUsage = openai::Usage;
    type Response = openai::CompletionResponse;

    fn prepare_request(
        &self,
        request: &mut openai::completion::CompletionRequest,
    ) -> Result<(), rig_core::completion::CompletionError> {
        // The header carries the user-facing id; the body carries the
        // enclave-internal one.
        request.model = crate::models::enclave_model_id(&request.model).to_string();
        Ok(())
    }
}

pub type PpqCompletionModel =
    openai::completion::GenericCompletionModel<PpqExt, EhbpHttp>;

impl PpqClient {
    /// A `rig-core` completion model for `id` (e.g. `private/glm-5-2`).
    ///
    /// The id is not validated against the catalogue: that would put a network
    /// round-trip on a hot path, and the attested enclave is the authority on
    /// what it serves.
    pub fn completion_model(&self, id: &str) -> PpqCompletionModel {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "X-Private-Model",
            http::HeaderValue::from_str(id).expect("model id is a valid header value"),
        );
        headers.insert("x-query-source", http::HeaderValue::from_static("api"));

        let client = openai::Client::builder(&self.api_key)
            .base_url(&format!("{}/private/v1", self.base_url))
            .custom_client(EhbpHttp::new(self.clone()))
            .extra_headers(headers)
            .build()
            .expect("client builds from a validated base URL");

        PpqCompletionModel::new(client, id)
    }
}
```

> The `openai::Client::builder` call above uses rig 0.41's builder. If the
> method names differ (`custom_client`/`extra_headers`), read
> `rig-core-0.41.0/src/client/mod.rs` and adapt — the requirement is that the
> built client uses `EhbpHttp` as its backend and sends the two headers. The
> `send_sealed` / `send_sealed_streaming` helpers reuse `PpqClient`'s existing
> sealing logic from Task 11; factor that method out of `client.rs` into a
> shared `pub(crate)` function rather than duplicating it.

- [ ] **Step 5: Run tests to verify they pass**

Run: `nix develop -c cargo test -p ppq-tee --features rig`
Expected: all pass, including the two new rig tests.

Run: `nix develop -c cargo check -p ppq-tee`
Expected: builds without rig-core in the tree.

Run: `nix develop -c cargo tree -p ppq-tee | grep rig`
Expected: no output — rig is genuinely optional.

- [ ] **Step 6: Write the example**

`crates/ppq-tee/examples/rig_agent.rs`:

```rust
//! Run with:
//!   PPQ_API_KEY=sk-... cargo run -p ppq-tee --features rig --example rig_agent

use rig_core::completion::Prompt;
use ppq_tee::PpqClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ppq = PpqClient::builder()
        .api_key(std::env::var("PPQ_API_KEY")?)
        .build()
        .await?;

    println!(
        "attested enclave {}, measurement {}",
        ppq.attestation().domain,
        hex::encode(&ppq.attestation().measurement[..8]),
    );

    let agent = rig_core::agent::AgentBuilder::new(ppq.completion_model("private/glm-5-2"))
        .preamble("You are concise.")
        .build();

    println!("{}", agent.prompt("Name three prime numbers.").await?);
    Ok(())
}
```

Run: `PPQ_API_KEY=$PPQ_API_KEY nix develop -c cargo run -p ppq-tee --features rig --example rig_agent`
Expected: prints the attested enclave line, then a model answer.

- [ ] **Step 7: Commit**

```bash
git add crates/ppq-tee/src/rig.rs crates/ppq-tee/src/lib.rs crates/ppq-tee/examples crates/ppq-tee/Cargo.toml Cargo.lock
git commit -m "feat: rig-core provider over the sealed EHBP transport"
```

---

### Task 13: README and clippy sweep

**Files:**
- Create: `README.md`
- Modify: any file clippy flags

**Interfaces:**
- Consumes: everything
- Produces: no new API

- [ ] **Step 1: Write `README.md`**

Cover, in this order: what the crate does and the guarantee it provides (PPQ
sees ciphertext only; the enclave is verified against a signed build
attestation); a quickstart with `PpqClient::builder()`; the rig example; how to
run offline tests and how to run live tests with `PPQ_API_KEY`; a "Security
model" section stating what is and is not protected — bodies are encrypted,
headers (including the model id and API key) are not, and the model catalogue is
unauthenticated metadata; and a pointer to the spec in `docs/superpowers/specs/`.

- [ ] **Step 2: Run the full check**

Run: `nix develop -c cargo clippy --all-targets --all-features -- -D warnings`
Expected: no warnings. Fix anything reported.

Run: `nix develop -c cargo fmt --all -- --check`
Expected: no diff.

Run: `nix develop -c cargo test --all-features`
Expected: all offline tests pass.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: README with quickstart and security model"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| §3 workspace layout | 1 |
| §4.1 pipeline steps 1, 5 | 2, 7, 11 |
| §4.1 step 2 sigstore | 4 |
| §4.1 steps 3–4 SNP | 5, 6, 7 |
| §4.2 Rekor verification time | 4 (offline mode, crate-native check) |
| §4.3–4.4 trust policy | 3, 4 |
| §5 EHBP | 8, 9, 10 |
| §6 PPQ request shape | 11, 12 |
| §7 model discovery | 11 |
| §7.1 catalogue not a trust input | 11 (doc comment) |
| §7.2 do not infer capabilities | 12 (const + test) |
| §8 rig integration | 12 |
| §9 testing | every task; live tests in 11 |
| §10 nix | 1 |

**Known gaps, deliberate:**
- The enclave TLS certificate is parsed but its fingerprint is not checked
  against `report_data[0..32]`. EHBP's guarantee rests on the HPKE key, and
  TLS is terminated by PPQ's CDN, so the fingerprint has no role in this
  design. It is exposed on `Attestation` for callers who want it.
- `xtask` has one subcommand. It takes no argument parsing until it needs a
  second one.

**Type consistency:** `enclave_model_id` (models.rs) is used by both `client.rs`
and `rig.rs` under that exact name. `ResponseSession::opener` returns
`FrameOpener`, consumed by `FrameDecoder::new` in Task 10 and `send_sealed` in
Task 11. `TrustPolicy` fields `signer_repository` / `oidc_issuer` /
`require_debug_disabled` are consistent across Tasks 3, 4, 6 and 11.
