//! What the verifier requires of an attestation before trusting it.

/// What the verifier requires of an attestation before trusting it.
///
/// The signer identity is pinned on the certificate's GitHub Actions
/// *repository* extension rather than its SAN. The SAN embeds the release tag
/// (`...@refs/tags/v0.0.141`) and `sigstore`'s `Identity` policy matches it
/// exactly, so pinning the SAN would fail on every Tinfoil release. Pinning
/// the repository extension instead is the same trust boundary and survives
/// releases.
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

/// Sigstore trusted root (Fulcio/Rekor/CT/TSA keys), verified against the
/// signed TUF targets metadata. See `testdata/amd/PROVENANCE.md` for the AMD
/// roots' provenance; this file's provenance is recorded in the Task 3
/// report.
pub const SIGSTORE_TRUSTED_ROOT: &str = include_str!("../../testdata/sigstore-trusted-root.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdProduct {
    Milan,
    Genoa,
    Turin,
}

/// ASK+ARK chain for a product line, as PEM (ASK at index 0, ARK at index 1
/// when parsed with `Certificate::load_pem_chain()`), matching the layout
/// AMD KDS's `cert_chain` endpoint returns.
pub fn amd_root(product: AmdProduct) -> &'static [u8] {
    match product {
        AmdProduct::Milan => include_bytes!("../../testdata/amd/Milan.pem"),
        AmdProduct::Genoa => include_bytes!("../../testdata/amd/Genoa.pem"),
        AmdProduct::Turin => include_bytes!("../../testdata/amd/Turin.pem"),
    }
}

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
