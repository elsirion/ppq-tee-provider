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
    /// Reject attestations whose Rekor entry is older than this.
    ///
    /// Both the deployment digest and the sigstore bundle in an attestation
    /// response come from the server being attested, so without this bound a
    /// malicious server could replay any attestation
    /// `tinfoilsh/confidential-model-router` has ever signed — including an
    /// older release with a known-bad measurement. The hardware layer cannot
    /// detect this; only freshness of the signed statement can.
    ///
    /// `None` disables the check.
    pub max_attestation_age: Option<std::time::Duration>,
    /// Check the bundle's `enclaveCert` against the report and the claimed
    /// `domain`: its SubjectPublicKeyInfo must hash to the report's TLS key
    /// fingerprint, and its subjectAltName must then cover `domain`.
    ///
    /// **This establishes that the presented certificate carries the public
    /// key the attested hardware vouched for, and that the certificate's SAN
    /// covers the claimed name. It does not establish that the certificate was
    /// issued by anyone** — its signature is never verified, so an attacker
    /// holding a genuine bundle can rebuild the certificate around the same
    /// SubjectPublicKeyInfo with any SAN it likes and still pass. So
    /// [`crate::attest::Attestation::domain`] is *not* an attested fact with
    /// this on; it is a misconfiguration and smoke-test guard, never a
    /// verification result or a basis for policy. See
    /// [`crate::attest::domain`] for what would make it trustworthy and why
    /// that is not done.
    ///
    /// Off, even that guard is skipped: the server can name any domain it
    /// likes and verification will not so much as look at the certificate.
    ///
    /// On by default — it is the fail-closed choice, and it catches a server
    /// whose certificate does not match its own claimed domain. It does
    /// *not* catch a client pointed at a genuine-but-wrong deployment: that
    /// bundle is internally self-consistent and passes. A caller who needs
    /// that must compare [`crate::attest::Attestation::domain`] against the
    /// domain it expected itself.
    pub check_enclave_certificate: bool,
}

/// Default bound for [`TrustPolicy::max_attestation_age`]: 90 days.
const DEFAULT_MAX_ATTESTATION_AGE: std::time::Duration =
    std::time::Duration::from_secs(90 * 24 * 60 * 60);

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            signer_repository: "tinfoilsh/confidential-model-router".to_string(),
            oidc_issuer: "https://token.actions.githubusercontent.com".to_string(),
            require_debug_disabled: true,
            max_attestation_age: Some(DEFAULT_MAX_ATTESTATION_AGE),
            check_enclave_certificate: true,
        }
    }
}

/// Sigstore trusted root (Fulcio/Rekor/CT/TSA keys), verified against the
/// signed TUF targets metadata.
///
/// Provenance — how it was obtained, its digest, and how to refresh it — is in
/// `testdata/sigstore-trusted-root.PROVENANCE.md`; the AMD roots' equivalent is
/// `testdata/amd/PROVENANCE.md`.
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
        assert_eq!(
            p.max_attestation_age,
            Some(std::time::Duration::from_secs(90 * 24 * 60 * 60))
        );
        assert!(
            p.check_enclave_certificate,
            "the enclave certificate check is on by default: it is the fail-closed choice"
        );
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
