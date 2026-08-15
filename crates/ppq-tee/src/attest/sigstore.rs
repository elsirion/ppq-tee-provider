//! Sigstore layer: what the enclave is *supposed* to be running.
//!
//! This module establishes the *expected* SEV-SNP launch measurement by verifying
//! Tinfoil's sigstore-signed build attestation. The hardware side (proving the
//! enclave actually booted that measurement) is a separate layer.
//!
//! Note the module-name collision with the `sigstore-*` crates: everything from
//! them is imported explicitly below.

use crate::attest::bundle::AttestationBundle;
use crate::attest::policy::{TrustPolicy, SIGSTORE_TRUSTED_ROOT};
use crate::{Error, Result};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Artifact, Bundle, SignatureContent};
use sigstore_verify::{VerificationPolicy, Verifier};
use x509_cert::der::{oid::ObjectIdentifier, Decode};
use x509_cert::Certificate;

/// Fulcio's "GitHub Workflow Repository" claim.
///
/// <https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md>. Like every
/// `1.3.6.1.4.1.57264.1.1`–`.6` extension, its value is a bare UTF-8 string
/// rather than a DER-encoded one.
const GITHUB_WORKFLOW_REPOSITORY_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.5");

/// The subset of Tinfoil's in-toto predicate this crate consumes.
#[derive(Debug, Clone)]
pub struct DeploymentPredicate {
    /// Expected SEV-SNP launch measurement, 48 bytes.
    pub snp_measurement: Vec<u8>,
}

/// Verify the sigstore bundle and return the deployment it attests to.
///
/// Everything is checked offline against the embedded, TUF-verified trusted
/// root: the certificate chains to Fulcio, its SCT is valid, the Rekor entry's
/// inclusion proof and checkpoint hold and are consistent with the envelope, the
/// DSSE signature is valid over the PAE, and the statement's subject is the
/// deployment digest the bundle claims.
///
/// Certificate expiry is checked against the Rekor entry's integrated time, not
/// against `now()`: Fulcio certificates live about ten minutes, so a wall-clock
/// check would reject every valid attestation older than that.
///
/// The signer is pinned on the certificate's *issuer* and its GitHub Actions
/// *repository* extension, never on the SAN — the SAN embeds the release tag, so
/// pinning it would break on every Tinfoil release.
pub fn verify(bundle: &AttestationBundle, policy: &TrustPolicy) -> Result<DeploymentPredicate> {
    let parsed = parse_bundle(bundle)?;

    let envelope = match &parsed.content {
        SignatureContent::DsseEnvelope(envelope) => envelope,
        SignatureContent::MessageSignature(_) => {
            return Err(Error::Attestation(
                "sigstore bundle is not a DSSE envelope".into(),
            ))
        }
    };

    // The verifier accepts an envelope if *any* of its signatures is valid, so an
    // attacker could otherwise append a signature of their own alongside the real
    // one. In-toto envelopes from Tinfoil carry exactly one.
    if envelope.signatures.len() != 1 {
        return Err(Error::Attestation(format!(
            "DSSE envelope has {} signatures, want exactly 1",
            envelope.signatures.len()
        )));
    }

    let digest = hex::decode(&bundle.digest)
        .map_err(|e| Error::Attestation(format!("bundle digest is not hex: {e}")))?;

    let root = TrustedRoot::from_json(SIGSTORE_TRUSTED_ROOT)
        .map_err(|e| Error::Attestation(format!("embedded trusted root is invalid: {e}")))?;
    let verifier = Verifier::new(&root);

    // Pin the OIDC issuer, but leave `identity` (the SAN) unset — see above. The
    // remaining defaults are the strict ones: transparency log, certificate chain
    // and SCT verification all stay on.
    let id_policy = VerificationPolicy::with_issuer(&policy.oidc_issuer);

    verifier
        .verify(Artifact::from_digest(&digest), &parsed, &id_policy)
        .map_err(|e| Error::Attestation(format!("sigstore verification failed: {e}")))?;

    // Only now that the certificate is known to chain back to Fulcio may its
    // claims be read. Issuer alone would accept any GitHub Actions workflow in
    // any repository, so the repository claim has to be pinned too; this crate's
    // policy has no extension check of its own.
    let cert = leaf_certificate(&parsed)?;
    let repository = signer_repository(&cert)?;
    if repository != policy.signer_repository {
        return Err(Error::Attestation(format!(
            "attestation was signed from {repository}, want {}",
            policy.signer_repository
        )));
    }

    // Only now is the DSSE payload trustworthy.
    let statement: serde_json::Value = serde_json::from_slice(envelope.payload.as_bytes())
        .map_err(|e| Error::Attestation(format!("dsse payload is not JSON: {e}")))?;

    // The signature covers the statement; the statement's subject digest must be
    // the one we just verified, or an attacker could pair a valid signature with
    // an unrelated deployment.
    let subject_digest = statement["subject"][0]["digest"]["sha256"]
        .as_str()
        .ok_or_else(|| Error::Attestation("statement has no subject digest".into()))?;
    if subject_digest != bundle.digest {
        return Err(Error::Attestation(format!(
            "statement subject {subject_digest} does not match bundle digest {}",
            bundle.digest
        )));
    }

    let measurement = statement["predicate"]["snp_measurement"]
        .as_str()
        .ok_or_else(|| Error::Attestation("predicate has no snp_measurement".into()))?;
    let snp_measurement = hex::decode(measurement)
        .map_err(|e| Error::Attestation(format!("snp_measurement is not hex: {e}")))?;
    if snp_measurement.len() != 48 {
        return Err(Error::Attestation(format!(
            "snp_measurement is {} bytes, want 48",
            snp_measurement.len()
        )));
    }

    Ok(DeploymentPredicate { snp_measurement })
}

fn parse_bundle(bundle: &AttestationBundle) -> Result<Bundle> {
    serde_json::from_value(bundle.sigstore_bundle.clone())
        .map_err(|e| Error::Attestation(format!("sigstore bundle is malformed: {e}")))
}

fn leaf_certificate(bundle: &Bundle) -> Result<Certificate> {
    let der = bundle
        .signing_certificate()
        .ok_or_else(|| Error::Attestation("bundle carries no signing certificate".into()))?;
    Certificate::from_der(der.as_bytes())
        .map_err(|e| Error::Attestation(format!("signing certificate is malformed: {e}")))
}

/// Read the GitHub Actions repository the certificate was issued to.
///
/// Requires exactly one such extension, so a certificate carrying two
/// contradictory claims is rejected rather than matched on whichever comes first.
fn signer_repository(cert: &Certificate) -> Result<String> {
    let mut found = cert
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|ext| ext.extn_id == GITHUB_WORKFLOW_REPOSITORY_OID);

    let (Some(ext), None) = (found.next(), found.next()) else {
        return Err(Error::Attestation(
            "signing certificate does not have exactly one GitHub workflow repository extension"
                .into(),
        ));
    };

    std::str::from_utf8(ext.extn_value.as_bytes())
        .map(str::to_owned)
        .map_err(|e| Error::Attestation(format!("repository extension is not UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::bundle;
    use crate::attest::policy::TrustPolicy;

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
        let err = verify(&fixture(), &policy).expect_err("must not verify");
        assert!(
            err.to_string().contains("attacker/evil-router"),
            "must fail on the repository pin, not incidentally: {err}"
        );
    }

    #[test]
    fn rejects_a_different_oidc_issuer() {
        let policy = TrustPolicy {
            oidc_issuer: "https://evil.example".to_string(),
            ..TrustPolicy::default()
        };
        let err = verify(&fixture(), &policy).expect_err("must not verify");
        assert!(
            err.to_string().contains("issuer mismatch"),
            "must fail on the issuer pin, not incidentally: {err}"
        );
    }

    #[test]
    fn rejects_a_corrupted_dsse_signature() {
        let mut b = fixture();
        let sig = b.sigstore_bundle["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str()
            .unwrap()
            .to_string();
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

    #[test]
    fn rejects_more_than_one_dsse_signature() {
        let mut b = fixture();
        let sig = b.sigstore_bundle["dsseEnvelope"]["signatures"][0].clone();
        b.sigstore_bundle["dsseEnvelope"]["signatures"]
            .as_array_mut()
            .unwrap()
            .push(sig);
        assert!(verify(&b, &TrustPolicy::default()).is_err());
    }

    #[test]
    fn reads_the_signer_repository_from_the_leaf_certificate() {
        let b = fixture();
        let cert = leaf_certificate(&parse_bundle(&b).unwrap()).unwrap();
        assert_eq!(
            signer_repository(&cert).unwrap(),
            "tinfoilsh/confidential-model-router"
        );
    }

    #[test]
    fn rejects_a_certificate_without_the_repository_extension() {
        use x509_cert::der::DecodePem;

        // The enclave's own TLS certificate is a real certificate that carries
        // none of Fulcio's OIDC extensions.
        let cert = x509_cert::Certificate::from_pem(fixture().enclave_cert.as_bytes()).unwrap();
        assert!(signer_repository(&cert).is_err());
    }
}
