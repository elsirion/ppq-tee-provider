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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::der::{oid::ObjectIdentifier, Decode};
use x509_cert::Certificate;

/// Fulcio's "GitHub Workflow Repository" claim.
///
/// <https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md>. Like every
/// `1.3.6.1.4.1.57264.1.1`–`.6` extension, its value is a bare UTF-8 string
/// rather than a DER-encoded one.
const GITHUB_WORKFLOW_REPOSITORY_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.5");

/// The in-toto predicate type Tinfoil's build attestation carries.
///
/// Pinned so that a statement of some other, differently-shaped predicate
/// (present or future) cannot be coerced into satisfying this crate's
/// expectations just because it happens to parse under the same field names.
const PREDICATE_TYPE: &str = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1";

/// Allowed clock skew when checking that a Rekor entry's `integratedTime` is
/// not in the future. Beyond this, a timestamp is treated as bogus rather
/// than merely early, since a far-future timestamp would otherwise make an
/// attestation immortal under the `max_attestation_age` check.
const FUTURE_TOLERANCE: Duration = Duration::from_secs(300);

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
///
/// Two further checks guard against *rollback*: both the deployment digest and
/// the sigstore bundle come from the server being attested, so without them a
/// malicious server could replay any attestation it has ever been issued,
/// including an older release with a known-bad measurement. The in-toto
/// `predicateType` is pinned to [`PREDICATE_TYPE`], and the Rekor entry's
/// `integratedTime` is bounded by `policy.max_attestation_age` (against
/// `SystemTime::now()`, not the Rekor-time-based certificate check above).
pub fn verify(bundle: &AttestationBundle, policy: &TrustPolicy) -> Result<DeploymentPredicate> {
    // An empty repository would match an empty (or absent-and-defaulted)
    // extension value; not reachable via `TrustPolicy::default()`, but a
    // hand-constructed policy could do it, so reject it before it is ever
    // compared against anything.
    if policy.signer_repository.is_empty() {
        return Err(Error::Attestation(
            "policy signer_repository must not be empty".into(),
        ));
    }

    let parsed = parse_bundle(bundle)?;

    check_attestation_age(rekor_integrated_time(bundle)?, policy.max_attestation_age)?;

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
    check_subject0_digest(&statement, &bundle.digest)?;

    // Pin the predicate type: without this, a statement of some other predicate
    // shape that happens to carry the same `snp_measurement` field would be
    // accepted, and a rollback to an older, differently-typed predicate could
    // slip through the checks above (they never inspect this field).
    let predicate_type = statement["predicateType"]
        .as_str()
        .ok_or_else(|| Error::Attestation("statement has no predicateType".into()))?;
    if predicate_type != PREDICATE_TYPE {
        return Err(Error::Attestation(format!(
            "statement predicateType is {predicate_type}, want {PREDICATE_TYPE}"
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

/// Confirm the statement's *first* subject digest is the one the bundle claims.
///
/// Deliberately narrower than the `sigstore-verify` crate's own DSSE-artifact
/// binding, which accepts a match anywhere in `subject[]`
/// (`subject.iter().any(...)`). The digest and the statement both originate
/// from the server being attested, so an attacker able to shape the statement
/// could pad `subject[]` with a second, matching digest behind an unrelated
/// first one; pinning index 0 specifically closes that gap. Factored out of
/// `verify()` so it can be unit tested directly: constructing a *signed*
/// statement with a mismatched first subject isn't possible in a test, since
/// editing `subject[]` in a real DSSE payload invalidates its signature
/// before this check would ever run.
fn check_subject0_digest(statement: &serde_json::Value, bundle_digest: &str) -> Result<()> {
    let subject_digest = statement["subject"][0]["digest"]["sha256"]
        .as_str()
        .ok_or_else(|| Error::Attestation("statement has no subject digest".into()))?;
    if subject_digest != bundle_digest {
        return Err(Error::Attestation(format!(
            "statement subject {subject_digest} does not match bundle digest {bundle_digest}"
        )));
    }
    Ok(())
}

/// Read the Rekor entry's `integratedTime` out of the raw bundle JSON.
///
/// The bundle carries this as a decimal string (e.g. `"1786661855"`), not a
/// JSON number, so it is read directly off `bundle.sigstore_bundle` rather
/// than through the already-parsed `sigstore_types::Bundle`, whose own field
/// defaults a missing value to zero and would hide the "absent" case from
/// this check.
fn rekor_integrated_time(bundle: &AttestationBundle) -> Result<SystemTime> {
    let raw = bundle.sigstore_bundle["verificationMaterial"]["tlogEntries"][0]["integratedTime"]
        .as_str()
        .ok_or_else(|| {
            Error::Attestation("rekor entry has no (string) integratedTime".into())
        })?;
    let secs: u64 = raw.parse().map_err(|e| {
        Error::Attestation(format!(
            "rekor integratedTime {raw:?} is not a valid unix timestamp: {e}"
        ))
    })?;
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

/// Reject attestations whose Rekor entry falls outside `max_age` of now.
///
/// A timestamp more than [`FUTURE_TOLERANCE`] in the future is always
/// rejected, independent of `max_age`, since otherwise it would never age out.
fn check_attestation_age(integrated_at: SystemTime, max_age: Option<Duration>) -> Result<()> {
    let now = SystemTime::now();

    if let Ok(skew) = integrated_at.duration_since(now) {
        if skew > FUTURE_TOLERANCE {
            return Err(Error::Attestation(format!(
                "rekor integratedTime is {skew:?} in the future, want at most {FUTURE_TOLERANCE:?} of clock skew"
            )));
        }
    }

    let Some(max_age) = max_age else {
        return Ok(());
    };

    let age = now.duration_since(integrated_at).unwrap_or(Duration::ZERO);
    if age > max_age {
        return Err(Error::Attestation(format!(
            "attestation is {age:?} old, want at most {max_age:?}"
        )));
    }
    Ok(())
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

    /// A `TrustPolicy` for tests that only need the fixture to verify.
    ///
    /// The committed fixture's Rekor `integratedTime` is fixed at whenever it
    /// was captured, so it will eventually age past the default 90-day
    /// `max_attestation_age` and start failing these tests for a reason
    /// unrelated to what they check. Disable the age check here; the age
    /// check itself is exercised separately, against a synthetic window, by
    /// `rejects_an_attestation_older_than_the_policy_max_age`.
    fn policy_ignoring_fixture_age() -> TrustPolicy {
        TrustPolicy {
            max_attestation_age: None,
            ..TrustPolicy::default()
        }
    }

    #[test]
    fn extracts_the_expected_measurement() {
        let p = verify(&fixture(), &policy_ignoring_fixture_age()).expect("verifies");
        assert_eq!(p.snp_measurement.len(), 48, "SNP measurements are 48 bytes");
    }

    #[test]
    fn rejects_a_different_signer_repository() {
        let policy = TrustPolicy {
            signer_repository: "attacker/evil-router".to_string(),
            ..policy_ignoring_fixture_age()
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
            ..policy_ignoring_fixture_age()
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
        let err = verify(&b, &policy_ignoring_fixture_age()).expect_err("must not verify");
        assert!(
            err.to_string().contains("sigstore verification failed"),
            "must fail on signature verification, not incidentally: {err}"
        );
    }

    #[test]
    fn rejects_a_tampered_subject_digest() {
        let mut b = fixture();
        b.digest = "0".repeat(64);
        let err = verify(&b, &policy_ignoring_fixture_age()).expect_err("must not verify");
        // Caught by `sigstore-verify`'s own DSSE-artifact binding
        // (`Artifact::from_digest` vs. the statement's `subject[]`), before
        // our own `check_subject0_digest` ever runs.
        assert!(
            err.to_string()
                .contains("does not match any subject in attestation"),
            "must fail on the subject/digest binding, not incidentally: {err}"
        );
    }

    #[test]
    fn rejects_more_than_one_dsse_signature() {
        let mut b = fixture();
        let sig = b.sigstore_bundle["dsseEnvelope"]["signatures"][0].clone();
        b.sigstore_bundle["dsseEnvelope"]["signatures"]
            .as_array_mut()
            .unwrap()
            .push(sig);
        let err = verify(&b, &policy_ignoring_fixture_age()).expect_err("must not verify");
        assert!(
            err.to_string()
                .contains("DSSE envelope has 2 signatures, want exactly 1"),
            "must fail on the signature-count check specifically, not incidentally: {err}"
        );
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

    #[test]
    fn rejects_an_empty_signer_repository_policy() {
        let policy = TrustPolicy {
            signer_repository: String::new(),
            ..policy_ignoring_fixture_age()
        };
        let err = verify(&fixture(), &policy).expect_err("must not verify");
        assert!(
            err.to_string().contains("signer_repository must not be empty"),
            "must fail on the empty-policy guard, not incidentally: {err}"
        );
    }

    #[test]
    fn rejects_an_attestation_older_than_the_policy_max_age() {
        // The fixture is at least a little older than an instant by the time this
        // runs, so a 1-second window is guaranteed to be exceeded without
        // depending on wall-clock date.
        let policy = TrustPolicy {
            max_attestation_age: Some(Duration::from_secs(1)),
            ..TrustPolicy::default()
        };
        let err = verify(&fixture(), &policy).expect_err("must not verify");
        assert!(
            err.to_string().contains("old, want at most"),
            "must fail on the age check, not incidentally: {err}"
        );
    }

    #[test]
    fn subject0_pin_rejects_a_digest_that_only_matches_the_second_subject() {
        // The crate's own `sigstore-verify` DSSE-artifact binding accepts a
        // match anywhere in `subject[]` (`subject.iter().any(...)`), which is
        // looser than this crate's `subject[0]` pin. That gap can't be
        // exercised through `verify()`: the DSSE signature covers the whole
        // payload, so editing a real, signed statement's `subject[]` to add a
        // second entry invalidates the signature before `check_subject0_digest`
        // would ever run (as `rejects_a_tampered_subject_digest` above
        // demonstrates for the single-subject case). So this tests the
        // extracted comparison function directly, against a hand-built
        // statement that was never signed.
        let statement = serde_json::json!({
            "subject": [
                { "digest": { "sha256": "1111111111111111111111111111111111111111111111111111111111111111" } },
                { "digest": { "sha256": "the-bundle-digest" } },
            ],
        });

        let err = check_subject0_digest(&statement, "the-bundle-digest")
            .expect_err("must reject a digest that only matches subject[1]");
        assert!(
            err.to_string().contains("does not match bundle digest"),
            "must fail on the subject[0] pin, not incidentally: {err}"
        );

        // Sanity check the positive path too, so a trivially-always-failing
        // comparison couldn't make the rejection above meaningless.
        check_subject0_digest(&statement, "1111111111111111111111111111111111111111111111111111111111111111")
            .expect("must accept a digest that matches subject[0]");
    }
}
