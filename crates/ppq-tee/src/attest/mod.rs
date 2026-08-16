pub mod bundle;
pub mod domain;
pub mod policy;
pub mod sigstore;
pub mod snp;

pub use bundle::AttestationBundle;
pub use policy::{AmdProduct, TrustPolicy};

use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

/// What a successful verification establishes about the enclave.
///
/// `hpke_public_key`, `tls_key_fingerprint` and `measurement` are read out of
/// the SEV-SNP report only after that report's signature chains to a pinned
/// AMD root and its measurement matches the sigstore-signed build attestation.
/// They are attested facts about the hardware that answered.
///
/// [`Attestation::domain`] is *not* one of them. It is copied out of the
/// untrusted bundle JSON, and the enclave certificate check the default policy
/// runs over it ([`TrustPolicy::check_enclave_certificate`]) does not make it
/// an attested fact. Read its documentation before relying on it for anything.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// The enclave's X25519 HPKE public key. Everything EHBP seals goes here.
    ///
    /// Attested: `report_data[32..64]` of the hardware-signed report.
    pub hpke_public_key: [u8; 32],
    /// SHA-256 of the enclave's TLS public key — specifically of the complete
    /// SubjectPublicKeyInfo DER, the ordinary SPKI fingerprint.
    ///
    /// Attested: `report_data[0..32]` of the hardware-signed report. Under the
    /// default policy this crate consumes it to check the enclave certificate
    /// carries this key; see [`Attestation::domain`].
    pub tls_key_fingerprint: [u8; 32],
    /// The enclave image's launch measurement.
    ///
    /// Attested: reported by the hardware and required to equal the
    /// measurement the signed build attestation names.
    pub measurement: [u8; 48],
    /// The domain the server claimed, echoed verbatim from the attestation
    /// bundle's JSON.
    ///
    /// **Not attested, under any policy.** Treat it as a label for logs and
    /// smoke tests, never as evidence of *which* deployment answered.
    ///
    /// With [`TrustPolicy::check_enclave_certificate`] on (the default), the
    /// bundle's `enclaveCert` is checked before this struct is handed back: its
    /// SubjectPublicKeyInfo must hash to [`Attestation::tls_key_fingerprint`]
    /// — the TLS key the *hardware* vouched for in `report_data[0..32]` — and
    /// its subjectAltName must then cover this name. That proves the presented
    /// certificate carries the attested public key, and that the certificate
    /// says it covers this domain.
    ///
    /// It does **not** prove the certificate was issued by anyone: nothing
    /// verifies its signature. An attacker holding a genuine bundle can
    /// rebuild the certificate around that same, byte-identical
    /// SubjectPublicKeyInfo, give it any subjectAltName it likes, leave the
    /// signature bits garbage, and pass both steps. `report_data[0..32]` binds
    /// *key → hardware*; the CA's issuance signature is what would bind
    /// *name → key*, and it is not checked. So this field is not trustworthy
    /// against an active attacker — it is a misconfiguration guard, not a
    /// verification result or a basis for policy.
    ///
    /// What would make it trustworthy: verifying that the certificate chains
    /// to a WebPKI root. That is not done because the bundle ships only the
    /// leaf — no intermediate — and the leaf rotates roughly every 90 days.
    /// See [`crate::attest::domain`].
    ///
    /// With that flag off, even the guard is skipped and a malicious PPQ can
    /// serve a genuine, currently-valid attestation for a real Tinfoil enclave
    /// under any `domain` it likes without the certificate being looked at.
    ///
    /// Either way, confidentiality does not rest on it: request bodies are
    /// sealed to [`Attestation::hpke_public_key`], which is attested
    /// regardless, so a false `domain` cannot make plaintext reachable by
    /// anyone but the enclave the hardware vouched for.
    pub domain: String,
}

/// Verify a bundle offline and extract the enclave's attested keys.
///
/// The order of the steps below is load-bearing. The enclave certificate check
/// reads `tls_key_fingerprint` out of the hardware report, which is worth
/// nothing until that report's own signature and measurement have been
/// verified — so it runs last, and only on a report that has already been
/// accepted.
pub fn verify_bundle(bundle: &AttestationBundle, policy: &TrustPolicy) -> Result<Attestation> {
    // 1. What *should* be running, per the signed build attestation.
    let deployment = sigstore::verify(bundle, policy)?;

    // 2. What *is* running, per the hardware.
    let raw = bundle::decode_report_body(&bundle.enclave_attestation_report.body)?;
    let report = snp::report::parse(&raw)?;

    let vcek_der = STANDARD
        .decode(&bundle.vcek)
        .map_err(|e| Error::Attestation(format!("VCEK is not base64: {e}")))?;
    let (vcek, product) = [AmdProduct::Milan, AmdProduct::Genoa, AmdProduct::Turin]
        .into_iter()
        .find_map(|p| snp::vcek::verify_chain(&vcek_der, p).ok().map(|k| (k, p)))
        .ok_or_else(|| {
            Error::Attestation(
                "VCEK does not chain to any known AMD root (Milan, Genoa, Turin)".into(),
            )
        })?;

    // 3. Tie them together.
    snp::verify::verify_report(&report, &vcek, &deployment.snp_measurement, policy, product)?;

    // 4. Check the enclave certificate carries the attested key and names the
    //    claimed domain. Strictly after step 3: this reads
    //    `tls_key_fingerprint` out of the report, which means nothing until
    //    the report's own signature and measurement have been checked. Note
    //    this does not make `domain` attested — see `Attestation::domain`.
    if policy.check_enclave_certificate {
        domain::check_enclave_certificate(
            &bundle.enclave_cert,
            &bundle.domain,
            &report.tls_key_fingerprint(),
        )?;
    }

    Ok(Attestation {
        hpke_public_key: report.hpke_public_key(),
        tls_key_fingerprint: report.tls_key_fingerprint(),
        measurement: report.measurement,
        domain: bundle.domain.clone(),
    })
}

/// Fetch and verify the live attestation for `base`.
///
/// Takes the caller's `http` client so the fetch inherits its timeouts; a
/// default client has none, and this call sits on the critical path of every
/// `PpqClient::build()`.
pub async fn attest(
    http: &reqwest::Client,
    base: &str,
    policy: &TrustPolicy,
) -> Result<Attestation> {
    let b = bundle::fetch(http, base).await?;
    verify_bundle(&b, policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy::TrustPolicy;

    const FIXTURE: &str = include_str!("../../testdata/attestation-bundle.json");
    const KEYS: &[u8] = include_bytes!("../../testdata/hpke-keys.bin");

    /// The committed fixture's Rekor `integratedTime` is fixed, so it ages
    /// past the default 90-day `max_attestation_age` over time. Mirrors
    /// `sigstore::tests::policy_ignoring_fixture_age`: these tests are about
    /// orchestration, not the freshness check, which is exercised on its own
    /// in `attest::sigstore`.
    fn policy_ignoring_fixture_age() -> TrustPolicy {
        TrustPolicy {
            max_attestation_age: None,
            ..TrustPolicy::default()
        }
    }

    #[test]
    fn verifies_the_live_bundle_end_to_end() {
        let b = bundle::parse(FIXTURE).unwrap();
        let a = verify_bundle(&b, &policy_ignoring_fixture_age()).expect("verifies");
        // Not a verification result: under the default policy the enclave
        // certificate hashes to the report's TLS key fingerprint and its SAN
        // covers this name, but nothing checked who issued that certificate.
        assert_eq!(a.domain, "inference.tinfoil.sh");
        assert_ne!(a.hpke_public_key, [0u8; 32]);
    }

    /// What the check does catch: a genuine bundle — genuine report, genuine
    /// signed deployment, genuine enclave certificate — with only the `domain`
    /// string swapped. (An attacker willing to rebuild the certificate around
    /// the attested SPKI still gets through; see `Attestation::domain`.)
    #[test]
    fn rejects_a_bundle_whose_claimed_domain_the_enclave_cert_does_not_cover() {
        let mut b = bundle::parse(FIXTURE).unwrap();
        b.domain = "evil.example.com".into();
        let err = verify_bundle(&b, &policy_ignoring_fixture_age())
            .expect_err("an uncovered domain must not verify");
        assert!(
            err.to_string()
                .contains(r#"does not cover domain "evil.example.com""#),
            "must fail on the claimed domain, not incidentally: {err}"
        );
    }

    /// ...and swapping in a different real certificate — the move that would
    /// otherwise let a server present a SAN of its own choosing — must fail on
    /// the key binding, before the SAN is ever consulted.
    #[test]
    fn rejects_a_bundle_whose_enclave_cert_is_not_the_attested_key() {
        let mut b = bundle::parse(FIXTURE).unwrap();
        let substitute = domain::sigstore_leaf_pem(&b);
        b.enclave_cert = substitute;
        let err = verify_bundle(&b, &policy_ignoring_fixture_age())
            .expect_err("a substituted certificate must not verify");
        assert!(
            err.to_string().contains("TLS key fingerprint"),
            "must fail on the key binding, not on parsing or the SAN: {err}"
        );
    }

    #[test]
    fn skips_the_enclave_certificate_check_when_the_policy_disables_it() {
        let mut b = bundle::parse(FIXTURE).unwrap();
        b.domain = "evil.example.com".into();
        let policy = TrustPolicy {
            check_enclave_certificate: false,
            ..policy_ignoring_fixture_age()
        };
        let a = verify_bundle(&b, &policy).expect("the rest of the bundle still verifies");
        assert_eq!(
            a.domain, "evil.example.com",
            "with the check off, the certificate is not even looked at"
        );
    }

    #[test]
    fn attested_key_matches_the_advertised_key_config() {
        let b = bundle::parse(FIXTURE).unwrap();
        let a = verify_bundle(&b, &policy_ignoring_fixture_age()).unwrap();
        // key_config layout: key_id(1) kem_id(2) public_key(32) ...
        assert_eq!(
            &KEYS[3..35],
            &a.hpke_public_key[..],
            "the enclave advertises exactly the key it attested to"
        );
    }

    #[test]
    fn rejects_a_bundle_whose_report_does_not_match_its_deployment() {
        let mut b = bundle::parse(FIXTURE).unwrap();
        // Point at a valid-looking but different measurement.
        b.digest = "0".repeat(64);
        assert!(verify_bundle(&b, &policy_ignoring_fixture_age()).is_err());
    }
}
