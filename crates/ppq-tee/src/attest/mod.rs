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
        assert_eq!(a.domain, "inference.tinfoil.sh");
        assert_ne!(a.hpke_public_key, [0u8; 32]);
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
