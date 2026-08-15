//! The hardware half of the trust decision: is this attestation report
//! genuinely signed by AMD silicon, and does it describe the build the
//! sigstore layer attested to?

use crate::attest::policy::TrustPolicy;
use crate::attest::snp::{report::Report, vcek::VcekKey};
use crate::{Error, Result};

/// Byte offsets of the meaningful components inside a packed `TCB_VERSION`.
///
/// The layout is bootloader, TEE, four reserved bytes, SNP firmware,
/// microcode. Expressed as bit shifts into the little-endian `u64` the report
/// parser produces.
const TCB_COMPONENT_SHIFTS: [u32; 4] = [0, 8, 48, 56];

/// Check that a report is genuine, matches the attested deployment, and
/// describes a guest we are willing to trust.
///
/// `vcek` must already have been chained to an AMD root by
/// [`super::vcek::verify_chain`] — that is the only way to obtain a
/// [`VcekKey`].
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

    // A report from a higher VMPL says nothing about what runs at VMPL 0,
    // which is where the workload we care about lives.
    if report.vmpl != 0 {
        return Err(Error::Attestation(format!(
            "report is from VMPL {}, want 0",
            report.vmpl
        )));
    }

    // A reported TCB below the committed TCB means the platform was rolled
    // back to firmware with known vulnerabilities.
    if let Some(rolled_back) = rolled_back_component(report.reported_tcb, report.committed_tcb) {
        return Err(Error::Attestation(format!(
            "reported TCB {:#018x} is below committed TCB {:#018x} in the component at byte {}",
            report.reported_tcb,
            report.committed_tcb,
            rolled_back / 8,
        )));
    }

    let sig = Signature::from_scalars(report.signature_r, report.signature_s)
        .map_err(|e| Error::Attestation(format!("malformed report signature: {e}")))?;
    vcek.0
        .verify(&report.signed_data, &sig)
        .map_err(|e| Error::Attestation(format!("report signature invalid: {e}")))?;

    Ok(())
}

/// The bit shift of the first `TCB_VERSION` component that `reported` rolls
/// back relative to `committed`, if any.
///
/// `TCB_VERSION` is a packed struct of independent per-component version
/// bytes, not a number: comparing the two `u64`s directly would let a rollback
/// in one component hide behind a bump in a more significant one — e.g. a
/// downgraded bootloader under a newer microcode. Every component has to be at
/// least the committed value.
fn rolled_back_component(reported: u64, committed: u64) -> Option<u32> {
    TCB_COMPONENT_SHIFTS
        .into_iter()
        .find(|shift| ((reported >> shift) as u8) < (committed >> shift) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{
        bundle,
        policy::{AmdProduct, TrustPolicy},
        sigstore,
        snp::{report, vcek},
    };
    use base64::{engine::general_purpose::STANDARD, Engine};

    const FIXTURE: &str = include_str!("../../../testdata/attestation-bundle.json");

    /// The committed fixture ages, so the sigstore layer's freshness bound has
    /// to be disabled here; these tests are about the hardware layer. The age
    /// check itself is covered in `attest::sigstore`'s tests.
    fn policy_ignoring_fixture_age() -> TrustPolicy {
        TrustPolicy {
            max_attestation_age: None,
            ..TrustPolicy::default()
        }
    }

    fn parts() -> (report::Report, vcek::VcekKey, Vec<u8>) {
        let b = bundle::parse(FIXTURE).unwrap();
        let raw = bundle::decode_report_body(&b.enclave_attestation_report.body).unwrap();
        let r = report::parse(&raw).unwrap();
        let der = STANDARD.decode(&b.vcek).unwrap();
        let k = vcek::verify_chain(&der, AmdProduct::Milan)
            .or_else(|_| vcek::verify_chain(&der, AmdProduct::Genoa))
            .or_else(|_| vcek::verify_chain(&der, AmdProduct::Turin))
            .expect("VCEK chains to an AMD root");
        let m = sigstore::verify(&b, &policy_ignoring_fixture_age())
            .unwrap()
            .snp_measurement;
        (r, k, m)
    }

    #[test]
    fn accepts_the_live_report() {
        let (r, k, m) = parts();
        verify_report(&r, &k, &m, &policy_ignoring_fixture_age()).expect("verifies");
    }

    #[test]
    fn rejects_a_flipped_measurement_byte() {
        let (mut r, k, m) = parts();
        r.measurement[0] ^= 0x01;
        assert!(verify_report(&r, &k, &m, &policy_ignoring_fixture_age()).is_err());
    }

    #[test]
    fn rejects_a_measurement_mismatching_the_deployment() {
        let (r, k, _) = parts();
        let wrong = vec![0u8; 48];
        assert!(verify_report(&r, &k, &wrong, &policy_ignoring_fixture_age()).is_err());
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let (mut r, k, m) = parts();
        r.signature_r[0] ^= 0xFF;
        assert!(verify_report(&r, &k, &m, &policy_ignoring_fixture_age()).is_err());
    }

    #[test]
    fn rejects_debug_enabled_guests() {
        let (mut r, k, m) = parts();
        r.policy |= 1 << 19;
        // Signature check would also fail, so assert the policy check
        // independently of it.
        assert!(r.debug_enabled());
        assert!(verify_report(&r, &k, &m, &policy_ignoring_fixture_age()).is_err());
    }

    #[test]
    fn rejects_reports_from_a_higher_vmpl() {
        let (mut r, k, m) = parts();
        r.vmpl = 1;
        let err =
            verify_report(&r, &k, &m, &policy_ignoring_fixture_age()).expect_err("must not verify");
        assert!(err.to_string().contains("VMPL"), "{err}");
    }

    #[test]
    fn rejects_a_rolled_back_tcb() {
        let (mut r, k, m) = parts();
        // Same TCB but one bootloader version lower than committed.
        r.committed_tcb = 0x0A_00_00_00_00_00_00_09;
        r.reported_tcb = 0x0A_00_00_00_00_00_00_08;
        let err =
            verify_report(&r, &k, &m, &policy_ignoring_fixture_age()).expect_err("must not verify");
        assert!(err.to_string().contains("below committed TCB"), "{err}");
    }

    #[test]
    fn a_bumped_microcode_does_not_mask_a_rolled_back_bootloader() {
        // Directly, because the packed-u64 comparison this replaces would
        // accept exactly this case.
        let committed = 0x0A_00_00_00_00_00_00_08u64;
        let reported = 0x0B_00_00_00_00_00_00_07u64;
        assert!(reported > committed, "the naive u64 comparison would pass");
        assert_eq!(rolled_back_component(reported, committed), Some(0));
        assert_eq!(rolled_back_component(committed, committed), None);
        assert_eq!(rolled_back_component(reported, reported), None);
    }
}
