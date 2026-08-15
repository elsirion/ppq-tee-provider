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
        assert_eq!(r.tls_key_fingerprint()[..], r.report_data[..32]);
        assert_eq!(r.hpke_public_key()[..], r.report_data[32..]);
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
