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

/// Size in bytes of a raw SEV-SNP attestation report (always exactly 0x4A0).
const SNP_REPORT_SIZE: u64 = 0x4A0;

/// Base64-decode then gunzip the report body.
///
/// The gzip stream is decompressed under a byte cap (`SNP_REPORT_SIZE` plus a small margin)
/// so that an attacker-supplied bundle cannot use a small gzip payload to inflate to an
/// unbounded size before verification has had a chance to reject it. A stream that would
/// decompress to more than the cap is rejected outright rather than silently truncated,
/// since a truncated-but-cap-sized buffer could otherwise slip past the length check in
/// `attest::snp::report::parse`.
pub fn decode_report_body(body: &str) -> Result<Vec<u8>> {
    let gz = STANDARD
        .decode(body)
        .map_err(|e| Error::Attestation(format!("report body is not base64: {e}")))?;

    // Allow one extra byte beyond the expected size: if we can still read that extra byte,
    // the stream is longer than expected and we reject it, instead of silently truncating.
    let limit = SNP_REPORT_SIZE + 1;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .take(limit)
        .read_to_end(&mut out)
        .map_err(|e| Error::Attestation(format!("report body is not gzip: {e}")))?;

    if out.len() as u64 > SNP_REPORT_SIZE {
        return Err(Error::Attestation(format!(
            "report body decompressed to more than {SNP_REPORT_SIZE} bytes"
        )));
    }

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
    fn rejects_non_base64_report_body() {
        assert!(decode_report_body("not-base64!!").is_err());
    }

    #[test]
    fn rejects_valid_base64_that_is_not_gzip() {
        // Valid base64, but the decoded bytes are not a gzip stream at all.
        let body = STANDARD.encode(b"this is definitely not a gzip stream");
        assert!(decode_report_body(&body).is_err());
    }

    #[test]
    fn rejects_oversized_decompressed_report_body() {
        use std::io::Write;

        // Gzip-compress a run of zero bytes well over the expected report size, so that
        // decompression would otherwise inflate far past `SNP_REPORT_SIZE`.
        let big = vec![0u8; 10 * (SNP_REPORT_SIZE as usize)];
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&big).expect("gzip encode succeeds");
        let gz = encoder.finish().expect("gzip finish succeeds");

        let body = STANDARD.encode(gz);
        assert!(decode_report_body(&body).is_err());
    }
}
