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
