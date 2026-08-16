//! Checking the bundle's claimed `domain` against the enclave certificate.
//!
//! The bundle's `domain` field is a string the server chose. This module does
//! **not** turn it into an attested fact. What it does, in two steps that must
//! run in order:
//!
//! 1. **Key binding.** `SHA-256` of the enclave certificate's
//!    SubjectPublicKeyInfo must equal the hardware report's
//!    `report_data[0..32]`. This proves the presented certificate carries the
//!    public key the attested hardware vouched for — until it holds, the
//!    certificate is just more untrusted JSON and its SAN could say anything.
//! 2. **Name coverage.** That certificate's subjectAltName must cover the
//!    claimed `domain`, by the RFC 6125 rules implemented in
//!    [`dns_name_matches`].
//!
//! Step 1 failing aborts; it never falls through to step 2.
//!
//! # What this does not establish
//!
//! It does not prove the certificate was issued by anyone. Nothing here — or
//! anywhere else in this crate — verifies the certificate's issuance
//! signature; `x509_cert::Certificate::from_pem` only parses. An attacker
//! holding a genuine bundle can rebuild the certificate around the same,
//! byte-identical `subjectPublicKeyInfo` (all step 1 hashes), give it whatever
//! subjectAltName it likes, and leave the signature bits garbage. Both steps
//! above still pass.
//!
//! `report_data[0..32]` binds *key → hardware*. The link that would bind
//! *name → key* is the CA's issuance signature over the certificate, and it is
//! not checked. So `domain` is **not trustworthy against an active attacker**:
//! treat these checks as a misconfiguration and smoke-test guard — they catch
//! a server that got its own certificate wrong, since the comparison is
//! between the bundle's `domain` and the bundle's own certificate
//! (self-consistency, not attestation) — never as a verification result or a
//! basis for policy. Catching a client pointed at a genuine-but-wrong
//! deployment is not this check's job: that bundle is internally
//! self-consistent and passes. A caller who needs that must compare
//! [`crate::attest::Attestation::domain`] against the domain it expected
//! itself.
//!
//! What would make it trustworthy is verifying that the certificate chains to
//! a WebPKI root: the CA's issuance is what binds the name to the key. That is
//! not done here because the bundle ships only the leaf — issuer Google Trust
//! Services WR1, no intermediate — and that leaf rotates roughly every 90
//! days, so the check would need a pinned, rotating intermediate and a time
//! anchor for the committed fixture.
//!
//! Confidentiality does not depend on any of this: request bodies are sealed
//! to the enclave's `hpke_public_key`, which *is* attested.

use crate::{Error, Result};
use sha2::{Digest, Sha256};
use x509_cert::{
    der::{DecodePem, Encode},
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

/// Check that `cert_pem` carries the public key the attested hardware vouched
/// for, and that its subjectAltName covers `domain`.
///
/// Success does **not** mean the certificate was issued by anyone: its
/// signature is never verified, so this is a misconfiguration guard rather
/// than a name verification. See the module documentation for exactly what
/// that leaves standing and what it does not.
///
/// `tls_key_fingerprint` must come from a report whose signature and
/// measurement have *already* been verified — see the ordering note on
/// [`crate::attest::verify_bundle`].
///
/// Every input here is attacker-controlled: `cert_pem` and `domain` are read
/// verbatim out of the untrusted bundle JSON. Every step below returns an
/// error rather than panicking on malformed input.
///
/// `domain` is compared as given. A trailing-dot FQDN (`example.com.`), a
/// wildcard, an empty label, or a non-ASCII name is refused rather than
/// normalised, so callers must pass the exact ASCII hostname.
pub fn check_enclave_certificate(
    cert_pem: &str,
    domain: &str,
    tls_key_fingerprint: &[u8; 32],
) -> Result<()> {
    let cert = Certificate::from_pem(cert_pem.as_bytes()).map_err(|e| {
        Error::Attestation(format!("enclave certificate is not a PEM certificate: {e}"))
    })?;

    check_key_binding(&cert, tls_key_fingerprint)?;
    check_domain_covered(&cert, domain)
}

/// Check that `cert`'s SubjectPublicKeyInfo hashes to `tls_key_fingerprint`.
///
/// The digest is over the complete SPKI DER structure — the `SEQUENCE` of
/// `AlgorithmIdentifier` and the key `BIT STRING`, tag and length included —
/// which is what Tinfoil's enclave puts in `report_data[0..32]`, and is also
/// the ordinary "SPKI fingerprint" of HTTP Public Key Pinning and friends.
/// Hashing the bare key bits instead would produce a different value.
///
/// The certificate is re-encoded rather than hashed as it arrived, so that a
/// non-canonical or padded encoding cannot present one set of bytes to the
/// hash and another to the SAN check.
fn check_key_binding(cert: &Certificate, tls_key_fingerprint: &[u8; 32]) -> Result<()> {
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| {
            Error::Attestation(format!("cannot re-encode enclave certificate SPKI: {e}"))
        })?;
    let digest: [u8; 32] = Sha256::digest(&spki).into();

    if digest != *tls_key_fingerprint {
        return Err(Error::Attestation(format!(
            "enclave certificate does not match the attested TLS key fingerprint: \
             its SubjectPublicKeyInfo hashes to {}, the report says {}",
            hex::encode(digest),
            hex::encode(tls_key_fingerprint),
        )));
    }
    Ok(())
}

/// Check that `cert`'s subjectAltName covers `domain`.
///
/// Establishes only that this certificate *says* it covers the name. Since the
/// certificate's own signature is never verified, nothing here establishes
/// that a CA agreed — see the module documentation.
///
/// Only `dNSName` entries count. Other `GeneralName` variants are ignored, and
/// there is deliberately no fallback to the subject's Common Name: CN-as-host
/// has been forbidden since RFC 6125 and accepting it here would let a
/// certificate with no name constraints at all pass for any domain.
///
/// A certificate with no subjectAltName extension, or one carrying no
/// `dNSName`, covers nothing and is rejected.
fn check_domain_covered(cert: &Certificate, domain: &str) -> Result<()> {
    let san = cert
        .tbs_certificate
        // Errors on a malformed SAN *and* on a certificate carrying more than
        // one, which would otherwise let a server hide a second name list.
        .get::<SubjectAltName>()
        .map_err(|e| {
            Error::Attestation(format!(
                "enclave certificate's subjectAltName is unusable: {e}"
            ))
        })?
        .ok_or_else(|| {
            Error::Attestation(format!(
                "enclave certificate has no subjectAltName, so it cannot cover domain {domain:?}"
            ))
        })?
        .1;

    let names: Vec<&str> = san
        .0
        .iter()
        .filter_map(|n| match n {
            GeneralName::DnsName(d) => Some(d.as_str()),
            _ => None,
        })
        .collect();

    if names
        .iter()
        .any(|pattern| dns_name_matches(pattern, domain))
    {
        return Ok(());
    }
    // A caller that passed a trailing-dot FQDN or a non-ASCII name matched
    // nothing for a reason that has nothing to do with the certificate. Say so,
    // rather than leaving the certificate looking like the culprit.
    let hint = if is_plain_name(domain) {
        ""
    } else {
        " (names are compared verbatim: a trailing dot, an empty label, a wildcard or a \
          non-ASCII name is refused rather than normalised)"
    };
    Err(Error::Attestation(format!(
        "enclave certificate does not cover domain {domain:?}; \
         its dNSName entries are {names:?}{hint}"
    )))
}

/// A name with no wildcard in it, no empty label, and nothing but ASCII.
///
/// Empty labels — which is what a leading, doubled or trailing dot produces —
/// and non-ASCII names are refused here rather than normalised away.
fn is_plain_name(s: &str) -> bool {
    !s.is_empty() && s.is_ascii() && !s.contains('*') && s.split('.').all(|label| !label.is_empty())
}

/// Does the SAN `dNSName` entry `pattern` match the host `host`?
///
/// RFC 6125 §6.4.3, in the strict reading modern TLS stacks use:
///
/// * comparison is case-insensitive (ASCII only — every label here is IA5),
/// * a wildcard is valid only as the *entire* leftmost label (`*.example.com`,
///   never `w*.example.com` or `foo.*.example.com`), and there may be only one,
/// * a wildcard matches exactly one label: `*.example.com` matches
///   `a.example.com` but neither `example.com` nor `a.b.example.com`.
///
/// One rule beyond RFC 6125: the part after the wildcard must be at least two
/// labels, so a single-label suffix like `*.com` is rejected outright. This is
/// a label-count floor, not a public-suffix check: `*.co.uk` still matches
/// `evil.co.uk`, and so do `*.com.au` and `*.github.io`. `*.com` matching
/// `evil.com` is mechanically what §6.4.3 says; this crate refuses only that
/// narrower, single-label case and implements no public-suffix list.
///
/// Empty labels — which is what a leading, doubled or trailing dot produces —
/// match nothing on either side, rather than being normalised away, and so do
/// non-ASCII names. `host` comes from the same untrusted JSON as `pattern`, so
/// it is held to the same shape and may never itself contain a wildcard.
fn dns_name_matches(pattern: &str, host: &str) -> bool {
    if !is_plain_name(host) {
        return false;
    }

    let Some(suffix) = pattern.strip_prefix("*.") else {
        return is_plain_name(pattern) && pattern.eq_ignore_ascii_case(host);
    };

    // Anything after the leftmost label must be an ordinary name: this is what
    // rejects a second wildcard, and `*.` on its own.
    if !is_plain_name(suffix) {
        return false;
    }
    // ...and at least two labels of it, so a registry-wide wildcard like
    // `*.com` cannot cover `evil.com`.
    if suffix.split('.').count() < 2 {
        return false;
    }
    // Splitting off exactly one label and requiring the remainder to match is
    // what keeps the wildcard from spanning a dot in either direction.
    let Some((_, rest)) = host.split_once('.') else {
        return false;
    };
    rest.eq_ignore_ascii_case(suffix)
}

/// The sigstore signing certificate carried by `bundle`, PEM-wrapped.
///
/// A real, structurally valid certificate that is emphatically *not* the
/// enclave's TLS certificate — exactly what a server substituting a
/// certificate of its own choosing would produce. Lives here rather than in
/// either test module because both this module's tests and `verify_bundle`'s
/// need it.
#[cfg(test)]
pub(crate) fn sigstore_leaf_pem(bundle: &crate::attest::AttestationBundle) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let raw = bundle.sigstore_bundle["verificationMaterial"]["certificate"]["rawBytes"]
        .as_str()
        .expect("fixture carries a sigstore leaf certificate");
    let der = STANDARD.decode(raw).expect("sigstore leaf is base64 DER");
    let b64 = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{bundle, snp};

    const FIXTURE: &str = include_str!("../../testdata/attestation-bundle.json");

    fn bundle() -> bundle::AttestationBundle {
        bundle::parse(FIXTURE).unwrap()
    }

    /// The TLS key fingerprint the fixture's hardware report actually carries.
    fn fingerprint() -> [u8; 32] {
        let b = bundle();
        let raw = bundle::decode_report_body(&b.enclave_attestation_report.body).unwrap();
        snp::report::parse(&raw).unwrap().tls_key_fingerprint()
    }

    fn sigstore_leaf_pem() -> String {
        super::sigstore_leaf_pem(&bundle())
    }

    #[test]
    fn binds_the_live_fixture_certificate_to_its_report() {
        check_enclave_certificate(
            &bundle().enclave_cert,
            "inference.tinfoil.sh",
            &fingerprint(),
        )
        .expect("the fixture's certificate carries the attested key and covers its domain");
    }

    /// `report_data[0..32]` is the digest of the *whole* SubjectPublicKeyInfo
    /// structure. The two neighbouring things one might hash instead — the key
    /// `BIT STRING`'s contents, and the entire certificate — are pinned here
    /// as *not* being it, so a later "simplification" to either cannot pass
    /// unnoticed.
    #[test]
    fn hashes_the_whole_spki_and_not_a_neighbour_of_it() {
        use x509_cert::der::{DecodePem, Encode};

        let b = bundle();
        let cert = x509_cert::Certificate::from_pem(b.enclave_cert.as_bytes()).unwrap();
        let spki = &cert.tbs_certificate.subject_public_key_info;

        let spki_der = spki.to_der().unwrap();
        assert_eq!(
            spki_der[0], 0x30,
            "the SPKI DER is the SEQUENCE, tag and all"
        );
        assert_eq!(
            <[u8; 32]>::from(sha2::Sha256::digest(&spki_der)),
            fingerprint()
        );
        assert_ne!(
            <[u8; 32]>::from(sha2::Sha256::digest(
                spki.subject_public_key.as_bytes().unwrap()
            )),
            fingerprint(),
            "not the bare public key bits"
        );
        assert_ne!(
            <[u8; 32]>::from(sha2::Sha256::digest(cert.to_der().unwrap())),
            fingerprint(),
            "not the whole certificate"
        );
    }

    /// Step 1 is load-bearing: without it the certificate is just more
    /// untrusted JSON, and a server could serve any certificate it liked —
    /// including one whose SAN covers whatever domain it wants to claim. (It
    /// is not sufficient either: nothing verifies the certificate's issuance
    /// signature, so an attacker can rebuild it around this same SPKI. See the
    /// module documentation.)
    #[test]
    fn rejects_a_certificate_that_is_not_the_attested_key() {
        let err =
            check_enclave_certificate(&sigstore_leaf_pem(), "inference.tinfoil.sh", &fingerprint())
                .expect_err("a substituted certificate must not verify");
        assert!(
            err.to_string().contains("TLS key fingerprint"),
            "must fail on the key binding, not on parsing or the SAN: {err}"
        );
    }

    /// The assertion pins the specific phrase, not just the domain string:
    /// `evil.example.com` also appears in the "no subjectAltName" and "SAN
    /// unusable" messages, so a substring check on it alone would pass for the
    /// wrong reason.
    #[test]
    fn rejects_a_domain_the_certificate_does_not_cover() {
        let err =
            check_enclave_certificate(&bundle().enclave_cert, "evil.example.com", &fingerprint())
                .expect_err("a domain outside the SAN must not verify");
        assert!(
            err.to_string()
                .contains(r#"does not cover domain "evil.example.com""#),
            "must fail on the SAN not covering the domain, not incidentally: {err}"
        );
    }

    /// A trailing-dot FQDN matches nothing, because names are compared
    /// verbatim. The error has to say why, or it reads as the certificate's
    /// fault.
    #[test]
    fn explains_that_a_trailing_dot_domain_is_not_normalised() {
        let err = check_enclave_certificate(
            &bundle().enclave_cert,
            "inference.tinfoil.sh.",
            &fingerprint(),
        )
        .expect_err("a trailing-dot FQDN is refused rather than normalised");
        let msg = err.to_string();
        assert!(
            msg.contains("does not cover domain") && msg.contains("trailing dot"),
            "must point at the trailing dot as the cause: {err}"
        );
    }

    /// The sigstore leaf's SAN holds a single URI GeneralName and no
    /// `dNSName`, so it exercises "SAN present, but nothing to match against"
    /// rather than "no SAN at all".
    #[test]
    fn rejects_a_certificate_whose_san_has_no_dns_names() {
        use x509_cert::der::DecodePem;
        let cert = x509_cert::Certificate::from_pem(sigstore_leaf_pem().as_bytes()).unwrap();
        let err = super::check_domain_covered(&cert, "inference.tinfoil.sh")
            .expect_err("a SAN without dNSName entries covers nothing");
        assert!(
            err.to_string().contains(
                r#"does not cover domain "inference.tinfoil.sh"; its dNSName entries are []"#
            ),
            "must fail on there being no dNSName to match, naming the domain: {err}"
        );
    }

    /// AMD's ARK and ASK carry no subjectAltName extension at all — the other
    /// half of "no dNSName to match", and the one where a CN fallback would
    /// silently take over.
    #[test]
    fn rejects_a_certificate_with_no_subject_alt_name_at_all() {
        use crate::attest::policy::{amd_root, AmdProduct};
        let chain = x509_cert::Certificate::load_pem_chain(amd_root(AmdProduct::Milan)).unwrap();
        for cert in &chain {
            let err = super::check_domain_covered(cert, "inference.tinfoil.sh")
                .expect_err("a certificate without a SAN covers nothing");
            assert!(
                err.to_string().contains("no subjectAltName"),
                "must fail on the missing extension, not incidentally: {err}"
            );
        }
    }

    #[test]
    fn rejects_a_certificate_that_is_not_pem() {
        let err = check_enclave_certificate(
            "this is not a certificate",
            "inference.tinfoil.sh",
            &[0; 32],
        )
        .expect_err("garbage must not verify");
        assert!(
            err.to_string().contains("is not a PEM certificate"),
            "must fail on the certificate parse, not incidentally: {err}"
        );
    }

    #[test]
    fn rejects_pem_wrapping_garbage() {
        let pem = "-----BEGIN CERTIFICATE-----\nZ2FyYmFnZQ==\n-----END CERTIFICATE-----\n";
        let err = check_enclave_certificate(pem, "inference.tinfoil.sh", &[0; 32])
            .expect_err("PEM-wrapped garbage must not verify");
        assert!(
            err.to_string().contains("is not a PEM certificate"),
            "must fail on the certificate parse, not incidentally: {err}"
        );
    }

    #[test]
    fn matches_an_exact_name_case_insensitively() {
        assert!(dns_name_matches(
            "inference.tinfoil.sh",
            "inference.tinfoil.sh"
        ));
        assert!(dns_name_matches(
            "Inference.Tinfoil.SH",
            "inference.tinfoil.sh"
        ));
        assert!(dns_name_matches(
            "inference.tinfoil.sh",
            "INFERENCE.TINFOIL.SH"
        ));
        assert!(!dns_name_matches("tinfoil.sh", "inference.tinfoil.sh"));
    }

    #[test]
    fn wildcard_matches_exactly_one_leftmost_label() {
        assert!(dns_name_matches(
            "*.inference.tinfoil.sh",
            "a.inference.tinfoil.sh"
        ));
        assert!(dns_name_matches(
            "*.inference.tinfoil.sh",
            "A.Inference.Tinfoil.sh"
        ));
        // A wildcard is not a "zero or more labels" glob: it must not swallow
        // the bare parent name...
        assert!(!dns_name_matches(
            "*.inference.tinfoil.sh",
            "inference.tinfoil.sh"
        ));
        // ...nor more than one label.
        assert!(!dns_name_matches(
            "*.inference.tinfoil.sh",
            "a.b.inference.tinfoil.sh"
        ));
    }

    /// Beyond RFC 6125: a wildcard whose suffix is a single label spans a
    /// whole registry. Mechanically §6.4.3 permits it; no CA issues one and no
    /// browser honours one, so it is refused here.
    #[test]
    fn rejects_a_wildcard_directly_under_a_single_label_suffix() {
        assert!(!dns_name_matches("*.com", "evil.com"));
        assert!(!dns_name_matches("*.sh", "tinfoil.sh"));
        assert!(!dns_name_matches("*.localhost", "a.localhost"));
        // Two labels of suffix is the floor, and the real pattern clears it.
        assert!(dns_name_matches("*.tinfoil.sh", "inference.tinfoil.sh"));
        assert!(dns_name_matches(
            "*.inference.tinfoil.sh",
            "a.inference.tinfoil.sh"
        ));
    }

    #[test]
    fn rejects_malformed_wildcards() {
        // Partial-label wildcards: valid only as the *entire* leftmost label.
        assert!(!dns_name_matches("w*.example.com", "www.example.com"));
        assert!(!dns_name_matches("*w.example.com", "www.example.com"));
        assert!(!dns_name_matches("w*w.example.com", "www.example.com"));
        // Not leftmost.
        assert!(!dns_name_matches("www.*.com", "www.example.com"));
        // More than one.
        assert!(!dns_name_matches("*.*.com", "www.example.com"));
        // Nothing but a wildcard.
        assert!(!dns_name_matches("*", "example.com"));
        assert!(!dns_name_matches("*", "example"));
        // A host may never carry one either.
        assert!(!dns_name_matches("*.example.com", "*.example.com"));
        assert!(!dns_name_matches("example.com", "*"));
    }

    #[test]
    fn rejects_empty_and_trailing_dot_names() {
        assert!(!dns_name_matches("", ""));
        assert!(!dns_name_matches("example.com", ""));
        assert!(!dns_name_matches("", "example.com"));
        assert!(!dns_name_matches(".", "."));
        assert!(!dns_name_matches("example.com.", "example.com"));
        assert!(!dns_name_matches("example.com", "example.com."));
        assert!(!dns_name_matches("*.example.com", ".example.com"));
        assert!(!dns_name_matches("*..example.com", "a..example.com"));
        assert!(!dns_name_matches(".example.com", ".example.com"));
    }
}
