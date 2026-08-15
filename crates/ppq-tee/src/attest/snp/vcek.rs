//! VCEK certificate chain verification against an embedded AMD root.
//!
//! The attestation bundle ships the VCEK (Versioned Chip Endorsement Key)
//! certificate for the exact chip that signed the report, so verification
//! needs no AMD KDS round-trip. What it does need is proof that the VCEK was
//! endorsed by AMD: VCEK -> ASK -> ARK, with the ARK pinned in this crate
//! (see `testdata/amd/PROVENANCE.md`).

use crate::attest::policy::{amd_root, AmdProduct};
use crate::{Error, Result};
use const_oid::ObjectIdentifier;
use p384::ecdsa::VerifyingKey;
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};

/// id-RSASSA-PSS. Every certificate in AMD's chain — ARK, ASK and VCEK alike —
/// is signed with this, because both the ARK and the ASK are RSA-4096 keys.
const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
/// id-mgf1.
const ID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
/// id-sha384.
const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
/// rsaEncryption — the SPKI algorithm of AMD's ARK and ASK keys.
const ID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// id-ecPublicKey — the SPKI algorithm of the VCEK's key.
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// secp384r1, a.k.a. NIST P-384.
const ID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// AMD signs with SHA-384 and a salt as long as the digest.
const PSS_SALT_LEN: u8 = 48;

/// The VCEK's public key, once the chain to an AMD root has been checked.
///
/// Constructing one is the only way to get a [`VerifyingKey`] out of this
/// module, so a caller cannot accidentally verify a report against an
/// unendorsed key.
#[derive(Debug)]
pub struct VcekKey(pub(crate) VerifyingKey);

/// Verify VCEK -> ASK -> ARK against the embedded root for `product`.
///
/// The VCEK ships inside the attestation bundle, so no AMD KDS round-trip is
/// needed at verification time.
///
/// `vcek_der` is attacker-controlled: it arrives from the server being
/// attested. Every step below returns an error rather than panicking on
/// malformed input.
///
/// Certificate validity periods are deliberately not checked. AMD's ARKs run
/// to 2047 and VCEKs are not revoked or rotated per-boot, so an expiry check
/// would add no security here while making a committed test fixture rot.
/// Freshness of the *deployment* is established by the sigstore layer's
/// `max_attestation_age`, and freshness of the *session* by the nonce bound
/// into `report_data`.
pub fn verify_chain(vcek_der: &[u8], product: AmdProduct) -> Result<VcekKey> {
    let vcek = Certificate::from_der(vcek_der)
        .map_err(|e| Error::Attestation(format!("VCEK is not a DER certificate: {e}")))?;

    let chain = Certificate::load_pem_chain(amd_root(product))
        .map_err(|e| Error::Attestation(format!("embedded AMD chain is invalid: {e}")))?;
    let ask = chain
        .first()
        .ok_or_else(|| Error::Attestation("AMD chain is empty".into()))?;
    let ark = chain
        .get(1)
        .ok_or_else(|| Error::Attestation("AMD chain has no root".into()))?;

    // ARK is self-signed; ASK is signed by ARK; VCEK is signed by ASK. The ARK
    // link is not a trust decision — the ARK is pinned — but it proves the
    // embedded root is internally consistent.
    verify_signed_by(ark, ark)?;
    verify_signed_by(ask, ark)?;
    verify_signed_by(&vcek, ask)?;

    let key = p384_key_from_spki(&vcek.tbs_certificate.subject_public_key_info)?;
    Ok(VcekKey(key))
}

/// Check that `spki` names the id-ecPublicKey algorithm on curve secp384r1 —
/// the only key type and curve AMD issues for a VCEK — and extract the key.
///
/// Split out from [`verify_chain`] so this fail-closed logic can be exercised
/// directly in tests: `spki` lives inside a certificate's signed
/// `tbsCertificate`, so a DER fixture with a tampered curve OID no longer
/// carries a valid CA signature, and driving such a fixture through the full
/// chain would be rejected by the signature check instead — for the wrong
/// reason.
fn p384_key_from_spki(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> Result<VerifyingKey> {
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return Err(Error::Attestation(format!(
            "VCEK key algorithm is {}, want id-ecPublicKey",
            spki.algorithm.oid
        )));
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| Error::Attestation("VCEK key names no curve".into()))?
        .decode_as::<ObjectIdentifier>()
        .map_err(|e| Error::Attestation(format!("VCEK curve is not an OID: {e}")))?;
    if curve != ID_SECP384R1 {
        return Err(Error::Attestation(format!(
            "VCEK key is on curve {curve}, want secp384r1"
        )));
    }

    VerifyingKey::from_sec1_bytes(
        spki.subject_public_key
            .as_bytes()
            .ok_or_else(|| Error::Attestation("VCEK public key is not aligned".into()))?,
    )
    .map_err(|e| Error::Attestation(format!("VCEK public key is not P-384: {e}")))
}

/// Check that `cert` names `issuer` as its issuer and that its signature
/// verifies under `issuer`'s public key.
///
/// AMD signs every certificate in the chain with RSASSA-PSS: the ARK and ASK
/// are RSA-4096 keys, so even the VCEK — whose *own* key is ECDSA-P384 —
/// carries an RSA-PSS signature made by the ASK. Any other signature algorithm
/// is rejected rather than assumed good.
fn verify_signed_by(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    use rsa::{pkcs1::RsaPssParams, pkcs8::DecodePublicKey, pss::Pss, RsaPublicKey};
    use sha2::{Digest, Sha384};

    // Names bind the link even before the cryptography does; without this a
    // caller could not tell "wrong product line" from "forged signature".
    let (subject, named_issuer) = (
        issuer
            .tbs_certificate
            .subject
            .to_der()
            .map_err(|e| Error::Attestation(format!("cannot re-encode issuer subject: {e}")))?,
        cert.tbs_certificate
            .issuer
            .to_der()
            .map_err(|e| Error::Attestation(format!("cannot re-encode issuer name: {e}")))?,
    );
    if subject != named_issuer {
        return Err(Error::Attestation(format!(
            "certificate issuer {} does not match {}",
            cert.tbs_certificate.issuer, issuer.tbs_certificate.subject,
        )));
    }

    let algorithm = &cert.signature_algorithm;
    if algorithm.oid != ID_RSASSA_PSS {
        return Err(Error::Attestation(format!(
            "unsupported certificate signature algorithm {}",
            algorithm.oid
        )));
    }
    // RFC 5280 §6.1 requires the outer, unsigned `signatureAlgorithm` to
    // equal the inner one in the signed `tbsCertificate.signature` field. A
    // mismatch would mean a verifier and a signer could each read a different
    // algorithm out of the same certificate.
    if *algorithm != cert.tbs_certificate.signature {
        return Err(Error::Attestation(
            "certificate's outer signatureAlgorithm does not match the signed \
             tbsCertificate.signature"
                .into(),
        ));
    }

    // Verify under the parameters the certificate itself declares, so a
    // certificate signed with a weaker hash cannot be checked as if it were
    // SHA-384.
    let params: RsaPssParams = algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| Error::Attestation("RSA-PSS signature declares no parameters".into()))?
        .decode_as()
        .map_err(|e| Error::Attestation(format!("malformed RSA-PSS parameters: {e}")))?;
    let mgf_hash = params.mask_gen.parameters.map(|p| p.oid);
    if params.hash.oid != ID_SHA384
        || params.mask_gen.oid != ID_MGF1
        || mgf_hash != Some(ID_SHA384)
        || params.salt_len != PSS_SALT_LEN
    {
        return Err(Error::Attestation(format!(
            "unsupported RSA-PSS parameters: hash {}, mgf {}, mgf hash {:?}, salt {}",
            params.hash.oid, params.mask_gen.oid, mgf_hash, params.salt_len,
        )));
    }

    let spki = &issuer.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != ID_RSA_ENCRYPTION {
        return Err(Error::Attestation(format!(
            "issuer key algorithm is {}, want rsaEncryption",
            spki.algorithm.oid
        )));
    }
    let key = RsaPublicKey::from_public_key_der(
        &spki
            .to_der()
            .map_err(|e| Error::Attestation(format!("cannot re-encode issuer SPKI: {e}")))?,
    )
    .map_err(|e| Error::Attestation(format!("issuer key is not RSA: {e}")))?;

    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::Attestation(format!("cannot re-encode tbsCertificate: {e}")))?;
    let signature = cert
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Attestation("signature is not aligned".into()))?;

    key.verify(
        Pss::new_with_salt::<Sha384>(PSS_SALT_LEN as usize),
        &Sha384::digest(&tbs),
        signature,
    )
    .map_err(|e| Error::Attestation(format!("certificate signature invalid: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{bundle, policy::AmdProduct};
    use base64::{engine::general_purpose::STANDARD, Engine};

    const FIXTURE: &str = include_str!("../../../testdata/attestation-bundle.json");

    /// Overwrite the content bytes (not the tag/length) of the *last* DER TLV
    /// encoding of `target` found in `der` with `replacement`'s own content
    /// bytes.
    ///
    /// The last occurrence is used deliberately: within a `Certificate`'s DER
    /// a repeated `AlgorithmIdentifier` OID occurs first inside the signed
    /// `tbsCertificate` and again in the outer, unsigned
    /// `signatureAlgorithm` field, so "last" reliably means "outer" — the one
    /// `verify_signed_by` checks and that isn't covered by the CA's
    /// signature. `target` and `replacement` must have equal-length DER
    /// content so no length octet in the enclosing structure has to move.
    fn replace_last_oid(der: &mut [u8], target: ObjectIdentifier, replacement: ObjectIdentifier) {
        use x509_cert::der::Encode;
        let target_tlv = target.to_der().unwrap();
        let replacement_content = replacement.as_bytes();
        assert_eq!(
            target.as_bytes().len(),
            replacement_content.len(),
            "swap requires equal-length OID content"
        );
        let pos = der
            .windows(target_tlv.len())
            .rposition(|w| w == target_tlv.as_slice())
            .expect("target OID TLV present in the fixture DER");
        // TLV = 1 tag octet + 1 short-form length octet + content.
        let content_start = pos + 2;
        der[content_start..content_start + replacement_content.len()]
            .copy_from_slice(replacement_content);
    }

    #[test]
    fn rejects_a_garbage_certificate() {
        assert!(verify_chain(&[0u8; 16], AmdProduct::Milan).is_err());
    }

    /// The outer `signatureAlgorithm` is not covered by the CA's signature
    /// over `tbsCertificate` (it's a sibling field), so it can be mutated in
    /// place without invalidating the certificate's signature — letting this
    /// exercise `verify_signed_by`'s algorithm-OID check specifically, rather
    /// than incidentally failing the signature check for an unrelated
    /// reason.
    #[test]
    fn rejects_a_vcek_whose_outer_signature_algorithm_is_not_rsassa_pss() {
        let b = bundle::parse(FIXTURE).unwrap();
        let mut der = STANDARD.decode(&b.vcek).unwrap();
        // id-mgf1 has the same 9-byte DER content length as id-RSASSA-PSS,
        // so the swap needs no length fixup, and it is a real PKCS#1 OID
        // that is definitely not RSASSA-PSS.
        replace_last_oid(&mut der, ID_RSASSA_PSS, ID_MGF1);
        let err = verify_chain(&der, AmdProduct::Genoa).expect_err("must not verify");
        assert!(
            err.to_string()
                .contains("unsupported certificate signature algorithm"),
            "must fail on the algorithm OID, not incidentally: {err}"
        );
    }

    /// Unlike the outer `signatureAlgorithm`, the SPKI (and its curve OID)
    /// lives inside the signed `tbsCertificate` — mutating it invalidates the
    /// ASK's signature over the VCEK, so driving a mutated fixture through
    /// `verify_chain` would be rejected by the signature check first, for an
    /// unrelated reason. `p384_key_from_spki` is exercised directly instead,
    /// on the real fixture VCEK's (parsed, mutated) SPKI, so the actual
    /// curve-check code path used by `verify_chain` is what's under test.
    #[test]
    fn rejects_a_vcek_whose_spki_curve_is_not_secp384r1() {
        use x509_cert::der::Decode;

        let b = bundle::parse(FIXTURE).unwrap();
        let mut der = STANDARD.decode(&b.vcek).unwrap();
        // secp256k1 (1.3.132.0.10) has the same 5-byte DER content length as
        // secp384r1 (1.3.132.0.34) — both are "1.3.132.0.<arc>" — and is a
        // real, different curve OID.
        const ID_SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
        replace_last_oid(&mut der, ID_SECP384R1, ID_SECP256K1);

        let cert = Certificate::from_der(&der).expect("still structurally valid DER");
        let err = p384_key_from_spki(&cert.tbs_certificate.subject_public_key_info)
            .expect_err("must not accept a non-secp384r1 curve");
        assert!(
            err.to_string().contains("secp384r1"),
            "must fail on the curve, not incidentally: {err}"
        );
    }

    #[test]
    fn rejects_a_vcek_from_the_wrong_product_line() {
        let b = bundle::parse(FIXTURE).unwrap();
        let der = STANDARD.decode(&b.vcek).unwrap();
        let ok = [AmdProduct::Milan, AmdProduct::Genoa, AmdProduct::Turin]
            .iter()
            .filter(|p| verify_chain(&der, **p).is_ok())
            .count();
        assert_eq!(ok, 1, "VCEK chains to exactly one product line");
    }

    #[test]
    fn rejects_a_vcek_with_a_tampered_signature() {
        let b = bundle::parse(FIXTURE).unwrap();
        let mut der = STANDARD.decode(&b.vcek).unwrap();
        // The signature is the last field of the certificate, so flipping a
        // byte near the end hits it without disturbing the DER structure.
        let last = der.len() - 1;
        der[last] ^= 0x01;
        let err = verify_chain(&der, AmdProduct::Genoa).expect_err("must not verify");
        assert!(
            err.to_string().contains("signature invalid"),
            "must fail on the signature, not incidentally: {err}"
        );
    }

    #[test]
    fn rejects_trailing_garbage_after_the_certificate() {
        let b = bundle::parse(FIXTURE).unwrap();
        let mut der = STANDARD.decode(&b.vcek).unwrap();
        der.push(0);
        let err = verify_chain(&der, AmdProduct::Genoa).expect_err("must not verify");
        assert!(
            err.to_string().contains("trailing data"),
            "must fail on the trailing bytes, not incidentally: {err}"
        );
    }

    #[test]
    fn every_embedded_chain_is_internally_consistent() {
        for product in [AmdProduct::Milan, AmdProduct::Genoa, AmdProduct::Turin] {
            let chain = Certificate::load_pem_chain(amd_root(product)).unwrap();
            assert_eq!(chain.len(), 2, "{product:?} chain is ASK+ARK");
            let (ask, ark) = (&chain[0], &chain[1]);
            verify_signed_by(ark, ark).unwrap_or_else(|e| panic!("{product:?} ARK: {e}"));
            verify_signed_by(ask, ark).unwrap_or_else(|e| panic!("{product:?} ASK: {e}"));
            // ...and not the other way around, which would mean the file is
            // ordered ARK-then-ASK and `verify_chain` is checking nothing.
            assert!(verify_signed_by(ark, ask).is_err());
        }
    }
}
