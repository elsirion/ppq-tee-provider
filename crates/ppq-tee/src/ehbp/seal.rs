//! HPKE-sealing an EHBP request body to the enclave's attested public key.

use crate::ehbp::open::{ResponseSession, RESPONSE_EXPORT_LABEL};
use crate::{Error, Result};
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, OpModeS, Serializable,
};

/// HPKE `info` for the request context, per the EHBP spec.
pub const REQUEST_INFO: &[u8] = b"ehbp request";

/// A request body sealed to the enclave, plus what is needed to read the reply.
pub struct SealedRequest {
    /// Goes in the `Ehbp-Encapsulated-Key` header, hex-encoded.
    pub enc: [u8; 32],
    /// Length-prefixed ciphertext frames, ready to send as the body.
    pub body: Vec<u8>,
    /// Retained so the response can be decrypted.
    pub session: ResponseSession,
}

/// Prepend the 4-byte big-endian ciphertext length required by EHBP framing.
///
/// The caller must keep `ciphertext` under `u32::MAX` bytes — the framing has
/// no way to express anything longer. Both producers in this crate ([`seal`]
/// and `FrameSealer::seal_frame`) check that before calling.
pub fn frame(ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ciphertext.len());
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

/// HPKE-seal a request body to the enclave's attested public key.
///
/// Suite: X25519-HKDF-SHA256 / HKDF-SHA256 / AES-256-GCM, `SetupBaseS` with
/// `info = "ehbp request"`, empty AAD.
///
/// The whole body is sent as a single frame: request bodies are small JSON
/// documents, and one frame keeps the sealer's sequence trivially in step with
/// the server's opener.
pub fn seal(public_key: &[u8; 32], plaintext: &[u8]) -> Result<SealedRequest> {
    // A request longer than u32::MAX could not be framed. Refuse rather than
    // truncate the length prefix.
    if plaintext.len() > u32::MAX as usize - 16 {
        return Err(Error::Ehbp("request body is too large to frame".into()));
    }

    let pk = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(public_key)
        .map_err(|e| Error::Ehbp(format!("bad enclave public key: {e}")))?;

    let (enc, mut ctx) = hpke::setup_sender::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &pk,
        REQUEST_INFO,
    )
    .map_err(|e| Error::Ehbp(format!("HPKE setup failed: {e}")))?;

    let ct = ctx
        .seal(plaintext, b"")
        .map_err(|e| Error::Ehbp(format!("sealing request failed: {e}")))?;

    let mut exported_secret = [0u8; 32];
    ctx.export(RESPONSE_EXPORT_LABEL, &mut exported_secret)
        .map_err(|e| Error::Ehbp(format!("HPKE export failed: {e}")))?;

    let enc_bytes: [u8; 32] = enc
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| Error::Ehbp("encapsulated key is not 32 bytes".into()))?;

    Ok(SealedRequest {
        enc: enc_bytes,
        body: frame(&ct),
        session: ResponseSession::new(exported_secret, enc_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_with_a_big_endian_length_prefix() {
        assert_eq!(frame(b""), vec![0, 0, 0, 0]);
        assert_eq!(frame(b"abc"), vec![0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn rejects_a_public_key_that_is_not_on_the_curve() {
        // All-zero is the canonical invalid X25519 public key (low order).
        assert!(seal(&[0u8; 32], b"hi").is_err());
    }

    #[test]
    fn seals_to_a_fresh_encapsulated_key_each_time() {
        use hpke::{Kem as _, Serializable as _};
        let (_sk, pk) = hpke::kem::X25519HkdfSha256::gen_keypair();
        let pk_bytes: [u8; 32] = pk.to_bytes().as_slice().try_into().unwrap();

        let a = seal(&pk_bytes, b"hi").unwrap();
        let b = seal(&pk_bytes, b"hi").unwrap();
        assert_ne!(a.enc, b.enc, "encapsulation must be randomized");
        assert_ne!(a.body, b.body);
        // 4-byte prefix + plaintext + 16-byte GCM tag.
        assert_eq!(a.body.len(), 4 + 2 + 16);
        assert_eq!(u32::from_be_bytes(a.body[..4].try_into().unwrap()), 18);
    }
}
