//! Deriving the EHBP response AEAD and opening response frames.
//!
//! The response keys are not part of the HPKE context: the server exports a
//! secret from it, mixes in the encapsulated key and a per-response nonce, and
//! both sides run HKDF over that.

use crate::{Error, Result};
use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HPKE export label for response keys, per the EHBP spec.
pub const RESPONSE_EXPORT_LABEL: &[u8] = b"ehbp response";

/// The response nonce the server sends in `Ehbp-Response-Nonce`.
pub const RESPONSE_NONCE_LEN: usize = 32;

/// Everything needed to decrypt one response, retained from the request.
///
/// `exported_secret` is key material: it is wiped on drop and never rendered
/// by `Debug`.
#[derive(Clone, ZeroizeOnDrop)]
pub struct ResponseSession {
    exported_secret: [u8; 32],
    #[zeroize(skip)]
    enc: [u8; 32],
}

impl core::fmt::Debug for ResponseSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResponseSession")
            .field("enc", &hex::encode(self.enc))
            .field("exported_secret", &"<redacted>")
            .finish()
    }
}

impl ResponseSession {
    pub fn new(exported_secret: [u8; 32], enc: [u8; 32]) -> Self {
        Self {
            exported_secret,
            enc,
        }
    }

    /// Derive the response AEAD from this session and the server's nonce.
    ///
    /// `response_nonce` comes off the wire and is validated here; anything but
    /// exactly [`RESPONSE_NONCE_LEN`] bytes is an error, never a panic.
    pub fn opener(&self, response_nonce: &[u8]) -> Result<FrameOpener> {
        let (cipher, base) = derive(&self.exported_secret, &self.enc, response_nonce)?;
        Ok(FrameOpener {
            cipher,
            base,
            seq: 0,
        })
    }
}

/// `prk = Extract(salt = enc ‖ response_nonce, ikm = secret)`, then
/// `key = Expand(prk, "key", 32)` and `nonce = Expand(prk, "nonce", 12)`.
fn derive(
    secret: &[u8; 32],
    enc: &[u8; 32],
    response_nonce: &[u8],
) -> Result<(Aes256Gcm, [u8; 12])> {
    if response_nonce.len() != RESPONSE_NONCE_LEN {
        return Err(Error::Ehbp(format!(
            "response nonce is {} bytes, want {RESPONSE_NONCE_LEN}",
            response_nonce.len()
        )));
    }
    let mut salt = Vec::with_capacity(enc.len() + RESPONSE_NONCE_LEN);
    salt.extend_from_slice(enc);
    salt.extend_from_slice(response_nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut key = [0u8; 32];
    hk.expand(b"key", &mut key)
        .map_err(|e| Error::Ehbp(format!("key expansion failed: {e}")))?;
    let mut base = [0u8; 12];
    hk.expand(b"nonce", &mut base)
        .map_err(|e| Error::Ehbp(format!("nonce expansion failed: {e}")))?;

    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key));
    key.zeroize();
    Ok((cipher, base))
}

/// Per-frame nonce: `base XOR seq`, with `seq` as a big-endian u64 in the
/// **last 8 bytes** of the 12-byte base. Confirmed against the Go reference
/// (`identity/derive.go`); the written spec is ambiguous on the placement.
fn frame_nonce(base: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *base;
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        n[4 + i] ^= b;
    }
    n
}

/// Opens response frames in order. Never emits plaintext for a frame that
/// failed authentication.
pub struct FrameOpener {
    cipher: Aes256Gcm,
    base: [u8; 12],
    seq: u64,
}

impl FrameOpener {
    /// Open one frame's ciphertext (without the length prefix).
    ///
    /// Returns `Err` for anything that does not authenticate under the current
    /// sequence number, and returns no plaintext in that case.
    pub fn open_frame(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = frame_nonce(&self.base, self.seq);
        let plain = self
            .cipher
            .decrypt(&Nonce::<Aes256Gcm>::from(nonce), ciphertext)
            .map_err(|_| Error::Ehbp("response frame failed authentication".into()))?;
        // Advance only after a frame authenticates, so a rejected frame cannot
        // desynchronise the sequence.
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Ehbp("response frame sequence exhausted".into()))?;
        Ok(plain)
    }
}

/// The server half of the response AEAD.
///
/// It lives beside [`FrameOpener`] so that the client's and server's key
/// derivations share one implementation and cannot drift apart. It is not part
/// of the default build — a client has no business sealing responses — but is
/// available behind the `test-server` feature to anyone writing an EHBP server
/// or an integration harness.
#[cfg(any(test, feature = "test-server"))]
pub struct FrameSealer {
    cipher: Aes256Gcm,
    base: [u8; 12],
    seq: u64,
}

#[cfg(any(test, feature = "test-server"))]
impl FrameSealer {
    pub fn new(secret: &[u8; 32], enc: &[u8; 32], response_nonce: &[u8]) -> Result<Self> {
        let (cipher, base) = derive(secret, enc, response_nonce)?;
        Ok(Self {
            cipher,
            base,
            seq: 0,
        })
    }

    /// Seal one frame, returning it length-prefixed and ready to write.
    pub fn seal_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = frame_nonce(&self.base, self.seq);
        let ct = self
            .cipher
            .encrypt(&Nonce::<Aes256Gcm>::from(nonce), plaintext)
            .map_err(|_| Error::Ehbp("sealing response frame failed".into()))?;
        if ct.len() > u32::MAX as usize {
            return Err(Error::Ehbp("response frame is too large to frame".into()));
        }
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Ehbp("response frame sequence exhausted".into()))?;
        Ok(crate::ehbp::seal::frame(&ct))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ehbp::seal;
    use hpke::{
        aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as _, OpModeR,
        Serializable,
    };

    type Kem = X25519HkdfSha256;

    fn keypair() -> (<Kem as hpke::Kem>::PrivateKey, [u8; 32]) {
        let (sk, pk) = Kem::gen_keypair();
        let pk_bytes: [u8; 32] = pk
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("X25519 pk is 32B");
        (sk, pk_bytes)
    }

    /// Server half: given the client's `enc` and the server private key, derive
    /// the same response keys and seal a body. Deliberately built on
    /// `hpke::setup_receiver` rather than on any of our own client code, so a
    /// passing round trip means our sender-side derivation agrees with an
    /// independent implementation of RFC 9180.
    fn server_respond(
        sk: &<Kem as hpke::Kem>::PrivateKey,
        enc_bytes: &[u8; 32],
        request_ct_frames: &[u8],
        responses: &[&[u8]],
    ) -> (Vec<u8>, [u8; 32]) {
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc_bytes).unwrap();
        let mut ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(
            &OpModeR::Base,
            sk,
            &enc,
            seal::REQUEST_INFO,
        )
        .unwrap();

        // Open every request frame so the AEAD sequence matches the client's.
        let mut rest = request_ct_frames;
        while rest.len() >= 4 {
            let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            rest = &rest[4..];
            ctx.open(&rest[..n], b"").unwrap();
            rest = &rest[n..];
        }

        let mut secret = [0u8; 32];
        ctx.export(RESPONSE_EXPORT_LABEL, &mut secret).unwrap();
        let response_nonce = [7u8; 32];
        let mut sealer = FrameSealer::new(&secret, enc_bytes, &response_nonce).unwrap();
        let mut out = Vec::new();
        for r in responses {
            out.extend_from_slice(&sealer.seal_frame(r).unwrap());
        }
        (out, response_nonce)
    }

    /// Split a framed stream into its ciphertexts.
    fn unframe(mut rest: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        while rest.len() >= 4 {
            let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            rest = &rest[4..];
            out.push(&rest[..n]);
            rest = &rest[n..];
        }
        out
    }

    #[test]
    fn round_trips_a_response_through_the_derived_keys() {
        let (sk, pk_bytes) = keypair();

        let sealed = seal::seal(&pk_bytes, b"{\"model\":\"glm-5-2\"}").unwrap();
        let (frames, nonce) =
            server_respond(&sk, &sealed.enc, &sealed.body, &[b"hello from the enclave"]);

        let mut opener = sealed.session.opener(&nonce).unwrap();
        let plain = opener.open_frame(unframe(&frames)[0]).unwrap();
        assert_eq!(plain, b"hello from the enclave");
    }

    #[test]
    fn round_trips_multiple_frames_in_order() {
        let (sk, pk_bytes) = keypair();

        let sealed = seal::seal(&pk_bytes, b"x").unwrap();
        let (frames, nonce) =
            server_respond(&sk, &sealed.enc, &sealed.body, &[b"one", b"two", b"three"]);

        let mut opener = sealed.session.opener(&nonce).unwrap();
        let cts = unframe(&frames);
        assert_eq!(cts.len(), 3);
        assert_eq!(opener.open_frame(cts[0]).unwrap(), b"one");
        assert_eq!(opener.open_frame(cts[1]).unwrap(), b"two");
        assert_eq!(opener.open_frame(cts[2]).unwrap(), b"three");
    }

    #[test]
    fn rejects_a_tampered_frame() {
        let (sk, pk_bytes) = keypair();

        let sealed = seal::seal(&pk_bytes, b"x").unwrap();
        let (mut frames, nonce) = server_respond(&sk, &sealed.enc, &sealed.body, &[b"secret"]);
        frames[6] ^= 0xFF;

        let mut opener = sealed.session.opener(&nonce).unwrap();
        let n = u32::from_be_bytes(frames[..4].try_into().unwrap()) as usize;
        assert!(opener.open_frame(&frames[4..4 + n]).is_err());
    }

    #[test]
    fn rejects_a_wrong_response_nonce() {
        let (sk, pk_bytes) = keypair();

        let sealed = seal::seal(&pk_bytes, b"x").unwrap();
        let (frames, _) = server_respond(&sk, &sealed.enc, &sealed.body, &[b"secret"]);

        let mut opener = sealed.session.opener(&[9u8; 32]).unwrap();
        assert!(opener.open_frame(unframe(&frames)[0]).is_err());
    }

    #[test]
    fn rejects_a_response_nonce_of_the_wrong_length() {
        let session = ResponseSession::new([1u8; 32], [2u8; 32]);
        assert!(session.opener(&[]).is_err());
        assert!(session.opener(&[0u8; 31]).is_err());
        assert!(session.opener(&[0u8; 33]).is_err());
        assert!(session.opener(&[0u8; 32]).is_ok());
    }

    #[test]
    fn a_rejected_frame_does_not_advance_the_sequence() {
        let (sk, pk_bytes) = keypair();

        let sealed = seal::seal(&pk_bytes, b"x").unwrap();
        let (frames, nonce) = server_respond(&sk, &sealed.enc, &sealed.body, &[b"one", b"two"]);
        let cts = unframe(&frames);

        let mut opener = sealed.session.opener(&nonce).unwrap();
        // Feed a corrupted frame 0; it must fail *and* leave the sequence at 0,
        // so the genuine frame 0 still opens afterwards.
        let mut bad = cts[0].to_vec();
        bad[0] ^= 0xFF;
        assert!(opener.open_frame(&bad).is_err());
        assert_eq!(opener.open_frame(cts[0]).unwrap(), b"one");
        assert_eq!(opener.open_frame(cts[1]).unwrap(), b"two");
    }

    #[test]
    fn frame_sequence_advances_per_frame() {
        // Two frames sealed under the same key must produce different
        // ciphertexts for identical plaintext, or the nonce is being reused.
        let secret = [1u8; 32];
        let enc = [2u8; 32];
        let nonce = [3u8; 32];
        let mut s = FrameSealer::new(&secret, &enc, &nonce).unwrap();
        let a = s.seal_frame(b"same").unwrap();
        let b = s.seal_frame(b"same").unwrap();
        assert_ne!(a, b, "frame nonces must not repeat");
    }

    #[test]
    fn frame_nonce_xors_the_sequence_into_the_last_eight_bytes() {
        let base = [0u8; 12];
        assert_eq!(frame_nonce(&base, 0), [0u8; 12]);
        assert_eq!(
            frame_nonce(&base, 1),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "sequence is big-endian in the last 8 bytes"
        );
        assert_eq!(
            frame_nonce(&base, 0x0102_0304_0506_0708),
            [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
        );
    }
}
