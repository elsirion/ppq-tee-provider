use crate::ehbp::open::FrameOpener;
use crate::{Error, Result};

/// Upper bound on a single EHBP frame's ciphertext length.
///
/// Responses are SSE chunks or JSON bodies coming back from the PPQ.AI API —
/// in practice a few KB up to a handful of MB for an unusually long
/// completion. 16 MiB leaves generous headroom above that while still
/// bounding how much a hostile length prefix (e.g. `0xFFFFFFFF`, ~4 GiB) can
/// make us buffer: we check the declared length against this cap as soon as
/// it is parsed, before waiting for a single additional byte of body, so an
/// attacker cannot use the prefix alone to drive unbounded memory growth.
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Reassembles EHBP frames from a byte stream that may split them anywhere.
///
/// A frame's plaintext is emitted only after that whole frame authenticates,
/// so a caller never sees bytes the enclave did not sign for.
///
/// # Poisoning
///
/// Any error from [`push`](Self::push) or [`finish`](Self::finish) poisons
/// the decoder: every call after that returns `Err` without touching
/// `opener` or `buf`. This is deliberate, not incidental. `push` decodes
/// zero or more frames per call and only drains its cursor into `buf` once,
/// at the very end, after the whole loop succeeds; an error return exits
/// before that drain, so bytes already consumed for earlier frames in the
/// same call would otherwise be re-parsed on the next `push`, while
/// `opener`'s AEAD sequence number has already moved past them. Without
/// poisoning, a caller that ignores an `Err` and keeps pushing would attempt
/// to re-open an already-opened frame at the wrong sequence number — today
/// that merely fails authentication, but nothing about the type guarantees
/// it always will, so the decoder refuses to proceed at all once it has
/// failed once.
pub struct FrameDecoder {
    opener: FrameOpener,
    buf: Vec<u8>,
    failed: bool,
}

impl FrameDecoder {
    pub fn new(opener: FrameOpener) -> Self {
        Self {
            opener,
            buf: Vec::new(),
            failed: false,
        }
    }

    /// Feed transport bytes; returns whatever plaintext became available.
    ///
    /// Every length read is bounds-checked before it is used to slice: `pos`
    /// only ever advances to an offset that has already been proven to lie
    /// within `self.buf`, so a truncated or hostile length prefix causes this
    /// to wait for more data (or return `Err` if it exceeds
    /// [`MAX_FRAME_LEN`]) rather than slicing out of bounds.
    ///
    /// Once this (or [`finish`](Self::finish)) has returned `Err`, every
    /// subsequent call returns `Err` immediately without touching `opener`
    /// or `buf` — see the poisoning note on the type.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        if self.failed {
            return Err(Error::Ehbp(
                "frame decoder is poisoned by an earlier failure".into(),
            ));
        }

        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        // Index-based cursor rather than repeated front-drains: draining the
        // consumed prefix once at the end, instead of once per frame, avoids
        // an O(frames^2) shift of the trailing bytes when one `push` call
        // completes many frames at once.
        let mut pos = 0usize;

        loop {
            let remaining = self.buf.len() - pos;
            if remaining < 4 {
                break;
            }
            let len_bytes: [u8; 4] = self.buf[pos..pos + 4].try_into().unwrap();
            let len = u32::from_be_bytes(len_bytes) as usize;
            if len > MAX_FRAME_LEN {
                self.failed = true;
                return Err(Error::Ehbp(format!(
                    "frame length {len} exceeds maximum of {MAX_FRAME_LEN} bytes"
                )));
            }
            if remaining < 4 + len {
                break;
            }
            let frame_start = pos + 4;
            let frame_end = frame_start + len;
            // Zero-length frames come from empty application writes;
            // receivers skip them without calling `open_frame`, so the AEAD
            // sequence never advances for a frame that carried no ciphertext.
            if len > 0 {
                match self.opener.open_frame(&self.buf[frame_start..frame_end]) {
                    Ok(plain) => out.extend(plain),
                    Err(e) => {
                        self.failed = true;
                        return Err(e);
                    }
                }
            }
            pos = frame_end;
        }

        self.buf.drain(..pos);
        Ok(out)
    }

    /// Assert the stream ended on a frame boundary.
    ///
    /// Transport EOF alone does not prove the application response is
    /// complete, but a partial length prefix or partial frame body proves it
    /// is *not*.
    ///
    /// If the decoder was already poisoned by an earlier failed `push`, this
    /// also returns `Err` — see the poisoning note on the type.
    pub fn finish(self) -> Result<()> {
        if self.failed {
            return Err(Error::Ehbp(
                "frame decoder is poisoned by an earlier failure".into(),
            ));
        }
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Ehbp(format!(
                "stream ended mid-frame with {} bytes buffered",
                self.buf.len()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ehbp::open::{FrameSealer, ResponseSession};

    fn pair() -> (FrameSealer, FrameDecoder) {
        let secret = [4u8; 32];
        let enc = [5u8; 32];
        let nonce = [6u8; 32];
        let sealer = FrameSealer::new(&secret, &enc, &nonce).unwrap();
        let session = ResponseSession::new(secret, enc);
        (sealer, FrameDecoder::new(session.opener(&nonce).unwrap()))
    }

    #[test]
    fn decodes_frames_split_across_arbitrary_chunk_boundaries() {
        let (mut s, mut d) = pair();
        let mut wire = s.seal_frame(b"data: one\n\n").unwrap();
        wire.extend(s.seal_frame(b"data: two\n\n").unwrap());

        // Feed one byte at a time — the worst case for framing bugs.
        let mut out = Vec::new();
        for b in &wire {
            out.extend(d.push(&[*b]).unwrap());
        }
        assert_eq!(out, b"data: one\n\ndata: two\n\n");
        d.finish().unwrap();
    }

    #[test]
    fn skips_zero_length_frames() {
        let (mut s, mut d) = pair();
        let mut wire = vec![0, 0, 0, 0]; // empty write from the application
        wire.extend(s.seal_frame(b"payload").unwrap());
        assert_eq!(d.push(&wire).unwrap(), b"payload");
    }

    #[test]
    fn rejects_eof_with_a_partial_length_prefix() {
        let (_, mut d) = pair();
        d.push(&[0, 0]).unwrap();
        assert!(d.finish().is_err());
    }

    #[test]
    fn rejects_eof_with_an_incomplete_frame() {
        let (mut s, mut d) = pair();
        let wire = s.seal_frame(b"truncated").unwrap();
        d.push(&wire[..wire.len() - 3]).unwrap();
        assert!(d.finish().is_err());
    }

    #[test]
    fn emits_nothing_for_an_unauthenticated_frame() {
        let (mut s, mut d) = pair();
        let mut wire = s.seal_frame(b"tampered").unwrap();
        wire[8] ^= 0xFF;
        assert!(
            d.push(&wire).is_err(),
            "must not emit unauthenticated bytes"
        );
    }

    #[test]
    fn rejects_a_hostile_length_prefix_without_buffering_it() {
        let (_, mut d) = pair();
        // Declares a ~4 GiB frame. Must error immediately from the length
        // prefix alone, never sit around waiting to buffer gigabytes.
        let hostile = 0xFFFF_FFFFu32.to_be_bytes();
        let err = d.push(&hostile).unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum"),
            "expected a maximum-length error, got: {err}"
        );
    }

    #[test]
    fn rejects_a_length_one_over_the_maximum() {
        let (_, mut d) = pair();
        let over = (MAX_FRAME_LEN as u32 + 1).to_be_bytes();
        let err = d.push(&over).unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum"),
            "expected a maximum-length error, got: {err}"
        );
    }

    #[test]
    fn accepts_a_length_exactly_at_the_maximum_and_waits_for_the_body() {
        let (_, mut d) = pair();
        let at_max = (MAX_FRAME_LEN as u32).to_be_bytes();
        // Only the length prefix has arrived; the (huge) body has not, so
        // this must return `Ok` with no output rather than erroring — the
        // cap is on the declared length, not on merely accepting it.
        assert_eq!(d.push(&at_max).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn rejects_a_frame_shorter_than_the_aead_tag_without_panicking() {
        let (_, mut d) = pair();
        // Declares a 1-byte frame — far too short to contain a 16-byte AEAD
        // tag. Must return `Err`, never panic, even on an older `aead` that
        // does not itself guard this case.
        assert!(d.push(&[0, 0, 0, 1, 0xAA]).is_err());
    }

    #[test]
    fn does_not_emit_an_earlier_authenticated_frame_when_a_later_one_fails_in_the_same_push() {
        let (mut s, mut d) = pair();
        let mut wire = s.seal_frame(b"data: one\n\n").unwrap();
        let mut second = s.seal_frame(b"data: two\n\n").unwrap();
        second[8] ^= 0xFF; // tamper with the second frame's ciphertext
        wire.extend(second);

        // Frame A authenticates, frame B does not, both in one `push` call:
        // the caller must see `Err`, never A's plaintext smuggled out ahead
        // of the failure.
        assert!(d.push(&wire).is_err());
    }

    #[test]
    fn poisons_the_decoder_after_a_hostile_length_prefix_follows_a_good_frame() {
        let (mut s, mut d) = pair();
        let mut wire = s.seal_frame(b"data: one\n\n").unwrap();
        wire.extend(0xFFFF_FFFFu32.to_be_bytes()); // hostile length prefix

        // First push: frame A decodes (advancing the opener's sequence to
        // 1), then the hostile length prefix errors out before the drain
        // that would normally persist `pos` into `buf`.
        assert!(d.push(&wire).is_err());

        // A second push carrying a perfectly valid frame must still fail —
        // proving the decoder is structurally poisoned, not merely that the
        // stray frame bytes happen to fail authentication at the wrong
        // sequence number.
        let valid = s.seal_frame(b"data: two\n\n").unwrap();
        let err = d.push(&valid).unwrap_err().to_string();
        assert!(
            err.contains("poisoned"),
            "expected a poisoned-decoder error, got: {err}"
        );

        assert!(d.finish().is_err());
    }
}
