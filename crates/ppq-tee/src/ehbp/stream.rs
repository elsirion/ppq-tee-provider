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
pub struct FrameDecoder {
    opener: FrameOpener,
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new(opener: FrameOpener) -> Self {
        Self {
            opener,
            buf: Vec::new(),
        }
    }

    /// Feed transport bytes; returns whatever plaintext became available.
    ///
    /// Every length read is bounds-checked before it is used to slice: `pos`
    /// only ever advances to an offset that has already been proven to lie
    /// within `self.buf`, so a truncated or hostile length prefix causes this
    /// to wait for more data (or return `Err` if it exceeds
    /// [`MAX_FRAME_LEN`]) rather than slicing out of bounds.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
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
                out.extend(self.opener.open_frame(&self.buf[frame_start..frame_end])?);
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
    pub fn finish(self) -> Result<()> {
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
        assert!(d.push(&wire).is_err(), "must not emit unauthenticated bytes");
    }

    #[test]
    fn rejects_a_hostile_length_prefix_without_buffering_it() {
        let (_, mut d) = pair();
        // Declares a ~4 GiB frame. Must error immediately from the length
        // prefix alone, never sit around waiting to buffer gigabytes.
        let hostile = 0xFFFF_FFFFu32.to_be_bytes();
        assert!(d.push(&hostile).is_err());
    }
}
