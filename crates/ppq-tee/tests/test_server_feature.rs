//! Proves the `test-server` feature exposes a usable EHBP server half from
//! outside the crate. Inert without the feature, which is also how we assert
//! that `FrameSealer` is absent from a default build.
#![cfg(feature = "test-server")]

use ppq_tee::ehbp::open::{FrameSealer, ResponseSession};

#[test]
fn an_external_server_can_seal_what_the_client_opens() {
    let secret = [0xABu8; 32];
    let enc = [0xCDu8; 32];
    let response_nonce = [0xEFu8; 32];

    let mut sealer = FrameSealer::new(&secret, &enc, &response_nonce).unwrap();
    let framed = sealer.seal_frame(b"from the enclave").unwrap();

    let n = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
    let mut opener = ResponseSession::new(secret, enc)
        .opener(&response_nonce)
        .unwrap();
    assert_eq!(
        opener.open_frame(&framed[4..4 + n]).unwrap(),
        b"from the enclave"
    );
}
