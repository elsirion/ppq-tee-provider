use crate::{Error, Result};

pub const KEM_X25519_HKDF_SHA256: u16 = 0x0020;
pub const KDF_HKDF_SHA256: u16 = 0x0001;
pub const AEAD_AES_256_GCM: u16 = 0x0002;

/// An RFC 9458 §3 `key_config`, as served from `/.well-known/hpke-keys`.
///
/// Layout: `key_id(1) ‖ kem_id(2) ‖ public_key(Npk) ‖ cipher_suites_len(2) ‖
/// (kdf_id(2) ‖ aead_id(2))*`
#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub key_id: u8,
    pub kem_id: u16,
    pub public_key: [u8; 32],
    pub kdf_id: u16,
    pub aead_id: u16,
}

pub fn parse(raw: &[u8]) -> Result<KeyConfig> {
    // 1 + 2 + 32 + 2 + 4
    if raw.len() < 41 {
        return Err(Error::Ehbp(format!(
            "key config is {} bytes, want at least 41",
            raw.len()
        )));
    }
    let key_id = raw[0];
    let kem_id = u16::from_be_bytes([raw[1], raw[2]]);
    if kem_id != KEM_X25519_HKDF_SHA256 {
        return Err(Error::Ehbp(format!("unsupported KEM {kem_id:#06x}")));
    }
    let public_key: [u8; 32] = raw[3..35].try_into().unwrap();

    let suites_len = u16::from_be_bytes([raw[35], raw[36]]) as usize;
    if suites_len < 4 || raw.len() < 37 + suites_len {
        return Err(Error::Ehbp("truncated cipher suite list".into()));
    }
    // Take the first suite; this implementation emits exactly one.
    let kdf_id = u16::from_be_bytes([raw[37], raw[38]]);
    let aead_id = u16::from_be_bytes([raw[39], raw[40]]);
    if kdf_id != KDF_HKDF_SHA256 || aead_id != AEAD_AES_256_GCM {
        return Err(Error::Ehbp(format!(
            "unsupported suite kdf={kdf_id:#06x} aead={aead_id:#06x}"
        )));
    }

    Ok(KeyConfig {
        key_id,
        kem_id,
        public_key,
        kdf_id,
        aead_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: &[u8] = include_bytes!("../../testdata/hpke-keys.bin");

    #[test]
    fn parses_the_live_key_config() {
        let c = parse(KEYS).expect("parses");
        assert_eq!(c.key_id, 0);
        assert_eq!(c.kem_id, 0x0020, "X25519-HKDF-SHA256");
        assert_eq!(c.kdf_id, 0x0001, "HKDF-SHA256");
        assert_eq!(c.aead_id, 0x0002, "AES-256-GCM");
    }

    #[test]
    fn rejects_a_truncated_config() {
        assert!(parse(&KEYS[..10]).is_err());
    }

    #[test]
    fn rejects_an_unsupported_kem() {
        let mut bad = KEYS.to_vec();
        bad[1] = 0x00; // corrupt kem_id
        bad[2] = 0x10;
        assert!(parse(&bad).is_err());
    }
}
