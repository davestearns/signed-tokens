use base64::{engine::general_purpose::URL_SAFE_NO_PAD, DecodeError, Engine as _};
use hmac::{
    digest::{MacError, OutputSizeUser},
    Hmac, Mac,
};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Clone)]
pub enum TokenVerificationError {
    #[error("error decoding token: {0}")]
    Decoding(#[from] DecodeError),
    #[error("error verifying signature: {0}")]
    Signature(#[from] MacError),
    #[error("the provided token is too short")]
    TooShort,
}

pub fn sign(payload: impl AsRef<[u8]>, signing_keys: &[impl AsRef<[u8]>]) -> String {
    assert!(
        signing_keys.len() <= 255,
        "Signing keys vector must be 255 entries or less"
    );
    let key_index = fastrand::usize(0..signing_keys.len());
    let mut mac = HmacSha256::new_from_slice(signing_keys[key_index].as_ref())
        .expect("Hmac should support any key length");

    let payload_bytes = payload.as_ref();
    assert!(payload_bytes.len() > 0);

    mac.update(payload_bytes);
    let signature = mac.finalize().into_bytes();

    let mut token_bytes: Vec<u8> = Vec::with_capacity(1 + signature.len() + payload_bytes.len());
    // this cast is protected by the assert!() above
    token_bytes.push(key_index as u8);
    token_bytes.extend(&signature);
    token_bytes.extend(payload_bytes);

    URL_SAFE_NO_PAD.encode(token_bytes)
}

pub fn verify(
    token: &str,
    signing_keys: &[impl AsRef<[u8]>],
) -> Result<Vec<u8>, TokenVerificationError> {
    let decoded = URL_SAFE_NO_PAD.decode(token)?;
    let sig_byte_len = <HmacSha256 as OutputSizeUser>::output_size();

    // Token must be at least the signature length plus two bytes
    // (key index and a payload of at least one byte)
    if decoded.len() < sig_byte_len + 2 {
        return Err(TokenVerificationError::TooShort);
    }

    let key_index = decoded[0];
    let signature = &decoded[1..sig_byte_len + 1];
    let payload = &decoded[sig_byte_len + 1..];

    let key = signing_keys[key_index as usize].as_ref();
    let mut mac = HmacSha256::new_from_slice(key).expect("any key length should be supported");
    mac.update(payload);
    mac.verify_slice(signature)?;

    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &[u8] = b"1234567890";
    const KEYS: [&'static [u8]; 3] = [b"signing key one", b"signing key two", b"signing key three"];

    #[test]
    fn round_trip() {
        let token = sign(PAYLOAD, &KEYS);
        assert!(token.len() > 0);

        let validated_payload = verify(&token, &KEYS).unwrap();
        assert_eq!(validated_payload, PAYLOAD);
    }

    #[test]
    fn keys_as_vector_of_strings() {
        let keys = vec![
            "one signing key".to_string(),
            "another signing key".to_string(),
        ];
        let token = sign(PAYLOAD, &keys);
        let validated_payload = verify(&token, &keys).unwrap();
        assert_eq!(validated_payload, PAYLOAD);
    }

    #[test]
    fn key_change_fails_verification() {
        let mut keys = vec!["my secret signing key".to_string()];
        let token = sign(PAYLOAD, &keys);
        keys[0] = "some other signing key".to_string();

        assert_eq!(
            verify(&token, &keys).unwrap_err(),
            TokenVerificationError::Signature(MacError)
        );
    }

    #[test]
    fn tampering_with_payload_fails_verification() {
        let token = sign(PAYLOAD, &KEYS);
        let mut decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
        let len_decoded = decoded.len();
        decoded[len_decoded - 1] += 1;

        let tampered = URL_SAFE_NO_PAD.encode(&decoded);
        assert_eq!(
            verify(&tampered, &KEYS).unwrap_err(),
            TokenVerificationError::Signature(MacError)
        );
    }

    #[test]
    fn invalid_encoding_fails_verification() {
        assert!(matches!(
            verify("*&<>", &KEYS).unwrap_err(),
            TokenVerificationError::Decoding(_)
        ));
    }

    #[test]
    fn too_short_fails_verification() {
        assert_eq!(
            verify("abcd", &KEYS).unwrap_err(),
            TokenVerificationError::TooShort
        );
    }
}
