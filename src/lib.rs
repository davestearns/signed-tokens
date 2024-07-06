use base64::{engine::general_purpose::URL_SAFE_NO_PAD, DecodeError, Engine as _};
use hmac::{
    digest::{MacError, OutputSizeUser},
    Hmac, Mac,
};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Clone)]
pub enum SignError {
    #[error("this supports up to 255 signing keys")]
    TooManyKeys,
    #[error("empty payload")]
    EmptyPayload,
}

#[derive(Debug, Error, PartialEq, Clone)]
pub enum VerifyError {
    #[error("error decoding token: {0}")]
    Decoding(#[from] DecodeError),
    #[error("error verifying signature: {0}")]
    Signature(#[from] MacError),
    #[error("the provided token is too short")]
    TooShort,
    #[error("the key index saved in the token does not match an entry in the signing keys array")]
    NoMatchingKey,
}

/// Signs the given payload using a randomly selected key from the signing_keys.
pub fn sign(
    payload: impl AsRef<[u8]>,
    signing_keys: &[impl AsRef<[u8]>],
) -> Result<String, SignError> {
    if signing_keys.len() > 255 {
        return Err(SignError::TooManyKeys);
    }
    let key_index = fastrand::usize(0..signing_keys.len());

    let payload_bytes = payload.as_ref();
    if payload_bytes.is_empty() {
        return Err(SignError::EmptyPayload);
    }
    let mut mac = HmacSha256::new_from_slice(signing_keys[key_index].as_ref())
        .expect("Hmac should support any key length");
    mac.update(payload_bytes);
    let signature = mac.finalize().into_bytes();

    let mut token_bytes: Vec<u8> =
        Vec::with_capacity(1 + HmacSha256::output_size() + payload_bytes.len());
    // this cast is protected by the assert!() above
    token_bytes.push(key_index as u8);
    token_bytes.extend(&signature);
    token_bytes.extend(payload_bytes);

    Ok(URL_SAFE_NO_PAD.encode(token_bytes))
}

/// Verifies a previously signed token. The key used to sign the toke must still
/// be in the signing_keys array at the same index.
pub fn verify(token: &str, signing_keys: &[impl AsRef<[u8]>]) -> Result<Vec<u8>, VerifyError> {
    let decoded = URL_SAFE_NO_PAD.decode(token)?;
    let sig_byte_len = HmacSha256::output_size();

    // Token must be at least the signature length plus a byte
    // for the key index, plus at least one byte of payload
    if decoded.len() < sig_byte_len + 2 {
        return Err(VerifyError::TooShort);
    }

    let key_index = decoded[0];
    let signature = &decoded[1..sig_byte_len + 1];
    let payload = &decoded[sig_byte_len + 1..];

    if key_index as usize >= signing_keys.len() {
        return Err(VerifyError::NoMatchingKey);
    }
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
        let token = sign(PAYLOAD, &KEYS).unwrap();
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
        let token = sign(PAYLOAD, &keys).unwrap();
        let validated_payload = verify(&token, &keys).unwrap();
        assert_eq!(validated_payload, PAYLOAD);
    }

    #[test]
    fn key_change_fails_verification() {
        let mut keys = vec!["my secret signing key".to_string()];
        let token = sign(PAYLOAD, &keys).unwrap();
        keys[0] = "some other signing key".to_string();

        assert_eq!(
            verify(&token, &keys).unwrap_err(),
            VerifyError::Signature(MacError)
        );
    }

    #[test]
    fn tampering_with_payload_fails_verification() {
        let token = sign(PAYLOAD, &KEYS).unwrap();
        let mut decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
        let decoded_len = decoded.len();
        decoded[decoded_len - 1] ^= 1;

        let tampered = URL_SAFE_NO_PAD.encode(&decoded);
        assert_eq!(
            verify(&tampered, &KEYS).unwrap_err(),
            VerifyError::Signature(MacError)
        );
    }

    #[test]
    fn invalid_encoding_fails_verification() {
        assert!(matches!(
            verify("*&<>", &KEYS).unwrap_err(),
            VerifyError::Decoding(_)
        ));
    }

    #[test]
    fn too_short_fails_verification() {
        assert_eq!(verify("abcd", &KEYS).unwrap_err(), VerifyError::TooShort);
    }

    #[test]
    fn no_matching_key() {
        let token = sign(PAYLOAD, &KEYS).unwrap();
        assert_eq!(verify(&token, &["";0]).unwrap_err(), VerifyError::NoMatchingKey);
    }
}
