use base64::{engine::general_purpose::URL_SAFE_NO_PAD, DecodeError, Engine as _};
use hmac::{
    digest::{MacError, OutputSizeUser},
    Hmac, Mac,
};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Potential errors returned from the [sign] function.
#[derive(Debug, Error, PartialEq, Clone)]
pub enum SignError {
    #[error("this supports up to 255 signing keys")]
    TooManyKeys,
    #[error("empty payload")]
    EmptyPayload,
    #[error("signing keys slice is empty")]
    NoSigningKeys,
}

/// Potential errors returned from the [verify] function.
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
    #[error("signing key is marked as do-not-use")]
    DoNotUseKey,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SigningKeyStatus {
    SignAndVerify,
    VerifyOnly,
    DoNotUse,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SigningKey {
    key: Vec<u8>,
    pub status: SigningKeyStatus,
}

impl SigningKey {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        Self::new_with_status(key, SigningKeyStatus::SignAndVerify)
    }

    pub fn new_with_status(key: impl AsRef<[u8]>, status: SigningKeyStatus) -> Self {
        Self {
            key: key.as_ref().to_vec(),
            status,
        }
    }

    pub fn new_do_not_use() -> Self {
        Self::new_with_status(&[], SigningKeyStatus::DoNotUse)
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Signs the given payload using a randomly selected key from the signing_keys.
/// The returned String is base64 encoded using a URL-safe alphabet, so you can
/// include it in your HTTP response as a secure HttpOnly cookie.
pub fn sign(payload: impl AsRef<[u8]>, signing_keys: &[SigningKey]) -> Result<String, SignError> {
    if signing_keys.len() > 255 {
        return Err(SignError::TooManyKeys);
    }

    let active_key_indexes: Vec<usize> = signing_keys
        .iter()
        .filter(|sk| sk.status == SigningKeyStatus::SignAndVerify)
        .enumerate()
        .map(|(idx, _sk)| idx)
        .collect();

    if active_key_indexes.is_empty() {
        return Err(SignError::NoSigningKeys);
    }
    let key_index = fastrand::usize(0..active_key_indexes.len());
    let key_bytes = &signing_keys[key_index].key;
    let payload_bytes = payload.as_ref();
    if payload_bytes.is_empty() {
        return Err(SignError::EmptyPayload);
    }
    let mut mac =
        HmacSha256::new_from_slice(&key_bytes).expect("Hmac should support any key length");
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

/// Verifies a previously signed token. The key used to sign the token must still
/// be in the signing_keys array at the same index. If the token has been tampered with,
/// the Result will contain a [VerifyError::Signature] error.
pub fn verify(token: &str, signing_keys: &[SigningKey]) -> Result<Vec<u8>, VerifyError> {
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
    let signing_key = &signing_keys[key_index as usize];
    if signing_key.status == SigningKeyStatus::DoNotUse {
        return Err(VerifyError::DoNotUseKey);
    }

    let mut mac =
        HmacSha256::new_from_slice(&signing_key.key).expect("any key length should be supported");
    mac.update(payload);
    mac.verify_slice(signature)?;

    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &[u8] = b"1234567890";

    fn keys() -> Vec<SigningKey> {
        vec![
            SigningKey::new(b"test key one"),
            SigningKey::new(b"test key two"),
            SigningKey::new(b"test key three"),
        ]
    }

    #[test]
    fn round_trip() {
        let keys = keys();
        let token = sign(PAYLOAD, &keys).unwrap();
        assert!(token.len() > 0);

        let validated_payload = verify(&token, &keys).unwrap();
        assert_eq!(validated_payload, PAYLOAD);
    }

    #[test]
    fn key_change_fails_verification() {
        let mut keys = vec![SigningKey::new("test key")];
        let token = sign(PAYLOAD, &keys).unwrap();
        keys[0] = SigningKey::new("some other key value");

        assert_eq!(
            verify(&token, &keys).unwrap_err(),
            VerifyError::Signature(MacError)
        );
    }

    #[test]
    fn tampering_with_payload_fails_verification() {
        let keys = keys();
        let token = sign(PAYLOAD, &keys).unwrap();
        let mut decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
        let decoded_len = decoded.len();
        decoded[decoded_len - 1] ^= 1;

        let tampered = URL_SAFE_NO_PAD.encode(&decoded);
        assert_eq!(
            verify(&tampered, &keys).unwrap_err(),
            VerifyError::Signature(MacError)
        );
    }

    #[test]
    fn invalid_encoding_fails_verification() {
        assert!(matches!(
            verify("*&<>", &keys()).unwrap_err(),
            VerifyError::Decoding(_)
        ));
    }

    #[test]
    fn too_short_fails_verification() {
        assert_eq!(verify("abcd", &keys()).unwrap_err(), VerifyError::TooShort);
    }

    #[test]
    fn no_matching_key_fails_verification() {
        let token = sign(PAYLOAD, &keys()).unwrap();
        assert_eq!(verify(&token, &[]).unwrap_err(), VerifyError::NoMatchingKey);
    }

    #[test]
    fn no_keys_fails_signing() {
        assert_eq!(sign(PAYLOAD, &[]).unwrap_err(), SignError::NoSigningKeys);
    }

    #[test]
    fn too_many_keys_fails_signing() {
        let keys = vec![SigningKey::new(b"1234"); 256];
        assert_eq!(sign(PAYLOAD, &keys).unwrap_err(), SignError::TooManyKeys);
    }

    #[test]
    fn empty_payload_fails_signing() {
        assert_eq!(sign(b"", &keys()).unwrap_err(), SignError::EmptyPayload);
    }

    #[test]
    fn sign_only_uses_active_keys() {
        let keys = vec![
            SigningKey::new("active key"),
            SigningKey::new_with_status("deprecated key", SigningKeyStatus::VerifyOnly),
            SigningKey::new_do_not_use(),
        ];
        let token = sign(PAYLOAD, &keys).unwrap();
        let payload = verify(&token, &keys[0..1]).unwrap();
        assert_eq!(&payload, &PAYLOAD);
    }

    #[test]
    fn verify_works_with_deprecated_key() {
        let mut keys = vec![SigningKey::new("test key")];
        let token = sign(PAYLOAD, &keys).unwrap();
        keys[0].status = SigningKeyStatus::VerifyOnly;
        assert!(verify(&token, &keys).is_ok());
    }

    #[test]
    fn verify_fails_with_do_not_use_key() {
        let mut keys = vec![SigningKey::new("test key")];
        let token = sign(PAYLOAD, &keys).unwrap();
        keys[0].status = SigningKeyStatus::DoNotUse;
        assert_eq!(verify(&token, &keys).unwrap_err(), VerifyError::DoNotUseKey);
    }
}
