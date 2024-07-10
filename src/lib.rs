use std::fmt::Display;

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
    #[error("signing keys may only have 255 entries")]
    TooManyKeys,
    #[error("empty payload")]
    EmptyPayload,
    #[error("no active keys found in the signing keys slice")]
    NoActiveSigningKeys,
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
}

/// Indicates the status of a [SigningKey].
#[derive(Debug, Clone, PartialEq)]
pub enum SigningKeyStatus {
    /// The key may be used to both sign new tokens, and verify existing tokens.
    SignAndVerify,
    /// The key may be used only to verify existing tokens. New tokens will never
    /// be signed using a key with this status. This allows you to deprecate a key
    /// you intend to replace.
    VerifyOnly,
}

/// Represents a key that can be used when building an HMAC digital signature.
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

    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Represents a signed token. Use the [to_string](ToString::to_string)
/// method to encode the token as a URL-safe base64 string.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedToken {
    buf: Vec<u8>,
    #[cfg(test)]
    key_index: usize,
}

impl SignedToken {
    /// Encodes the signed token as a URL-safe base64 String
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.buf)
    }
}

impl Display for SignedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

/// Represents a verified token.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedToken {
    payload: Vec<u8>,
    key_status: SigningKeyStatus,
}

impl VerifiedToken {
    /// Returns the payload from the token. This is guaranteed
    /// to be the same as the payload that was used when signing
    /// the token. If the payload was tampered with, the token
    /// verification will return a [VerifyError] instead.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the [SigningKeyStatus] of the key used to verify
    /// the token. This is useful when rotating signing keys.
    /// If this matches [SigningKeyStatus::VerifyOnly], you should
    /// sign a new token with the same payload to get a refreshed
    /// token that is signed using one of the remaining active keys.
    /// You can then replace the verify-only key with a new one after
    /// the outstanding tokens have been refreshed.
    pub fn key_status(&self) -> &SigningKeyStatus {
        &self.key_status
    }
}

/// Signs the given payload using a randomly selected active key from the signing_keys.
pub fn sign(
    payload: impl AsRef<[u8]>,
    signing_keys: &[SigningKey],
) -> Result<SignedToken, SignError> {
    if signing_keys.len() > u8::MAX as usize {
        return Err(SignError::TooManyKeys);
    }

    let active_key_indexes: Vec<usize> = signing_keys
        .iter()
        .enumerate()
        .filter(|(_idx, sk)| sk.status == SigningKeyStatus::SignAndVerify)
        .map(|(idx, _sk)| idx)
        .collect();

    if active_key_indexes.is_empty() {
        return Err(SignError::NoActiveSigningKeys);
    }
    let key_index = active_key_indexes[fastrand::usize(0..active_key_indexes.len())];
    let key_bytes = &signing_keys[key_index].key;
    let payload_bytes = payload.as_ref();
    if payload_bytes.is_empty() {
        return Err(SignError::EmptyPayload);
    }
    let mut mac =
        HmacSha256::new_from_slice(key_bytes).expect("Hmac should support any key length");
    mac.update(payload_bytes);
    let signature = mac.finalize().into_bytes();

    let mut token_bytes: Vec<u8> =
        Vec::with_capacity(1 + HmacSha256::output_size() + payload_bytes.len());
    // this cast is protected by the assert!() above
    token_bytes.push(key_index as u8);
    token_bytes.extend(&signature);
    token_bytes.extend(payload_bytes);

    Ok(SignedToken {
        buf: token_bytes,
        #[cfg(test)]
        key_index,
    })
}

/// Verifies a previously signed token. The key used to sign the token must still
/// be in the signing_keys array at the same index. If the token has been tampered with,
/// the Result will contain a [VerifyError::Signature] error.
pub fn verify(token: &str, signing_keys: &[SigningKey]) -> Result<VerifiedToken, VerifyError> {
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
    let mut mac =
        HmacSha256::new_from_slice(&signing_key.key).expect("any key length should be supported");
    mac.update(payload);
    mac.verify_slice(signature)?;

    Ok(VerifiedToken {
        payload: payload.to_vec(),
        key_status: signing_key.status.clone(),
    })
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
        let token = sign(PAYLOAD, &keys).unwrap().to_base64();
        assert!(token.len() > 0);

        let verified = verify(&token, &keys).unwrap();
        assert_eq!(verified.payload(), PAYLOAD);
    }

    #[test]
    fn key_change_fails_verification() {
        let mut keys = vec![SigningKey::new("test key")];
        let token = sign(PAYLOAD, &keys).unwrap().to_string();
        keys[0] = SigningKey::new("some other key value");

        assert_eq!(
            verify(&token, &keys).unwrap_err(),
            VerifyError::Signature(MacError)
        );
    }

    #[test]
    fn tampering_with_payload_fails_verification() {
        let keys = keys();
        let token = sign(PAYLOAD, &keys).unwrap().to_string();
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
        let token = sign(PAYLOAD, &keys()).unwrap().to_string();
        assert_eq!(verify(&token, &[]).unwrap_err(), VerifyError::NoMatchingKey);
    }

    #[test]
    fn no_keys_fails_signing() {
        assert_eq!(
            sign(PAYLOAD, &[]).unwrap_err(),
            SignError::NoActiveSigningKeys
        );
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
            SigningKey::new_with_status("deprecated key 1", SigningKeyStatus::VerifyOnly),
            SigningKey::new_with_status("deprecated key 2", SigningKeyStatus::VerifyOnly),
            SigningKey::new("active key"),
            SigningKey::new_with_status("deprecated key 3", SigningKeyStatus::VerifyOnly),
            SigningKey::new_with_status("deprecated key 4", SigningKeyStatus::VerifyOnly),
        ];
        let token = sign(PAYLOAD, &keys).unwrap();
        assert_eq!(token.key_index, 2);

        let verified = verify(&token.to_string(), &keys).unwrap();
        assert_eq!(verified.payload(), PAYLOAD);
        assert_eq!(verified.key_status, SigningKeyStatus::SignAndVerify);
    }

    #[test]
    fn verify_works_with_deprecated_key() {
        let mut keys = vec![SigningKey::new("test key")];
        let token = sign(PAYLOAD, &keys).unwrap().to_string();

        keys[0].status = SigningKeyStatus::VerifyOnly;
        let verified_token = verify(&token, &keys).unwrap();

        assert_eq!(verified_token.payload(), PAYLOAD);
        assert_eq!(verified_token.key_status(), &SigningKeyStatus::VerifyOnly);

        keys[0] = SigningKey::new("rotated key");

        let refreshed_token = sign(verified_token.payload(), &keys).unwrap().to_string();
        let reverified_token = verify(&refreshed_token, &keys).unwrap();
        assert_eq!(reverified_token.payload(), PAYLOAD);
        assert_eq!(reverified_token.key_status(), &SigningKeyStatus::SignAndVerify);
    }
}
