# Signed Tokens

[![CI](https://github.com/davestearns/signed-tokens/actions/workflows/ci.yml/badge.svg)](https://github.com/davestearns/signed-tokens/actions/workflows/ci.yml)

A simple Rust crate for creating and verifying HMAC-signed tokens, with multiple rotating keys.

The canonical use-case for this is authenticated session tokens. After a user successfully signs in, your system should:
1. Generate a random session ID, perhaps using the [uuid crate](https://crates.io/crates/uuid)
1. Put the account information into a cache (e.g., Redis) using the session ID as the key
1. Use this crate to digitally sign the session ID and encode it in base64
1. Include the signed token as a [secure, HTTP-only cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#block_access_to_your_cookies)

During subsequent requests, use this crate to verify the signed token and retrieve the session ID so you can look up the session data in your cache.

## Usage

First use `cargo` to add the crate as a dependency:

```bash
cargo add --git https://github.com/davestearns/signed-tokens
```

After the user successfully signs in, generate a random value for the session ID--a UUID works well for this:

```rust
// Remember to `cargo add uuid --features v4` 
// if you want to use UUIDs for session IDs
use uuid::Uuid;

let session_id = Uuid::new_v4().to_string();
```

To digitally sign the session ID, you'll also need some secret keys. Your server is the only one that needs to know about these keys, but they should remain the same after a server restart so that existing sessions will still be valid. You can read them from environment variables, or a file, or a secrets manager service, or whatever. But they should remain secret to your server and never be added directly to your source code.

```rust
use signed_tokens::SigningKey;

let signing_keys = vec![
    SigningKey::new(env::var("SESSION_SIGNING_KEY_1").unwrap()),
    SigningKey::new(env::var("SESSION_SIGNING_KEY_2").unwrap()),
    SigningKey::new(env::var("SESSION_SIGNING_KEY_3").unwrap()),
];
```

You can have up to 255 signing keys. Each key has a `status`, which defaults to `SigningKeyStatus::SignAndVerify`. This can be changed to `VerifyOnly` when you want to stop signing new tokens with the key, but allow existing tokens to be verified with it.

When you sign a session ID, this crate will randomly choose one of the sign-and-verify keys. The chosen key's slice index will be added to the signed and encoded token so that the library knows which key to use when later verifying the token.

To sign your session ID, pass it and your slice of signing keys to the `sign()` function:

```rust
let token = signed_tokens::sign(&session_id, &signing_keys)?;
let url_safe_base64_token = token.to_string();
```

The `sign()` method returns a `SignedToken` struct, which wraps a binary buffer containing the chosen signing key index, the payload (your session ID in this case) and an HMAC signature. This can be turned into a base64-encoded String using the `to_string()` method.

When you respond to the client, include the base64-encoded string as a [secure HttpOnly cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#block_access_to_your_cookies). When this cookie comes back in subsequent requests, verify it using the `verify()` function.

```rust
// Use the same set of signing keys as you did when signing
let verified_token = signed_tokens::verify(&token_from_request_cookie, &signing_keys)?
let session_id = verified_token.payload();

// look up account info in your cache using `session_id`...
```

The `VerifiedToken` returned from `verify()` contains not only the payload you passed when signing the token, but also the `SigningKeyStatus` of the key used to verify the token. This is useful for rotating keys over time (see next section for more details).

The `verify()` function will return an error `Result` if any of the following occur:
- The token has been tampered with--i.e., the payload or signature has been changed since signing
- The token contains a signing key index that is no longer in the provided array of signing keys
- The token is not a valid base64 string
- The token is too short to be a valid token

## Rotating Keys Over Time

It's a good idea to rotate your signing keys over time, even if they are never compromised. To do so without interruption to your clients, follow this set of steps:

1. Change the `status` of the key you want to replace to `VerifyOnly`. This will deprecate the key so that existing tokens will still verify, but no new tokens will be signed using that key.
1. After a successful verification, if the `VerifiedToken.key_status()` method returns `SigningKeyStatus::VerifyOnly`, call the `sign()` method again passing the payload from the `VerifiedToken` to generate a new `SignedToken` using an active signing key. You can then include this new signed token in your response as the new value for your session cookie. The client will then send this new token back to your server during subsequent requests.
1. After enough time has passed, replace the deprecated `SigningKey` with a new active one. If a client previously got a token signed with the deprecated key and never returned to your site after it was deprecated, that client's token will no longer verify. The client can simply sign in again to get a refreshed session token.
