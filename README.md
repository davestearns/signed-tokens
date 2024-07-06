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
use session_tokens::SigningKey;

let signing_keys = vec![
    SigningKey::new(env::var("SESSION_SIGNING_KEY_1").unwrap()),
    SigningKey::new(env::var("SESSION_SIGNING_KEY_2").unwrap()),
    SigningKey::new(env::var("SESSION_SIGNING_KEY_3").unwrap()),
]
```

You can have up to 255 signing keys. Each key has a status, which defaults to `SigningKeyStatus::SignAndVerify`. This can be changed to `VerifyOnly` when you want to stop signing new tokens with the key, but allow existing tokens to be verified with it. You can also change it to `DoNotUse` if you don't want the key used at all anymore (i.e., it's just a placeholder to keep the indexes in the slice the same). 

When you sign a session ID, this crate will randomly choose one of the sign-and-verify keys, and add the slice index to the generated token so it knows which one it used. When you verify a token, pass the same slice of keys so that this crate uses the correct key to verify the signature.

To sign your session ID, pass it and your slice of signing keys to the `sign()` function:

```rust
let token = session_tokens::sign(&session_id, &signing_keys);
```

The value of `token` is a base64-encoded, digitally-signed `String`. The binary version contains the index of the signing key used, your session ID, and an HMAC signature of that session ID using the chosen signing key.

You can then add this `token` value as a secure HttpOnly cookie in your response. When this cookie comes back in subsequent requests, verify it using the `verify()` function.

```rust
// Use the same set of signing keys as you did when signing
match session_tokens::verify(&token, &signing_keys) {
    Err(err) => // ... handle error,
    Ok(session_id) => // ... get account info from your cache
}
```

The `verify()` function will return an error `Result` if any of the following occur:
- The token has been tampered with--i.e., the session ID or signature has been changed since signing
- The token contains a signing key index that is no longer in the provided array of signing keys
- The token contains a signing key index that is now marked as `DoNotUse`
- The token is not a valid base64 string
- The token is too short to be a valid token

## Rotating Keys Over Time

It's a good idea to rotate your signing keys over time. Do so following this procedure:

1. Change the `status` of the key you want to replace to `VerifyOnly`. This will allow existing tokens signed with that key to still verify correctly, but it will no longer be used to sign new tokens.
1. After your normal session timeout period, replace that key with a new one, and set the status back to `SignAndVerify`.

If you don't have a session timeout, you can add new keys to the end of the slice, and mark the older keys as `VerifyOnly`.