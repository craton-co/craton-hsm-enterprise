// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! OIDC JTI replay prevention — integration coverage.
//!
//! This file exercises the full craft-token / validate / replay path via the
//! public `oidc-test-harness` helpers (`OidcAuthProvider::for_testing` and
//! `OidcAuthProvider::craft_id_token_for_testing`).  A pre-seeded JWKS cache
//! avoids any network I/O.
//!
//! What is covered here (separate from the crate-internal tests in
//! `src/auth/oidc.rs`):
//!   - The `require_jti` configuration field is plumbed through serde,
//!     including its documented default (`false`).
//!   - Full round trip: crafted token accepted on first use, rejected on
//!     replay.
//!   - Replay keying is on `jti`, not on `sub`.
//!   - Expired, wrong-audience, wrong-issuer tokens are still rejected.
//!   - JWKS rotation does not drop replay state.

#![cfg(feature = "oidc-test-harness")]

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;

use craton_hsm::error::HsmError;
use craton_hsm_auth::auth::oidc::{OidcAuthProvider, OidcConfig};
use craton_hsm_auth::auth::provider::{AuthCredentials, AuthProvider};

// ---------------------------------------------------------------------------
// Harness helpers
// ---------------------------------------------------------------------------

/// Base64url (no padding) encoding as required by JWK `n`, `e`.
fn b64url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Build a `JwkSet` containing a single RSA public key with the given `kid`.
fn jwk_set_from_pub(pk: &RsaPublicKey, kid: &str) -> JwkSet {
    let n = b64url(&pk.n().to_bytes_be());
    let e = b64url(&pk.e().to_bytes_be());
    let json = json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": n,
            "e": e,
        }]
    });
    serde_json::from_value(json).expect("valid JwkSet")
}

struct Harness {
    enc: EncodingKey,
    #[allow(dead_code)]
    dec: DecodingKey,
    pk: RsaPublicKey,
}

fn new_harness() -> Harness {
    let priv_key =
        RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("RSA keygen must succeed in tests");
    let pub_key = RsaPublicKey::from(&priv_key);

    // EncodingKey via PKCS#8 DER.
    let pkcs8 = priv_key.to_pkcs8_der().expect("encode pkcs8");
    let enc = EncodingKey::from_rsa_der(pkcs8.as_bytes());

    // DecodingKey via SubjectPublicKeyInfo DER.
    let spki = pub_key.to_public_key_der().expect("encode spki");
    let dec = DecodingKey::from_rsa_der(spki.as_ref());

    Harness {
        enc,
        dec,
        pk: pub_key,
    }
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn default_config() -> OidcConfig {
    OidcConfig {
        issuer_url: "https://issuer.example.com".to_string(),
        audience: "craton-hsm".to_string(),
        role_claim: "role".to_string(),
        tenant_claim: None,
        mfa_claim: None,
        jwks_refresh_secs: 3600,
        request_timeout_secs: 10,
        stale_cache_max_age_secs: 86_400,
        clock_skew_secs: 5,
        rate_limit: None,
        require_jti: true,
    }
}

fn token_creds(s: String) -> AuthCredentials {
    AuthCredentials::Token {
        bearer_token: zeroize::Zeroizing::new(s),
    }
}

// ---------------------------------------------------------------------------
// Pre-existing serde coverage (retained from prior sweep)
// ---------------------------------------------------------------------------

#[test]
fn require_jti_defaults_to_false_in_serde() {
    let json = r#"{
        "issuer_url": "https://issuer.example.com",
        "audience": "craton-hsm",
        "role_claim": "role"
    }"#;
    let config: OidcConfig = serde_json::from_str(json).expect("parse");
    assert!(!config.require_jti, "require_jti default must be false");
}

#[test]
fn require_jti_roundtrips_through_serde() {
    let json = r#"{
        "issuer_url": "https://issuer.example.com",
        "audience": "craton-hsm",
        "role_claim": "role",
        "require_jti": true
    }"#;
    let config: OidcConfig = serde_json::from_str(json).expect("parse");
    assert!(config.require_jti);

    let s = serde_json::to_string(&config).unwrap();
    let reparsed: OidcConfig = serde_json::from_str(&s).unwrap();
    assert!(reparsed.require_jti);
}

#[test]
fn invalid_issuer_url_rejected_at_config_validate() {
    let json = r#"{
        "issuer_url": "http://insecure.example.com",
        "audience": "craton-hsm",
        "role_claim": "role"
    }"#;
    let config: OidcConfig = serde_json::from_str(json).expect("parse");
    assert!(
        config.validate().is_err(),
        "non-https issuer must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Full round-trip coverage through the harness helpers
// ---------------------------------------------------------------------------

#[test]
fn crafted_token_accepted_on_first_use_rejected_on_replay() {
    let h = new_harness();
    let kid = "replay-k1";
    let jwks = jwk_set_from_pub(&h.pk, kid);
    let provider = OidcAuthProvider::for_testing(default_config(), jwks);

    let now = now_ts();
    let claims = json!({
        "sub": "user-replay",
        "iss": "https://issuer.example.com",
        "aud": "craton-hsm",
        "exp": now + 3600,
        "iat": now,
        "role": "user",
        "jti": "jti-aaa",
    });
    let token = OidcAuthProvider::craft_id_token_for_testing(&claims, &h.enc, kid, None)
        .expect("craft token");

    // First use succeeds.
    provider
        .authenticate(&token_creds(token.clone()))
        .expect("first use accepted");

    // Replay rejected.
    let err = provider.authenticate(&token_creds(token)).unwrap_err();
    assert!(
        matches!(err, HsmError::PinIncorrect),
        "expected PinIncorrect on replay, got {err:?}"
    );
}

#[test]
fn crafted_token_with_different_jti_accepted_same_subject() {
    let h = new_harness();
    let kid = "replay-k2";
    let jwks = jwk_set_from_pub(&h.pk, kid);
    let provider = OidcAuthProvider::for_testing(default_config(), jwks);

    let now = now_ts();
    let mk = |jti: &str| {
        let claims = json!({
            "sub": "user-same",
            "iss": "https://issuer.example.com",
            "aud": "craton-hsm",
            "exp": now + 3600,
            "iat": now,
            "role": "user",
            "jti": jti,
        });
        OidcAuthProvider::craft_id_token_for_testing(&claims, &h.enc, kid, None)
            .expect("craft token")
    };

    provider
        .authenticate(&token_creds(mk("jti-1")))
        .expect("first jti accepted");
    provider
        .authenticate(&token_creds(mk("jti-2")))
        .expect("different jti, same sub must also be accepted");
}

#[test]
fn crafted_token_expired_rejected() {
    let h = new_harness();
    let kid = "replay-k3";
    let jwks = jwk_set_from_pub(&h.pk, kid);
    let provider = OidcAuthProvider::for_testing(default_config(), jwks);

    let now = now_ts();
    let claims = json!({
        "sub": "user-exp",
        "iss": "https://issuer.example.com",
        "aud": "craton-hsm",
        "exp": now - 3600, // expired
        "iat": now - 7200,
        "role": "user",
        "jti": "jti-expired",
    });
    let token = OidcAuthProvider::craft_id_token_for_testing(&claims, &h.enc, kid, None)
        .expect("craft token");

    let err = provider.authenticate(&token_creds(token)).unwrap_err();
    assert!(
        matches!(err, HsmError::PinIncorrect),
        "expired token must be rejected; got {err:?}"
    );
}

#[test]
fn crafted_token_wrong_audience_rejected() {
    let h = new_harness();
    let kid = "replay-k4";
    let jwks = jwk_set_from_pub(&h.pk, kid);
    let provider = OidcAuthProvider::for_testing(default_config(), jwks);

    let now = now_ts();
    let claims = json!({
        "sub": "user-aud",
        "iss": "https://issuer.example.com",
        "aud": "not-craton",
        "exp": now + 3600,
        "iat": now,
        "role": "user",
        "jti": "jti-wrong-aud",
    });
    let token = OidcAuthProvider::craft_id_token_for_testing(&claims, &h.enc, kid, None)
        .expect("craft token");

    let err = provider.authenticate(&token_creds(token)).unwrap_err();
    assert!(
        matches!(err, HsmError::PinIncorrect),
        "wrong-aud token must be rejected; got {err:?}"
    );
}

#[test]
fn crafted_token_wrong_issuer_rejected() {
    let h = new_harness();
    let kid = "replay-k5";
    let jwks = jwk_set_from_pub(&h.pk, kid);
    let provider = OidcAuthProvider::for_testing(default_config(), jwks);

    let now = now_ts();
    let claims = json!({
        "sub": "user-iss",
        "iss": "https://evil.example.com",
        "aud": "craton-hsm",
        "exp": now + 3600,
        "iat": now,
        "role": "user",
        "jti": "jti-wrong-iss",
    });
    let token = OidcAuthProvider::craft_id_token_for_testing(&claims, &h.enc, kid, None)
        .expect("craft token");

    let err = provider.authenticate(&token_creds(token)).unwrap_err();
    assert!(
        matches!(err, HsmError::PinIncorrect),
        "wrong-iss token must be rejected; got {err:?}"
    );
}

#[test]
fn jwks_rotation_does_not_lose_replay_state() {
    // First key set — sign + authenticate a token, then rotate JWKS.  The
    // replayed token under the rotated JWKS must still be rejected because
    // the jti cache is not cleared by rotation.
    let h1 = new_harness();
    let kid1 = "rot-k1";
    let jwks1 = jwk_set_from_pub(&h1.pk, kid1);
    let provider = OidcAuthProvider::for_testing(default_config(), jwks1);

    let now = now_ts();
    let claims = json!({
        "sub": "user-rot",
        "iss": "https://issuer.example.com",
        "aud": "craton-hsm",
        "exp": now + 3600,
        "iat": now,
        "role": "user",
        "jti": "jti-rotation",
    });
    let token = OidcAuthProvider::craft_id_token_for_testing(&claims, &h1.enc, kid1, None)
        .expect("craft token");

    provider
        .authenticate(&token_creds(token.clone()))
        .expect("first use accepted");

    // Rotate JWKS: new key material, but JTI cache persists.
    let h2 = new_harness();
    let kid2 = "rot-k2";
    // Merge old + new keys so the original token's `kid` still resolves;
    // otherwise the rejection would be due to unknown-kid rather than replay.
    let combined = {
        let mut old = jwk_set_from_pub(&h1.pk, kid1);
        let mut new_set = jwk_set_from_pub(&h2.pk, kid2);
        old.keys.append(&mut new_set.keys);
        old
    };
    provider.replace_jwks_for_testing(combined);

    // Same jti must still be caught as a replay.
    let err = provider.authenticate(&token_creds(token)).unwrap_err();
    assert!(
        matches!(err, HsmError::PinIncorrect),
        "replay after rotation must be rejected; got {err:?}"
    );

    // A fresh jti signed by the new key must be accepted: rotation worked.
    let fresh = json!({
        "sub": "user-rot",
        "iss": "https://issuer.example.com",
        "aud": "craton-hsm",
        "exp": now + 3600,
        "iat": now,
        "role": "user",
        "jti": "jti-post-rotation",
    });
    let token2 = OidcAuthProvider::craft_id_token_for_testing(&fresh, &h2.enc, kid2, None)
        .expect("craft token2");
    provider
        .authenticate(&token_creds(token2))
        .expect("post-rotation token accepted");
}
