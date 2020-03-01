use super::*;
use base64;
pub use biscuit::jws::Compact as Jws;
use biscuit::{CompactJson, Empty, SingleOrMultiple};
use serde::{Deserialize, Serialize};
use url::Url;

pub type IdToken = Jws<Claims, Empty>;

/// ID Token contents. [See spec.](https://openid.net/specs/openid-connect-basic-1_0.html#IDToken)
#[derive(Deserialize, Serialize, Debug)]
pub struct Claims {
    pub iss: Url,
    // Max 255 ASCII chars
    // Can't deserialize a [u8; 255]
    pub sub: String,
    // Either an array of audiences, or just the client_id
    pub aud: SingleOrMultiple<String>,
    // Not perfectly accurate for what time values we can get back...
    // By spec, this is an arbitrarilly large number. In practice, an
    // i64 unix time is up to 293 billion years from 1970.
    //
    // Make sure this cannot silently underflow, see:
    // https://github.com/serde-rs/json/blob/8e01f44f479b3ea96b299efc0da9131e7aff35dc/src/de.rs#L341
    pub exp: i64,
    pub iat: i64,
    // required for max_age request
    #[serde(default)]
    pub auth_time: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
    // base64 encoded, need to decode it!
    #[serde(default)]
    at_hash: Option<String>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Option<Vec<String>>,
    // If exists, must be client_id
    #[serde(default)]
    pub azp: Option<String>,
}

impl Claims {
    /// Decodes at_hash. Returns None if it doesn't exist or something goes wrong.
    ///
    /// See [spec 3.1.3.6](https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken)
    ///
    /// The returned Vec is the first 128 bits of the access token hash using alg's hash alg
    pub fn at_hash(&self) -> Option<Vec<u8>> {
        if let Some(ref hash) = self.at_hash {
            return base64::decode_config(hash.as_str(), base64::URL_SAFE).ok();
        }
        None
    }
}

// THIS IS CRAZY VOODOO WITCHCRAFT MAGIC
impl CompactJson for Claims {}

/// An OpenID Connect token. This is the only token allowed by spec.
/// Has an access_token for bearer, and the id_token for authentication.
/// Wraps an oauth bearer token.
#[derive(Deserialize)]
pub struct Token {
    pub bearer: Bearer,
    pub id_token: Option<IdToken>,
}

impl From<Bearer> for Token {
    fn from(bearer: Bearer) -> Self {
        let id_token = bearer
            .id_token
            .as_ref()
            .map(|token| Jws::new_encoded(token));
        Self { bearer, id_token }
    }
}
