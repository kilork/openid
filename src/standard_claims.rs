use crate::{Userinfo, Claims};
use biscuit::{CompactJson, SingleOrMultiple};
use serde::{Deserialize, Serialize};
use url::Url;


/// ID Token contents. [See spec.](https://openid.net/specs/openid-connect-basic-1_0.html#IDToken)
#[derive(Deserialize, Serialize, Debug)]
pub struct StandardClaims {
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
    // base64 encoded, need to decode it!
    #[serde(default)]
    c_hash: Option<String>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Option<Vec<String>>,
    // If exists, must be client_id
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(flatten)]
    pub userinfo: Userinfo,
}

impl Claims for StandardClaims {
    fn userinfo(&self) -> &Userinfo {
        &self.userinfo
    }
    fn c_hash(&self) -> Option<&String> {
        self.c_hash.as_ref()
    }
    fn at_hash(&self) -> Option<&String> {
        self.at_hash.as_ref()
    }
    fn iss(&self) -> &Url {
        &self.iss
    }
    fn sub(&self) -> &str {
        &self.sub
    }
    fn aud(&self) -> &SingleOrMultiple<String> {
        &self.aud
    }
    fn exp(&self) -> i64 {
        self.exp
    }
    fn iat(&self) -> i64 {
        self.iat
    }
    fn auth_time(&self) -> Option<i64> {
        self.auth_time
    }
    fn nonce(&self) -> Option<&String> {
        self.nonce.as_ref()
    }
    fn acr(&self) -> Option<&String> {
        self.acr.as_ref()
    }
    fn amr(&self) -> Option<&Vec<String>> {
        self.amr.as_ref()
    }
    fn azp(&self) -> Option<&String> {
        self.azp.as_ref()
    }
}

// THIS IS CRAZY VOODOO WITCHCRAFT MAGIC
impl CompactJson for StandardClaims {}
