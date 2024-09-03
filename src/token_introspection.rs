use crate::SingleOrMultiple;
use biscuit::CompactJson;
use serde::{Deserialize, Serialize};
use url::Url;

/// This struct contains all fields defined in [the spec](https://datatracker.ietf.org/doc/html/rfc7662#section-2.2).
#[derive(Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
pub struct TokenIntrospection<I> {
    #[serde(default)]
    /// Boolean indicator of whether or not the presented token is currently active. The specifics
    /// of a token's "active" state will vary depending on the implementation of the authorization
    /// server and the information it keeps about its tokens, but a "true" value return for the
    /// "active" property will generally indicate that a given token has been issued by this
    /// authorization server, has not been revoked by the resource owner, and is within its given
    /// time window of validity (e.g., after its issuance time and before its expiration time).
    /// See [Section 4](https://datatracker.ietf.org/doc/html/rfc7662#section-4) for information on
    /// implementation of such checks.
    pub active: bool,

    #[serde(default)]
    /// A JSON string containing a space-separated list of scopes associated with this token,
    /// in the format described in [Section 3.3](https://datatracker.ietf.org/doc/html/rfc7662#section-3.3)
    /// of OAuth 2.0 [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749).
    pub scope: Option<String>,

    #[serde(default)]
    /// Client identifier for the OAuth 2.0 client that requested this token.
    pub client_id: Option<String>,

    #[serde(default)]
    /// Human-readable identifier for the resource owner who authorized this token.
    pub username: Option<String>,

    #[serde(default)]
    /// Type of the token as defined in [Section 5.1](https://datatracker.ietf.org/doc/html/rfc7662#section-5.1)
    /// of OAuth 2.0 [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749).
    pub token_type: Option<String>,

    // Not perfectly accurate for what time values we can get back...
    // By spec, this is an arbitrarilly large number. In practice, an
    // i64 unix time is up to 293 billion years from 1970.
    //
    // Make sure this cannot silently underflow, see:
    // https://github.com/serde-rs/json/blob/8e01f44f479b3ea96b299efc0da9131e7aff35dc/src/de.rs#L341
    #[serde(default)]
    /// Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating
    /// when this token will expire, as defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
    pub exp: Option<i64>,
    #[serde(default)]
    /// Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating
    /// when this token was originally issued, as defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
    pub iat: Option<i64>,
    #[serde(default)]
    /// Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating
    /// when this token is not to be used before, as defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
    pub nbf: Option<i64>,

    // Max 255 ASCII chars
    // Can't deserialize a [u8; 255]
    #[serde(default)]
    /// Subject of the token, as defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
    /// Usually a machine-readable identifier of the resource owner who authorized this token.
    pub sub: Option<String>,

    // Either an array of audiences, or just the client_id
    #[serde(default)]
    /// Service-specific string identifier or list of string identifiers representing the intended
    /// audience for this token, as defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
    pub aud: Option<SingleOrMultiple<String>>,

    #[serde(default)]
    /// String representing the issuer of this token, as defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
    pub iss: Option<Url>,

    #[serde(default)]
    /// String identifier for the token, as defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
    pub jti: Option<String>,

    #[serde(flatten)]
    /// Any custom fields which are not defined in the RFC.
    pub custom: Option<I>,
}

impl<I> biscuit::CompactJson for TokenIntrospection<I> where I: CompactJson {}
