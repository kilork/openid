/*!
OAuth 2.0 errors.
*/
use serde::Deserialize;
use std::{error, fmt};

/// OAuth 2.0 error.
///
/// See [RFC 6749, section 5.2](http://tools.ietf.org/html/rfc6749#section-5.2).
#[derive(Deserialize, Debug)]
pub struct OAuth2Error {
    /// Error code.
    pub error: OAuth2ErrorCode,

    /// Human-readable text providing additional information about the error.
    pub error_description: Option<String>,

    /// A URI identifying a human-readable web page with information about the error.
    pub error_uri: Option<String>,
}

impl fmt::Display for OAuth2Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self.error)?;
        if let Some(ref description) = self.error_description {
            write!(f, ": {}", description)?;
        }
        if let Some(ref uri) = self.error_uri {
            write!(f, " ({})", uri)?;
        }
        Ok(())
    }
}

impl error::Error for OAuth2Error {
    fn description(&self) -> &str {
        "OAuth 2.0 API error"
    }
}

/// OAuth 2.0 error codes.
///
/// See [RFC 6749, section 5.2](http://tools.ietf.org/html/rfc6749#section-5.2).
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum OAuth2ErrorCode {
    /// The request is missing a required parameter, includes an unsupported parameter value (other
    /// than grant type), repeats a parameter, includes multiple credentials, utilizes more than
    /// one mechanism for authenticating the client, or is otherwise malformed.
    InvalidRequest,

    /// Client authentication failed (e.g., unknown client, no client authentication included, or
    /// unsupported authentication method).
    InvalidClient,

    /// The provided authorization grant (e.g., authorization code, resource owner credentials) or
    /// refresh token is invalid, expired, revoked, does not match the redirection URI used in the
    /// authorization request, or was issued to another client.
    InvalidGrant,

    /// The authenticated client is not authorized to use this authorization grant type.
    UnauthorizedClient,

    /// The authorization grant type is not supported by the authorization server.
    UnsupportedGrantType,

    /// The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the
    /// resource owner.
    InvalidScope,

    /// An unrecognized error code, not defined in RFC 6749.
    Unrecognized(String),
}

impl<'a> From<&'a str> for OAuth2ErrorCode {
    fn from(s: &str) -> OAuth2ErrorCode {
        match s {
            "invalid_request" => OAuth2ErrorCode::InvalidRequest,
            "invalid_client" => OAuth2ErrorCode::InvalidClient,
            "invalid_grant" => OAuth2ErrorCode::InvalidGrant,
            "unauthorized_client" => OAuth2ErrorCode::UnauthorizedClient,
            "unsupported_grant_type" => OAuth2ErrorCode::UnsupportedGrantType,
            "invalid_scope" => OAuth2ErrorCode::InvalidScope,
            s => OAuth2ErrorCode::Unrecognized(s.to_owned()),
        }
    }
}
#[derive(Debug)]
pub enum ClientError {
    /// IO error.
    Io(std::io::Error),

    /// URL error.
    Url(url::ParseError),

    /// Reqwest error.
    Reqwest(reqwest::Error),

    /// JSON error.
    Json(serde_json::Error),

    /// Response parse error.
    //    Parse(ParseError),

    /// OAuth 2.0 error.
    OAuth2(OAuth2Error),

    /// UMA2 error.
    #[cfg(feature = "uma2")]
    Uma2(Uma2Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            ClientError::Io(ref err) => write!(f, "{}", err),
            ClientError::Url(ref err) => write!(f, "{}", err),
            ClientError::Reqwest(ref err) => write!(f, "{}", err),
            ClientError::Json(ref err) => write!(f, "{}", err),
            ClientError::OAuth2(ref err) => write!(f, "{}", err),
            #[cfg(feature = "uma2")]
            ClientError::Uma2(ref err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for ClientError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            ClientError::Io(ref err) => Some(err),
            ClientError::Url(ref err) => Some(err),
            ClientError::Reqwest(ref err) => Some(err),
            ClientError::Json(ref err) => Some(err),
            ClientError::OAuth2(ref err) => Some(err),
            #[cfg(feature = "uma2")]
            ClientError::Uma2(ref err) => Some(err),
        }
    }
}

macro_rules! impl_from {
    ($v:path, $t:ty) => {
        impl From<$t> for ClientError {
            fn from(err: $t) -> Self {
                $v(err)
            }
        }
    };
}

impl_from!(ClientError::Io, std::io::Error);
impl_from!(ClientError::Url, url::ParseError);
impl_from!(ClientError::Reqwest, reqwest::Error);
impl_from!(ClientError::Json, serde_json::Error);
impl_from!(ClientError::OAuth2, OAuth2Error);

pub use biscuit::errors::Error as Jose;
pub use reqwest::Error as Http;
pub use serde_json::Error as Json;

use thiserror::Error;

#[cfg(feature = "uma2")]
use crate::uma2::Uma2Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Jose(#[from] Jose),
    #[error(transparent)]
    Http(#[from] Http),
    #[error(transparent)]
    Json(#[from] Json),
    #[error(transparent)]
    Decode(#[from] Decode),
    #[error(transparent)]
    Validation(#[from] Validation),
    #[error(transparent)]
    Userinfo(#[from] Userinfo),
    #[error("Url must use TLS: '{0}'")]
    Insecure(::reqwest::Url),
    #[error("Scope must contain Openid")]
    MissingOpenidScope,
    #[error("Url: Path segments is cannot-be-a-base")]
    CannotBeABase,
    #[error(transparent)]
    ClientError(#[from] ClientError),
}

#[derive(Debug, Error)]
pub enum Decode {
    #[error("Token Missing a Key Id when the key set has multiple keys")]
    MissingKid,
    #[error("Token wants this key id not in the key set: {0}")]
    MissingKey(String),
    #[error("JWK Set is empty")]
    EmptySet,
}

#[derive(Debug, Error)]
pub enum Validation {
    #[error(transparent)]
    Mismatch(#[from] Mismatch),
    #[error(transparent)]
    Missing(#[from] Missing),
    #[error(transparent)]
    Expired(#[from] Expiry),
}

#[derive(Debug, Error)]
pub enum Mismatch {
    #[error("Client ID and Token authorized party mismatch: '{expected}', '{actual}'")]
    AuthorizedParty { expected: String, actual: String },
    #[error("Configured issuer and token issuer mismatch: '{expected}', '{actual}'")]
    Issuer { expected: String, actual: String },
    #[error("Given nonce does not match token nonce: '{expected}', '{actual}'")]
    Nonce { expected: String, actual: String },
}

#[derive(Debug, Error)]
pub enum Missing {
    #[error("Token missing Audience")]
    Audience,
    #[error("Token missing AZP")]
    AuthorizedParty,
    #[error("Token missing Auth Time")]
    AuthTime,
    #[error("Token missing Nonce")]
    Nonce,
}

#[derive(Debug, Error)]
pub enum Expiry {
    #[error("Token expired at: {0}")]
    Expires(::chrono::naive::NaiveDateTime),
    #[error("Token is too old: {0}")]
    MaxAge(::chrono::Duration),
}

#[derive(Debug, Error)]
pub enum Userinfo {
    #[error("Config has no userinfo url")]
    NoUrl,
    #[error("Token and Userinfo Subjects mismatch: '{expected}', '{actual}'")]
    MismatchSubject { expected: String, actual: String },
}
