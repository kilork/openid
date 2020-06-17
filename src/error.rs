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
            // ClientError::Parse(ref err) => write!(f, "{}", err),
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
            // ClientError::Parse(ref err) => Some(err),
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
// impl_from!(ClientError::Parse, ParseError);
impl_from!(ClientError::OAuth2, OAuth2Error);

pub use biscuit::errors::Error as Jose;
pub use reqwest::Error as Http;
// pub use reqwest::UrlError as Url;
pub use serde_json::Error as Json;

use failure::Fail;

#[cfg(feature = "uma2")]
use crate::uma2::Uma2Error;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "{}", _0)]
    Jose(#[fail(cause)] Jose),
    //    #[fail(display = "{}", _0)]
    //    Oauth(#[fail(cause)] Oauth),
    #[fail(display = "{}", _0)]
    Http(#[fail(cause)] Http),
    // #[fail(display = "{}", _0)]
    // Url(#[fail(cause)] Url),
    #[fail(display = "{}", _0)]
    Json(#[fail(cause)] Json),
    #[fail(display = "{}", _0)]
    Decode(#[fail(cause)] Decode),
    #[fail(display = "{}", _0)]
    Validation(#[fail(cause)] Validation),
    #[fail(display = "{}", _0)]
    Userinfo(#[fail(cause)] Userinfo),
    #[fail(display = "Url must use TLS: '{}'", _0)]
    Insecure(::reqwest::Url),
    #[fail(display = "Scope must contain Openid")]
    MissingOpenidScope,
    #[fail(display = "Url: Path segments is cannot-be-a-base")]
    CannotBeABase,
    #[fail(display = "{}", _0)]
    ClientError(#[fail(cause)] ClientError),
}

macro_rules! from {
    ($from:ident) => {
        impl From<$from> for Error {
            fn from(e: $from) -> Self {
                Error::$from(e)
            }
        }
    };
}

from!(Jose);
from!(Json);
// from!(Oauth);
from!(Http);
from!(ClientError);
// from!(Url);
from!(Decode);
from!(Validation);
from!(Userinfo);

#[derive(Debug, Fail)]
pub enum Decode {
    #[fail(display = "Token Missing a Key Id when the key set has multiple keys")]
    MissingKid,
    #[fail(display = "Token wants this key id not in the key set: {}", _0)]
    MissingKey(String),
    #[fail(display = "JWK Set is empty")]
    EmptySet,
}

#[derive(Debug, Fail)]
pub enum Validation {
    #[fail(display = "{}", _0)]
    Mismatch(#[fail(cause)] Mismatch),
    #[fail(display = "{}", _0)]
    Missing(#[fail(cause)] Missing),
    #[fail(display = "{}", _0)]
    Expired(#[fail(cause)] Expiry),
}

#[derive(Debug, Fail)]
pub enum Mismatch {
    #[fail(
        display = "Client ID and Token authorized party mismatch: '{}', '{}'",
        expected, actual
    )]
    AuthorizedParty { expected: String, actual: String },
    #[fail(
        display = "Configured issuer and token issuer mismatch: '{}' '{}'",
        expected, actual
    )]
    Issuer { expected: String, actual: String },
    #[fail(
        display = "Given nonce does not match token nonce: '{}', '{}'",
        expected, actual
    )]
    Nonce { expected: String, actual: String },
}

#[derive(Debug, Fail)]
pub enum Missing {
    #[fail(display = "Token missing Audience")]
    Audience,
    #[fail(display = "Token missing AZP")]
    AuthorizedParty,
    #[fail(display = "Token missing Auth Time")]
    AuthTime,
    #[fail(display = "Token missing Nonce")]
    Nonce,
}

#[derive(Debug, Fail)]
pub enum Expiry {
    #[fail(display = "Token expired at: {}", _0)]
    Expires(::chrono::naive::NaiveDateTime),
    #[fail(display = "Token is too old: {}", _0)]
    MaxAge(::chrono::Duration),
}

#[derive(Debug, Fail)]
pub enum Userinfo {
    #[fail(display = "Config has no userinfo url")]
    NoUrl,
    #[fail(
        display = "Token and Userinfo Subjects mismatch: '{}', '{}'",
        expected, actual
    )]
    MismatchSubject { expected: String, actual: String },
}
