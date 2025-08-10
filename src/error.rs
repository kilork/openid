/*!
Library errors for OAuth 2.0 and OpenID.
*/
use std::{error, fmt};

use serde::Deserialize;

/// OAuth 2.0 error.
///
/// See [RFC 6749, section 5.2](http://tools.ietf.org/html/rfc6749#section-5.2).
#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct OAuth2Error {
    /// Error code.
    pub error: OAuth2ErrorCode,

    /// Human-readable text providing additional information about the error.
    pub error_description: Option<String>,

    /// A URI identifying a human-readable web page with information about the
    /// error.
    pub error_uri: Option<String>,
}

impl fmt::Display for OAuth2Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self.error)?;
        if let Some(ref description) = self.error_description {
            write!(f, ": {description}")?;
        }
        if let Some(ref uri) = self.error_uri {
            write!(f, " ({uri})")?;
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
#[serde(rename_all = "snake_case")]
pub enum OAuth2ErrorCode {
    /// The request is missing a required parameter, includes an unsupported
    /// parameter value (other than grant type), repeats a parameter,
    /// includes multiple credentials, utilizes more than one mechanism for
    /// authenticating the client, or is otherwise malformed.
    InvalidRequest,

    /// Client authentication failed (e.g., unknown client, no client
    /// authentication included, or unsupported authentication method).
    InvalidClient,

    /// The provided authorization grant (e.g., authorization code, resource
    /// owner credentials) or refresh token is invalid, expired, revoked,
    /// does not match the redirection URI used in the authorization
    /// request, or was issued to another client.
    InvalidGrant,

    /// The authenticated client is not authorized to use this authorization
    /// grant type.
    UnauthorizedClient,

    /// The authorization grant type is not supported by the authorization
    /// server.
    UnsupportedGrantType,

    /// The requested scope is invalid, unknown, malformed, or exceeds the scope
    /// granted by the resource owner.
    InvalidScope,

    /// An unrecognized error code, not defined in RFC 6749.
    Unrecognized(String),
}

impl From<&str> for OAuth2ErrorCode {
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

/// Client side error.
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

    /// OAuth 2.0 error.
    OAuth2(OAuth2Error),

    /// UMA2 error.
    #[cfg(feature = "uma2")]
    Uma2(Uma2Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            ClientError::Io(ref err) => write!(f, "{err}"),
            ClientError::Url(ref err) => write!(f, "{err}"),
            ClientError::Reqwest(ref err) => write!(f, "{err}"),
            ClientError::Json(ref err) => write!(f, "{err}"),
            ClientError::OAuth2(ref err) => write!(f, "{err}"),
            #[cfg(feature = "uma2")]
            ClientError::Uma2(ref err) => write!(f, "{err}"),
        }
    }
}

impl error::Error for ClientError {
    fn cause(&self) -> Option<&dyn error::Error> {
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

/// openid library error.
///
/// Wraps different sources of errors under one error type for library.
#[derive(Debug, Error)]
pub enum Error {
    /// [biscuit] errors.
    #[error(transparent)]
    Jose(#[from] Jose),
    /// [reqwest] errors.
    #[error(transparent)]
    Http(#[from] Http),
    /// [serde_json] errors.
    #[error(transparent)]
    Json(#[from] Json),
    /// Decode token error.
    #[error(transparent)]
    Decode(#[from] Decode),
    /// Validation error.
    #[error(transparent)]
    Validation(#[from] Validation),
    /// Errors related to userinfo endpoint.
    #[error(transparent)]
    Userinfo(#[from] Userinfo),
    /// Errors related to introspection endpoint.
    #[error(transparent)]
    Introspection(#[from] Introspection),
    /// Secure connection is required.
    #[error("Url must use TLS: '{0}'")]
    Insecure(::reqwest::Url),
    /// The scope must contain `openid`.
    #[error("Scope must contain Openid")]
    MissingOpenidScope,
    /// Path segments in url is cannot-be-a-base.
    #[error("Url: Path segments is cannot-be-a-base")]
    CannotBeABase,
    /// Client side error.
    #[error(transparent)]
    ClientError(#[from] ClientError),
}

/// Decode token error.
#[derive(Debug, Error)]
pub enum Decode {
    /// Token missing a key id when the key set has multiple keys.
    #[error("Token missing a key id when the key set has multiple keys")]
    MissingKid,
    /// Token wants this key id not in the key set.
    #[error("Token wants this key id not in the key set: {0}")]
    MissingKey(String),
    /// JWK Set is empty.
    #[error("JWK Set is empty")]
    EmptySet,
    /// No support for EC keys yet.
    #[error("No support for EC keys yet")]
    UnsupportedEllipticCurve,
    /// No support for Octet key pair yet.
    #[error("No support for Octet key pair yet")]
    UnsupportedOctetKeyPair,
}

/// Validation failure related to mismatch of values, missing values or expired
/// values.
#[derive(Debug, Error)]
pub enum Validation {
    /// Mismatch in token attribute.
    #[error(transparent)]
    Mismatch(#[from] Mismatch),
    /// Missing required token attribute.
    #[error(transparent)]
    Missing(#[from] Missing),
    /// Token expired.
    #[error(transparent)]
    Expired(#[from] Expiry),
}

/// Mismatch in token attribute.
#[derive(Debug, Error)]
pub enum Mismatch {
    /// Client ID and Token authorized party mismatch.
    #[error("Client ID and Token authorized party mismatch: '{expected}', '{actual}'")]
    AuthorizedParty {
        /// Expected value.
        expected: String,
        /// Actual value.
        actual: String,
    },
    /// Configured issuer and token issuer mismatch.
    #[error("Configured issuer and token issuer mismatch: '{expected}', '{actual}'")]
    Issuer {
        /// Expected value.
        expected: String,
        /// Actual value.
        actual: String,
    },
    /// Given nonce does not match token nonce.
    #[error("Given nonce does not match token nonce: '{expected}', '{actual}'")]
    Nonce {
        /// Expected value.
        expected: String,
        /// Actual value.
        actual: String,
    },
}

/// Missing required token attribute.
#[derive(Debug, Clone, Copy, Error)]
pub enum Missing {
    /// Token missing Audience.
    #[error("Token missing Audience")]
    Audience,
    /// Token missing AZP.
    #[error("Token missing AZP")]
    AuthorizedParty,
    /// Token missing Auth Time.
    #[error("Token missing Auth Time")]
    AuthTime,
    /// Token missing Nonce.
    #[error("Token missing Nonce")]
    Nonce,
}

/// Token expiration variants.
#[derive(Debug, Clone, Copy, Error)]
pub enum Expiry {
    /// Token expired.
    #[error("Token expired at: {0}")]
    Expires(::chrono::DateTime<::chrono::Utc>),
    /// Token is too old.
    #[error("Token is too old: {0}")]
    MaxAge(::chrono::Duration),
    /// Token exp is not valid UNIX timestamp.
    #[error("Token exp is not valid UNIX timestamp: {0}")]
    NotUnix(i64),
}

/// Errors related to userinfo endpoint.
#[derive(Debug, Error)]
pub enum Userinfo {
    /// Config has no userinfo url.
    #[error("Config has no userinfo url")]
    NoUrl,
    /// The UserInfo Endpoint MUST return a content-type header to indicate
    /// which format is being returned.
    #[error(
        "The UserInfo Endpoint MUST return a content-type header to indicate which format is being returned"
    )]
    MissingContentType,
    /// Not parsable content type header.
    #[error("Not parsable content type header: {content_type}")]
    ParseContentType {
        /// Content type header value.
        content_type: String,
    },
    /// Wrong content type header.
    ///
    /// The following are accepted content types: `application/json`,
    /// `application/jwt`.
    #[error(
        "Wrong content type header: {content_type}. The following are accepted content types: application/json, application/jwt"
    )]
    WrongContentType {
        /// Content type header value.
        content_type: String,
        /// Request body for analyze.
        body: Vec<u8>,
    },
    /// Token and Userinfo Subjects mismatch.
    #[error("Token and Userinfo Subjects mismatch: '{expected}', '{actual}'")]
    MismatchSubject {
        /// Expected token subject value.
        expected: String,
        /// Actual token subject value.
        actual: String,
    },
    /// The sub (subject) Claim MUST always be returned in the UserInfo
    /// Response.
    #[error(transparent)]
    MissingSubject(#[from] StandardClaimsSubjectMissing),
}

/// The sub (subject) Claim MUST always be returned in the UserInfo Response.
#[derive(Debug, Copy, Clone, Error)]
#[error("The sub (subject) Claim MUST always be returned in the UserInfo Response")]
pub struct StandardClaimsSubjectMissing;

/// Introspection error details.
#[derive(Debug, Error)]
pub enum Introspection {
    /// Config has no introspection url.
    #[error("Config has no introspection url")]
    NoUrl,
    /// The Introspection Endpoint MUST return a `content-type` header to
    /// indicate which format is being returned.
    #[error(
        "The Introspection Endpoint MUST return a content-type header to indicate which format is being returned"
    )]
    MissingContentType,
    /// Not parsable content type header.
    #[error("Not parsable content type header: {content_type}")]
    ParseContentType {
        /// Content type header value.
        content_type: String,
    },
    /// Wrong content type header.
    ///
    /// The following are accepted content types: `application/json`.
    #[error(
        "Wrong content type header: {content_type}. The following are accepted content types: application/json"
    )]
    WrongContentType {
        /// Content type header value.
        content_type: String,
        /// Request body for analyze.
        body: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn it_deserializes_error() {
        let error_json = json!({
            "error": "invalid_request",
            "error_description": "Only resources with owner managed accessed can have policies",
        });

        let error: OAuth2Error = serde_json::from_value(error_json).unwrap();

        assert_eq!(
            error,
            OAuth2Error {
                error: OAuth2ErrorCode::InvalidRequest,
                error_description: Some(
                    "Only resources with owner managed accessed can have policies".to_string()
                ),
                error_uri: None,
            }
        );
    }
}
