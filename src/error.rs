use serde::Deserialize;
use std::{error::Error, fmt};

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

impl Error for OAuth2Error {
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
