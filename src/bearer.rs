use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Deserializer, Serialize};

/// The bearer token type.
///
/// See:
/// - [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse)
/// - [RFC 6750](http://tools.ietf.org/html/rfc6750).
/// - [RFC 6749 5.1](https://datatracker.ietf.org/doc/html/rfc6749#section-5.1)
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Bearer {
    /// The access token issued by the authorization server.
    ///
    /// See:
    /// - [RFC 6749 1.4](https://datatracker.ietf.org/doc/html/rfc6749#section-1.4)
    pub access_token: String,
    /// The type of the token issued.
    ///
    /// Value is case insensitive.
    ///
    /// See:
    /// - [RFC 6749 7.1](https://datatracker.ietf.org/doc/html/rfc6749#section-7.1)
    pub token_type: String,
    /// OPTIONAL, if identical to the scope requested by the client; otherwise,
    /// REQUIRED
    pub scope: Option<String>,
    /// OAuth 2.0 state value. REQUIRED if the state parameter is present in the
    /// Authorization Request. Clients MUST verify that the state value is equal
    /// to the value of state parameter in the Authorization Request.
    pub state: Option<String>,
    /// The refresh token, which can be used to obtain new access tokens using
    /// the same authorization grant.
    ///
    /// See:
    /// - [RFC 6749 1.5](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5)
    pub refresh_token: Option<String>,
    /// The lifetime in seconds of the access token.
    ///
    /// For example, the value "3600" denotes that the access token will
    /// expire in one hour from the time the response was generated.
    /// If omitted, the authorization server SHOULD provide the
    /// expiration time via other means or document the default value.
    #[serde(default, deserialize_with = "expires_in")]
    pub expires_in: Option<u64>,
    /// ID Token value associated with the authenticated session.
    ///
    /// See:
    /// - [OpenID Connect Core 1.0: Token Response](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse)
    pub id_token: Option<String>,
    /// Additional properties which are not part of the standard OAuth 2.0
    /// response.
    #[serde(flatten)]
    pub extra: Option<HashMap<String, serde_json::Value>>,
}

fn expires_in<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
    match v {
        serde_json::Value::Number(num) => Ok(num.as_u64()),
        serde_json::Value::String(s) => s.parse::<u64>().map(Some).map_err(serde::de::Error::custom),
        _ => Err(serde::de::Error::custom("expected number expression")),
    }
}

/// Manages bearer tokens along with their expiration times.
#[derive(Debug)]
pub struct TemporalBearerGuard {
    bearer: Bearer,
    expires_at: Option<DateTime<Utc>>,
}

impl TemporalBearerGuard {
    /// Calculates whether the bearer has expired.
    ///
    /// The current time is compared to `self.expires_at` and a boolean
    /// value indicating whether the bearer has expired is returned.
    pub fn expired(&self) -> bool {
        self.expires_at
            .map(|expires_at| Utc::now() >= expires_at)
            .unwrap_or_default()
    }

    /// Calculates whether the bearer will expire at a given point in time.
    ///
    /// Returns `true` if the bearer token's expiration time matches the
    /// provided `expiration_point`.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }
}

impl AsRef<Bearer> for TemporalBearerGuard {
    fn as_ref(&self) -> &Bearer {
        &self.bearer
    }
}

impl From<Bearer> for TemporalBearerGuard {
    fn from(bearer: Bearer) -> Self {
        let expires_at = bearer
            .expires_in
            .map(|expires_in| Utc::now() + Duration::seconds(expires_in as i64));
        Self { bearer, expires_at }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_successful_response() {
        let json = r#"
        {
            "access_token":"2YotnFZFEjr1zCsicMWpAA",
            "token_type":"example",
            "expires_in":3600,
            "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter":"example_value"
        }
        "#;
        let bearer: Bearer = serde_json::from_str(json).unwrap();
        assert_eq!("2YotnFZFEjr1zCsicMWpAA", bearer.access_token);
        assert_eq!("example", bearer.token_type);
        assert_eq!(Some(3600), bearer.expires_in);
        assert_eq!(Some("tGzv3JOkF0XG5Qx2TlKWIA".into()), bearer.refresh_token);
        assert_eq!(
            Some(
                [("example_parameter".into(), "example_value".into())]
                    .into_iter()
                    .collect()
            ),
            bearer.extra
        );
    }

    #[test]
    fn from_response_refresh() {
        let json = r#"
            {
                "token_type":"Bearer",
                "access_token":"aaaaaaaa",
                "expires_in":3600,
                "refresh_token":"bbbbbbbb"
            }
        "#;
        let bearer: Bearer = serde_json::from_str(json).unwrap();
        assert_eq!("aaaaaaaa", bearer.access_token);
        assert_eq!(None, bearer.scope);
        assert_eq!(Some("bbbbbbbb".into()), bearer.refresh_token);
        assert_eq!(Some(3600), bearer.expires_in);
    }


    #[test]
    fn from_response_static() {
        let json = r#"
            {
                "token_type":"Bearer",
                "access_token":"aaaaaaaa"
            }
        "#;
        let bearer: Bearer = serde_json::from_str(json).unwrap();
        assert_eq!("aaaaaaaa", bearer.access_token);
        assert_eq!(None, bearer.scope);
        assert_eq!(None, bearer.refresh_token);
        assert_eq!(None, bearer.expires_in);
    }

    #[test]
    fn from_response_expires_in_text() {
        let json = r#"
            {
                "token_type":"Bearer",
                "access_token":"aaaaaaaa",
                "expires_in":"3600"
            }
        "#;
        let bearer: Bearer = serde_json::from_str(json).unwrap();
        assert_eq!("aaaaaaaa", bearer.access_token);
        assert_eq!(None, bearer.scope);
        assert_eq!(None, bearer.refresh_token);
        assert_eq!(Some(3600), bearer.expires_in);
    }
}
