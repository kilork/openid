use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The bearer token type.
///
/// See [RFC 6750](http://tools.ietf.org/html/rfc6750).
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Bearer {
    pub access_token: String,
    pub token_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub id_token: Option<String>,
    #[serde(flatten)]
    pub extra: Option<HashMap<String, serde_json::Value>>,
}

/// Manages bearer tokens along with their expiration times.
pub struct TemporalBearerGuard {
    bearer: Bearer,
    expires_at: Option<DateTime<Utc>>,
}

impl TemporalBearerGuard {
    pub fn expired(&self) -> bool {
        self.expires_at
            .map(|expires_at| Utc::now() >= expires_at)
            .unwrap_or_default()
    }

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
}
