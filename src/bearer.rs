use chrono::{DateTime, Duration, SubsecRound, Utc};
use serde::{Deserialize, Serialize};

/// The bearer token type.
///
/// See [RFC 6750](http://tools.ietf.org/html/rfc6750).
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(from = "BearerData", into = "BearerData")]
pub struct Bearer {
    pub access_token: String,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub id_token: Option<String>,
    pub received_at: DateTime<Utc>,
}

impl From<BearerData> for Bearer {
    fn from(data: BearerData) -> Self {
        Bearer {
            access_token: data.access_token,
            scope: data.scope,
            refresh_token: data.refresh_token,
            expires: data
                .expires_in
                .map(|expiry_duration| data.received_at + Duration::seconds(expiry_duration)),
            id_token: data.id_token,
            received_at: data.received_at,
        }
    }
}

impl Into<BearerData> for Bearer {
    fn into(self) -> BearerData {
        BearerData {
            access_token: self.access_token,
            scope: self.scope,
            refresh_token: self.refresh_token,
            expires_in: self
                .expires
                .map(|expiration| (expiration - self.received_at).num_seconds()),
            received_at: self.received_at,
            id_token: self.id_token,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct BearerData {
    pub access_token: String,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    #[serde(default = "now")]
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub received_at: DateTime<Utc>,
    pub id_token: Option<String>,
}

fn now() -> DateTime<Utc> {
    // round timestamp to milliseconds,
    // since this is our precision during serialization of DateTime
    Utc::now().round_subsecs(3)
}

impl Bearer {
    pub fn expired(&self) -> bool {
        if let Some(expires) = self.expires {
            expires < Utc::now()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let expires = bearer.expires.unwrap();
        assert!(expires > (Utc::now() + Duration::seconds(3599)));
        assert!(expires <= (Utc::now() + Duration::seconds(3600)));
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
        assert_eq!(None, bearer.expires);
    }

    #[test]
    fn round_trip() {
        let json = r#"
            {
                "token_type":"Bearer",
                "access_token":"aaaaaaaa",
                "expires_in":3600,
                "refresh_token":"bbbbbbbb"
            }
        "#;
        let bearer: Bearer = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&bearer).unwrap();
        let de_serialized = serde_json::from_str(&serialized).unwrap();

        assert_eq!(bearer, de_serialized);
    }
}
