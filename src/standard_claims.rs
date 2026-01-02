use biscuit::{CompactJson, SingleOrMultiple};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Claims, Userinfo};

/// ID Token contents. [See spec.](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
pub struct StandardClaims {
    /// Issuer Identifier for the Issuer of the response.
    ///
    /// The `iss` value is a case-sensitive URL using the `https` scheme that
    /// contains scheme, host, and optionally, port number and path components
    /// and no query or fragment components.
    pub iss: Url,
    // Either an array of audiences, or just the client_id
    /// Audience(s) that this ID Token is intended for.
    ///
    /// It MUST contain the OAuth 2.0 `client_id` of the Relying Party as an
    /// audience value. It MAY also contain identifiers for other audiences. In
    /// the general case, the `aud` value is an array of case-sensitive strings.
    /// In the common special case when there is one audience, the `aud` value
    /// MAY be a single case-sensitive string.
    pub aud: SingleOrMultiple<String>,
    // Not perfectly accurate for what time values we can get back...
    // By spec, this is an arbitrarilly large number. In practice, an
    // i64 unix time is up to 293 billion years from 1970.
    //
    // Make sure this cannot silently underflow, see:
    // https://github.com/serde-rs/json/blob/8e01f44f479b3ea96b299efc0da9131e7aff35dc/src/de.rs#L341
    /// Expiration time on or after which the ID Token MUST NOT be accepted by
    /// the RP when performing authentication with the OP.
    ///
    /// The processing of this parameter requires that the current date/time
    /// MUST be before the expiration date/time listed in the value.
    /// Implementers MAY provide for some small leeway, usually no more than a
    /// few minutes, to account for clock skew. Its value is a JSON [RFC8259]
    /// number representing the number of seconds from `1970-01-01T00:00:00Z` as
    /// measured in UTC until the date/time. See RFC 3339 [RFC3339] for details
    /// regarding date/times in general and UTC in particular. NOTE: The ID
    /// Token expiration time is unrelated the lifetime of the authenticated
    /// session between the RP and the OP.
    pub exp: i64,
    /// Time at which the JWT was issued.
    ///
    /// Its value is a JSON number representing the number of seconds from
    /// `1970-01-01T00:00:00Z` as measured in UTC until the date/time.
    pub iat: i64,
    // required for max_age request
    /// Time when the End-User authentication occurred.
    ///
    /// Its value is a JSON number representing the number of seconds from
    /// `1970-01-01T00:00:00Z` as measured in UTC until the date/time. When a
    /// `max_age` request is made or when `auth_time` is requested as an
    /// Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion
    /// is OPTIONAL. (The `auth_time` Claim semantically corresponds to the
    /// OpenID 2.0 PAPE [OpenID.PAPE] `auth_time` response parameter.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// String value used to associate a Client session with an ID Token, and to
    /// mitigate replay attacks.
    ///
    /// The value is passed through unmodified from the Authentication Request
    /// to the ID Token. If present in the ID Token, Clients MUST verify that
    /// the `nonce` Claim Value is equal to the value of the `nonce` parameter
    /// sent in the Authentication Request. If present in the Authentication
    /// Request, Authorization Servers MUST include a `nonce` Claim in the ID
    /// Token with the Claim Value being the `nonce` value sent in the
    /// Authentication Request. Authorization Servers SHOULD perform no other
    /// processing on `nonce` values used. The `nonce` value is a case-sensitive
    /// string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    // base64 encoded, need to decode it!
    /// Access Token hash value. Its value is the base64url encoding of the
    /// left-most half of the hash of the octets of the ASCII representation of
    /// the access_token value, where the hash algorithm used is the hash
    /// algorithm used in the alg Header Parameter of the ID Token's JOSE
    /// Header. For instance, if the alg is RS256, hash the access_token value
    /// with SHA-256, then take the left-most 128 bits and base64url-encode
    /// them. The at_hash value is a case-sensitive string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    at_hash: Option<String>,
    // base64 encoded, need to decode it!
    /// Code hash value. Its value is the base64url encoding of the left-most
    /// half of the hash of the octets of the ASCII representation of the code
    /// value, where the hash algorithm used is the hash algorithm used in the
    /// alg Header Parameter of the ID Token's JOSE Header. For instance, if the
    /// alg is HS512, hash the code value with SHA-512, then take the left-most
    /// 256 bits and base64url-encode them. The c_hash value is a case-sensitive
    /// string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    c_hash: Option<String>,
    /// Authentication Context Class Reference.
    ///
    /// String specifying an Authentication Context Class Reference value that
    /// identifies the Authentication Context Class that the authentication
    /// performed satisfied. The value "0" indicates the End-User authentication
    /// did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1. For
    /// historic reasons, the value "0" is used to indicate that there is no
    /// confidence that the same person is actually there. Authentications with
    /// level 0 SHOULD NOT be used to authorize access to any resource of any
    /// monetary value. (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE]
    /// `nist_auth_level` 0.) An absolute URI or an RFC 6711 [RFC6711]
    /// registered name SHOULD be used as the `acr` value; registered names MUST
    /// NOT be used with a different meaning than that which is registered.
    /// Parties using this claim will need to agree upon the meanings of the
    /// values used, which may be context specific. The `acr` value is a
    /// case-sensitive string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Authentication Methods References.
    ///
    /// JSON array of strings that are identifiers for authentication methods
    /// used in the authentication. For instance, values might indicate that
    /// both password and OTP authentication methods were used. The `amr` value
    /// is an array of case-sensitive strings. Values used in the `amr` Claim
    /// SHOULD be from those registered in the IANA Authentication Method
    /// Reference Values registry [IANA.AMR] established by [RFC8176]; parties
    /// using this claim will need to agree upon the meanings of any
    /// unregistered values used, which may be context specific.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    // If exists, must be client_id
    /// Authorized party - the party to which the ID Token was issued. If
    /// present, it MUST contain the OAuth 2.0 Client ID of this party. The
    /// `azp` value is a case-sensitive string containing a StringOrURI value.
    /// Note that in practice, the `azp` Claim only occurs when extensions
    /// beyond the scope of this specification are used; therefore,
    /// implementations not using such extensions are encouraged to not use
    /// `azp` and to ignore it when it does occur.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    /// The standard claims.
    ///
    /// See [Standard Claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
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
        &self.userinfo.sub
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

#[cfg(test)]
mod tests {
    use biscuit::SingleOrMultiple;
    use url::Url;

    use crate::{StandardClaims, Userinfo};

    #[test]
    fn serialization_roundtrip() {
        let claims = StandardClaims {
            iss: Url::parse("https://example.com").unwrap(),
            aud: SingleOrMultiple::Single("client123".to_string()),
            exp: 1630456800,
            iat: 1630456600,
            auth_time: Some(1630456500),
            nonce: Some("nonce123".to_string()),
            acr: Some("acr123".to_string()),
            amr: Some(vec!["amr123".to_string()]),
            azp: Some("azp123".to_string()),
            at_hash: None,
            c_hash: None,
            userinfo: Userinfo {
                sub: "user123".to_string().into(),
                name: Some("username".to_string()),
                ..Default::default()
            },
        };

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized_claims: StandardClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(claims, deserialized_claims);
    }
}
