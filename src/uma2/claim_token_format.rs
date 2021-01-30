use core::fmt;

/// UMA2 claim token format
/// Either is an access token (urn:ietf:params:oauth:token-type:jwt) or an OIDC ID token
pub enum Uma2ClaimTokenFormat {
    OAuthJwt,    // urn:ietf:params:oauth:token-type:jwt
    OidcIdToken, // https://openid.net/specs/openid-connect-core-1_0.html#IDToken
}

impl fmt::Display for Uma2ClaimTokenFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Uma2ClaimTokenFormat::OAuthJwt => "urn:ietf:params:oauth:token-type:jwt",
                Uma2ClaimTokenFormat::OidcIdToken =>
                    "https://openid.net/specs/openid-connect-core-1_0.html#IDToken",
            }
        )
    }
}
