pub use biscuit::jws::Compact as Jws;
use biscuit::CompactJson;

use crate::{Bearer, Claims, IdToken, StandardClaims};

/// An OpenID Connect token. This is the only token allowed by spec.
/// Has an `access_token` for bearer, and the `id_token` for authentication.
/// Wraps an oauth bearer token.
#[allow(missing_debug_implementations)]
pub struct Token<C: CompactJson + Claims = StandardClaims> {
    /// Bearer Token.
    ///
    /// `access_token`
    pub bearer: Bearer,
    /// ID Token
    ///
    /// `id_token`
    pub id_token: Option<IdToken<C>>,
}

impl<C: CompactJson + Claims> From<Bearer> for Token<C> {
    fn from(bearer: Bearer) -> Self {
        let id_token = bearer
            .id_token
            .as_ref()
            .map(|token| Jws::new_encoded(token));
        Self { bearer, id_token }
    }
}
