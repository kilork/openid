use crate::{
    client::{validate_token_aud, validate_token_exp, validate_token_nonce, Client},
    error::Error,
    Claims, Configurable, IdToken, Provider, Token,
};
use biscuit::CompactJson;
use chrono::Duration;

/// Given an auth_code and auth options, request the token, decode, and validate it.
/// This validation is specific to Microsoft OIDC provider, it skips issuer validation.
pub async fn authenticate<C: CompactJson + Claims, P: Provider + Configurable>(
    client: &Client<P, C>,
    auth_code: &str,
    nonce: Option<&str>,
    max_age: Option<&Duration>,
) -> Result<Token<C>, Error> {
    let bearer = client.request_token(auth_code).await.map_err(Error::from)?;
    let mut token: Token<C> = bearer.into();

    if let Some(mut id_token) = token.id_token.as_mut() {
        client.decode_token(&mut id_token)?;
        validate_token(client, &id_token, nonce, max_age)?;
    }

    Ok(token)
}

/// Validate a decoded token for Microsoft OpenID. If you don't get an error, its valid! Nonce and max_age come from
/// your auth_uri options. Errors are:
///
/// - Jose Error if the Token isn't decoded
/// - Validation::Mismatch::Nonce if a given nonce and the token nonce mismatch
/// - Validation::Missing::Nonce if either the token or args has a nonce and the other does not
/// - Validation::Missing::Audience if the token aud doesn't contain the client id
/// - Validation::Missing::AuthorizedParty if there are multiple audiences and azp is missing
/// - Validation::Mismatch::AuthorizedParty if the azp is not the client_id
/// - Validation::Expired::Expires if the current time is past the expiration time
/// - Validation::Expired::MaxAge is the token is older than the provided max_age
/// - Validation::Missing::Authtime if a max_age was given and the token has no auth time
pub fn validate_token<C: CompactJson + Claims, P: Provider + Configurable>(
    client: &Client<P, C>,
    token: &IdToken<C>,
    nonce: Option<&str>,
    max_age: Option<&Duration>,
) -> Result<(), Error> {
    let claims = token.payload()?;

    validate_token_nonce(claims, nonce)?;

    validate_token_aud(claims, &client.client_id)?;

    validate_token_exp(claims, max_age)?;

    Ok(())
}
