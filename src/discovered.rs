use crate::{error::Error, Config, Provider};
use biscuit::jwk::JWKSet;
use biscuit::Empty;
use reqwest::Client;
use url::Url;

pub struct Discovered(pub Config);

impl Provider for Discovered {
    fn auth_uri(&self) -> &Url {
        &self.0.authorization_endpoint
    }

    fn token_uri(&self) -> &Url {
        &self.0.token_endpoint
    }
}

pub async fn discover(client: &Client, mut issuer: Url) -> Result<Config, Error> {
    issuer
        .path_segments_mut()
        .map_err(|_| Error::CannotBeABase)?
        .extend(&[".well-known", "openid-configuration"]);
    let resp = client.get(issuer).send().await?;
    resp.json().await.map_err(Error::from)
}

/// Get the JWK set from the given Url. Errors are either a reqwest error or an Insecure error if
/// the url isn't https.
pub async fn jwks(client: &Client, url: Url) -> Result<JWKSet<Empty>, Error> {
    let resp = client.get(url).send().await?;
    resp.json().await.map_err(Error::from)
}
