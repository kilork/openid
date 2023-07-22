use crate::{error::Error, Config, Configurable, Provider};
use biscuit::jwk::JWKSet;
use biscuit::Empty;
use reqwest_maybe_middleware::Client;
use url::Url;

#[derive(Debug, Clone)]
pub struct Discovered(Config);

impl Provider for Discovered {
    fn auth_uri(&self) -> &Url {
        &self.0.authorization_endpoint
    }

    fn token_uri(&self) -> &Url {
        &self.0.token_endpoint
    }
}

impl Configurable for Discovered {
    fn config(&self) -> &Config {
        &self.0
    }
}

impl From<Config> for Discovered {
    fn from(value: Config) -> Self {
        Self(value)
    }
}

pub async fn discover(client: &Client, mut issuer: Url) -> Result<Config, Error> {
    issuer
        .path_segments_mut()
        .map_err(|_| Error::CannotBeABase)?
        .extend(&[".well-known", "openid-configuration"]);

    let resp = client.get(issuer).send().await?.error_for_status()?;
    resp.json().await.map_err(Error::from)
}

/// Get the JWK set from the given Url. Errors are either a reqwest error or an Insecure error if
/// the url isn't https.
pub async fn jwks(client: &Client, url: Url) -> Result<JWKSet<Empty>, Error> {
    let resp = client.get(url).send().await?.error_for_status()?;
    resp.json().await.map_err(Error::from)
}
