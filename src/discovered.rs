use biscuit::{Empty, jwk::JWKSet};
use reqwest::Client;
use url::Url;

use crate::{Config, Configurable, Provider, error::Error};

/// A discovered provider.
///
/// This struct is used to store configuration for a provider that was
/// discovered using the discovery protocol.
#[derive(Debug, Clone)]
pub struct Discovered {
    config: Config,
    credentials_in_body: bool,
}

impl Provider for Discovered {
    fn auth_uri(&self) -> &Url {
        &self.config.authorization_endpoint
    }

    fn token_uri(&self) -> &Url {
        &self.config.token_endpoint
    }

    fn credentials_in_body(&self) -> bool {
        self.credentials_in_body
    }
}

impl Configurable for Discovered {
    fn config(&self) -> &Config {
        &self.config
    }
}

impl From<Config> for Discovered {
    fn from(value: Config) -> Self {
        Self {
            config: value,
            credentials_in_body: false,
        }
    }
}

impl Discovered {
    /// Set the credentials in body flag for a discovered provider
    pub fn set_credentials_in_body(&mut self, in_body: bool) {
        self.credentials_in_body = in_body;
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

/// Get the JWK set from the given Url. Errors are either a reqwest error or an
/// Insecure error if the url isn't https.
pub async fn jwks(client: &Client, url: Url) -> Result<JWKSet<Empty>, Error> {
    let resp = client.get(url).send().await?.error_for_status()?;
    resp.json().await.map_err(Error::from)
}
