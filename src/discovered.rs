use crate::{error::Error, Config, Provider};
use biscuit::jwk::JWKSet;
use biscuit::Empty;
use reqwest::Client;
use url::Url;
#[cfg(feature = "uma2")]
use crate::uma2::Uma2Provider;

pub struct Discovered(pub Config);

impl Provider for Discovered {
    fn auth_uri(&self) -> &Url {
        &self.0.authorization_endpoint
    }

    fn token_uri(&self) -> &Url {
        &self.0.token_endpoint
    }
}

#[cfg(feature = "uma2")]
impl Uma2Provider for Discovered {
    fn uma2_discovered(&self) -> bool {
        self.0.resource_registration_endpoint.is_some()
    }

    fn resource_registration_uri(&self) -> Option<&Url> {
        self.0.resource_registration_endpoint.as_ref()
    }

    fn permission_uri(&self) -> Option<&Url> {
        self.0.permission_endpoint.as_ref()
    }

    fn uma_policy_uri(&self) -> Option<&Url> {
        self.0.policy_endpoint.as_ref()
    }
}

#[cfg(not(feature = "uma2"))]
pub async fn discover(client: &Client, issuer: &Url) -> Result<Config, Error> {
    let mut issuer= issuer.clone();
    issuer
        .path_segments_mut()
        .map_err(|_| Error::CannotBeABase)?
        .extend(&[".well-known", "openid-configuration"]);

    let resp = client.get(issuer).send().await?;
    resp.json().await.map_err(Error::from)
}

#[cfg(feature = "uma2")]
pub async fn discover_uma2(client: &Client, issuer: &Url) -> Result<Config, Error> {
    let mut issuer = issuer.clone();
    issuer
        .path_segments_mut()
        .map_err(|_| Error::CannotBeABase)?
        .extend(&[".well-known", "uma2-configuration"]);
    let resp = client.get(issuer).send().await?;
    resp.json().await.map_err(Error::from)
}

/// Get the JWK set from the given Url. Errors are either a reqwest error or an Insecure error if
/// the url isn't https.
pub async fn jwks(client: &Client, url: Url) -> Result<JWKSet<Empty>, Error> {
    let resp = client.get(url).send().await?;
    resp.json().await.map_err(Error::from)
}
