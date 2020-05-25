use crate::{error::Error, Config, Provider};
use biscuit::jwk::JWKSet;
use biscuit::Empty;
use reqwest::Client;
use url::Url;

pub struct Discovered(pub Config, pub Option<Config>);

impl Provider for Discovered {
    fn auth_uri(&self) -> &Url {
        &self.0.authorization_endpoint
    }

    fn token_uri(&self) -> &Url {
        &self.0.token_endpoint
    }

    fn uma2_discovered(&self) -> bool {
        self.1.is_some()
    }

    fn resource_registration_uri(&self) -> Option<&Url> {
        self.1.as_ref().and_then(|i| i.resource_registration_endpoint.as_ref())
    }

    fn permission_uri(&self) -> Option<&Url> {
        self.1.as_ref().and_then(|i| i.permission_endpoint.as_ref())
    }
}

pub async fn discover(client: &Client, mut issuer: Url) -> Result<(Config, Option<Config>), Error> {
    let mut uma2_issuer = issuer.clone();
    issuer
        .path_segments_mut()
        .map_err(|_| Error::CannotBeABase)?
        .extend(&[".well-known", "openid-configuration"]);

    uma2_issuer
        .path_segments_mut()
        .map_err(|_| Error::CannotBeABase)?
        .extend(&[".well-known", "uma2-configuration"]);

    let resp = client.get(issuer).send().await?;
    let uma2_resp = client.get(uma2_issuer).send().await?;
    let uma2_resp : Option<Config> = uma2_resp.json().await.ok();
    resp.json().await.map_err(Error::from).map(|c1| (c1, uma2_resp))
}

/// Get the JWK set from the given Url. Errors are either a reqwest error or an Insecure error if
/// the url isn't https.
pub async fn jwks(client: &Client, url: Url) -> Result<JWKSet<Empty>, Error> {
    let resp = client.get(url).send().await?;
    resp.json().await.map_err(Error::from)
}
