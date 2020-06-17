use crate::{
    error::Error,
    uma2::{Uma2Config, Uma2Provider},
    Claims, Client, Config, Configurable, Provider,
};
use biscuit::CompactJson;
use url::Url;

pub struct DiscoveredUma2(Uma2Config);

impl Provider for DiscoveredUma2 {
    fn auth_uri(&self) -> &Url {
        &self.config().authorization_endpoint
    }

    fn token_uri(&self) -> &Url {
        &self.config().token_endpoint
    }
}

impl Configurable for DiscoveredUma2 {
    fn config(&self) -> &Config {
        &self.0.config
    }
}

impl From<Uma2Config> for DiscoveredUma2 {
    fn from(value: Uma2Config) -> Self {
        Self(value)
    }
}

impl Uma2Provider for DiscoveredUma2 {
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

impl<C: CompactJson + Claims> Client<DiscoveredUma2, C> {
    /// Constructs a client from an issuer url and client parameters via discovery
    pub async fn discover_uma2(
        id: String,
        secret: String,
        redirect: Option<String>,
        issuer: Url,
    ) -> Result<Self, Error> {
        let http_client = reqwest::Client::new();
        let uma2_config = discover_uma2(&http_client, &issuer).await?;
        let jwks =
            crate::discovered::jwks(&http_client, uma2_config.config.jwks_uri.clone()).await?;

        let provider = uma2_config.into();

        Ok(Self::new(
            provider,
            id,
            secret,
            redirect,
            http_client,
            Some(jwks),
        ))
    }
}

pub async fn discover_uma2(client: &reqwest::Client, issuer: &Url) -> Result<Uma2Config, Error> {
    let mut issuer = issuer.clone();
    issuer
        .path_segments_mut()
        .map_err(|_| Error::CannotBeABase)?
        .extend(&[".well-known", "uma2-configuration"]);
    let resp = client.get(issuer).send().await?;
    resp.json().await.map_err(Error::from)
}
