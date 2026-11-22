use biscuit::CompactJson;
use url::Url;

use crate::{
    Claims, Client, Config, Configurable, Provider,
    discovered::well_known_url,
    error::Error,
    uma2::{Uma2Config, Uma2Provider},
};

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
    /// Constructs a client from an issuer url and client parameters via
    /// discovery
    pub async fn discover_uma2(
        id: String,
        secret: String,
        redirect: impl Into<Option<String>>,
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
            redirect.into(),
            http_client,
            Some(jwks),
        ))
    }
}

/// Well-known path segments of the UMA2 discovery document.
const WELL_KNOWN_SUFFIX: [&str; 2] = [".well-known", "uma2-configuration"];

pub async fn discover_uma2(client: &reqwest::Client, issuer: &Url) -> Result<Uma2Config, Error> {
    let well_known = well_known_url(issuer, &WELL_KNOWN_SUFFIX)?;
    let resp = client.get(well_known).send().await?;
    let config: Uma2Config = crate::http::json(resp).await.map_err(Error::from)?;
    crate::discovered::validate_discovered_issuer(issuer, &config.config.issuer)?;
    Ok(config)
}

#[cfg(test)]
mod test {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("valid url")
    }

    #[test]
    fn well_known_url_uses_the_uma2_suffix() {
        let cases = [
            (
                "https://example.com",
                "https://example.com/.well-known/uma2-configuration",
            ),
            (
                "https://example.com/",
                "https://example.com/.well-known/uma2-configuration",
            ),
            (
                "https://example.com/auth/realms/test",
                "https://example.com/auth/realms/test/.well-known/uma2-configuration",
            ),
            // A terminating slash must be removed, not doubled: see issue #106.
            (
                "https://example.com/auth/realms/test/",
                "https://example.com/auth/realms/test/.well-known/uma2-configuration",
            ),
        ];

        for (issuer, expected) in cases {
            let actual = well_known_url(&url(issuer), &WELL_KNOWN_SUFFIX).expect("well known url");
            assert_eq!(actual, url(expected), "issuer {issuer}");
        }
    }

    #[test]
    fn uma2_issuer_is_pinned_to_the_requested_url_including_its_trailing_slash() {
        // The terminating slash is only dropped for the well-known url; the
        // discovered issuer must still match what the caller asked for.
        let requested = url("https://example.com/auth/realms/test/");
        assert!(crate::discovered::validate_discovered_issuer(&requested, &requested).is_ok());
        assert!(
            crate::discovered::validate_discovered_issuer(
                &requested,
                &url("https://example.com/auth/realms/test")
            )
            .is_err()
        );
        assert!(
            crate::discovered::validate_discovered_issuer(
                &requested,
                &url("https://attacker.example/auth/realms/test/")
            )
            .is_err()
        );
    }
}
