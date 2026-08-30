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
    let config: Config = crate::http::json(resp).await.map_err(Error::from)?;
    Ok(config)
}

/// Get the JWK set from the given Url.
///
/// # Errors
///
/// - [Error::Insecure] if the url isn't https; use [jwks_insecure] to allow
///   insecure urls, e.g. for a development provider like Keycloak at
///   `http://localhost:8080`
/// - reqwest errors
/// - JSON deserialization errors
///
/// This is a low-level helper, useful when working with providers that are not
/// fully OIDC compliant, e.g. when discovery documents are served from
/// non-standard locations and the [Client::discover](crate::Client::discover)
/// flow cannot be used.
///
/// The fetched keys are used for ID token signature verification, so only
/// point this at the `jwks_uri` of a provider you trust.
pub async fn jwks(client: &Client, url: Url) -> Result<JWKSet<Empty>, Error> {
    validate_https(&url)?;
    let resp = client.get(url).send().await?.error_for_status()?;
    resp.json().await.map_err(Error::from)
}

/// Get the JWK set from the given Url without https enforcement.
///
/// Same as [jwks], but allows non-https urls. The fetched keys are used for ID
/// token signature verification as well, so use it only with providers you
/// trust, e.g. a development Keycloak at `http://localhost:8080`.
///
/// # Errors
///
/// - reqwest errors
/// - JSON deserialization errors
pub async fn jwks_insecure(client: &Client, url: Url) -> Result<JWKSet<Empty>, Error> {
    let resp = client.get(url).send().await?.error_for_status()?;
    crate::http::json(resp).await.map_err(Error::from)
}

/// Get the JWK set from the given Url, enforcing the https scheme and a
/// custom response size limit.
///
/// Same as [jwks], but accepts a maximum response size, for providers whose
/// JWK set exceeds the default limit of 1 MiB (providers with many signing
/// keys). Use [jwks_insecure_with_max_size] to allow non-https urls.
///
/// A `max_response_size` of [usize::MAX] disables the limit.
///
/// # Errors
///
/// - [Error::Insecure] if the url isn't https
/// - [Error::ClientError](`ClientError::ResponseTooBig`) if the response
///   exceeds `max_response_size`
/// - reqwest errors
/// - JSON deserialization errors
pub async fn jwks_with_max_size(
    client: &Client,
    url: Url,
    max_response_size: usize,
) -> Result<JWKSet<Empty>, Error> {
    validate_https(&url)?;
    jwks_insecure_with_max_size(client, url, max_response_size).await
}

/// Get the JWK set from the given Url with a custom response size limit and
/// without https enforcement.
///
/// Same as [jwks_insecure], but accepts a maximum response size, for
/// providers whose JWK set exceeds the default limit of 1 MiB. The fetched
/// keys are used for ID token signature verification as well, so use it only
/// with providers you trust.
pub async fn jwks_insecure_with_max_size(
    client: &Client,
    url: Url,
    max_response_size: usize,
) -> Result<JWKSet<Empty>, Error> {
    let resp = client.get(url).send().await?.error_for_status()?;
    crate::http::json_with_limit(resp, max_response_size)
        .await
        .map_err(Error::from)
}

/// Errors if the url is not https.
fn validate_https(url: &Url) -> Result<(), Error> {
    if url.scheme() != "https" {
        return Err(Error::Insecure(url.clone()));
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("valid url")
    }

    #[test]
    fn validate_https_rejects_http_and_accepts_https() {
        assert!(validate_https(&url("http://localhost:8080/realms/test")).is_err());
        assert!(validate_https(&url("https://example.com/jwks")).is_ok());
    }
}
