use biscuit::{Empty, jwk::JWKSet};
use reqwest::Client;
use url::Url;

use crate::{
    Config, Configurable, Provider,
    error::{Error, Mismatch, Validation},
};

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

/// Discovers provider configuration, validating the issuer of the discovered
/// configuration against the requested issuer.
pub async fn discover(client: &Client, mut issuer: Url) -> Result<Config, Error> {
    let requested = issuer.clone();
    issuer
        .path_segments_mut()
        .map_err(|_| Error::CannotBeABase)?
        .extend(&[".well-known", "openid-configuration"]);

    let resp = client.get(issuer).send().await?.error_for_status()?;
    let config: Config = resp.json().await.map_err(Error::from)?;
    validate_discovered_issuer(&requested, &config.issuer)?;
    Ok(config)
}

/// Validates that the issuer of the discovered provider configuration matches
/// the requested issuer, as required by [OpenID Connect Discovery
/// 3.1.2.2](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation).
///
/// A `{tenantid}` segment (also percent encoded as `%7Btenantid%7D`) is
/// accepted as a template matching any segment value, following the Microsoft
/// identity platform multi-tenant application convention.
///
/// # Errors
///
/// - [Error::Validation] if the discovered issuer mismatches the requested
///   issuer
pub fn validate_discovered_issuer(requested: &Url, discovered: &Url) -> Result<(), Error> {
    let matches = requested == discovered
        || (requested.scheme() == discovered.scheme()
            && requested.host() == discovered.host()
            && requested.port() == discovered.port()
            && requested
                .path_segments()
                .zip(discovered.path_segments())
                .map(|(requested, discovered)| segments_match(requested, discovered))
                .unwrap_or_else(|| requested.path() == discovered.path())
            && requested.query().is_none() == discovered.query().is_none()
            && requested.fragment().is_none() == discovered.fragment().is_none());

    if matches {
        Ok(())
    } else {
        Err(Validation::Mismatch(Mismatch::Issuer {
            expected: requested.to_string(),
            actual: discovered.to_string(),
        })
        .into())
    }
}

/// Checks whether a segment is a `{tenantid}` issuer template placeholder.
fn is_tenantid_template(segment: &str) -> bool {
    matches!(
        segment.to_ascii_lowercase().as_str(),
        "{tenantid}" | "%7btenantid%7d"
    )
}

fn segments_match<'a, I, J>(requested: I, discovered: J) -> bool
where
    I: Iterator<Item = &'a str>,
    J: Iterator<Item = &'a str>,
{
    let requested: Vec<&str> = requested.collect();
    let discovered: Vec<&str> = discovered.collect();
    requested.len() == discovered.len()
        && requested
            .iter()
            .zip(discovered.iter())
            .all(|(requested, discovered)| {
                requested == discovered
                    || is_tenantid_template(requested)
                    || is_tenantid_template(discovered)
            })
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
    resp.json().await.map_err(Error::from)
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

    #[test]
    fn validate_discovered_issuer_pins_issuer() {
        let requested = url("https://login.microsoftonline.com/common/v2.0");
        let template = url("https://login.microsoftonline.com/%7Btenantid%7D/v2.0");
        assert!(validate_discovered_issuer(&requested, &requested).is_ok());
        assert!(validate_discovered_issuer(&requested, &template).is_ok());
        assert!(validate_discovered_issuer(&template, &requested).is_ok());

        assert!(
            validate_discovered_issuer(&requested, &url("https://attacker.example/common/v2.0"))
                .is_err()
        );
        assert!(
            validate_discovered_issuer(
                &requested,
                &url("https://login.microsoftonline.com/common/v2.0/extra")
            )
            .is_err()
        );
        let mismatch = validate_discovered_issuer(
            &requested,
            &url("http://login.microsoftonline.com/common/v2.0"),
        )
        .unwrap_err();
        assert!(mismatch.to_string().contains("issuer"));
    }
}
