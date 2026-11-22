//! Policy for the provider endpoints that the library fetches or posts to.

use url::Url;

/// Whether a client may talk to provider endpoints that are not https.
///
/// Provider endpoints carry credentials: the token endpoint carries the client
/// secret (or the user credentials in the password grant), the userinfo and
/// UMA2 endpoints carry bearer tokens, and the discovery document and the JWK
/// set decide which keys are trusted to sign id tokens. All of them must use
/// https, so [EndpointSecurity::RequireHttps] is the default.
///
/// [EndpointSecurity::AllowInsecure] is the explicit opt-out for development
/// providers, e.g. Keycloak at `http://localhost:8080`. It is reachable only
/// through the `*_insecure` methods and
/// [Client::allow_insecure_endpoints](crate::Client::allow_insecure_endpoints).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum EndpointSecurity {
    /// Provider endpoints must use https.
    #[default]
    RequireHttps,
    /// Non-https provider endpoints are allowed.
    AllowInsecure,
}

impl EndpointSecurity {
    /// Returns the url if this policy allows it, the url as an error otherwise.
    ///
    /// The caller decides which error type to report, since provider endpoints
    /// are reached both from the [Error](crate::error::Error) and from the
    /// [ClientError](crate::error::ClientError) api.
    pub(crate) fn check(self, url: &Url) -> Result<&Url, Url> {
        match self {
            EndpointSecurity::RequireHttps if url.scheme() != "https" => Err(url.clone()),
            _ => Ok(url),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("valid url")
    }

    #[test]
    fn require_https_rejects_non_https_urls() {
        let security = EndpointSecurity::RequireHttps;
        for rejected in [
            "http://example.com/realms/test",
            "http://localhost:8080/auth/realms/test",
            // A scheme that merely starts with https is not https.
            "https+unix://example.com/run/openid.sock",
        ] {
            let rejected = url(rejected);
            assert_eq!(security.check(&rejected), Err(rejected.clone()));
        }
    }

    #[test]
    fn require_https_accepts_https_urls() {
        let security = EndpointSecurity::RequireHttps;
        for accepted in [
            "https://example.com/realms/test",
            "https://localhost:8443/realms/test",
        ] {
            let accepted = url(accepted);
            assert_eq!(security.check(&accepted), Ok(&accepted));
        }
    }

    #[test]
    fn allow_insecure_accepts_any_url() {
        let security = EndpointSecurity::AllowInsecure;
        for accepted in [
            "http://localhost:8080/auth/realms/test",
            "https://example.com/realms/test",
        ] {
            let accepted = url(accepted);
            assert_eq!(security.check(&accepted), Ok(&accepted));
        }
    }

    #[test]
    fn default_is_https_only() {
        assert_eq!(EndpointSecurity::default(), EndpointSecurity::RequireHttps);
    }
}
