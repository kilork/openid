/*!
OAuth 2.0 providers.
*/
#[cfg(any(feature = "microsoft", doc))]
/// Microsoft OpenID Connect.
///
/// See [Microsoft identity platform and OpenID Connect protocol](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc)
pub mod microsoft;

use url::Url;

/// OAuth 2.0 providers.
pub trait Provider {
    /// The authorization endpoint URI.
    ///
    /// See [RFC 6749, section 3.1](http://tools.ietf.org/html/rfc6749#section-3.1).
    fn auth_uri(&self) -> &Url;

    /// The token endpoint URI.
    ///
    /// See [RFC 6749, section 3.2](http://tools.ietf.org/html/rfc6749#section-3.2).
    fn token_uri(&self) -> &Url;

    /// Provider requires credentials via request body.
    ///
    /// Although not recommended by the RFC, some providers require `client_id` and `client_secret`
    /// as part of the request body.
    ///
    /// See [RFC 6749, section 2.3.1](http://tools.ietf.org/html/rfc6749#section-2.3.1).
    fn credentials_in_body(&self) -> bool {
        false
    }
}

/// Google OAuth 2.0 providers.
///
/// See [Using OAuth 2.0 to Access Google
/// APIs](https://developers.google.com/identity/protocols/OAuth2).
pub mod google {
    use super::Provider;
    use url::Url;

    /// Signals the server to return the authorization code by prompting the user to copy and
    /// paste.
    ///
    /// See [Choosing a redirect URI][uri].
    ///
    /// [uri]: https://developers.google.com/identity/protocols/OAuth2InstalledApp#choosingredirecturi
    pub const REDIRECT_URI_OOB: &str = "urn:ietf:wg:oauth:2.0:oob";

    /// Signals the server to return the authorization code in the page title.
    ///
    /// See [Choosing a redirect URI][uri].
    ///
    /// [uri]: https://developers.google.com/identity/protocols/OAuth2InstalledApp#choosingredirecturi
    pub const REDIRECT_URI_OOB_AUTO: &str = "urn:ietf:wg:oauth:2.0:oob:auto";

    lazy_static! {
        static ref AUTH_URI: Url =
            Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap();
        static ref TOKEN_URI: Url =
            Url::parse("https://www.googleapis.com/oauth2/v4/token").unwrap();
    }

    /// Google OAuth 2.0 provider for web applications.
    ///
    /// See [Using OAuth 2.0 for Web Server
    /// Applications](https://developers.google.com/identity/protocols/OAuth2WebServer).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Web;
    impl Provider for Web {
        fn auth_uri(&self) -> &Url {
            &AUTH_URI
        }
        fn token_uri(&self) -> &Url {
            &TOKEN_URI
        }
    }

    /// Google OAuth 2.0 provider for installed applications.
    ///
    /// See [Using OAuth 2.0 for Installed
    /// Applications](https://developers.google.com/identity/protocols/OAuth2InstalledApp).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Installed;
    impl Provider for Installed {
        fn auth_uri(&self) -> &Url {
            &AUTH_URI
        }
        fn token_uri(&self) -> &Url {
            &TOKEN_URI
        }
    }
}

lazy_static! {
    static ref GITHUB_AUTH_URI: Url =
        Url::parse("https://github.com/login/oauth/authorize").unwrap();
    static ref GITHUB_TOKEN_URI: Url =
        Url::parse("https://github.com/login/oauth/access_token").unwrap();
    static ref IMGUR_AUTH_URI: Url = Url::parse("https://api.imgur.com/oauth2/authorize").unwrap();
    static ref IMGUR_TOKEN_URI: Url = Url::parse("https://api.imgur.com/oauth2/token").unwrap();
}

/// GitHub OAuth 2.0 provider.
///
/// See [OAuth, GitHub Developer Guide](https://developer.github.com/v3/oauth/).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitHub;
impl Provider for GitHub {
    fn auth_uri(&self) -> &Url {
        &GITHUB_AUTH_URI
    }
    fn token_uri(&self) -> &Url {
        &GITHUB_TOKEN_URI
    }
}

/// Imgur OAuth 2.0 provider.
///
/// See [OAuth 2.0, Imgur](https://api.imgur.com/oauth2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Imgur;
impl Provider for Imgur {
    fn auth_uri(&self) -> &Url {
        &IMGUR_AUTH_URI
    }
    fn token_uri(&self) -> &Url {
        &IMGUR_TOKEN_URI
    }
}

#[test]
fn google_urls() {
    let prov = google::Web;
    prov.auth_uri();
    prov.token_uri();
    let prov = google::Installed;
    prov.auth_uri();
    prov.token_uri();
}

#[test]
fn github_urls() {
    let prov = GitHub;
    prov.auth_uri();
    prov.token_uri();
}

#[test]
fn imgur_urls() {
    let prov = Imgur;
    prov.auth_uri();
    prov.token_uri();
}
