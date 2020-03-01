use super::*;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::Value;
use std::error::Error;
use std::{fmt, io};
use url::{form_urlencoded::Serializer, Url};

/// OAuth 2.0 client.
#[derive(Debug, Clone)]
pub struct Client<P> {
    /// OAuth provider.
    pub provider: P,

    /// Client ID.
    pub client_id: String,

    /// Client secret.
    pub client_secret: String,

    /// Redirect URI.
    pub redirect_uri: Option<String>,

    pub http_client: reqwest::Client,
}

impl<P: Provider> Client<P> {
    /// Creates a client.
    ///
    /// # Examples
    ///
    /// ```
    /// use openid::Client;
    /// use openid::provider::google::Installed;
    ///
    /// let client = Client::new(
    ///     Installed,
    ///     String::from("CLIENT_ID"),
    ///     String::from("CLIENT_SECRET"),
    ///     Some(String::from("urn:ietf:wg:oauth:2.0:oob")),
    ///     reqwest::Client::new(),
    /// );
    /// ```
    pub fn new(
        provider: P,
        client_id: String,
        client_secret: String,
        redirect_uri: Option<String>,
        http_client: reqwest::Client,
    ) -> Self {
        Client {
            provider,
            client_id,
            client_secret,
            redirect_uri,
            http_client,
        }
    }

    /// Returns an authorization endpoint URI to direct the user to.
    ///
    /// See [RFC 6749, section 3.1](http://tools.ietf.org/html/rfc6749#section-3.1).
    ///
    /// # Examples
    ///
    /// ```
    /// use openid::Client;
    /// use openid::provider::google::Installed;
    ///
    /// let client = Client::new(
    ///     Installed,
    ///     String::from("CLIENT_ID"),
    ///     String::from("CLIENT_SECRET"),
    ///     Some(String::from("urn:ietf:wg:oauth:2.0:oob")),
    ///     reqwest::Client::new(),
    /// );
    ///
    /// let auth_uri = client.auth_uri(
    ///     Some("https://www.googleapis.com/auth/userinfo.email"),
    ///     None,
    /// );
    /// ```
    pub fn auth_uri(&self, scope: Option<&str>, state: Option<&str>) -> Url {
        let mut uri = self.provider.auth_uri().clone();

        {
            let mut query = uri.query_pairs_mut();

            query.append_pair("response_type", "code");
            query.append_pair("client_id", &self.client_id);

            if let Some(ref redirect_uri) = self.redirect_uri {
                query.append_pair("redirect_uri", redirect_uri);
            }
            if let Some(scope) = scope {
                query.append_pair("scope", scope);
            }
            if let Some(state) = state {
                query.append_pair("state", state);
            }
        }

        uri
    }

    async fn post_token(&self, body: String) -> Result<Value, ClientError> {
        let json = self
            .http_client
            .post(self.provider.token_uri().clone())
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            Ok(json)
        }
    }

    /// Requests an access token using an authorization code.
    ///
    /// See [RFC 6749, section 4.1.3](http://tools.ietf.org/html/rfc6749#section-4.1.3).
    pub async fn request_token(&self, code: &str) -> Result<Bearer, ClientError> {
        let mut body = Serializer::new(String::new());
        body.append_pair("grant_type", "authorization_code");
        body.append_pair("code", code);

        if let Some(ref redirect_uri) = self.redirect_uri {
            body.append_pair("redirect_uri", redirect_uri);
        }

        if self.provider.credentials_in_body() {
            body.append_pair("client_id", &self.client_id);
            body.append_pair("client_secret", &self.client_secret);
        }
        let body = body.finish();

        let json = self.post_token(body).await?;
        let token: Bearer = serde_json::from_value(json)?;
        Ok(token)
    }
}

impl<P> Client<P>
where
    P: Provider,
{
    /// Refreshes an access token.
    ///
    /// See [RFC 6749, section 6](http://tools.ietf.org/html/rfc6749#section-6).
    pub async fn refresh_token(
        &self,
        token: Bearer,
        scope: Option<&str>,
    ) -> Result<Bearer, ClientError> {
        let mut body = Serializer::new(String::new());
        body.append_pair("grant_type", "refresh_token");
        body.append_pair(
            "refresh_token",
            token
                .refresh_token
                .as_ref()
                .map(String::as_str)
                .expect("No refresh_token field"),
        );

        if let Some(scope) = scope {
            body.append_pair("scope", scope);
        }

        if self.provider.credentials_in_body() {
            body.append_pair("client_id", &self.client_id);
            body.append_pair("client_secret", &self.client_secret);
        }
        let body = body.finish();

        let json = self.post_token(body).await?;
        let mut new_token: Bearer = serde_json::from_value(json)?;
        if new_token.refresh_token.is_none() {
            new_token.refresh_token = token.refresh_token.clone();
        }
        Ok(new_token)
    }

    /// Ensures an access token is valid by refreshing it if necessary.
    pub async fn ensure_token(&self, token: Bearer) -> Result<Bearer, ClientError> {
        if token.expired() {
            self.refresh_token(token, None).await
        } else {
            Ok(token)
        }
    }
}

#[derive(Debug)]
pub enum ClientError {
    /// IO error.
    Io(io::Error),

    /// URL error.
    Url(url::ParseError),

    /// Reqwest error.
    Reqwest(reqwest::Error),

    /// JSON error.
    Json(serde_json::Error),

    /// Response parse error.
    //    Parse(ParseError),

    /// OAuth 2.0 error.
    OAuth2(OAuth2Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            ClientError::Io(ref err) => write!(f, "{}", err),
            ClientError::Url(ref err) => write!(f, "{}", err),
            ClientError::Reqwest(ref err) => write!(f, "{}", err),
            ClientError::Json(ref err) => write!(f, "{}", err),
            // ClientError::Parse(ref err) => write!(f, "{}", err),
            ClientError::OAuth2(ref err) => write!(f, "{}", err),
        }
    }
}

impl Error for ClientError {
    fn description(&self) -> &str {
        match *self {
            ClientError::Io(ref err) => err.description(),
            ClientError::Url(ref err) => err.description(),
            ClientError::Reqwest(ref err) => err.description(),
            ClientError::Json(ref err) => err.description(),
            // ClientError::Parse(ref err) => err.description(),
            ClientError::OAuth2(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            ClientError::Io(ref err) => Some(err),
            ClientError::Url(ref err) => Some(err),
            ClientError::Reqwest(ref err) => Some(err),
            ClientError::Json(ref err) => Some(err),
            // ClientError::Parse(ref err) => Some(err),
            ClientError::OAuth2(ref err) => Some(err),
        }
    }
}

macro_rules! impl_from {
    ($v:path, $t:ty) => {
        impl From<$t> for ClientError {
            fn from(err: $t) -> Self {
                $v(err)
            }
        }
    };
}

impl_from!(ClientError::Io, io::Error);
impl_from!(ClientError::Url, url::ParseError);
impl_from!(ClientError::Reqwest, reqwest::Error);
impl_from!(ClientError::Json, serde_json::Error);
// impl_from!(ClientError::Parse, ParseError);
impl_from!(ClientError::OAuth2, OAuth2Error);

#[cfg(test)]
mod tests {
    use super::Client;
    use crate::provider::Provider;
    use url::Url;

    struct Test {
        auth_uri: Url,
        token_uri: Url,
    }
    impl Provider for Test {
        fn auth_uri(&self) -> &Url {
            &self.auth_uri
        }
        fn token_uri(&self) -> &Url {
            &self.token_uri
        }
    }
    impl Test {
        fn new() -> Self {
            Test {
                auth_uri: Url::parse("http://example.com/oauth2/auth").unwrap(),
                token_uri: Url::parse("http://example.com/oauth2/token").unwrap(),
            }
        }
    }

    #[test]
    fn auth_uri() {
        let http_client = reqwest::Client::new();
        let client = Client::new(
            Test::new(),
            String::from("foo"),
            String::from("bar"),
            None,
            http_client,
        );
        assert_eq!(
            "http://example.com/oauth2/auth?response_type=code&client_id=foo",
            client.auth_uri(None, None).as_str()
        );
    }

    #[test]
    fn auth_uri_with_redirect_uri() {
        let http_client = reqwest::Client::new();
        let client = Client::new(
            Test::new(),
            String::from("foo"),
            String::from("bar"),
            Some(String::from("http://example.com/oauth2/callback")),
            http_client,
        );
        assert_eq!(
            "http://example.com/oauth2/auth?response_type=code&client_id=foo&redirect_uri=http%3A%2F%2Fexample.com%2Foauth2%2Fcallback",
            client.auth_uri(None, None).as_str()
        );
    }

    #[test]
    fn auth_uri_with_scope() {
        let http_client = reqwest::Client::new();
        let client = Client::new(
            Test::new(),
            String::from("foo"),
            String::from("bar"),
            None,
            http_client,
        );
        assert_eq!(
            "http://example.com/oauth2/auth?response_type=code&client_id=foo&scope=baz",
            client.auth_uri(Some("baz"), None).as_str()
        );
    }

    #[test]
    fn auth_uri_with_state() {
        let http_client = reqwest::Client::new();
        let client = Client::new(
            Test::new(),
            String::from("foo"),
            String::from("bar"),
            None,
            http_client,
        );
        assert_eq!(
            "http://example.com/oauth2/auth?response_type=code&client_id=foo&state=baz",
            client.auth_uri(None, Some("baz")).as_str()
        );
    }
}
