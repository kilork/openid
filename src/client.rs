use super::*;
use biscuit::jwa::{self, SignatureAlgorithm};
use biscuit::jwk::{AlgorithmParameters, JWKSet};
use biscuit::jws::{Compact, Secret};
use biscuit::{Empty, SingleOrMultiple};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
// use std::error::Error;
use crate::discovery::{self, Config, Discovered};
use crate::error::{ClientError, Decode, Error, Expiry, Mismatch, Missing, Validation};
use crate::token::{Claims, Token};
use chrono::{Duration, NaiveDate, Utc};
use url::{form_urlencoded::Serializer, Url};
use validator::Validate;
use validator_derive::Validate;

type IdToken = Compact<Claims, Empty>;

/// OAuth 2.0 client.
#[derive(Debug)]
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

    pub jwks: Option<JWKSet<Empty>>,
}

// Common pattern in the Client::decode function when dealing with mismatched keys
macro_rules! wrong_key {
    ($expected:expr, $actual:expr) => {
        Err(error::Jose::WrongKeyType {
            expected: format!("{:?}", $expected),
            actual: format!("{:?}", $actual),
        }
        .into())
    };
}

impl Client<Discovered> {
    /// Constructs a client from an issuer url and client parameters via discovery
    pub async fn discover(
        id: String,
        secret: String,
        redirect: Option<String>,
        issuer: Url,
    ) -> Result<Self, Error> {
        let http_client = reqwest::Client::new();
        let config = discovery::discover(&http_client, issuer).await?;
        let jwks = discovery::jwks(&http_client, config.jwks_uri.clone()).await?;
        let provider = Discovered(config);
        Ok(Self::new(
            provider,
            id,
            secret,
            redirect,
            http_client,
            Some(jwks),
        ))
    }
    /// Passthrough to the redirect_url stored in inth_oauth2 as a str.
    pub fn redirect_url(&self) -> &str {
        self.redirect_uri
            .as_ref()
            .expect("We always require a redirect to construct client!")
    }

    /// A reference to the config document of the provider obtained via discovery
    pub fn config(&self) -> &Config {
        &self.provider.0
    }

    /// Constructs the auth_url to redirect a client to the provider. Options are... optional. Use
    /// them as needed. Keep the Options struct around for authentication, or at least the nonce
    /// and max_age parameter - we need to verify they stay the same and validate if you used them.
    pub fn auth_url(&self, options: &Options) -> Url {
        let scope = match options.scope {
            Some(ref scope) => {
                if !scope.contains("openid") {
                    String::from("openid ") + scope
                } else {
                    scope.clone()
                }
            }
            // Default scope value
            None => String::from("openid"),
        };

        let mut url = self.auth_uri(Some(&scope), options.state.as_ref().map(String::as_str));
        {
            let mut query = url.query_pairs_mut();
            if let Some(ref nonce) = options.nonce {
                query.append_pair("nonce", nonce.as_str());
            }
            if let Some(ref display) = options.display {
                query.append_pair("display", display.as_str());
            }
            if let Some(ref prompt) = options.prompt {
                let s = prompt
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                query.append_pair("prompt", s.as_str());
            }
            if let Some(max_age) = options.max_age {
                query.append_pair("max_age", max_age.num_seconds().to_string().as_str());
            }
            if let Some(ref ui_locales) = options.ui_locales {
                query.append_pair("ui_locales", ui_locales.as_str());
            }
            if let Some(ref claims_locales) = options.claims_locales {
                query.append_pair("claims_locales", claims_locales.as_str());
            }
            if let Some(ref id_token_hint) = options.id_token_hint {
                query.append_pair("id_token_hint", id_token_hint.as_str());
            }
            if let Some(ref login_hint) = options.login_hint {
                query.append_pair("login_hint", login_hint.as_str());
            }
            if let Some(ref acr_values) = options.acr_values {
                query.append_pair("acr_values", acr_values.as_str());
            }
        }
        url
    }

    /// Given an auth_code and auth options, request the token, decode, and validate it.
    pub async fn authenticate(
        &self,
        auth_code: &str,
        nonce: Option<&str>,
        max_age: Option<&Duration>,
    ) -> Result<Token, Error> {
        let bearer = self.request_token(auth_code).await.map_err(Error::from)?;
        let mut token: Token = bearer.into();
        if let Some(mut id_token) = token.id_token.as_mut() {
            self.decode_token(&mut id_token)?;
            self.validate_token(&id_token, nonce, max_age)?;
        }
        Ok(token)
    }

    /// Mutates a Compact::encoded Token to Compact::decoded. Errors are:
    ///
    /// - Decode::MissingKid if the keyset has multiple keys but the key id on the token is missing
    /// - Decode::MissingKey if the given key id is not in the key set
    /// - Decode::EmptySet if the keyset is empty
    /// - Jose::WrongKeyType if the alg of the key and the alg in the token header mismatch
    /// - Jose::WrongKeyType if the specified key alg isn't a signature algorithm
    /// - Jose error if decoding fails
    pub fn decode_token(&self, token: &mut IdToken) -> Result<(), Error> {
        // This is an early return if the token is already decoded
        if let Compact::Decoded { .. } = *token {
            return Ok(());
        }

        if self.jwks.is_none() {
            return Ok(());
        }

        let jwks = self.jwks.as_ref().unwrap();

        let header = token.unverified_header()?;
        // If there is more than one key, the token MUST have a key id
        let key = if jwks.keys.len() > 1 {
            let token_kid = header.registered.key_id.ok_or(Decode::MissingKid)?;
            jwks.find(&token_kid).ok_or(Decode::MissingKey(token_kid))?
        } else {
            // TODO We would want to verify the keyset is >1 in the constructor
            // rather than every decode call, but we can't return an error in new().
            jwks.keys.first().as_ref().ok_or(Decode::EmptySet)?
        };

        if let Some(alg) = key.common.algorithm.as_ref() {
            if let &jwa::Algorithm::Signature(sig) = alg {
                if header.registered.algorithm != sig {
                    return wrong_key!(sig, header.registered.algorithm);
                }
            } else {
                return wrong_key!(SignatureAlgorithm::default(), alg);
            }
        }

        let alg = header.registered.algorithm;
        match key.algorithm {
            // HMAC
            AlgorithmParameters::OctetKey { ref value, .. } => match alg {
                SignatureAlgorithm::HS256
                | SignatureAlgorithm::HS384
                | SignatureAlgorithm::HS512 => {
                    *token = token.decode(&Secret::Bytes(value.clone()), alg)?;
                    Ok(())
                }
                _ => wrong_key!("HS256 | HS384 | HS512", alg),
            },
            AlgorithmParameters::RSA(ref params) => match alg {
                SignatureAlgorithm::RS256
                | SignatureAlgorithm::RS384
                | SignatureAlgorithm::RS512 => {
                    let pkcs = Secret::RSAModulusExponent {
                        n: params.n.clone(),
                        e: params.e.clone(),
                    };
                    *token = token.decode(&pkcs, alg)?;
                    Ok(())
                }
                _ => wrong_key!("RS256 | RS384 | RS512", alg),
            },
            AlgorithmParameters::EllipticCurve(_) => unimplemented!("No support for EC keys yet"),
        }
    }

    /// Validate a decoded token. If you don't get an error, its valid! Nonce and max_age come from
    /// your auth_uri options. Errors are:
    ///
    /// - Jose Error if the Token isn't decoded
    /// - Validation::Mismatch::Issuer if the provider issuer and token issuer mismatch
    /// - Validation::Mismatch::Nonce if a given nonce and the token nonce mismatch
    /// - Validation::Missing::Nonce if either the token or args has a nonce and the other does not
    /// - Validation::Missing::Audience if the token aud doesn't contain the client id
    /// - Validation::Missing::AuthorizedParty if there are multiple audiences and azp is missing
    /// - Validation::Mismatch::AuthorizedParty if the azp is not the client_id
    /// - Validation::Expired::Expires if the current time is past the expiration time
    /// - Validation::Expired::MaxAge is the token is older than the provided max_age
    /// - Validation::Missing::Authtime if a max_age was given and the token has no auth time
    pub fn validate_token(
        &self,
        token: &IdToken,
        nonce: Option<&str>,
        max_age: Option<&Duration>,
    ) -> Result<(), Error> {
        let claims = token.payload()?;

        if claims.iss != self.config().issuer {
            let expected = self.config().issuer.as_str().to_string();
            let actual = claims.iss.as_str().to_string();
            return Err(Validation::Mismatch(Mismatch::Issuer { expected, actual }).into());
        }

        match nonce {
            Some(expected) => match claims.nonce {
                Some(ref actual) => {
                    if expected != actual {
                        let expected = expected.to_string();
                        let actual = actual.to_string();
                        return Err(
                            Validation::Mismatch(Mismatch::Nonce { expected, actual }).into()
                        );
                    }
                }
                None => return Err(Validation::Missing(Missing::Nonce).into()),
            },
            None => {
                if claims.nonce.is_some() {
                    return Err(Validation::Missing(Missing::Nonce).into());
                }
            }
        }

        if !claims.aud.contains(&self.client_id) {
            return Err(Validation::Missing(Missing::Audience).into());
        }
        // By spec, if there are multiple auds, we must have an azp
        if let SingleOrMultiple::Multiple(_) = claims.aud {
            if let None = claims.azp {
                return Err(Validation::Missing(Missing::AuthorizedParty).into());
            }
        }
        // If there is an authorized party, it must be our client_id
        if let Some(ref actual) = claims.azp {
            if actual != &self.client_id {
                let expected = self.client_id.to_string();
                let actual = actual.to_string();
                return Err(
                    Validation::Mismatch(Mismatch::AuthorizedParty { expected, actual }).into(),
                );
            }
        }

        let now = Utc::now();
        // Now should never be less than the time this code was written!
        if now.timestamp() < 1504758600 {
            panic!("chrono::Utc::now() can never be before this was written!")
        }
        if claims.exp <= now.timestamp() {
            return Err(Validation::Expired(Expiry::Expires(
                chrono::naive::NaiveDateTime::from_timestamp(claims.exp, 0),
            ))
            .into());
        }

        if let Some(max) = max_age {
            match claims.auth_time {
                Some(time) => {
                    let age = chrono::Duration::seconds(now.timestamp() - time);
                    if age >= *max {
                        return Err(error::Validation::Expired(Expiry::MaxAge(age)).into());
                    }
                }
                None => return Err(Validation::Missing(Missing::AuthTime).into()),
            }
        }

        Ok(())
    }

    /// Get a userinfo json document for a given token at the provider's userinfo endpoint.
    /// Errors are:
    ///
    /// - Userinfo::NoUrl if this provider doesn't have a userinfo endpoint
    /// - Error::Insecure if the userinfo url is not https
    /// - Error::Jose if the token is not decoded
    /// - Error::Http if something goes wrong getting the document
    /// - Error::Json if the response is not a valid Userinfo document
    /// - Userinfo::MismatchSubject if the returned userinfo document and tokens subject mismatch
    pub async fn request_userinfo(&self, token: &Token) -> Result<Userinfo, Error> {
        match self.config().userinfo_endpoint {
            Some(ref url) => {
                let claims = token.id_token.as_ref().map(|x| x.payload()).transpose()?;
                let auth_code = token.bearer.access_token.to_string();
                let resp = self
                    .http_client
                    .get(url.clone())
                    .bearer_auth(auth_code)
                    .send()
                    .await?;
                let info: Userinfo = resp.json().await?;
                if let Some(claims) = claims {
                    if claims.sub != info.sub {
                        let expected = info.sub.clone();
                        let actual = claims.sub.clone();
                        return Err(error::Userinfo::MismatchSubject { expected, actual }.into());
                    }
                }
                Ok(info)
            }
            None => Err(error::Userinfo::NoUrl.into()),
        }
    }
}

/// Optional parameters that [OpenID specifies](https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters) for the auth URI.
/// Derives Default, so remember to ..Default::default() after you specify what you want.
#[derive(Default)]
pub struct Options {
    /// MUST contain openid. By default this is ONLY openid. Official optional scopes are
    /// email, profile, address, phone, offline_access. Check the Discovery config
    /// `scopes_supported` to see what is available at your provider!
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub display: Option<Display>,
    pub prompt: Option<std::collections::HashSet<Prompt>>,
    pub max_age: Option<Duration>,
    pub ui_locales: Option<String>,
    pub claims_locales: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub acr_values: Option<String>,
}

/// The userinfo struct contains all possible userinfo fields regardless of scope. [See spec.](https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims)
// TODO is there a way to use claims_supported in config to simplify this struct?
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct Userinfo {
    pub sub: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub middle_name: Option<String>,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub profile: Option<Url>,
    #[serde(default)]
    pub picture: Option<Url>,
    #[serde(default)]
    pub website: Option<Url>,
    #[serde(default)]
    #[validate(email)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    // Isn't required to be just male or female
    #[serde(default)]
    pub gender: Option<String>,
    // ISO 9601:2004 YYYY-MM-DD or YYYY.
    #[serde(default)]
    pub birthdate: Option<NaiveDate>,
    // Region/City codes. Should also have a more concrete serializer form.
    #[serde(default)]
    pub zoneinfo: Option<String>,
    // Usually RFC5646 langcode-countrycode, maybe with a _ sep, could be arbitrary
    #[serde(default)]
    pub locale: Option<String>,
    // Usually E.164 format number
    #[serde(default)]
    pub phone_number: Option<String>,
    #[serde(default)]
    pub phone_number_verified: bool,
    #[serde(default)]
    pub address: Option<Address>,
    #[serde(default)]
    pub updated_at: Option<i64>,
}

/// The four values for the preferred display parameter in the Options. See spec for details.
pub enum Display {
    Page,
    Popup,
    Touch,
    Wap,
}

impl Display {
    fn as_str(&self) -> &'static str {
        use self::Display::*;
        match *self {
            Page => "page",
            Popup => "popup",
            Touch => "touch",
            Wap => "wap",
        }
    }
}

/// The four possible values for the prompt parameter set in Options. See spec for details.
#[derive(PartialEq, Eq, Hash)]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

impl Prompt {
    fn as_str(&self) -> &'static str {
        use self::Prompt::*;
        match *self {
            None => "none",
            Login => "login",
            Consent => "consent",
            SelectAccount => "select_account",
        }
    }
}

/// Address Claim struct. Can be only formatted, only the rest, or both.
#[derive(Debug, Deserialize, Serialize)]
pub struct Address {
    #[serde(default)]
    pub formatted: Option<String>,
    #[serde(default)]
    pub street_address: Option<String>,
    #[serde(default)]
    pub locality: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    // Countries like the UK use alphanumeric postal codes, so you can't just use a number here
    #[serde(default)]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
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
    ///     reqwest::Client::new(), None,
    /// );
    /// ```
    pub fn new(
        provider: P,
        client_id: String,
        client_secret: String,
        redirect_uri: Option<String>,
        http_client: reqwest::Client,
        jwks: Option<JWKSet<Empty>>,
    ) -> Self {
        Client {
            provider,
            client_id,
            client_secret,
            redirect_uri,
            http_client,
            jwks,
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
    ///     reqwest::Client::new(), None,
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
        // Ensure the non thread-safe `Serializer` is not kept across
        // an `await` boundary by localizing it to this inner scope.
        let body = {
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
            body.finish()
        };

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
            None,
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
            None,
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
            None,
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
            None,
        );
        assert_eq!(
            "http://example.com/oauth2/auth?response_type=code&client_id=foo&state=baz",
            client.auth_uri(None, Some("baz")).as_str()
        );
    }
}
