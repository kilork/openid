use crate::{
    discovered,
    error::{
        ClientError, Decode, Error, Expiry, Jose, Mismatch, Missing, Userinfo as ErrorUserinfo,
        Validation,
    },
    Bearer, Claims, Config, Configurable, Discovered, IdToken, OAuth2Error, Options, Provider,
    StandardClaims, Token, Userinfo,
};
use biscuit::{
    jwa::{self, SignatureAlgorithm},
    jwk::{AlgorithmParameters, JWKSet},
    jws::{Compact, Secret},
    CompactJson, Empty, SingleOrMultiple,
};
use chrono::{Duration, Utc};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::Value;
use std::marker::PhantomData;
use url::{form_urlencoded::Serializer, Url};

/// OAuth 2.0 client.
#[derive(Debug)]
pub struct Client<P = Discovered, C: CompactJson + Claims = StandardClaims> {
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
    marker: PhantomData<C>,
}

// Common pattern in the Client::decode function when dealing with mismatched keys
macro_rules! wrong_key {
    ($expected:expr, $actual:expr) => {
        Err(Jose::WrongKeyType {
            expected: format!("{:?}", $expected),
            actual: format!("{:?}", $actual),
        }
        .into())
    };
}

impl<C: CompactJson + Claims> Client<Discovered, C> {
    /// Constructs a client from an issuer url and client parameters via discovery
    pub async fn discover(
        id: String,
        secret: String,
        redirect: Option<String>,
        issuer: Url,
    ) -> Result<Self, Error> {
        Self::discover_with_client(reqwest::Client::new(), id, secret, redirect, issuer).await
    }

    /// Constructs a client from an issuer url and client parameters via discovery
    pub async fn discover_with_client(
        http_client: reqwest::Client,
        id: String,
        secret: String,
        redirect: Option<String>,
        issuer: Url,
    ) -> Result<Self, Error> {
        let config = discovered::discover(&http_client, issuer).await?;
        let jwks = discovered::jwks(&http_client, config.jwks_uri.clone()).await?;

        let provider = config.into();

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

pub fn validate_token_issuer<C: Claims>(claims: &C, config: &Config) -> Result<(), Error> {
    if claims.iss() != &config.issuer {
        let expected = config.issuer.as_str().to_string();
        let actual = claims.iss().as_str().to_string();
        return Err(Validation::Mismatch(Mismatch::Issuer { expected, actual }).into());
    }

    Ok(())
}

pub fn validate_token_nonce<C: Claims>(claims: &C, nonce: Option<&str>) -> Result<(), Error> {
    match nonce {
        Some(expected) => match claims.nonce() {
            Some(actual) => {
                if expected != actual {
                    let expected = expected.to_string();
                    let actual = actual.to_string();
                    return Err(Validation::Mismatch(Mismatch::Nonce { expected, actual }).into());
                }
            }
            None => return Err(Validation::Missing(Missing::Nonce).into()),
        },
        None => {
            if claims.nonce().is_some() {
                return Err(Validation::Missing(Missing::Nonce).into());
            }
        }
    }

    Ok(())
}

pub fn validate_token_aud<C: Claims>(claims: &C, client_id: &str) -> Result<(), Error> {
    if !claims.aud().contains(client_id) {
        return Err(Validation::Missing(Missing::Audience).into());
    }
    // By spec, if there are multiple auds, we must have an azp
    if let SingleOrMultiple::Multiple(_) = claims.aud() {
        if claims.azp().is_none() {
            return Err(Validation::Missing(Missing::AuthorizedParty).into());
        }
    }
    // If there is an authorized party, it must be our client_id
    if let Some(actual) = claims.azp() {
        if actual != client_id {
            let expected = client_id.to_string();
            let actual = actual.to_string();
            return Err(
                Validation::Mismatch(Mismatch::AuthorizedParty { expected, actual }).into(),
            );
        }
    }

    Ok(())
}

pub fn validate_token_exp<C: Claims>(claims: &C, max_age: Option<&Duration>) -> Result<(), Error> {
    let now = Utc::now();
    // Now should never be less than the time this code was written!
    if now.timestamp() < 1504758600 {
        panic!("chrono::Utc::now() can never be before this was written!")
    }
    if claims.exp() <= now.timestamp() {
        return Err(Validation::Expired(Expiry::Expires(
            chrono::naive::NaiveDateTime::from_timestamp(claims.exp(), 0),
        ))
        .into());
    }

    if let Some(max) = max_age {
        match claims.auth_time() {
            Some(time) => {
                let age = chrono::Duration::seconds(now.timestamp() - time);
                if age >= *max {
                    return Err(Validation::Expired(Expiry::MaxAge(age)).into());
                }
            }
            None => return Err(Validation::Missing(Missing::AuthTime).into()),
        }
    }

    Ok(())
}

impl<C: CompactJson + Claims, P: Provider + Configurable> Client<P, C> {
    /// Passthrough to the redirect_url stored in inth_oauth2 as a str.
    pub fn redirect_url(&self) -> &str {
        self.redirect_uri
            .as_ref()
            .expect("We always require a redirect to construct client!")
    }

    /// A reference to the config document of the provider obtained via discovery
    pub fn config(&self) -> &Config {
        self.provider.config()
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

        let mut url = self.auth_uri(Some(&scope), options.state.as_deref());
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
    ) -> Result<Token<C>, Error> {
        let bearer = self.request_token(auth_code).await.map_err(Error::from)?;
        let mut token: Token<C> = bearer.into();
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
    pub fn decode_token(&self, token: &mut IdToken<C>) -> Result<(), Error> {
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
            if let jwa::Algorithm::Signature(sig) = *alg {
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
            AlgorithmParameters::OctetKey(ref parameters) => match alg {
                SignatureAlgorithm::HS256
                | SignatureAlgorithm::HS384
                | SignatureAlgorithm::HS512 => {
                    *token = token.decode(&Secret::Bytes(parameters.value.clone()), alg)?;
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
            AlgorithmParameters::OctetKeyPair(_) => {
                unimplemented!("No support for Octet key pair yet")
            }
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
        token: &IdToken<C>,
        nonce: Option<&str>,
        max_age: Option<&Duration>,
    ) -> Result<(), Error> {
        let claims = token.payload()?;
        let config = self.config();

        validate_token_issuer(claims, config)?;

        validate_token_nonce(claims, nonce)?;

        validate_token_aud(claims, &self.client_id)?;

        validate_token_exp(claims, max_age)?;

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
    pub async fn request_userinfo(&self, token: &Token<C>) -> Result<Userinfo, Error> {
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
                    if let Some(info_sub) = &info.sub {
                        if claims.sub() != info_sub {
                            let expected = info_sub.clone();
                            let actual = claims.sub().to_string();
                            return Err(ErrorUserinfo::MismatchSubject { expected, actual }.into());
                        }
                    }
                }
                Ok(info)
            }
            None => Err(ErrorUserinfo::NoUrl.into()),
        }
    }
}

impl<P, C> Client<P, C>
where
    P: Provider,
    C: CompactJson + Claims,
{
    /// Creates a client.
    ///
    /// # Examples
    ///
    /// ```
    /// use openid::{Client, StandardClaims};
    /// use openid::provider::google::Installed;
    ///
    /// let client: Client<_, StandardClaims> = Client::new(
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
            marker: PhantomData,
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
    /// let client: Client<_> = Client::new(
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

    /// Requests an access token using the Client Credentials Grant flow
    ///
    /// See [RFC 6749, section 4.4](https://tools.ietf.org/html/rfc6749#section-4.4)
    pub async fn request_token_using_client_credentials(&self) -> Result<Bearer, ClientError> {
        // Ensure the non thread-safe `Serializer` is not kept across
        // an `await` boundary by localizing it to this inner scope.
        let body = {
            let mut body = Serializer::new(String::new());
            body.append_pair("grant_type", "client_credentials");
            body.append_pair("client_id", &self.client_id);
            body.append_pair("client_secret", &self.client_secret);
            body.finish()
        };

        let json = self.post_token(body).await?;
        let token: Bearer = serde_json::from_value(json)?;
        Ok(token)
    }

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
                .as_deref()
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
        let client: Client<_> = Client::new(
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
        let client: Client<_> = Client::new(
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
        let client: Client<_> = Client::new(
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
        let client: Client<_> = Client::new(
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
