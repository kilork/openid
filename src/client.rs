use std::{borrow::Cow, marker::PhantomData};

use biscuit::{
    CompactJson, Empty,
    jwa::{self, SignatureAlgorithm},
    jwk::{AlgorithmParameters, JWKSet},
    jws::{Compact, Secret},
};
use chrono::Duration;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::Value;
use url::{Url, form_urlencoded::Serializer};

use crate::{
    Bearer, Claims, Config, Configurable, Discovered, IdToken, OAuth2Error, Options, Provider,
    StandardClaims, Token, TokenIntrospection, Userinfo,
    bearer::TemporalBearerGuard,
    discovered,
    error::{
        ClientError, Decode, Error, Introspection as ErrorIntrospection, Jose,
        Userinfo as ErrorUserinfo,
    },
    pkce::{Pkce, generate_s256_pkce},
    standard_claims_subject::StandardClaimsSubject,
    validation::{
        validate_token_aud, validate_token_exp, validate_token_issuer, validate_token_nonce,
    },
};

/// OpenID Connect 1.0 / OAuth 2.0 client.
#[derive(Debug, Clone)]
pub struct Client<P = Discovered, C: CompactJson + Claims = StandardClaims> {
    /// OAuth provider.
    pub provider: P,

    /// Client ID.
    pub client_id: String,

    /// Client secret.
    pub client_secret: Option<String>,

    /// Redirect URI.
    pub redirect_uri: Option<String>,

    /// Reqwest client used to send HTTP requests.
    pub http_client: reqwest::Client,

    /// The set of JSON Web Keys for this client. They will be discovered via an
    /// OIDC discovery process.
    pub jwks: Option<JWKSet<Empty>>,

    /// PKCE parameters.
    pub pkce: Option<Pkce>,

    marker: PhantomData<C>,
}

// Common pattern in the Client::decode function when dealing with mismatched
// keys
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
    /// Constructs a client from an issuer url and client parameters via
    /// discovery
    pub async fn discover(
        id: String,
        secret: impl Into<Option<String>>,
        redirect: impl Into<Option<String>>,
        issuer: Url,
    ) -> Result<Self, Error> {
        Self::discover_with_client(reqwest::Client::new(), id, secret, redirect, issuer).await
    }

    /// Constructs a client from an issuer url and client parameters via
    /// discovery
    pub async fn discover_with_client(
        http_client: reqwest::Client,
        id: String,
        secret: impl Into<Option<String>>,
        redirect: impl Into<Option<String>>,
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

impl<C: CompactJson + Claims, P: Provider + Configurable> Client<P, C> {
    /// Passthrough to the redirect_url stored in inth_oauth2 as a str.
    pub fn redirect_url(&self) -> Option<&str> {
        self.redirect_uri.as_deref()
    }

    /// A reference to the config document of the provider obtained via
    /// discovery
    pub fn config(&self) -> &Config {
        self.provider.config()
    }

    /// Constructs the auth_url to redirect a client to the provider. Options
    /// are... optional. Use them as needed. Keep the Options struct around
    /// for authentication, or at least the `nonce` and `max_age` parameter - we
    /// need to verify they stay the same and validate if you used them.
    pub fn auth_url(&self, options: &Options) -> Url {
        self.auth_url_internal(options, self.pkce.as_ref())
    }

    /// This is similar to auth_url but generates a new PKCE with every call, returning it
    /// to the caller along with the URL. Note that calling this method ignores disable_pkce().
    pub fn auth_url_with_new_pkce(&self, options: &Options) -> (Url, Pkce) {
        let pkce = generate_s256_pkce();
        (self.auth_url_internal(options, Some(&pkce)), pkce)
    }

    /// Extracts the main logic of url creation which is called from different public methods
    fn auth_url_internal(&self, options: &Options, pkce: Option<&Pkce>) -> Url {
        let scope = match options.scope.as_deref() {
            Some(scope) => {
                if !scope.contains("openid") {
                    Cow::Owned(String::from("openid ") + scope)
                } else {
                    Cow::Borrowed(scope)
                }
            }
            // Default scope value
            None => Cow::Borrowed("openid"),
        };

        let mut url = self.auth_uri_internal(&*scope, options.state.as_deref(), pkce);
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
            if let Some(ref response_mode) = options.response_mode {
                query.append_pair("response_mode", response_mode.as_str());
            }
        }
        url
    }

    /// Given an auth_code and auth options, request the token, decode, and
    /// validate it.
    pub async fn authenticate(
        &self,
        auth_code: &str,
        nonce: impl Into<Option<&str>>,
        max_age: impl Into<Option<&Duration>>,
    ) -> Result<Token<C>, Error> {
        let bearer = self.request_token(auth_code).await.map_err(Error::from)?;
        let mut token: Token<C> = bearer.into();
        if let Some(id_token) = token.id_token.as_mut() {
            self.decode_token(id_token)?;
            self.validate_token(id_token, nonce, max_age)?;
        }
        Ok(token)
    }

    /// Mutates a Compact::encoded Token to Compact::decoded.
    ///
    /// # Errors
    ///
    /// - [Decode::MissingKid] if the keyset has multiple keys but the key id on
    ///   the token is missing
    /// - [Decode::MissingKey] if the given key id is not in the key set
    /// - [Decode::EmptySet] if the keyset is empty
    /// - [Jose::WrongKeyType] if the alg of the key and the alg in the token
    ///   header mismatch
    /// - [Jose::WrongKeyType] if the specified key alg isn't a signature
    ///   algorithm
    /// - [Decode::UnsupportedEllipticCurve] if the alg is cryptographic curve
    /// - [Decode::UnsupportedOctetKeyPair] if the alg is octet key pair
    /// - [Error::Jose] error if decoding fails
    pub fn decode_token<T: CompactJson>(&self, token: &mut IdToken<T>) -> Result<(), Error> {
        // This is an early return if the token is already decoded
        if let Compact::Decoded { .. } = *token {
            return Ok(());
        }

        if self.jwks.is_none() {
            return Ok(());
        }

        let Some(jwks) = self.jwks.as_ref() else {
            return Err(Decode::EmptySet.into());
        };

        let header = token.unverified_header()?;
        // If there is more than one key, the token MUST have a key id
        let key = if jwks.keys.len() > 1 {
            let token_kid = header.registered.key_id.ok_or(Decode::MissingKid)?;
            jwks.find(&token_kid).ok_or(Decode::MissingKey(token_kid))?
        } else {
            // TODO We would want to verify the keyset is >1 in the constructor
            // rather than every decode call, but we can't return an error in new().
            jwks.keys.first().ok_or(Decode::EmptySet)?
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
        let secret = match key.algorithm {
            // HMAC
            AlgorithmParameters::OctetKey(ref parameters) => match alg {
                SignatureAlgorithm::HS256
                | SignatureAlgorithm::HS384
                | SignatureAlgorithm::HS512 => {
                    Ok::<_, Error>(Secret::Bytes(parameters.value.clone()))
                }
                _ => wrong_key!("HS256 | HS384 | HS512", alg),
            },
            AlgorithmParameters::RSA(ref params) => match alg {
                SignatureAlgorithm::RS256
                | SignatureAlgorithm::RS384
                | SignatureAlgorithm::RS512 => Ok(params.jws_public_key_secret()),
                _ => wrong_key!("RS256 | RS384 | RS512", alg),
            },
            AlgorithmParameters::EllipticCurve(_) => Err(Decode::UnsupportedEllipticCurve.into()),
            AlgorithmParameters::OctetKeyPair(_) => Err(Decode::UnsupportedOctetKeyPair.into()),
        }?;

        *token = token.decode(&secret, alg)?;

        Ok(())
    }

    /// Validate a decoded token. If you don't get an error, its valid! Nonce
    /// and max_age come from your auth_uri options.
    ///
    /// # Errors
    ///
    /// - [Error::Jose] Error if the Token isn't decoded
    /// - [Error::Validation]::[Mismatch](crate::error::Validation::Mismatch)::[Issuer](crate::error::Mismatch::Issuer) if the provider issuer and token issuer mismatch
    /// - [Error::Validation]::[Mismatch](crate::error::Validation::Mismatch)::[Nonce](crate::error::Mismatch::Nonce) if a given nonce and the token nonce mismatch
    /// - [Error::Validation]::[Missing](crate::error::Validation::Missing)::[Nonce](crate::error::Missing::Nonce) if args has a nonce and the token does not
    /// - [Error::Validation]::[Missing](crate::error::Validation::Missing)::[Audience](crate::error::Missing::Audience) if the token aud doesn't contain the client id
    /// - [Error::Validation]::[Missing](crate::error::Validation::Missing)::[AuthorizedParty](crate::error::Missing::AuthorizedParty) if there are multiple audiences and azp is missing
    /// - [Error::Validation]::[Mismatch](crate::error::Validation::Mismatch)::[AuthorizedParty](crate::error::Mismatch::AuthorizedParty) if the azp is not the client_id
    /// - [Error::Validation]::[Expired](crate::error::Validation::Expired)::[Expires](crate::error::Expiry::Expires) if the current time is past the expiration time
    /// - [Error::Validation]::[Expired](crate::error::Validation::Expired)::[MaxAge](crate::error::Expiry::MaxAge) is the token is older than the provided max_age
    /// - [Error::Validation]::[Missing](crate::error::Validation::Missing)::[AuthTime](crate::error::Missing::AuthTime) if a max_age was given and the token has no auth time
    pub fn validate_token<'nonce, 'max_age>(
        &self,
        token: &IdToken<C>,
        nonce: impl Into<Option<&'nonce str>>,
        max_age: impl Into<Option<&'max_age Duration>>,
    ) -> Result<(), Error> {
        let claims = token.payload()?;
        let config = self.config();

        validate_token_issuer(claims, config)?;

        validate_token_nonce(claims, nonce)?;

        validate_token_aud(claims, &self.client_id)?;

        validate_token_exp(claims, max_age)?;

        Ok(())
    }

    /// Get a userinfo json document for a given token at the provider's
    /// userinfo endpoint. Returns [Standard Claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) as [Userinfo] struct.
    ///
    /// # Errors
    ///
    /// - [ErrorUserinfo::NoUrl] if this provider doesn't have a userinfo
    ///   endpoint
    /// - [Error::Insecure] if the userinfo url is not https
    /// - [Error::Jose] if the token is not decoded
    /// - [Error::Http] if something goes wrong getting the document
    /// - [Error::Json] if the response is not a valid Userinfo document
    /// - [ErrorUserinfo::MissingSubject] if subject (sub) is missing
    /// - [ErrorUserinfo::MismatchSubject] if the returned userinfo document and
    ///   tokens subject mismatch
    pub async fn request_userinfo(&self, token: &Token<C>) -> Result<Userinfo, Error> {
        self.request_userinfo_custom(token).await
    }

    /// Get a userinfo json document for a given token at the provider's
    /// userinfo endpoint. Returns [UserInfo Response](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)
    /// including non-standard claims. The sub (subject) Claim MUST always be
    /// returned in the UserInfo Response.
    ///
    /// # Errors
    ///
    /// - [ErrorUserinfo::NoUrl] if this provider doesn't have a userinfo
    ///   endpoint
    /// - [Error::Insecure] if the userinfo url is not https
    /// - [Decode::MissingKid] if the keyset has multiple keys but the key id on
    ///   the token is missing
    /// - [Decode::MissingKey] if the given key id is not in the key set
    /// - [Decode::EmptySet] if the keyset is empty
    /// - [Jose::WrongKeyType] if the alg of the key and the alg in the token
    ///   header mismatch
    /// - [Jose::WrongKeyType] if the specified key alg isn't a signature
    ///   algorithm
    /// - [Error::Jose] if the token is not decoded
    /// - [Error::Http] if something goes wrong getting the document
    /// - [Error::Json] if the response is not a valid Userinfo document
    /// - [ErrorUserinfo::MissingSubject] if subject (sub) is missing
    /// - [ErrorUserinfo::MismatchSubject] if the returned userinfo document and
    ///   tokens subject mismatch
    /// - [ErrorUserinfo::MissingContentType] if content-type header is missing
    /// - [ErrorUserinfo::ParseContentType] if content-type header is not
    ///   parsable
    /// - [ErrorUserinfo::WrongContentType] if content-type header is not
    ///   accepted
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use openid::{Bearer, DiscoveredClient, error::StandardClaimsSubjectMissing, StandardClaims, StandardClaimsSubject, Token};
    /// # use serde::{Deserialize, Serialize};
    /// # async fn _main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let bearer: Bearer = serde_json::from_str("{}").unwrap();
    /// # let token = Token::<StandardClaims>::from(bearer);
    /// # let client = DiscoveredClient::discover("client_id".to_string(), "client_secret".to_string(), "http://redirect".to_string(), url::Url::parse("http://issuer".into()).unwrap(),).await?;
    /// #[derive(Debug, Deserialize, Serialize)]
    /// struct CustomUserinfo(std::collections::HashMap<String, serde_json::Value>);
    ///
    /// impl StandardClaimsSubject for CustomUserinfo {
    ///    fn sub(&self) -> Result<&str, StandardClaimsSubjectMissing> {
    ///        self.0
    ///            .get("sub")
    ///            .and_then(|x| x.as_str())
    ///            .ok_or(StandardClaimsSubjectMissing)
    ///    }
    /// }
    ///
    /// impl openid::CompactJson for CustomUserinfo {}
    ///
    /// let custom_userinfo: CustomUserinfo = client.request_userinfo_custom(&token).await?;
    /// # Ok(()) }
    /// ```
    pub async fn request_userinfo_custom<U>(&self, token: &Token<C>) -> Result<U, Error>
    where
        U: StandardClaimsSubject,
    {
        match self.config().userinfo_endpoint {
            Some(ref url) => {
                let auth_code = token.bearer.access_token.to_string();

                let response = self
                    .http_client
                    .get(url.clone())
                    .bearer_auth(auth_code)
                    .send()
                    .await?
                    .error_for_status()?;

                let content_type = response
                    .headers()
                    .get(&CONTENT_TYPE)
                    .and_then(|content_type| content_type.to_str().ok())
                    .ok_or(ErrorUserinfo::MissingContentType)?;

                let mime_type = match content_type {
                    "application/json" => mime::APPLICATION_JSON,
                    content_type => content_type.parse::<mime::Mime>().map_err(|_| {
                        ErrorUserinfo::ParseContentType {
                            content_type: content_type.to_string(),
                        }
                    })?,
                };

                let info: U = match (mime_type.type_(), mime_type.subtype().as_str()) {
                    (mime::APPLICATION, "json") => {
                        let info_value: Value = response.json().await?;
                        if info_value.get("error").is_some() {
                            let oauth2_error: OAuth2Error = serde_json::from_value(info_value)?;
                            return Err(Error::ClientError(oauth2_error.into()));
                        }
                        serde_json::from_value(info_value)?
                    }
                    (mime::APPLICATION, "jwt") => {
                        let jwt = response.text().await?;
                        let mut jwt_encoded: Compact<U, Empty> = Compact::new_encoded(&jwt);
                        self.decode_token(&mut jwt_encoded)?;
                        let (_, info) = jwt_encoded.unwrap_decoded();
                        info
                    }
                    _ => {
                        return Err(ErrorUserinfo::WrongContentType {
                            content_type: content_type.to_string(),
                            body: response.bytes().await?.to_vec(),
                        }
                        .into());
                    }
                };

                let claims = token.id_token.as_ref().map(|x| x.payload()).transpose()?;
                if let Some(claims) = claims {
                    let info_sub = info.sub().map_err(ErrorUserinfo::from)?;
                    if claims.sub() != info_sub {
                        let expected = info_sub.to_string();
                        let actual = claims.sub().to_string();
                        return Err(ErrorUserinfo::MismatchSubject { expected, actual }.into());
                    }
                }

                Ok(info)
            }
            None => Err(ErrorUserinfo::NoUrl.into()),
        }
    }

    /// Get a token introspection json document for a given token at the
    /// provider's token introspection endpoint. Returns [Token Introspection Response](https://datatracker.ietf.org/doc/html/rfc7662#section-2.2)
    /// as [TokenIntrospection] struct.
    ///
    /// # Errors
    ///
    /// - [Error::Http] if something goes wrong getting the document
    /// - [Error::Insecure] if the token introspection url is not https
    /// - [Error::Json] if the response is not a valid TokenIntrospection
    ///   document
    /// - [ErrorIntrospection::MissingContentType] if content-type header is
    ///   missing
    /// - [ErrorIntrospection::NoUrl] if this provider doesn't have a token
    ///   introspection endpoint
    /// - [ErrorIntrospection::ParseContentType] if content-type header is not
    ///   parsable
    /// - [ErrorIntrospection::WrongContentType] if content-type header is not
    ///   accepted
    pub async fn request_token_introspection<I>(
        &self,
        token: &Token<C>,
    ) -> Result<TokenIntrospection<I>, Error>
    where
        I: CompactJson,
    {
        match self.config().introspection_endpoint {
            Some(ref url) => {
                let access_token = token.bearer.access_token.to_string();

                let body = {
                    let mut body = Serializer::new(String::new());
                    body.append_pair("token", &access_token);
                    body.finish()
                };

                let response = self
                    .http_client
                    .post(url.clone())
                    .basic_auth(&self.client_id, self.client_secret.as_ref())
                    .header(ACCEPT, "application/json")
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(body)
                    .send()
                    .await?
                    .error_for_status()?;

                let content_type = response
                    .headers()
                    .get(&CONTENT_TYPE)
                    .and_then(|content_type| content_type.to_str().ok())
                    .ok_or(ErrorIntrospection::MissingContentType)?;

                let mime_type = match content_type {
                    "application/json" => mime::APPLICATION_JSON,
                    content_type => content_type.parse::<mime::Mime>().map_err(|_| {
                        ErrorIntrospection::ParseContentType {
                            content_type: content_type.to_string(),
                        }
                    })?,
                };

                let info: TokenIntrospection<I> =
                    match (mime_type.type_(), mime_type.subtype().as_str()) {
                        (mime::APPLICATION, "json") => {
                            let info_value: Value = response.json().await?;
                            if info_value.get("error").is_some() {
                                let oauth2_error: OAuth2Error = serde_json::from_value(info_value)?;
                                return Err(Error::ClientError(oauth2_error.into()));
                            }
                            serde_json::from_value(info_value)?
                        }
                        _ => {
                            return Err(ErrorIntrospection::WrongContentType {
                                content_type: content_type.to_string(),
                                body: response.bytes().await?.to_vec(),
                            }
                            .into());
                        }
                    };

                Ok(info)
            }
            None => Err(ErrorIntrospection::NoUrl.into()),
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
        client_secret: impl Into<Option<String>>,
        redirect_uri: impl Into<Option<String>>,
        http_client: reqwest::Client,
        jwks: Option<JWKSet<Empty>>,
    ) -> Self {
        Client {
            provider,
            client_id,
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client,
            jwks,
            pkce: Some(generate_s256_pkce()),
            marker: PhantomData,
        }
    }

    /// Returns an authorization endpoint URI to direct the user to.
    ///
    /// This function is used by [Client::auth_url].
    /// In most situations it is non needed to use it directly.
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
    pub fn auth_uri<'scope, 'state>(
        &self,
        scope: impl Into<Option<&'scope str>>,
        state: impl Into<Option<&'state str>>,
    ) -> Url {
        self.auth_uri_internal(scope, state, self.pkce.as_ref())
    }

    /// Extracts the core logic of creating the authorization endpoint URI. This is
    /// called from different public methods
    fn auth_uri_internal<'scope, 'state>(
        &self,
        scope: impl Into<Option<&'scope str>>,
        state: impl Into<Option<&'state str>>,
        pkce: Option<&Pkce>,
    ) -> Url {
        let mut uri = self.provider.auth_uri().clone();

        {
            let mut query = uri.query_pairs_mut();

            query.append_pair("response_type", "code");
            query.append_pair("client_id", &self.client_id);

            if let Some(ref redirect_uri) = self.redirect_uri {
                query.append_pair("redirect_uri", redirect_uri);
            }

            if let Some(pkce) = pkce {
                query.append_pair("code_challenge", pkce.code_challenge());
                query.append_pair("code_challenge_method", pkce.code_challenge_method());
            }

            self.append_scope(&mut query, scope);

            if let Some(state) = state.into() {
                query.append_pair("state", state);
            }
        }

        uri
    }

    /// Requests an access token using an authorization code with code verifier
    /// from PKCE configuration.
    ///
    /// See [RFC 6749, section 4.1.3](http://tools.ietf.org/html/rfc6749#section-4.1.3).
    /// See [RFC 7636, section 4.5](https://tools.ietf.org/html/rfc7636#section-4.5).
    pub async fn request_token(&self, code: &str) -> Result<Bearer, ClientError> {
        self.request_token_pkce(code, self.pkce.as_ref().map(|pkce| pkce.code_verifier()))
            .await
    }

    /// Requests an access token using an authorization code with code verifier.
    ///
    /// See [RFC 6749, section 4.1.3](http://tools.ietf.org/html/rfc6749#section-4.1.3).
    /// See [RFC 7636, section 4.5](https://tools.ietf.org/html/rfc7636#section-4.5).
    pub async fn request_token_pkce(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<Bearer, ClientError> {
        // Ensure the non thread-safe `Serializer` is not kept across
        // an `await` boundary by localizing it to this inner scope.
        let body = {
            let mut body = Serializer::new(String::new());
            body.append_pair("grant_type", "authorization_code");
            body.append_pair("code", code);

            if let Some(code_verifier) = code_verifier {
                body.append_pair("code_verifier", code_verifier);
            }

            if let Some(ref redirect_uri) = self.redirect_uri {
                body.append_pair("redirect_uri", redirect_uri);
            }

            self.append_credentials(&mut body);

            body.finish()
        };

        let json = self.post_token(body).await?;
        let token: Bearer = serde_json::from_value(json)?;
        Ok(token)
    }

    /// Requests an access token using the Resource Owner Password Credentials
    /// Grant flow
    ///
    /// See [RFC 6749, section 4.3](https://tools.ietf.org/html/rfc6749#section-4.3)
    pub async fn request_token_using_password_credentials(
        &self,
        username: &str,
        password: &str,
        scope: impl Into<Option<&str>>,
    ) -> Result<Bearer, ClientError> {
        // Ensure the non thread-safe `Serializer` is not kept across
        // an `await` boundary by localizing it to this inner scope.
        let body = {
            let mut body = Serializer::new(String::new());
            body.append_pair("grant_type", "password");
            body.append_pair("username", username);
            body.append_pair("password", password);

            self.append_scope(&mut body, scope);

            self.append_credentials(&mut body);

            body.finish()
        };

        let json = self.post_token(body).await?;
        let token: Bearer = serde_json::from_value(json)?;
        Ok(token)
    }

    /// Requests an access token using the Client Credentials Grant flow
    ///
    /// See [RFC 6749, section 4.4](https://tools.ietf.org/html/rfc6749#section-4.4)
    pub async fn request_token_using_client_credentials(
        &self,
        scope: impl Into<Option<&str>>,
    ) -> Result<Bearer, ClientError> {
        // Ensure the non thread-safe `Serializer` is not kept across
        // an `await` boundary by localizing it to this inner scope.
        let body = {
            let mut body = Serializer::new(String::new());
            body.append_pair("grant_type", "client_credentials");

            self.append_scope(&mut body, scope);

            self.append_credentials(&mut body);

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
        token: impl AsRef<Bearer>,
        scope: impl Into<Option<&str>>,
    ) -> Result<Bearer, ClientError> {
        // Ensure the non thread-safe `Serializer` is not kept across
        // an `await` boundary by localizing it to this inner scope.
        let body = {
            let mut body = Serializer::new(String::new());
            body.append_pair("grant_type", "refresh_token");
            body.append_pair(
                "refresh_token",
                token
                    .as_ref()
                    .refresh_token
                    .as_deref()
                    .expect("refresh_token field"),
            );

            self.append_scope(&mut body, scope);

            self.append_credentials(&mut body);

            body.finish()
        };

        let json = self.post_token(body).await?;
        let mut new_token: Bearer = serde_json::from_value(json)?;
        if new_token.refresh_token.is_none() {
            new_token.refresh_token = token.as_ref().refresh_token.clone();
        }
        Ok(new_token)
    }

    /// Ensures an access token is valid by refreshing it if necessary.
    pub async fn ensure_token(
        &self,
        token_guard: TemporalBearerGuard,
    ) -> Result<TemporalBearerGuard, ClientError> {
        if token_guard.expired() {
            self.refresh_token(token_guard, None).await.map(From::from)
        } else {
            Ok(token_guard)
        }
    }

    /// Disable PKCE of this [`Client<P, C>`].
    pub fn disable_pkce(&mut self) {
        self.pkce = None;
    }

    /// Refresh PKCE of this [`Client<P, C>`].
    pub fn refresh_pkce(&mut self) {
        self.pkce = Some(generate_s256_pkce());
    }

    async fn post_token(&self, body: String) -> Result<Value, ClientError> {
        let json = self
            .http_client
            .post(self.provider.token_uri().clone())
            .basic_auth(&self.client_id, self.client_secret.as_ref())
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

    fn append_credentials(&self, body: &mut Serializer<String>) {
        if self.provider.credentials_in_body() {
            body.append_pair("client_id", &self.client_id);
            if let Some(client_secret) = self.client_secret.as_deref() {
                body.append_pair("client_secret", client_secret);
            }
        }
    }

    fn append_scope<'scope, T>(
        &self,
        body: &mut Serializer<T>,
        scope: impl Into<Option<&'scope str>>,
    ) where
        T: url::form_urlencoded::Target,
    {
        if let Some(scope) = scope.into() {
            body.append_pair("scope", scope);
        }
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::Client;
    use crate::{
        Config,
        configurable::Configurable,
        options::Options,
        pkce::{Pkce, PkceSha256},
        provider::Provider,
    };

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

    // This is required to meet the trait bound on the impl block where the auth_uri and auth_url
    // methods sit although this isn't called in those methods
    impl Configurable for Test {
        fn config(&self) -> &Config {
            unimplemented!("not needed for auth_url tests")
        }
    }

    fn test_pkce() -> Option<Pkce> {
        Some(Pkce::S256(PkceSha256 {
            code_verifier: String::from("code_verifier"),
            code_challenge: String::from("code_challenge"),
        }))
    }

    #[test]
    fn auth_uri() {
        let http_client = reqwest::Client::new();
        let mut client: Client<_> = Client::new(
            Test::new(),
            String::from("foo"),
            String::from("bar"),
            None,
            http_client,
            None,
        );
        client.pkce = test_pkce();
        assert_eq!(
            "http://example.com/oauth2/auth?response_type=code&client_id=foo&code_challenge=code_challenge&code_challenge_method=S256",
            client.auth_uri(None, None).as_str()
        );
    }

    #[test]
    fn auth_uri_with_redirect_uri() {
        let http_client = reqwest::Client::new();
        let mut client: Client<_> = Client::new(
            Test::new(),
            String::from("foo"),
            String::from("bar"),
            Some(String::from("http://example.com/oauth2/callback")),
            http_client,
            None,
        );
        client.pkce = test_pkce();
        assert_eq!(
            "http://example.com/oauth2/auth?response_type=code&client_id=foo&redirect_uri=http%3A%2F%2Fexample.com%2Foauth2%2Fcallback&code_challenge=code_challenge&code_challenge_method=S256",
            client.auth_uri(None, None).as_str()
        );
    }

    #[test]
    fn auth_uri_with_scope() {
        let http_client = reqwest::Client::new();
        let mut client: Client<_> = Client::new(
            Test::new(),
            String::from("foo"),
            String::from("bar"),
            None,
            http_client,
            None,
        );
        client.pkce = test_pkce();
        assert_eq!(
            "http://example.com/oauth2/auth?response_type=code&client_id=foo&code_challenge=code_challenge&code_challenge_method=S256&scope=baz",
            client.auth_uri(Some("baz"), None).as_str()
        );
    }

    #[test]
    fn auth_uri_with_state() {
        let http_client = reqwest::Client::new();
        let mut client: Client<_> = Client::new(
            Test::new(),
            String::from("foo"),
            String::from("bar"),
            None,
            http_client,
            None,
        );
        client.pkce = test_pkce();
        assert_eq!(
            "http://example.com/oauth2/auth?response_type=code&client_id=foo&code_challenge=code_challenge&code_challenge_method=S256&state=baz",
            client.auth_uri(None, Some("baz")).as_str()
        );
    }

    #[test]
    fn auth_url_with_static_pkce() {
        let http_client = reqwest::Client::new();
        let client: Client<_> = Client::new(
            Test::new(),
            String::from("foo"),
            String::from("bar"),
            None,
            http_client,
            None,
        );
        let url = client.auth_url(&Options::default());
        let url_str = url.as_str();
        assert!(
            url_str.starts_with("http://example.com/oauth2/auth?response_type=code&client_id=foo")
        );
        assert!(url_str.contains("code_challenge_method=S256"));
    }

    #[test]
    fn auth_url_with_disable_pkce() {
        let http_client = reqwest::Client::new();
        let mut client: Client<_> = Client::new(
            Test::new(),
            String::from("foo"),
            String::from("bar"),
            None,
            http_client,
            None,
        );
        client.disable_pkce();
        let url = client.auth_url(&Options::default());
        let url_str = url.as_str();
        assert!(
            url_str
                .eq("http://example.com/oauth2/auth?response_type=code&client_id=foo&scope=openid")
        );
    }

    #[test]
    fn auth_url_with_new_pkce() {
        let http_client = reqwest::Client::new();
        let mut client: Client<_> = Client::new(
            Test::new(),
            String::from("foo"),
            String::from("bar"),
            None,
            http_client,
            None,
        );
        client.disable_pkce();
        let (url, pkce) = client.auth_url_with_new_pkce(&Options::default());
        let url_str = url.as_str();
        assert!(
            url_str.starts_with("http://example.com/oauth2/auth?response_type=code&client_id=foo")
        );
        assert!(url_str.contains(&format!("code_challenge={}", pkce.code_challenge())));
    }
}
