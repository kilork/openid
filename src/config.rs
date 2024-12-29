use serde::{Deserialize, Serialize};
use url::Url;

/// Config represents an OpenID / OAuth 2.0 provider metadata.
///
/// OpenID / OAuth 2.0 Providers have metadata describing their configuration.
/// These OpenID / OAuth 2.0 Provider Metadata values are used by OpenID Connect
/// / OAuth 2.0 Authorization.
///
/// See:
///
/// - [OpenID Connect Discovery 1.0: OpenID Provider Metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
/// - [https://datatracker.ietf.org/doc/html/rfc8414](https://datatracker.ietf.org/doc/html/rfc8414)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// The authorization server's issuer identifier.
    ///
    /// URL using the `https` scheme with no query or fragment components that
    /// the OP asserts as its Issuer Identifier. If Issuer discovery is
    /// supported (see [Section 2](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)), this value MUST be identical to the issuer value
    /// returned by WebFinger. This also MUST be identical to the `iss` Claim
    /// value in ID Tokens issued from this Issuer.
    pub issuer: Url,
    /// URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core](https://openid.net/specs/openid-connect-discovery-1_0.html#OpenID.Core).
    ///
    /// This URL MUST use the `https` scheme and MAY contain port, path, and
    /// query parameter components.
    pub authorization_endpoint: Url,
    // Only optional in the implicit flow
    // TODO For now, we only support code flows.
    /// URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core](https://openid.net/specs/openid-connect-discovery-1_0.html#OpenID.Core).
    ///
    /// This is the URL where clients will send a request to exchange an
    /// authorization code for an access token. This URL MUST use the `https`
    /// scheme and MAY contain port, path, and query parameter components.
    pub token_endpoint: Url,
    /// The user info endpoint.
    ///
    /// URL of the OP's UserInfo Endpoint [OpenID.Core](https://openid.net/specs/openid-connect-discovery-1_0.html#OpenID.Core). This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components.
    #[serde(default)]
    pub userinfo_endpoint: Option<Url>,
    /// The JWKS URI.
    ///
    /// URL of the OP's JWK Set [JWK](https://openid.net/specs/openid-connect-discovery-1_0.html#JWK) document,
    /// which MUST use the `https` scheme. This contains the signing key(s) the
    /// RP uses to validate signatures from the OP. The JWK Set MAY also
    /// contain the Server's encryption key(s), which are used by RPs to
    /// encrypt requests to the Server. When both signing and encryption
    /// keys are made available, a `use` (public key use) parameter value is
    /// REQUIRED for all keys in the referenced JWK Set to indicate each
    /// key's intended usage. Although some algorithms allow the same key to
    /// be used for both signatures and encryption, doing so is NOT
    /// RECOMMENDED, as it is less secure. The JWK `x5c` parameter MAY be
    /// used to provide X.509 representations of keys provided. When used,
    /// the bare key values MUST still be present and MUST match those in
    /// the certificate. The JWK Set MUST NOT contain private or symmetric
    /// key values.
    pub jwks_uri: Url,
    /// The dynamic client registration endpoint.
    ///
    /// URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration](https://openid.net/specs/openid-connect-discovery-1_0.html#OpenID.Registration),
    /// which MUST use the `https` scheme.
    #[serde(default)]
    pub registration_endpoint: Option<Url>,
    /// The scopes supported.
    ///
    /// JSON array containing a list of the [OAuth 2.0: RFC6749](https://openid.net/specs/openid-connect-discovery-1_0.html#RFC6749) scope values
    /// that this server supports. The server MUST support the `openid` scope
    /// value. Servers MAY choose not to advertise some supported scope values
    /// even when this parameter is used, although those defined in
    /// [OpenID.Core](https://openid.net/specs/openid-connect-discovery-1_0.html#OpenID.Core) SHOULD be listed, if supported.
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
    // There are only three valid response types, plus combinations of them, and none
    // If we want to make these user friendly we want a struct to represent all 7 types
    /// JSON array containing a list of the OAuth 2.0 `response_type` values
    /// that this OP supports. Dynamic OpenID Providers MUST support the
    /// `code,id_token`, and the `id_token` token Response Type values.
    pub response_types_supported: Vec<String>,
    // There are only two possible values here, query and fragment. Default is both.
    /// JSON array containing a list of the OAuth 2.0 `response_mode` values that this OP supports, as specified in [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/openid-connect-discovery-1_0.html#OAuth.Responses). If omitted, the default for Dynamic OpenID Providers is `["query", "fragment"]`.
    #[serde(default)]
    pub response_modes_supported: Option<Vec<String>>,
    // Must support at least authorization_code and implicit.
    /// JSON array containing a list of the OAuth 2.0 Grant Type values that
    /// this OP supports. Dynamic OpenID Providers MUST support the
    /// `authorization_code` and `implicit` Grant Type values and MAY support
    /// other Grant Types. If omitted, the default value is
    /// `["authorization_code", "implicit"]`.
    #[serde(default)]
    pub grant_types_supported: Option<Vec<String>>,
    /// JSON array containing a list of the Authentication Context Class
    /// References that this OP supports.
    #[serde(default)]
    pub acr_values_supported: Option<Vec<String>>,
    // pairwise and public are valid by spec, but servers can add more
    /// JSON array containing a list of the Subject Identifier types that this
    /// OP supports. Valid types include `pairwise` and `public`.
    #[serde(default = "empty_string_vec")]
    pub subject_types_supported: Vec<String>,
    // Must include at least RS256, none is only allowed with response types without id tokens
    /// JSON array containing a list of the JWS signing algorithms (`alg`
    /// values) supported by the OP for the ID Token to encode the Claims in a
    /// [JWT](https://openid.net/specs/openid-connect-discovery-1_0.html#JWT). The algorithm `RS256` MUST be included. The value `none` MAY be
    /// supported but MUST NOT be used unless the Response Type used returns no
    /// ID Token from the Authorization Endpoint (such as when using the
    /// Authorization Code Flow).
    #[serde(default = "empty_string_vec")]
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// JSON array containing a list of the [JWE](https://openid.net/specs/openid-connect-discovery-1_0.html#JWE) encryption algorithms (`alg`
    /// values) supported by the OP for the ID Token to encode the Claims in a
    /// [JWT](https://openid.net/specs/openid-connect-discovery-1_0.html#JWT).
    #[serde(default)]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    /// JSON array containing a list of the [JWE](https://openid.net/specs/openid-connect-discovery-1_0.html#JWE) encryption algorithms (`enc`
    /// values) supported by the OP for the ID Token to encode the Claims in a
    /// [JWT](https://openid.net/specs/openid-connect-discovery-1_0.html#JWT).
    #[serde(default)]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    /// JSON array containing a list of the [JWS](https://openid.net/specs/openid-connect-discovery-1_0.html#JWS) signing algorithms (`alg`
    /// values) [JWA](https://openid.net/specs/openid-connect-discovery-1_0.html#JWA) supported by the UserInfo Endpoint to encode the Claims in
    /// a [JWT](https://openid.net/specs/openid-connect-discovery-1_0.html#JWT). The value `none` MAY be included.
    #[serde(default)]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    /// JSON array containing a list of the [JWE](https://openid.net/specs/openid-connect-discovery-1_0.html#JWE) encryption algorithms (`alg` values) [JWA](https://openid.net/specs/openid-connect-discovery-1_0.html#JWA) supported by the UserInfo Endpoint to encode the Claims in a [JWT](https://openid.net/specs/openid-connect-discovery-1_0.html#JWT).
    #[serde(default)]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    /// JSON array containing a list of the [JWE](https://openid.net/specs/openid-connect-discovery-1_0.html#JWE) encryption algorithms (`enc` values) [JWA](https://openid.net/specs/openid-connect-discovery-1_0.html#JWA) supported by the UserInfo Endpoint to encode the Claims in a [JWT](https://openid.net/specs/openid-connect-discovery-1_0.html#JWT).
    #[serde(default)]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    /// JSON array containing a list of the [JWS](https://openid.net/specs/openid-connect-discovery-1_0.html#JWS) signing algorithms (`alg` values)
    /// supported by the OP for Request Objects, which are described in Section
    /// 6.1 of OpenID Connect Core 1.0 [OpenID.Core](https://openid.net/specs/openid-connect-discovery-1_0.html#OpenID.Core). These algorithms are used
    /// both when the Request Object is passed by value (using the `request`
    /// parameter) and when it is passed by reference (using the `request_uri`
    /// parameter). Servers SHOULD support `none` and `RS256`.
    #[serde(default)]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    /// JSON array containing a list of the [JWE](https://openid.net/specs/openid-connect-discovery-1_0.html#JWE) encryption algorithms (`alg`
    /// values) supported by the OP for Request Objects. These algorithms are
    /// used both when the Request Object is passed by value and when it is
    /// passed by reference.
    #[serde(default)]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    /// JSON array containing a list of the [JWE](https://openid.net/specs/openid-connect-discovery-1_0.html#JWE) encryption algorithms (`enc`
    /// values) supported by the OP for Request Objects. These algorithms are
    /// used both when the Request Object is passed by value and when it is
    /// passed by reference.
    #[serde(default)]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    // Spec options are client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt
    // If omitted, client_secret_basic is used
    /// JSON array containing a list of Client Authentication methods supported
    /// by this Token Endpoint. The options are `client_secret_post`,
    /// `client_secret_basic`, `client_secret_jwt`, and `private_key_jwt`, as
    /// described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core](https://openid.net/specs/openid-connect-discovery-1_0.html#OpenID.Core). Other
    /// authentication methods MAY be defined by extensions. If omitted, the
    /// default is client_secret_basic -- the HTTP Basic Authentication Scheme
    /// specified in Section 2.3.1 of [OAuth 2.0: RFC6749](https://openid.net/specs/openid-connect-discovery-1_0.html#RFC6749).
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    // Only wanted with jwt auth methods, should have RS256, none not allowed
    /// JSON array containing a list of the JWS signing algorithms (alg values)
    /// supported by the Token Endpoint for the signature on the [JWT](https://openid.net/specs/openid-connect-discovery-1_0.html#JWT) used to
    /// authenticate the Client at the Token Endpoint for the private_key_jwt
    /// and client_secret_jwt authentication methods. Servers SHOULD support
    /// RS256. The value none MUST NOT be used.
    #[serde(default)]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// JSON array containing a list of the display parameter values that the
    /// OpenID Provider supports. These values are described in Section 3.1.2.1
    /// of OpenID Connect Core 1.0 [OpenID.Core](https://openid.net/specs/openid-connect-discovery-1_0.html#OpenID.Core)
    #[serde(default)]
    pub display_values_supported: Option<Vec<String>>,
    // Valid options are normal, aggregated, and distributed. If omitted, only use normal
    /// The claim types supported by the OpenID Connect provider.
    ///
    /// JSON array containing a list of the Claim Types that the OpenID Provider
    /// supports. These Claim Types are described in Section 5.6 of OpenID
    /// Connect Core 1.0 [OpenID.Core](https://openid.net/specs/openid-connect-discovery-1_0.html#OpenID.Core). Values defined by this specification are
    /// normal, aggregated, and distributed. If omitted, the implementation
    /// supports only normal Claims.
    #[serde(default)]
    pub claim_types_supported: Option<Vec<String>>,
    /// The claims supported by the OpenID Connect provider.
    ///
    /// JSON array containing a list of the Claim Names of the Claims that the
    /// OpenID Provider MAY be able to supply values for. Note that for privacy
    /// or other reasons, this might not be an exhaustive list.
    #[serde(default)]
    pub claims_supported: Option<Vec<String>>,
    /// The service documentation URL of the OpenID Connect provider.
    ///
    /// URL of a page containing human-readable information that developers
    /// might want or need to know when using the OpenID Provider. In
    /// particular, if the OpenID Provider does not support Dynamic Client
    /// Registration, then information on how to register Clients needs to be
    /// provided in this documentation.
    #[serde(default)]
    pub service_documentation: Option<Url>,
    /// The supported claim locales for the OpenID Connect provider.
    ///
    /// Languages and scripts supported for values in Claims being returned,
    /// represented as a JSON array of BCP47 [RFC5646](https://openid.net/specs/openid-connect-discovery-1_0.html#RFC5646) language tag values. Not
    /// all languages and scripts are necessarily supported for all Claim
    /// values.
    #[serde(default)]
    pub claims_locales_supported: Option<Vec<String>>,
    /// The UI locales supported by the OpenID Connect provider.
    ///
    /// Languages and scripts supported for the user interface, represented as a
    /// JSON array of BCP47 [RFC5646](https://openid.net/specs/openid-connect-discovery-1_0.html#RFC5646) language tag values.
    #[serde(default)]
    pub ui_locales_supported: Option<Vec<String>>,
    /// Boolean value specifying whether the OP supports use of the `claims`
    /// parameter, with `true` indicating support. If omitted, the default value
    /// is `false`.
    #[serde(default)]
    pub claims_parameter_supported: bool,
    /// Boolean value specifying whether the OP supports use of the `request`
    /// parameter, with `true` indicating support. If omitted, the default value
    /// is `false`.
    #[serde(default)]
    pub request_parameter_supported: bool,
    /// Boolean value specifying whether the OP supports use of the
    /// `request_uri` parameter, with `true` indicating support. If omitted,
    /// the default value is `false`.
    #[serde(default = "tru")]
    pub request_uri_parameter_supported: bool,
    /// Boolean value specifying whether the OP requires any `request_uri`
    /// values used to be pre-registered using the `request_uris`
    /// registration parameter. Pre-registration is REQUIRED when the value
    /// is `true`. If omitted, the default value is `false`.
    #[serde(default)]
    pub require_request_uri_registration: bool,
    /// URL that the OpenID Provider provides to the person registering the
    /// Client to read about the OP's requirements on how the Relying Party can
    /// use the data provided by the OP. The registration process SHOULD display
    /// this URL to the person registering the Client if it is given.
    #[serde(default)]
    pub op_policy_uri: Option<Url>,
    /// URL that the OpenID Provider provides to the person registering the
    /// Client to read about the OpenID Provider's terms of service. The
    /// registration process SHOULD display this URL to the person registering
    /// the Client if it is given.
    #[serde(default)]
    pub op_tos_uri: Option<Url>,
    /// The end session endpoint of the OpenID Connect provider.
    ///
    /// This is the URL where clients will send a request to invalidate an
    /// existing authorization code. It should be a fully qualified URL and
    /// must include a scheme (such as `http` or `https`) followed by a host,
    /// path, query parameters, and fragment.
    #[serde(default)]
    pub end_session_endpoint: Option<Url>,
    /// The introspection endpoint of the OpenID Connect provider.
    ///
    /// This is the URL where clients will send a request to check the validity
    /// of an access token. It should be a fully qualified URL and must
    /// include a scheme (such as `http` or `https`) followed by a host,
    /// path, query parameters, and fragment.
    #[serde(default)]
    pub introspection_endpoint: Option<Url>,
    /// The code challenge methods supported by the OpenID Connect provider.
    ///
    /// This is an optional list of code challenge method strings that the
    /// service supports. This is a NONSTANDARD extension Google uses that
    /// is a part of the OAuth discovery draft.
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

// This seems really dumb...
fn tru() -> bool {
    true
}

fn empty_string_vec() -> Vec<String> {
    vec![]
}
