use serde::{Deserialize, Serialize};
use url::Url;

// TODO I wish we could impl default for this, but you cannot have a config without issuer etc
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub issuer: Url,
    pub authorization_endpoint: Url,
    // Only optional in the implicit flow
    // TODO For now, we only support code flows.
    pub token_endpoint: Url,
    #[serde(default)]
    pub token_introspection_endpoint: Option<Url>,
    #[serde(default)]
    pub userinfo_endpoint: Option<Url>,
    #[serde(default)]
    pub end_session_endpoint: Option<Url>,
    pub jwks_uri: Url,
    #[serde(default)]
    pub registration_endpoint: Option<Url>,
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
    // There are only three valid response types, plus combinations of them, and none
    // If we want to make these user friendly we want a struct to represent all 7 types
    pub response_types_supported: Vec<String>,
    // There are only two possible values here, query and fragment. Default is both.
    #[serde(default)]
    pub response_modes_supported: Option<Vec<String>>,
    // Must support at least authorization_code and implicit.
    #[serde(default)]
    pub grant_types_supported: Option<Vec<String>>,
    #[serde(default)]
    pub acr_values_supported: Option<Vec<String>>,
    // pairwise and public are valid by spec, but servers can add more
    #[serde(default = "empty_string_vec")]
    pub subject_types_supported: Vec<String>,
    // Must include at least RS256, none is only allowed with response types without id tokens
    #[serde(default = "empty_string_vec")]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    // Spec options are client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt
    // If omitted, client_secret_basic is used
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    // Only wanted with jwt auth methods, should have RS256, none not allowed
    #[serde(default)]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub display_values_supported: Option<Vec<String>>,
    // Valid options are normal, aggregated, and distributed. If omitted, only use normal
    #[serde(default)]
    pub claim_types_supported: Option<Vec<String>>,
    #[serde(default)]
    pub claims_supported: Option<Vec<String>>,
    #[serde(default)]
    pub service_documentation: Option<Url>,
    #[serde(default)]
    pub claims_locales_supported: Option<Vec<String>>,
    #[serde(default)]
    pub ui_locales_supported: Option<Vec<String>>,
    #[serde(default)]
    pub claims_parameter_supported: bool,
    #[serde(default)]
    pub request_parameter_supported: bool,
    #[serde(default = "tru")]
    pub request_uri_parameter_supported: bool,
    #[serde(default)]
    pub require_request_uri_registration: bool,

    #[serde(default)]
    pub op_policy_uri: Option<Url>,
    #[serde(default)]
    pub op_tos_uri: Option<Url>,
    // This is a NONSTANDARD extension Google uses that is a part of the Oauth discovery draft
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
