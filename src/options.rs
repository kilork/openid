use crate::{Display, Prompt};
use chrono::Duration;
use std::collections::HashSet;

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
    pub prompt: Option<HashSet<Prompt>>,
    pub max_age: Option<Duration>,
    pub ui_locales: Option<String>,
    pub claims_locales: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub acr_values: Option<String>,
}
