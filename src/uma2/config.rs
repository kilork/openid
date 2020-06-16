use crate::Config;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub struct Uma2Config {
    // UMA2 additions
    #[serde(default)]
    pub resource_registration_endpoint: Option<Url>,
    #[serde(default)]
    pub permission_endpoint: Option<Url>,
    #[serde(default)]
    pub policy_endpoint: Option<Url>,
    #[serde(default)]
    pub introspection_endpoint: Option<Url>,

    #[serde(flatten)]
    pub config: Config,
}
