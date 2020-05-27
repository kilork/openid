use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Uma2PermissionLogic {
    Positive,
    Negative
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Uma2PermissionDecisionStrategy {
    Unanimous,
    Affirmative,
    Consensus
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Uma2PermissionAssociation {
    pub id: Option<String>,
    pub name: String,
    pub description: String,
    pub scopes: Vec<String>,
    pub roles: Option<Vec<String>>,
    pub groups: Option<Vec<String>>,
    pub clients: Option<Vec<String>>,
    pub owner: Option<String>,
    #[serde(rename = "type")]
    pub permission_type: Option<String>,
    pub logic: Option<Uma2PermissionLogic>,
    #[serde(rename = "decisionStrategy")]
    pub decision_strategy: Option<Uma2PermissionDecisionStrategy>
}
