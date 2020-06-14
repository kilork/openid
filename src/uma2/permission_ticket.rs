use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Uma2PermissionTicket {
    pub resource_id: String,
    pub resource_scopes: Option<Vec<String>>,
    pub claims: Option<HashMap<String, String>>
}
