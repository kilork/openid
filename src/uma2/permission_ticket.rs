use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Uma2PermissionTicketRequest {
    pub resource_id: String,
    pub resource_scopes: Option<Vec<String>>,
    pub claims: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Uma2PermissionTicketResponse {
    pub ticket: String,
}
