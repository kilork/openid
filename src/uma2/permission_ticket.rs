use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Uma2PermissionTicket<T>
    where T: Serialize + core::fmt::Debug + Clone + PartialEq + Eq {
    pub resource_id: String,
    pub resource_scopes: Option<Vec<String>>,
    pub claims: Option<T>
}
