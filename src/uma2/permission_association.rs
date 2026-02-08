use biscuit::CompactJson;
use serde::{Deserialize, Serialize};

use crate::{
    Claims, Client, Provider,
    error::ClientError,
    uma2::{Uma2Provider, error::Uma2Error::*},
};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Uma2PermissionLogic {
    Positive,
    Negative,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Uma2PermissionDecisionStrategy {
    Unanimous,
    Affirmative,
    Consensus,
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
    pub decision_strategy: Option<Uma2PermissionDecisionStrategy>,
}

impl<P, C> Client<P, C>
where
    P: Provider + Uma2Provider,
    C: CompactJson + Claims,
{
    /// Used when permissions can be set to resources by resource servers on
    /// behalf of their users
    ///
    /// # Arguments
    /// * `token`   This API is protected by a bearer token that must represent
    ///   a consent granted by the user to the resource server to manage
    ///   permissions on his behalf. The bearer token can be a regular access
    ///   token obtained from the token endpoint using:
    ///         - Resource Owner Password Credentials Grant Type
    ///         - Token Exchange, in order to exchange an access token granted
    ///           to some client (public client) for a token where audience is
    ///           the resource server
    /// * `resource_id` Resource ID to be protected
    /// * `name` Name for the permission
    /// * `description` Description for the permission
    /// * `scopes` A list of scopes given on this resource to the user if the
    ///   permission validates
    /// * `roles` Give the permission to users in a list of roles
    /// * `groups` Give the permission to users in a list of groups
    /// * `clients` Give the permission to users using a specific list of
    ///   clients
    /// * `owner` Give the permission to the owner
    /// * `logic` Positive: If the user is in the required groups/roles or using
    ///   the right client, then give the permission to the user. Negative - the
    ///   inverse
    /// * `decision_strategy` Go through the required conditions. If it is more
    ///   than one condition, give the permission to the user if the following
    ///   conditions are met:
    ///         - Unanimous: The default strategy if none is provided. In this
    ///           case, all policies must evaluate to a positive decision for
    ///           the final decision to be also positive.
    ///         - Affirmative: In this case, at least one policy must evaluate
    ///           to a positive decision in order for the final decision to be
    ///           also positive.
    ///         - Consensus: In this case, the number of positive decisions must
    ///           be greater than the number of negative decisions. If the
    ///           number of positive and negative decisions is the same, the
    ///           final decision will be negative
    #[allow(clippy::too_many_arguments)]
    pub async fn associate_uma2_resource_with_a_permission(
        &self,
        token: String,
        resource_id: String,
        name: String,
        description: String,
        scopes: Vec<String>,
        roles: impl Into<Option<Vec<String>>>,
        groups: impl Into<Option<Vec<String>>>,
        clients: impl Into<Option<Vec<String>>>,
        owner: impl Into<Option<String>>,
        logic: impl Into<Option<Uma2PermissionLogic>>,
        decision_strategy: impl Into<Option<Uma2PermissionDecisionStrategy>>,
    ) -> Result<Uma2PermissionAssociation, ClientError> {
        let url = self.asserted_uma2_policy_url_id(&resource_id)?;

        let permission = Uma2PermissionAssociation {
            id: None,
            name,
            description,
            scopes,
            roles: roles.into(),
            groups: groups.into(),
            clients: clients.into(),
            owner: owner.into(),
            permission_type: None,
            logic: logic.into(),
            decision_strategy: decision_strategy.into(),
        };

        self.post(url, token, permission).await
    }

    /// Update a UMA2 resource's associated permission
    ///
    /// # Arguments
    /// * `id` The ID of the the associated permission
    /// * `token`   This API is protected by a bearer token that must represent
    ///   a consent granted by the user to the resource server to manage
    ///   permissions on his behalf. The bearer token can be a regular access
    ///   token obtained from the token endpoint using:
    ///         - Resource Owner Password Credentials Grant Type
    ///         - Token Exchange, in order to exchange an access token granted
    ///           to some client (public client) for a token where audience is
    ///           the resource server
    /// * `name` Name for the permission
    /// * `description` Description for the permission
    /// * `scopes` A list of scopes given on this resource to the user if the
    ///   permission validates
    /// * `roles` Give the permission to users in a list of roles
    /// * `groups` Give the permission to users in a list of groups
    /// * `clients` Give the permission to users using a specific list of
    ///   clients
    /// * `owner` Give the permission to the owner
    /// * `logic` Positive: If the user is in the required groups/roles or using
    ///   the right client, then give the permission to the user. Negative - the
    ///   inverse
    /// * `decision_strategy` Go through the required conditions. If it is more
    ///   than one condition, give the permission to the user if the following
    ///   conditions are met:
    ///         - Unanimous: The default strategy if none is provided. In this
    ///           case, all policies must evaluate to a positive decision for
    ///           the final decision to be also positive.
    ///         - Affirmative: In this case, at least one policy must evaluate
    ///           to a positive decision in order for the final decision to be
    ///           also positive.
    ///         - Consensus: In this case, the number of positive decisions must
    ///           be greater than the number of negative decisions. If the
    ///           number of positive and negative decisions is the same, the
    ///           final decision will be negative
    #[allow(clippy::too_many_arguments)]
    pub async fn update_uma2_resource_permission(
        &self,
        id: String,
        token: String,
        name: String,
        description: String,
        scopes: Vec<String>,
        roles: impl Into<Option<Vec<String>>>,
        groups: impl Into<Option<Vec<String>>>,
        clients: impl Into<Option<Vec<String>>>,
        owner: impl Into<Option<String>>,
        logic: impl Into<Option<Uma2PermissionLogic>>,
        decision_strategy: impl Into<Option<Uma2PermissionDecisionStrategy>>,
    ) -> Result<Uma2PermissionAssociation, ClientError> {
        let url = self.asserted_uma2_policy_url_id(&id)?;

        let permission = Uma2PermissionAssociation {
            id: Some(id),
            name,
            description,
            scopes,
            roles: roles.into(),
            groups: groups.into(),
            clients: clients.into(),
            owner: owner.into(),
            permission_type: Some("uma".to_string()),
            logic: logic.into(),
            decision_strategy: decision_strategy.into(),
        };

        self.put(url, token, permission).await
    }

    /// Delete a UMA2 resource's permission
    ///
    /// # Arguments
    /// * `id` The ID of the resource permission
    /// * `token`   This API is protected by a bearer token that must represent
    ///   a consent granted by the user to the resource server to manage
    ///   permissions on his behalf. The bearer token can be a regular access
    ///   token obtained from the token endpoint using:
    ///         - Resource Owner Password Credentials Grant Type
    ///         - Token Exchange, in order to exchange an access token granted
    ///           to some client (public client) for a token where audience is
    ///           the resource server
    pub async fn delete_uma2_resource_permission(
        &self,
        id: String,
        token: String,
    ) -> Result<(), ClientError> {
        let url = self.asserted_uma2_policy_url_id(&id)?;

        self.delete(url, token).await
    }

    /// Search for UMA2 resource associated permissions
    ///
    /// # Arguments
    /// * `token`   This API is protected by a bearer token that must represent
    ///   a consent granted by the user to the resource server to manage
    ///   permissions on his behalf. The bearer token can be a regular access
    ///   token obtained from the token endpoint using:
    ///         - Resource Owner Password Credentials Grant Type
    ///         - Token Exchange, in order to exchange an access token granted
    ///           to some client (public client) for a token where audience is
    ///           the resource server
    /// * `resource` Search by resource id
    /// * `name` Search by name
    /// * `scope` Search by scope
    /// * `offset` Skip n amounts of permissions.
    /// * `count` Max amount of permissions to return. Should be used especially
    ///   with large return sets
    pub async fn search_for_uma2_resource_permission(
        &self,
        token: String,
        resource: impl Into<Option<String>>,
        name: impl Into<Option<String>>,
        scope: impl Into<Option<String>>,
        offset: impl Into<Option<u32>>,
        count: impl Into<Option<u32>>,
    ) -> Result<Vec<Uma2PermissionAssociation>, ClientError> {
        let mut url = self.asserted_uma2_policy_url()?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(resource) = resource.into().as_deref() {
                query.append_pair("resource", resource);
            }
            if let Some(name) = name.into().as_deref() {
                query.append_pair("name", name);
            }
            if let Some(scope) = scope.into().as_deref() {
                query.append_pair("scope", scope);
            }
            if let Some(offset) = offset.into() {
                query.append_pair("first", &format!("{offset}"));
            }
            if let Some(count) = count.into() {
                query.append_pair("max", &format!("{count}"));
            }
        }

        self.get(url, token).await
    }

    fn asserted_uma2_policy_url(&self) -> Result<url::Url, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        self.provider
            .uma_policy_uri()
            .cloned()
            .ok_or(ClientError::Uma2(NoPolicyAssociationEndpoint))
    }

    fn asserted_uma2_policy_url_id(&self, id: &str) -> Result<url::Url, ClientError> {
        let mut url = self.asserted_uma2_policy_url()?;
        url.path_segments_mut()
            .map_err(|_| ClientError::Uma2(PolicyAssociationEndpointMalformed))?
            .extend(&[id]);
        Ok(url)
    }
}
