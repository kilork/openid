use crate::error::ClientError;
use crate::uma2::error::Uma2Error::*;
use crate::uma2::Uma2Provider;
use crate::{Claims, Client, OAuth2Error, Provider};
use biscuit::CompactJson;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    /// Used when permissions can be set to resources by resource servers on behalf of their users
    ///
    /// # Arguments
    /// * `token`   This API is protected by a bearer token that must represent a consent granted by
    ///     the user to the resource server to manage permissions on his behalf. The bearer token
    ///     can be a regular access token obtained from the token endpoint using:
    ///         -  Resource Owner Password Credentials Grant Type
    ///         - Token Exchange, in order to exchange an access token granted to some client
    ///            (public client) for a token where audience is the resource server
    /// * `resource_id` Resource ID to be protected
    /// * `name` Name for the permission
    /// * `description` Description for the permission
    /// * `scopes` A list of scopes given on this resource to the user if the permission validates
    /// * `roles` Give the permission to users in a list of roles
    /// * `groups` Give the permission to users in a list of groups
    /// * `clients` Give the permission to users using a specific list of clients
    /// * `owner` Give the permission to the owner
    /// * `logic` Positive: If the user is in the required groups/roles or using the right client, then
    ///     give the permission to the user. Negative - the inverse
    /// * `decision_strategy` Go through the required conditions. If it is more than one condition,
    ///     give the permission to the user if the following conditions are met:
    ///         - Unanimous: The default strategy if none is provided. In this case, all policies must evaluate
    ///             to a positive decision for the final decision to be also positive.
    ///         - Affirmative: In this case, at least one policy must evaluate to a positive decision
    ///             in order for the final decision to be also positive.
    ///         - Consensus: In this case, the number of positive decisions must be greater than
    ///             the number of negative decisions. If the number of positive and negative
    ///             decisions is the same, the final decision will be negative
    pub async fn associate_uma2_resource_with_a_permission(
        &self,
        token: String,
        resource_id: String,
        name: String,
        description: String,
        scopes: Vec<String>,
        roles: Option<Vec<String>>,
        groups: Option<Vec<String>>,
        clients: Option<Vec<String>>,
        owner: Option<String>,
        logic: Option<Uma2PermissionLogic>,
        decision_strategy: Option<Uma2PermissionDecisionStrategy>,
    ) -> Result<Uma2PermissionAssociation, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.uma_policy_uri().is_none() {
            return Err(ClientError::Uma2(NoPolicyAssociationEndpoint));
        }
        let mut url = self.provider.uma_policy_uri().unwrap().clone();
        url.path_segments_mut()
            .map_err(|_| ClientError::Uma2(PolicyAssociationEndpointMalformed))?
            .extend(&[resource_id]);

        let permission = Uma2PermissionAssociation {
            id: None,
            name,
            description,
            scopes,
            roles,
            groups,
            clients,
            owner,
            permission_type: None,
            logic,
            decision_strategy,
        };

        let json = self
            .http_client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", token))
            .header(ACCEPT, "application/json")
            .json(&permission)
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            let association: Uma2PermissionAssociation = serde_json::from_value(json)?;
            Ok(association)
        }
    }

    /// Update a UMA2 resource's associated permission
    ///
    /// # Arguments
    /// * `id` The ID of the the associated permission
    /// * `token`   This API is protected by a bearer token that must represent a consent granted by
    ///     the user to the resource server to manage permissions on his behalf. The bearer token
    ///     can be a regular access token obtained from the token endpoint using:
    ///         -  Resource Owner Password Credentials Grant Type
    ///         - Token Exchange, in order to exchange an access token granted to some client
    ///            (public client) for a token where audience is the resource server
    /// * `name` Name for the permission
    /// * `description` Description for the permission
    /// * `scopes` A list of scopes given on this resource to the user if the permission validates
    /// * `roles` Give the permission to users in a list of roles
    /// * `groups` Give the permission to users in a list of groups
    /// * `clients` Give the permission to users using a specific list of clients
    /// * `owner` Give the permission to the owner
    /// * `logic` Positive: If the user is in the required groups/roles or using the right client, then
    ///     give the permission to the user. Negative - the inverse
    /// * `decision_strategy` Go through the required conditions. If it is more than one condition,
    ///     give the permission to the user if the following conditions are met:
    ///         - Unanimous: The default strategy if none is provided. In this case, all policies must evaluate
    ///             to a positive decision for the final decision to be also positive.
    ///         - Affirmative: In this case, at least one policy must evaluate to a positive decision
    ///             in order for the final decision to be also positive.
    ///         - Consensus: In this case, the number of positive decisions must be greater than
    ///             the number of negative decisions. If the number of positive and negative
    ///             decisions is the same, the final decision will be negative
    pub async fn update_uma2_resource_permission(
        &self,
        id: String,
        token: String,
        name: String,
        description: String,
        scopes: Vec<String>,
        roles: Option<Vec<String>>,
        groups: Option<Vec<String>>,
        clients: Option<Vec<String>>,
        owner: Option<String>,
        logic: Option<Uma2PermissionLogic>,
        decision_strategy: Option<Uma2PermissionDecisionStrategy>,
    ) -> Result<Uma2PermissionAssociation, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.uma_policy_uri().is_none() {
            return Err(ClientError::Uma2(NoPolicyAssociationEndpoint));
        }

        let mut url = self.provider.uma_policy_uri().unwrap().clone();
        url.path_segments_mut()
            .map_err(|_| ClientError::Uma2(PolicyAssociationEndpointMalformed))?
            .extend(&[&id]);

        let permission = Uma2PermissionAssociation {
            id: Some(id),
            name,
            description,
            scopes,
            roles,
            groups,
            clients,
            owner,
            permission_type: Some("uma".to_string()),
            logic,
            decision_strategy,
        };

        let json = self
            .http_client
            .put(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", token))
            .json(&permission)
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            let association: Uma2PermissionAssociation = serde_json::from_value(json)?;
            Ok(association)
        }
    }

    /// Delete a UMA2 resource's permission
    ///
    /// # Arguments
    /// * `id` The ID of the resource permission
    /// * `token`   This API is protected by a bearer token that must represent a consent granted by
    ///     the user to the resource server to manage permissions on his behalf. The bearer token
    ///     can be a regular access token obtained from the token endpoint using:
    ///         -  Resource Owner Password Credentials Grant Type
    ///         - Token Exchange, in order to exchange an access token granted to some client
    ///            (public client) for a token where audience is the resource server
    pub async fn delete_uma2_resource_permission(
        &self,
        id: String,
        token: String,
    ) -> Result<(), ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.uma_policy_uri().is_none() {
            return Err(ClientError::Uma2(NoPolicyAssociationEndpoint));
        }

        let mut url = self.provider.uma_policy_uri().unwrap().clone();
        url.path_segments_mut()
            .map_err(|_| ClientError::Uma2(PolicyAssociationEndpointMalformed))?
            .extend(&[&id]);

        let json = self
            .http_client
            .delete(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", token))
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json);

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            Ok(())
        }
    }

    /// Search for UMA2 resource associated permissions
    ///
    /// # Arguments
    /// * `token`   This API is protected by a bearer token that must represent a consent granted by
    ///     the user to the resource server to manage permissions on his behalf. The bearer token
    ///     can be a regular access token obtained from the token endpoint using:
    ///         -  Resource Owner Password Credentials Grant Type
    ///         - Token Exchange, in order to exchange an access token granted to some client
    ///            (public client) for a token where audience is the resource server
    /// * `resource` Search by resource id
    /// * `name` Search by name
    /// * `scope` Search by scope
    /// * `offset` Skip n amounts of permissions.
    /// * `count` Max amount of permissions to return. Should be used especially with large return sets
    pub async fn search_for_uma2_resource_permission(
        &self,
        token: String,
        resource: Option<String>,
        name: Option<String>,
        scope: Option<String>,
        offset: Option<u32>,
        count: Option<u32>,
    ) -> Result<Vec<Uma2PermissionAssociation>, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.uma_policy_uri().is_none() {
            return Err(ClientError::Uma2(NoPolicyAssociationEndpoint));
        }

        let mut url = self.provider.uma_policy_uri().unwrap().clone();
        {
            let mut query = url.query_pairs_mut();
            if resource.is_some() {
                query.append_pair("resource", resource.unwrap().as_str());
            }
            if name.is_some() {
                query.append_pair("name", name.unwrap().as_str());
            }
            if scope.is_some() {
                query.append_pair("scope", scope.unwrap().as_str());
            }
            if offset.is_some() {
                query.append_pair("first", format!("{}", offset.unwrap()).as_str());
            }
            if count.is_some() {
                query.append_pair("max", format!("{}", count.unwrap()).as_str());
            }
        }

        let json = self
            .http_client
            .get(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", token))
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            let resource: Vec<Uma2PermissionAssociation> = serde_json::from_value(json)?;
            Ok(resource)
        }
    }
}
