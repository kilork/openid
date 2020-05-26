use crate::{Client, Provider, Claims, OAuth2Error, Bearer};
use biscuit::CompactJson;
use url::{form_urlencoded::Serializer};
use serde::{Deserialize, Serialize};
use crate::error::ClientError;
use crate::error::Uma2Error::{NoUma2Discovered, AudienceFieldRequired, NoResourceSetEndpoint, ResourceSetEndpointMalformed, NoPermissionsEndpoint, NoPolicyAssociationEndpoint, PolicyAssociationEndpointMalformed};
use reqwest::header::{CONTENT_TYPE, AUTHORIZATION};
use serde_json::Value;
use core::fmt;
use serde::export::Formatter;

/// UMA2 claim token format
/// Either is an access token (urn:ietf:params:oauth:token-type:jwt) or an OIDC ID token
pub enum Uma2ClaimTokenFormat {
    OAuthJwt, // urn:ietf:params:oauth:token-type:jwt
    OidcIdToken // https://openid.net/specs/openid-connect-core-1_0.html#IDToken
}

impl fmt::Display for Uma2ClaimTokenFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}",
               match *self {
                   Uma2ClaimTokenFormat::OAuthJwt => "urn:ietf:params:oauth:token-type:jwt",
                   Uma2ClaimTokenFormat::OidcIdToken => "https://openid.net/specs/openid-connect-core-1_0.html#IDToken",
               }
        )
    }
}

pub enum Uma2AuthenticationMethod {
    Bearer,
    Basic
}

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

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Uma2Resource {
    #[serde(rename = "_id")]
    id: Option<String>,
    name: String,
    #[serde(rename = "type")]
    resource_type: Option<String>,
    icon_uri: Option<String>,
    resource_scopes: Option<Vec<String>>,
    description: Option<String>,
    owner: Option<String>,
    #[serde(rename = "ownerManagedAccess")]
    owner_managed_access: Option<bool>
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Uma2PermissionTicket<T>
    where T: Serialize + core::fmt::Debug + Clone + PartialEq + Eq {
    resource_id: String,
    resource_scopes: Option<Vec<String>>,
    claims: Option<T>
}

impl<P, C> Client<P, C>
    where
        P: Provider,
        C: CompactJson + Claims,
{
    ///
    /// Obtain an RPT from a UMA2 compliant OIDC server
    ///
    ///  # Arguments
    /// * `token` Bearer token to do the RPT call
    /// * `ticket` The most recent permission ticket received by the client as part of the UMA authorization process
    /// * `claim_token` A string representing additional claims that should be considered by the
    ///     server when evaluating permissions for the resource(s) and scope(s) being requested.
    /// * `claim_token_format` urn:ietf:params:oauth:token-type:jwt or https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    /// * `rpt` A previously issued RPT which permissions should also be evaluated and added in a
    ///     new one. This parameter allows clients in possession of an RPT to perform incremental
    ///     authorization where permissions are added on demand.
    /// * `permission` String representing a set of one or more resources and scopes the client is
    ///     seeking access. This parameter can be defined multiple times in order to request
    ///     permission for multiple resource and scopes. This parameter is an extension to
    ///     urn:ietf:params:oauth:grant-type:uma-ticket grant type in order to allow clients to
    ///     send authorization requests without a permission ticket
    /// * `audience` The client identifier of the resource server to which the client is seeking
    ///  access. This parameter is mandatory in case the permission parameter is defined
    /// * `response_include_resource_name` A boolean value indicating to the server whether
    ///     resource names should be included in the RPT’s permissions. If false, only the
    ///     resource identifier is included
    /// * `response_permissions_limit` An integer N that defines a limit for the amount of
    ///     permissions an RPT can have. When used together with rpt parameter, only the last N
    ///     requested permissions will be kept in the RPT.
    /// * `submit_request` A boolean value indicating whether the server should create permission
    ///     requests to the resources and scopes referenced by a permission ticket. This parameter
    ///     only have effect if used together with the ticket parameter as part of a UMA authorization process
    pub async fn obtain_requesting_party_token(
        &self,
        token: String,
        auth_method: Uma2AuthenticationMethod,
        ticket: Option<String>,
        claim_token: Option<String>,
        claim_token_format: Option<Uma2ClaimTokenFormat>,
        rpt: Option<String>,
        permission: Option<Vec<String>>,
        audience: Option<String>,
        response_include_resource_name: Option<bool>,
        response_permissions_limit: Option<u32>,
        submit_request: Option<bool>
    ) -> Result<String, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if let Some(p) = permission.as_ref() {
            if p.is_empty() && audience.is_none() {
                return Err(ClientError::Uma2(AudienceFieldRequired));
            }
        }

        let mut body = Serializer::new(String::new());
        body.append_pair("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
        if ticket.is_some() {
            body.append_pair("ticket", ticket.unwrap().as_str());
        }

        if claim_token.is_some() {
            body.append_pair("claim_token", claim_token.unwrap().as_str());
        }

        if claim_token_format.is_some() {
            body.append_pair("claim_token_format", claim_token_format.map(|b| b.to_string()).unwrap().as_str());
        }

        if rpt.is_some() {
            body.append_pair("rpt", rpt.unwrap().as_str());
        }

        if permission.is_some() {
            permission.unwrap().iter().for_each(|perm| {
                body.append_pair("permission", perm.as_str());
            });
        }

        if audience.is_some() {
            body.append_pair("audience", audience.unwrap().as_str());
        }

        if response_include_resource_name.is_some() {
            body.append_pair(
                "response_include_resource_name",
                response_include_resource_name.map(|b| if b { "true" } else { "false" }).unwrap()
            );
        }
        if response_permissions_limit.is_some() {
            body.append_pair(
                "response_permissions_limit",
                format!("{:}", response_permissions_limit.unwrap()).as_str()
            );
        }

        if submit_request.is_some() {
            body.append_pair(
                "submit_request",
                format!("{:}", submit_request.unwrap()).as_str()
            );
        }

        let body = body.finish();
        let auth_method = match auth_method {
            Uma2AuthenticationMethod::Basic => format!("Basic {:}", token),
            Uma2AuthenticationMethod::Bearer => format!("Bearer {:}", token)
        };

        let json = self
            .http_client
            .post(self.provider.token_uri().clone())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, auth_method.as_str())
            .body(body)
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            let new_token: Bearer = serde_json::from_value(json)?;
            Ok(new_token.access_token)
        }
    }

    ///
    /// Create a UMA2 managed resource
    ///
    /// # Arguments
    /// * `pat_token` A Protection API token (PAT) is like any OAuth2 token, but should have the
    /// uma_protection scope defined
    /// * `name` User readable name for this resource.
    /// * `resource_type` The type of resource. Helps to categorise resources
    /// * `icon_uri` User visible icon's URL
    /// * `resource_scopes` A list of scopes attached to this resource
    /// * `description` A readable description
    /// * `owner` Resource server is the default user, unless this value is set. Can be the username
    /// of the user or its server identifier
    /// * `owner_managed_access` Whether to allow user managed access of this resource
    pub async fn create_uma2_resource(
        &self,
        pat_token: String,
        name: String,
        resource_type: Option<String>,
        icon_uri: Option<String>,
        resource_scopes: Option<Vec<String>>,
        description: Option<String>,
        owner: Option<String>,
        owner_managed_access: Option<bool>
    ) -> Result<Uma2Resource, ClientError> {

        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.resource_registration_uri().is_none() {
            return Err(ClientError::Uma2(NoResourceSetEndpoint));
        }

        let url = self.provider.resource_registration_uri().unwrap().clone();

        let body = Uma2Resource {
            id: None,
            name,
            resource_type,
            icon_uri,
            resource_scopes,
            description,
            owner,
            owner_managed_access
        };

        let json = self
            .http_client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", pat_token))
            .json(&body)
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            let resource: Uma2Resource = serde_json::from_value(json)?;
            Ok(resource)
        }
    }

    ///
    /// Update a UMA2 managed resource
    ///
    /// # Arguments
    /// * `pat_token` A Protection API token (PAT) is like any OAuth2 token, but should have the
    /// uma_protection scope defined
    /// * `name` User readable name for this resource.
    /// * `resource_type` The type of resource. Helps to categorise resources
    /// * `icon_uri` User visible icon's URL
    /// * `resource_scopes` A list of scopes attached to this resource
    /// * `description` A readable description
    /// * `owner` Resource server is the default user, unless this value is set. Can be the username
    /// of the user or its server identifier
    /// * `owner_managed_access` Whether to allow user managed access of this resource
    pub async fn update_uma2_resource(
        &self,
        pat_token: String,
        name: String,
        resource_type: Option<String>,
        icon_uri: Option<String>,
        resource_scopes: Option<Vec<String>>,
        description: Option<String>,
        owner: Option<String>,
        owner_managed_access: Option<bool>
    ) -> Result<Uma2Resource, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.resource_registration_uri().is_none() {
            return Err(ClientError::Uma2(NoResourceSetEndpoint));
        }

        let url = self.provider.resource_registration_uri().unwrap().clone();

        let body = Uma2Resource {
            id: None,
            name,
            resource_type,
            icon_uri,
            resource_scopes,
            description,
            owner,
            owner_managed_access
        };

        let json = self
            .http_client
            .put(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", pat_token))
            .json(&body)
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            let resource: Uma2Resource = serde_json::from_value(json)?;
            Ok(resource)
        }
    }

    /// Deletes a UMA2 managed resource
    ///
    /// # Arguments
    /// * `pat_token` A Protection API token (PAT) is like any OAuth2 token, but should have the
    /// * `id` The server identifier of the resource
    pub async fn delete_uma2_resource(&self, pat_token: String, id: String) -> Result<(), ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.resource_registration_uri().is_none() {
            return Err(ClientError::Uma2(NoResourceSetEndpoint));
        }

        let mut url = self.provider.resource_registration_uri().unwrap().clone();

        url.path_segments_mut()
            .map_err(|_| ClientError::Uma2(ResourceSetEndpointMalformed))?
            .extend(&[id]);

        let json = self
            .http_client
            .delete(url)
            .header(AUTHORIZATION, format!("Bearer {:}", pat_token))
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

    /// Get a UMA2 managed resource by its identifier
    ///
    /// # Arguments
    /// * `pat_token` A Protection API token (PAT) is like any OAuth2 token, but should have the
    /// * `id` The server identifier of the resource
    pub async fn get_uma2_resource_by_id(&self, pat_token: String, id: String) -> Result<Uma2Resource, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.resource_registration_uri().is_none() {
            return Err(ClientError::Uma2(NoResourceSetEndpoint));
        }

        let mut url = self.provider.resource_registration_uri().unwrap().clone();

        url.path_segments_mut()
            .map_err(|_| ClientError::Uma2(ResourceSetEndpointMalformed))?
            .extend(&[id]);

        let json = self
            .http_client
            .get(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", pat_token))
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            let resource: Uma2Resource = serde_json::from_value(json)?;
            Ok(resource)
        }
    }

    ///
    /// Search for a UMA2 resource
    ///
    /// # Arguments
    /// * `pat_token` A Protection API token (PAT) is like any OAuth2 token, but should have the
    /// * `name` Search by the resource's name
    /// * `uri` Search by the resource's uri
    /// * `owner` Search by the resource's owner
    /// * `resource_type` Search by the resource's type
    /// * `scope` Search by the resource's scope
    ///
    pub async fn search_for_uma2_resources(
        &self,
        pat_token: String,
        name: Option<String>,
        uri: Option<String>,
        owner: Option<String>,
        resource_type: Option<String>,
        scope: Option<String>
    ) -> Result<Vec<Uma2Resource>, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.resource_registration_uri().is_none() {
            return Err(ClientError::Uma2(NoResourceSetEndpoint));
        }

        let mut url = self.provider.resource_registration_uri().unwrap().clone();
        {
            let mut query = url.query_pairs_mut();
            if name.is_some() {
                query.append_pair("name", name.unwrap().as_str());
            }
            if uri.is_some() {
                query.append_pair("uri", uri.unwrap().as_str());
            }
            if owner.is_some() {
                query.append_pair("owner", owner.unwrap().as_str());
            }
            if resource_type.is_some() {
                query.append_pair("type", resource_type.unwrap().as_str());
            }
            if scope.is_some() {
                query.append_pair("scope", scope.unwrap().as_str());
            }
        }

        let json = self
            .http_client
            .get(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", pat_token))
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            let resources: Vec<Uma2Resource> = serde_json::from_value(json)?;
            Ok(resources)
        }
    }

    ///
    /// Create a permission ticket.
    /// A permission ticket is a special security token type representing a permission request.
    /// Per the UMA specification, a permission ticket is:
    /// A correlation handle that is conveyed from an authorization server to a resource server,
    /// from a resource server to a client, and ultimately from a client back to an authorization
    /// server, to enable the authorization server to assess the correct policies to apply to a
    /// request for authorization data.
    ///
    /// # Arguments
    /// * `pat_token` A Protection API token (PAT) is like any OAuth2 token, but should have the
    /// * `resource_id` The resource's Id for which the ticket needs to be created for
    /// * `resource_scopes` A list of scopes that should be attached to the ticket
    /// * `claims` A set of claims that can be added for the authentication server to check whether such
    ///     a ticket should be allowed to be created
    pub async fn create_uma2_permission_ticket<T>(
        &self,
        pat_token: String,
        resource_id: String,
        resource_scopes: Option<Vec<String>>,
        claims: Option<T>
    ) -> Result<(), ClientError>
        where T: Serialize + core::fmt::Debug + Clone + PartialEq + Eq {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.permission_uri().is_none() {
            return Err(ClientError::Uma2(NoPermissionsEndpoint));
        }
        let url = self.provider.permission_uri().unwrap().clone();

        let ticket = Uma2PermissionTicket {
            resource_id,
            resource_scopes,
            claims
        };

        let json = self
            .http_client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", pat_token))
            .json(&ticket)
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json);

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            // TODO need to inspect the return of this to return something proper
            Ok(())
        }
    }

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
        decision_strategy: Option<Uma2PermissionDecisionStrategy>
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
            decision_strategy
        };

        let json = self
            .http_client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", token))
            .json(&permission)
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json);

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            // TODO need to inspect the return of this to return something proper
            Ok(())
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
        decision_strategy: Option<Uma2PermissionDecisionStrategy>
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
            decision_strategy
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

        let error: Result<OAuth2Error, _> = serde_json::from_value(json);

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            // TODO need to inspect the return of this to return something proper
            Ok(())
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
        token: String
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
            // TODO need to inspect the return of this to return something proper
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
        count: Option<u32>
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
