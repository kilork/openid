use crate::{Client, Provider, Claims, OAuth2Error, Bearer};
use biscuit::CompactJson;
use url::{form_urlencoded::Serializer};
use serde::{Deserialize, Serialize};
use crate::error::ClientError;
use crate::error::Uma2Error::{NoUma2Discovered, AudienceFieldRequired, NoResourceSetEndpoint, ResourceSetEndpointMalformed, NoPermissionsEndpoint};
use reqwest::header::{CONTENT_TYPE, AUTHORIZATION};
use serde_json::Value;

/// UMA2 claim token format
/// Either is an access token (urn:ietf:params:oauth:token-type:jwt) or an OIDC ID token
pub enum Uma2ClaimTokenFormat {
    OAuthJwt, // urn:ietf:params:oauth:token-type:jwt
    OidcIdToken // https://openid.net/specs/openid-connect-core-1_0.html#IDToken
}

pub enum Uma2AuthenticationMethod {
    Bearer,
    Basic
}

impl ToString for Uma2ClaimTokenFormat {
    fn to_string(&self) -> String {
        if let Uma2ClaimTokenFormat::OAuthJwt = *self {
            String::from("urn:ietf:params:oauth:token-type:jwt")
        } else {
            String::from("https://openid.net/specs/openid-connect-core-1_0.html#IDToken")
        }
    }
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

        if !self.provider.resource_registration_uri().is_none() {
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

        if !self.provider.resource_registration_uri().is_none() {
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

        if !self.provider.resource_registration_uri().is_none() {
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

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

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

        if !self.provider.resource_registration_uri().is_none() {
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

        if !self.provider.resource_registration_uri().is_none() {
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

        if !self.provider.permission_uri().is_none() {
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

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            // TODO need to inspect the return of this to return something proper
            Ok(())
        }
    }

}
