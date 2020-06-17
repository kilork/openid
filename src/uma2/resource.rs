use crate::error::ClientError;
use crate::uma2::error::Uma2Error::*;
use crate::uma2::Uma2Provider;
use crate::{Claims, Client, OAuth2Error, Provider};
use biscuit::CompactJson;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Uma2Resource {
    #[serde(rename = "_id")]
    pub id: Option<String>,
    pub name: String,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    pub icon_uri: Option<String>,
    pub resource_scopes: Option<Vec<Uma2ResourceScope>>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub owner: Option<Uma2Owner>,
    #[serde(rename = "ownerManagedAccess")]
    pub owner_managed_access: Option<bool>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Uma2ResourceScope {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Uma2Owner {
    pub id: Option<String>,
    pub name: Option<String>,
}

impl<P, C> Client<P, C>
where
    P: Provider + Uma2Provider,
    C: CompactJson + Claims,
{
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
        display_name: Option<String>,
        owner: Option<Uma2Owner>,
        owner_managed_access: Option<bool>,
    ) -> Result<Uma2Resource, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.resource_registration_uri().is_none() {
            return Err(ClientError::Uma2(NoResourceSetEndpoint));
        }

        let resource_scopes = resource_scopes.map(|names| {
            names
                .iter()
                .map(|name| Uma2ResourceScope {
                    name: Some(name.clone()),
                    id: None,
                })
                .collect()
        });

        let url = self.provider.resource_registration_uri().unwrap().clone();

        let body = Uma2Resource {
            id: None,
            name,
            resource_type,
            icon_uri,
            resource_scopes,
            display_name,
            owner,
            owner_managed_access,
        };

        let json = self
            .http_client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", pat_token))
            .header(ACCEPT, "application/json")
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
        display_name: Option<String>,
        owner: Option<Uma2Owner>,
        owner_managed_access: Option<bool>,
    ) -> Result<Uma2Resource, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        if self.provider.resource_registration_uri().is_none() {
            return Err(ClientError::Uma2(NoResourceSetEndpoint));
        }

        let resource_scopes = resource_scopes.map(|names| {
            names
                .iter()
                .map(|name| Uma2ResourceScope {
                    name: Some(name.clone()),
                    id: None,
                })
                .collect()
        });

        let url = self.provider.resource_registration_uri().unwrap().clone();

        let body = Uma2Resource {
            id: None,
            name,
            resource_type,
            icon_uri,
            resource_scopes,
            display_name,
            owner,
            owner_managed_access,
        };

        let json = self
            .http_client
            .put(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", pat_token))
            .header(ACCEPT, "application/json")
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
    pub async fn delete_uma2_resource(
        &self,
        pat_token: String,
        id: String,
    ) -> Result<(), ClientError> {
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
    pub async fn get_uma2_resource_by_id(
        &self,
        pat_token: String,
        id: String,
    ) -> Result<Uma2Resource, ClientError> {
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
        scope: Option<String>,
    ) -> Result<Vec<String>, ClientError> {
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
            .header(ACCEPT, "application/json")
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            let resources: Vec<String> = serde_json::from_value(json)?;
            Ok(resources)
        }
    }
}
