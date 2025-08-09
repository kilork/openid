use biscuit::CompactJson;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::ClientError,
    uma2::{error::Uma2Error::*, Uma2Provider},
    Claims, Client, OAuth2Error, Provider,
};

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
    /// * `pat_token` A Protection API token (PAT) is like any OAuth2 token, but
    ///   should have the
    /// uma_protection scope defined
    /// * `name` User readable name for this resource.
    /// * `resource_type` The type of resource. Helps to categorise resources
    /// * `icon_uri` User visible icon's URL
    /// * `resource_scopes` A list of scopes attached to this resource
    /// * `description` A readable description
    /// * `owner` Resource server is the default user, unless this value is set.
    ///   Can be the username
    /// of the user or its server identifier
    /// * `owner_managed_access` Whether to allow user managed access of this
    ///   resource
    #[allow(clippy::too_many_arguments)]
    pub async fn create_uma2_resource(
        &self,
        pat_token: String,
        name: String,
        resource_type: impl Into<Option<String>>,
        icon_uri: impl Into<Option<String>>,
        resource_scopes: impl Into<Option<Vec<String>>>,
        display_name: impl Into<Option<String>>,
        owner: impl Into<Option<Uma2Owner>>,
        owner_managed_access: impl Into<Option<bool>>,
    ) -> Result<Uma2Resource, ClientError> {
        let url = self.asserted_uma2_resource_url()?;

        let resource_scopes = resource_scopes.into().map(|names| {
            names
                .iter()
                .map(|name| Uma2ResourceScope {
                    name: Some(name.clone()),
                    id: None,
                })
                .collect()
        });

        let body = Uma2Resource {
            id: None,
            name,
            resource_type: resource_type.into(),
            icon_uri: icon_uri.into(),
            resource_scopes,
            display_name: display_name.into(),
            owner: owner.into(),
            owner_managed_access: owner_managed_access.into(),
        };

        self.post(url, pat_token, body).await
    }

    ///
    /// Update a UMA2 managed resource
    ///
    /// # Arguments
    /// * `pat_token` A Protection API token (PAT) is like any OAuth2 token, but
    ///   should have the
    /// uma_protection scope defined
    /// * `name` User readable name for this resource.
    /// * `resource_type` The type of resource. Helps to categorise resources
    /// * `icon_uri` User visible icon's URL
    /// * `resource_scopes` A list of scopes attached to this resource
    /// * `description` A readable description
    /// * `owner` Resource server is the default user, unless this value is set.
    ///   Can be the username
    /// of the user or its server identifier
    /// * `owner_managed_access` Whether to allow user managed access of this
    ///   resource
    #[allow(clippy::too_many_arguments)]
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
        let url = self.asserted_uma2_resource_url()?;

        let resource_scopes = resource_scopes.map(|names| {
            names
                .iter()
                .map(|name| Uma2ResourceScope {
                    name: Some(name.clone()),
                    id: None,
                })
                .collect()
        });

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

        self.put(url, pat_token, body).await
    }

    /// Deletes a UMA2 managed resource
    ///
    /// # Arguments
    /// * `pat_token` A Protection API token (PAT) is like any OAuth2 token, but
    ///   should have the
    /// * `id` The server identifier of the resource
    pub async fn delete_uma2_resource(
        &self,
        pat_token: String,
        id: String,
    ) -> Result<(), ClientError> {
        let url = self.asserted_uma2_resource_url_id(&id)?;

        self.delete(url, pat_token).await
    }

    /// Get a UMA2 managed resource by its identifier
    ///
    /// # Arguments
    /// * `pat_token` A Protection API token (PAT) is like any OAuth2 token, but
    ///   should have the
    /// * `id` The server identifier of the resource
    pub async fn get_uma2_resource_by_id(
        &self,
        pat_token: String,
        id: String,
    ) -> Result<Uma2Resource, ClientError> {
        let url = self.asserted_uma2_resource_url_id(&id)?;

        self.get(url, pat_token).await
    }

    ///
    /// Search for a UMA2 resource
    ///
    /// # Arguments
    /// * `pat_token` A Protection API token (PAT) is like any OAuth2 token, but
    ///   should have the
    /// * `name` Search by the resource's name
    /// * `uri` Search by the resource's uri
    /// * `owner` Search by the resource's owner
    /// * `resource_type` Search by the resource's type
    /// * `scope` Search by the resource's scope
    pub async fn search_for_uma2_resources(
        &self,
        pat_token: String,
        name: impl Into<Option<String>>,
        uri: impl Into<Option<String>>,
        owner: impl Into<Option<String>>,
        resource_type: impl Into<Option<String>>,
        scope: impl Into<Option<String>>,
    ) -> Result<Vec<String>, ClientError> {
        let mut url = self.asserted_uma2_resource_url()?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(name) = name.into().as_deref() {
                query.append_pair("name", name);
            }
            if let Some(uri) = uri.into().as_deref() {
                query.append_pair("uri", uri);
            }
            if let Some(owner) = owner.into().as_deref() {
                query.append_pair("owner", owner);
            }
            if let Some(resource_type) = resource_type.into().as_deref() {
                query.append_pair("type", resource_type);
            }
            if let Some(scope) = scope.into().as_deref() {
                query.append_pair("scope", scope);
            }
        }

        self.get(url, pat_token).await
    }

    pub(crate) async fn post<T, B>(
        &self,
        url: url::Url,
        token: String,
        body: B,
    ) -> Result<T, ClientError>
    where
        T: DeserializeOwned,
        B: Serialize,
    {
        self.request(url, token, reqwest::Method::POST, body).await
    }

    pub(crate) async fn put<T, B>(
        &self,
        url: url::Url,
        token: String,
        body: B,
    ) -> Result<T, ClientError>
    where
        T: DeserializeOwned,
        B: Serialize,
    {
        self.request(url, token, reqwest::Method::PUT, body).await
    }

    pub(crate) async fn get<T: DeserializeOwned>(
        &self,
        url: url::Url,
        token: String,
    ) -> Result<T, ClientError> {
        let json = self
            .http_client
            .get(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", token))
            .header(ACCEPT, "application/json")
            .send()
            .await?
            .json()
            .await?;

        self.json_to_oauth2_result(json)
    }

    pub(crate) async fn delete(&self, url: url::Url, token: String) -> Result<(), ClientError> {
        let json = self
            .http_client
            .delete(url)
            .header(AUTHORIZATION, format!("Bearer {:}", token))
            .send()
            .await?
            .json()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json);

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            Ok(())
        }
    }

    async fn request<T, B>(
        &self,
        url: url::Url,
        token: String,
        method: reqwest::Method,
        body: B,
    ) -> Result<T, ClientError>
    where
        T: DeserializeOwned,
        B: Serialize,
    {
        let json = self
            .http_client
            .request(method, url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", token))
            .header(ACCEPT, "application/json")
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        self.json_to_oauth2_result(json)
    }

    fn json_to_oauth2_result<T: DeserializeOwned>(&self, json: Value) -> Result<T, ClientError> {
        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            Ok(serde_json::from_value(json)?)
        }
    }

    fn asserted_uma2_resource_url(&self) -> Result<url::Url, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        self.provider
            .resource_registration_uri()
            .cloned()
            .ok_or(ClientError::Uma2(NoResourceSetEndpoint))
    }

    fn asserted_uma2_resource_url_id(&self, id: &str) -> Result<url::Url, ClientError> {
        let mut url = self.asserted_uma2_resource_url()?;

        url.path_segments_mut()
            .map_err(|_| ClientError::Uma2(ResourceSetEndpointMalformed))?
            .extend(&[id]);

        Ok(url)
    }
}
