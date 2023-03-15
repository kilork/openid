use crate::{
    error::ClientError,
    uma2::{error::Uma2Error::*, permission_ticket::Uma2PermissionTicketRequest, *},
    Bearer, Claims, Client, OAuth2Error, Provider,
};

use biscuit::CompactJson;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use url::form_urlencoded::Serializer;

pub enum Uma2AuthenticationMethod {
    Bearer,
    Basic,
}

impl<P, C> Client<P, C>
where
    P: Provider + Uma2Provider,
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
    #[allow(clippy::too_many_arguments)]
    pub async fn obtain_requesting_party_token(
        &self,
        token: String,
        auth_method: Uma2AuthenticationMethod,
        ticket: impl Into<Option<String>>,
        claim_token: impl Into<Option<String>>,
        claim_token_format: impl Into<Option<Uma2ClaimTokenFormat>>,
        rpt: impl Into<Option<String>>,
        permission: impl Into<Option<Vec<String>>>,
        audience: impl Into<Option<String>>,
        response_include_resource_name: impl Into<Option<bool>>,
        response_permissions_limit: impl Into<Option<u32>>,
        submit_request: impl Into<Option<bool>>,
    ) -> Result<String, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        let permission = permission.into();
        let audience = audience.into();
        if let Some(p) = permission.as_ref() {
            if p.is_empty() && audience.is_none() {
                return Err(ClientError::Uma2(AudienceFieldRequired));
            }
        }

        let body = {
            let mut body = Serializer::new(String::new());
            body.append_pair("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
            if let Some(ticket) = ticket.into() {
                body.append_pair("ticket", &ticket);
            }

            if let Some(claim_token) = claim_token.into() {
                body.append_pair("claim_token", &claim_token);
            }

            if let Some(claim_token_format) = claim_token_format.into() {
                body.append_pair(
                    "claim_token_format",
                    claim_token_format.to_string().as_str(),
                );
            }

            if let Some(rpt) = rpt.into() {
                body.append_pair("rpt", &rpt);
            }

            if let Some(permission) = permission {
                permission.iter().for_each(|perm| {
                    body.append_pair("permission", perm.as_str());
                });
            }

            if let Some(audience) = audience {
                body.append_pair("audience", &audience);
            }

            if let Some(response_include_resource_name) = response_include_resource_name.into() {
                body.append_pair(
                    "response_include_resource_name",
                    if response_include_resource_name {
                        "true"
                    } else {
                        "false"
                    },
                );
            }
            if let Some(response_permissions_limit) = response_permissions_limit.into() {
                body.append_pair(
                    "response_permissions_limit",
                    format!("{:}", response_permissions_limit).as_str(),
                );
            }

            if let Some(submit_request) = submit_request.into() {
                body.append_pair("submit_request", format!("{:}", submit_request).as_str());
            }

            body.finish()
        };
        let auth_method = match auth_method {
            Uma2AuthenticationMethod::Basic => format!("Basic {:}", token),
            Uma2AuthenticationMethod::Bearer => format!("Bearer {:}", token),
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
    /// * `requests` A list of resources, optionally with their scopes, optionally with extra claims to be
    ///     processed.
    pub async fn create_uma2_permission_ticket(
        &self,
        pat_token: String,
        requests: Vec<Uma2PermissionTicketRequest>,
    ) -> Result<Uma2PermissionTicketResponse, ClientError> {
        if !self.provider.uma2_discovered() {
            return Err(ClientError::Uma2(NoUma2Discovered));
        }

        let Some(url) = self.provider.permission_uri().cloned() else {
            return Err(ClientError::Uma2(NoPermissionsEndpoint));
        };

        let json = self
            .http_client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {:}", pat_token))
            .json(&requests)
            .send()
            .await?
            .json::<Value>()
            .await?;

        let error: Result<OAuth2Error, _> = serde_json::from_value(json.clone());

        if let Ok(error) = error {
            Err(ClientError::from(error))
        } else {
            let response = serde_json::from_value(json)?;
            Ok(response)
        }
    }
}
