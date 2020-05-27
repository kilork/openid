use url::Url;

pub trait Uma2Provider {
    /// Whether UMA2 capabilities have been discovered
    fn uma2_discovered(&self) -> bool;

    /// UMA-compliant Resource Registration Endpoint which resource servers can use to manage their
    /// protected resources and scopes. This endpoint provides operations create, read, update and
    /// delete resources and scopes
    fn resource_registration_uri(&self) -> Option<&Url>;

    /// UMA-compliant Permission Endpoint which resource servers can use to manage permission
    /// tickets. This endpoint provides operations create, read, update, and delete permission tickets
    fn permission_uri(&self) -> Option<&Url>;

    /// API from where permissions can be set to resources by resource servers on behalf of their users.
    fn uma_policy_uri(&self) -> Option<&Url>;
}
