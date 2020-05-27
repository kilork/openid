
#[derive(Debug)]
pub enum Uma2Error {
    NoUma2Discovered,
    AudienceFieldRequired,
    NoResourceSetEndpoint,
    NoPermissionsEndpoint,
    NoPolicyAssociationEndpoint,
    ResourceSetEndpointMalformed,
    PolicyAssociationEndpointMalformed
}

impl std::error::Error for Uma2Error {
    fn description(&self) -> &str {
        "UMA2 API error"
    }
}

impl std::fmt::Display for Uma2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}",
               match *self {
                   Uma2Error::NoUma2Discovered => "No UMA2 discovered",
                   Uma2Error::AudienceFieldRequired => "Audience field required",
                   Uma2Error::NoResourceSetEndpoint => "No resource_set endpoint discovered",
                   Uma2Error::NoPermissionsEndpoint => "No permissions endpoint discovered",
                   Uma2Error::NoPolicyAssociationEndpoint => "No permissions policy association endpoint discovered",
                   Uma2Error::ResourceSetEndpointMalformed => "resource_set endpoint is malformed",
                   Uma2Error::PolicyAssociationEndpointMalformed => "policy_endpoint is malformed"
               }
        )
    }
}
