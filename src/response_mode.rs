/// Response mode for returning parameters from the Authorization Endpoint.
///
/// See: [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
#[derive(Debug, Clone, Copy)]
pub enum ResponseMode {
    /// The Authorization Server returns the response using the query component
    /// of the redirect URI. This is the default for the Authorization Code Flow
    /// and the `none` response type.
    Query,
    /// The Authorization Server returns the response using the fragment component
    /// of the redirect URI. This is the default for the Implicit Flow (`token`
    /// and `id_token` response types).
    Fragment,
    /// The Authorization Server returns the response using the HTML form POST
    /// method. This allows sensitive data to be sent via POST body instead of
    /// being exposed in the URL.
    FormPost,
}

impl ResponseMode {
    pub(crate) fn as_str(&self) -> &'static str {
        use ResponseMode::*;
        match *self {
            Query => "query",
            Fragment => "fragment",
            FormPost => "form_post",
        }
    }
}
