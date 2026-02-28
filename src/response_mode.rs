/// Response mode for returning parameters from the Authorization Endpoint.
///
/// See: [OpenID Connect Core 1.0: Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
#[derive(Debug, Clone, Copy)]
pub enum ResponseMode {
    /// The Authorization Server returns the response using the query component
    /// of the redirect URI. This is the default for the Authorization Code Flow.
    Query,
    /// The Authorization Server returns the response using the fragment component
    /// of the redirect URI. This is the default for the Implicit Flow.
    Fragment,
    /// The Authorization Server returns the response using the HTML form POST
    /// method. This allows sensitive data to be sent via POST body instead of
    /// being exposed in the URL.
    FormPost,
    /// The Authorization Server returns the response using the query component
    /// of the redirect URI. This is equivalent to query but explicitly named
    /// for OAuth 2.0 Form Post response mode.
    QueryJwt,
}

impl ResponseMode {
    pub(crate) fn as_str(&self) -> &'static str {
        use ResponseMode::*;
        match *self {
            Query => "query",
            Fragment => "fragment",
            FormPost => "form_post",
            QueryJwt => "query.jwt",
        }
    }
}
