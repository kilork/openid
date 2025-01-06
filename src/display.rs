/// The four values for the preferred `display` parameter in the Options. See
/// spec for details.
///
/// See: [OpenID Connect Core 1.0: Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
#[derive(Debug, Clone, Copy)]
pub enum Display {
    /// The Authorization Server SHOULD display the authentication and consent
    /// UI consistent with a full User Agent page view. If the display parameter
    /// is not specified, this is the default display mode.
    Page,
    /// The Authorization Server SHOULD display the authentication and consent
    /// UI consistent with a popup User Agent window. The popup User Agent
    /// window should be of an appropriate size for a login-focused dialog and
    /// should not obscure the entire window that it is popping up over.
    Popup,
    /// The Authorization Server SHOULD display the authentication and consent
    /// UI consistent with a device that leverages a touch interface.
    Touch,
    /// The Authorization Server SHOULD display the authentication and consent
    /// UI consistent with a "feature phone" type display.
    Wap,
}

impl Display {
    pub(crate) fn as_str(&self) -> &'static str {
        use Display::*;
        match *self {
            Page => "page",
            Popup => "popup",
            Touch => "touch",
            Wap => "wap",
        }
    }
}
