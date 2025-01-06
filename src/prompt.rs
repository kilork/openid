/// Authorization Server prompts.
///
/// The four possible values for the prompt parameter set in Options.
///
/// See [OpenID: 3.1.2.1. Authentication Request prompt](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prompt {
    /// The Authorization Server MUST NOT display any authentication or consent
    /// user interface pages. An error is returned if an End-User is not already
    /// authenticated or the Client does not have pre-configured consent for the
    /// requested Claims or does not fulfill other conditions for processing the
    /// request. The error code will typically be `login_required`,
    /// `interaction_required`, or another code defined in [Section 3.1.2.6](https://openid.net/specs/openid-connect-core-1_0.html#AuthError). This
    /// can be used as a method to check for existing authentication and/or
    /// consent.
    None,
    /// The Authorization Server SHOULD prompt the End-User for
    /// reauthentication. If it cannot reauthenticate the End-User, it MUST
    /// return an error, typically `login_required`.
    Login,
    /// The Authorization Server SHOULD prompt the End-User for consent before
    /// returning information to the Client. If it cannot obtain consent, it
    /// MUST return an error, typically `consent_required`.
    Consent,
    /// The Authorization Server SHOULD prompt the End-User to select a user
    /// account. This enables an End-User who has multiple accounts at the
    /// Authorization Server to select amongst the multiple accounts that they
    /// might have current sessions for. If it cannot obtain an account
    /// selection choice made by the End-User, it MUST return an error,
    /// typically `account_selection_required`.
    SelectAccount,
}

impl Prompt {
    pub(crate) fn as_str(&self) -> &'static str {
        use Prompt::*;
        match *self {
            None => "none",
            Login => "login",
            Consent => "consent",
            SelectAccount => "select_account",
        }
    }
}
