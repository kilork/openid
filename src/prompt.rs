/// The four possible values for the prompt parameter set in Options. See spec for details.
#[derive(PartialEq, Eq, Hash)]
pub enum Prompt {
    None,
    Login,
    Consent,
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
