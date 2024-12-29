/// The four values for the preferred display parameter in the Options. See spec
/// for details.
#[derive(Debug, Clone, Copy)]
pub enum Display {
    Page,
    Popup,
    Touch,
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
