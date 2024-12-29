use serde::{Deserialize, Serialize};

/// Address Claim struct. Can be only formatted, only the rest, or both.
#[derive(Debug, Deserialize, Serialize, Clone, Eq, PartialEq)]
pub struct Address {
    #[serde(default)]
    /// Full mailing address, formatted for display or use on a mailing label.
    /// This field MAY contain multiple lines, separated by newlines. Newlines
    /// can be represented either as a carriage return/line feed pair ("\r\n")
    /// or as a single line feed character ("\n").
    pub formatted: Option<String>,
    #[serde(default)]
    /// Full street address component, which MAY include house number, street
    /// name, Post Office Box, and multi-line extended street address
    /// information. This field MAY contain multiple lines, separated by
    /// newlines. Newlines can be represented either as a carriage return/line
    /// feed pair ("\r\n") or as a single line feed character ("\n").
    pub street_address: Option<String>,
    #[serde(default)]
    /// City or locality component.
    pub locality: Option<String>,
    #[serde(default)]
    /// State, province, prefecture, or region component.
    pub region: Option<String>,
    // Countries like the UK use alphanumeric postal codes, so you can't just use a number here
    #[serde(default)]
    /// Zip code or postal code component.
    pub postal_code: Option<String>,
    #[serde(default)]
    /// Country name component.
    pub country: Option<String>,
}
