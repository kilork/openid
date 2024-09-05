#![doc = include_str!("../README.md")]
/*
#![warn(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    variant_size_differences
)]
*/
#[macro_use]
extern crate lazy_static;

mod address;
mod bearer;
mod claims;
mod client;
mod config;
mod configurable;
mod custom_claims;
mod deserializers;
mod discovered;
mod display;
pub mod error;
mod options;
mod prompt;
pub mod provider;
mod standard_claims;
mod standard_claims_subject;
mod token;
mod token_introspection;
mod userinfo;
pub mod validation;

#[cfg(any(feature = "uma2", doc))]
/// UMA2 OIDC/OAuth2 extension.
///
/// See [Federated Authorization for User-Managed Access (UMA) 2.0](https://docs.kantarainitiative.org/uma/wg/oauth-uma-federated-authz-2.0-09.html)
pub mod uma2;

pub use ::biscuit::jws::Compact as Jws;
pub use ::biscuit::{Compact, CompactJson, Empty, SingleOrMultiple};
pub use address::Address;
pub use bearer::{Bearer, TemporalBearerGuard};
pub use claims::Claims;
pub use client::Client;
pub use config::Config;
pub use configurable::Configurable;
pub use custom_claims::CustomClaims;
pub use discovered::Discovered;
pub use display::Display;
pub use error::{OAuth2Error, OAuth2ErrorCode};
pub use options::Options;
pub use prompt::Prompt;
pub use provider::Provider;
pub use standard_claims::StandardClaims;
pub use standard_claims_subject::StandardClaimsSubject;
pub use token::Token;
pub use token_introspection::TokenIntrospection;
pub use userinfo::Userinfo;

/// Reimport `biscuit` dependency.
pub mod biscuit {
    pub use biscuit::*;
}

pub type IdToken<T> = Jws<T, Empty>;
pub type DiscoveredClient = Client<Discovered, StandardClaims>;
#[cfg(feature = "uma2")]
pub type DiscoveredUma2Client = Client<uma2::DiscoveredUma2, StandardClaims>;
