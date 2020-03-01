/*!
# openid description

## Features

## Usage

Add dependency to Cargo.toml:

```toml
[dependencies]
openid = "0.1"
```

*/
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

pub mod bearer;
pub mod client;
pub mod error;
pub mod provider;

pub use bearer::Bearer;
pub use client::Client;
pub use error::{OAuth2Error, OAuth2ErrorCode};
pub use provider::Provider;
