/*!
# OpenID Connect & Discovery client library using async / await

## Legal

Dual-licensed under `MIT` or the [UNLICENSE](http://unlicense.org/).

## Features

Implements [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) and [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html).

Implements [UMA2](https://docs.kantarainitiative.org/uma/wg/oauth-uma-federated-authz-2.0-09.html) - User Managed Access, an extension to OIDC/OAuth2. Use feature flag `uma2` to enable this feature.

It supports Microsoft OIDC with feature `microsoft`. This adds methods for authentication and token validation, those skip issuer check.

This library is a quick and dirty rewrite of [inth-oauth2](https://crates.io/crates/inth-oauth2) and [oidc](https://crates.io/crates/oidc) to use async / await. Basic idea was to solve particular task, as result most of good ideas from original crates were perverted and over-simplified.

Using [reqwest](https://crates.io/crates/reqwest) for the HTTP client and [biscuit](https://crates.io/crates/biscuit) for Javascript Object Signing and Encryption (JOSE).

## Usage

Add dependency to Cargo.toml:

```toml
[dependencies]
openid = "0.8"
```

### Use case: [Warp](https://crates.io/crates/warp) web server with [JHipster](https://www.jhipster.tech/) generated frontend and [Google OpenID Connect](https://developers.google.com/identity/protocols/OpenIDConnect)

This example provides only Rust part, assuming just default JHipster frontend settings.

Cargo.toml:

```toml
[package]
name = 'openid-example'
version = '0.1.0'
authors = ['Alexander Korolev <alexander.korolev.germany@gmail.com>']
edition = '2018'

[dependencies]
anyhow = "1.0"
cookie = "0.14"
log = "0.4"
openid = "0.8"
pretty_env_logger = "0.4"
reqwest = "0.11"
serde = { version = "1", features = [ "derive" ] }
tokio = { version = "1", features = [ "full" ] }
uuid = { version = "0.8", features = [ "v4" ] }
warp = "0.3"
```

src/main.rs:

```rust#ignore
use std::{collections::HashMap, convert::Infallible, env, sync::Arc};

use log::{error, info};
use openid::{Client, Discovered, DiscoveredClient, Options, StandardClaims, Token, Userinfo};
use openid_warp_example::INDEX_HTML;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use warp::{
    http::{Response, StatusCode},
    reject, Filter, Rejection, Reply,
};

type OpenIDClient = Client<Discovered, StandardClaims>;

const EXAMPLE_COOKIE: &str = "openid_warp_example";

#[derive(Deserialize, Debug)]
pub struct LoginQuery {
    pub code: String,
    pub state: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct User {
    pub(crate) id: String,
    pub(crate) login: Option<String>,
    pub(crate) first_name: Option<String>,
    pub(crate) last_name: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) image_url: Option<String>,
    pub(crate) activated: bool,
    pub(crate) lang_key: Option<String>,
    pub(crate) authorities: Vec<String>,
}

#[derive(Default)]
struct Sessions {
    map: HashMap<String, (User, Token, Userinfo)>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if env::var_os("RUST_LOG").is_none() {
        // Set `RUST_LOG=openid_warp_example=debug` to see debug logs,
        // this only shows access logs.
        env::set_var("RUST_LOG", "openid_warp_example=info");
    }
    pretty_env_logger::init();

    let client_id = env::var("CLIENT_ID").unwrap_or("<client id>".to_string());
    let client_secret = env::var("CLIENT_SECRET").unwrap_or("<client secret>".to_string());
    let issuer_url = env::var("ISSUER").unwrap_or("https://accounts.google.com".to_string());
    let redirect = Some(host("/login/oauth2/code/oidc"));
    let issuer = reqwest::Url::parse(&issuer_url)?;

    eprintln!("redirect: {:?}", redirect);
    eprintln!("issuer: {}", issuer);

    let client =
        Arc::new(DiscoveredClient::discover(client_id, client_secret, redirect, issuer).await?);

    eprintln!("discovered config: {:?}", client.config());

    let with_client = |client: Arc<Client<_>>| warp::any().map(move || client.clone());

    let sessions = Arc::new(RwLock::new(Sessions::default()));

    let with_sessions = |sessions: Arc<RwLock<Sessions>>| warp::any().map(move || sessions.clone());

    let index = warp::path::end()
        .and(warp::get())
        .map(|| warp::reply::html(INDEX_HTML));

    let authorize = warp::path!("oauth2" / "authorization" / "oidc")
        .and(warp::get())
        .and(with_client(client.clone()))
        .and_then(reply_authorize);

    let login = warp::path!("login" / "oauth2" / "code" / "oidc")
        .and(warp::get())
        .and(with_client(client.clone()))
        .and(warp::query::<LoginQuery>())
        .and(with_sessions(sessions.clone()))
        .and_then(reply_login);

    let api_account = warp::path!("api" / "account")
        .and(warp::get())
        .and(with_user(sessions))
        .map(|user: User| warp::reply::json(&user));

    let routes = index
        .or(authorize)
        .or(login)
        .or(api_account)
        .recover(handle_rejections);

    let logged_routes = routes.with(warp::log("openid_warp_example"));

    warp::serve(logged_routes).run(([127, 0, 0, 1], 8080)).await;

    Ok(())
}

async fn request_token(
    oidc_client: Arc<OpenIDClient>,
    login_query: &LoginQuery,
) -> anyhow::Result<Option<(Token, Userinfo)>> {
    let mut token: Token = oidc_client.request_token(&login_query.code).await?.into();

    if let Some(mut id_token) = token.id_token.as_mut() {
        oidc_client.decode_token(&mut id_token)?;
        oidc_client.validate_token(&id_token, None, None)?;
        info!("token: {:?}", id_token);
    } else {
        return Ok(None);
    }

    let userinfo = oidc_client.request_userinfo(&token).await?;

    info!("user info: {:?}", userinfo);

    Ok(Some((token, userinfo)))
}

async fn reply_login(
    oidc_client: Arc<OpenIDClient>,
    login_query: LoginQuery,
    sessions: Arc<RwLock<Sessions>>,
) -> Result<impl warp::Reply, Infallible> {
    let request_token = request_token(oidc_client, &login_query).await;
    match request_token {
        Ok(Some((token, user_info))) => {
            let id = uuid::Uuid::new_v4().to_string();

            let login = user_info.preferred_username.clone();
            let email = user_info.email.clone();

            let user = User {
                id: user_info.sub.clone().unwrap_or_default(),
                login,
                last_name: user_info.family_name.clone(),
                first_name: user_info.name.clone(),
                email,
                activated: user_info.email_verified,
                image_url: user_info.picture.clone().map(|x| x.to_string()),
                lang_key: Some("en".to_string()),
                authorities: vec!["ROLE_USER".to_string()],
            };

            let authorization_cookie = ::cookie::Cookie::build(EXAMPLE_COOKIE, &id)
                .path("/")
                .http_only(true)
                .finish()
                .to_string();

            sessions
                .write()
                .await
                .map
                .insert(id, (user, token, user_info));

            let redirect_url = login_query.state.clone().unwrap_or_else(|| host("/"));

            Ok(Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(warp::http::header::LOCATION, redirect_url)
                .header(warp::http::header::SET_COOKIE, authorization_cookie)
                .body("")
                .unwrap())
        }
        Ok(None) => {
            error!("login error in call: no id_token found");

            Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("")
                .unwrap())
        }
        Err(err) => {
            error!("login error in call: {:?}", err);

            Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("")
                .unwrap())
        }
    }
}

async fn reply_authorize(oidc_client: Arc<OpenIDClient>) -> Result<impl warp::Reply, Infallible> {
    let origin_url = env::var("ORIGIN").unwrap_or(host(""));

    let auth_url = oidc_client.auth_url(&Options {
        scope: Some("openid email profile".into()),
        state: Some(origin_url),
        ..Default::default()
    });

    info!("authorize: {}", auth_url);

    let url = auth_url.into_string();

    Ok(warp::reply::with_header(
        StatusCode::FOUND,
        warp::http::header::LOCATION,
        url,
    ))
}

#[derive(Debug)]
struct Unauthorized;

impl reject::Reject for Unauthorized {}

async fn extract_user(
    session_id: Option<String>,
    sessions: Arc<RwLock<Sessions>>,
) -> Result<User, Rejection> {
    if let Some(session_id) = session_id {
        if let Some((user, _, _)) = sessions.read().await.map.get(&session_id) {
            Ok(user.clone())
        } else {
            Err(warp::reject::custom(Unauthorized))
        }
    } else {
        Err(warp::reject::custom(Unauthorized))
    }
}

fn with_user(
    sessions: Arc<RwLock<Sessions>>,
) -> impl Filter<Extract = (User,), Error = Rejection> + Clone {
    warp::cookie::optional(EXAMPLE_COOKIE)
        .and(warp::any().map(move || sessions.clone()))
        .and_then(extract_user)
}

async fn handle_rejections(err: Rejection) -> Result<impl Reply, Infallible> {
    let code = if err.is_not_found() {
        StatusCode::NOT_FOUND
    } else if let Some(Unauthorized) = err.find() {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };

    Ok(warp::reply::with_status(warp::reply(), code))
}

/// This host is the address, where user would be redirected after initial authorization.
/// For DEV environment with WebPack this is usually something like `http://localhost:9000`.
/// We are using `http://localhost:8080` in all-in-one example.
pub fn host(path: &str) -> String {
    env::var("REDIRECT_URL").unwrap_or("http://localhost:8080".to_string()) + path
}
```

See full example: [openid-examples: warp](https://github.com/kilork/openid-examples/blob/v0.8/examples/warp.rs)

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
mod token;
mod userinfo;

#[cfg(any(feature = "uma2", doc))]
/// UMA2 OIDC/OAuth2 extension.
///
/// See [Federated Authorization for User-Managed Access (UMA) 2.0](https://docs.kantarainitiative.org/uma/wg/oauth-uma-federated-authz-2.0-09.html)
pub mod uma2;

pub use ::biscuit::jws::Compact as Jws;
pub use ::biscuit::{Compact, CompactJson, Empty, SingleOrMultiple};
pub use address::Address;
pub use bearer::Bearer;
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
pub use token::Token;
pub use userinfo::Userinfo;

/// Reimport `biscuit` dependency.
pub mod biscuit {
    pub use biscuit::*;
}

pub type IdToken<T> = Jws<T, Empty>;
pub type DiscoveredClient = Client<Discovered, StandardClaims>;
#[cfg(feature = "uma2")]
pub type DiscoveredUma2Client = Client<uma2::DiscoveredUma2, StandardClaims>;
