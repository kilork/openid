use serde::{de::DeserializeOwned, Serialize};

use crate::{Claims, StandardClaims};

/// Custom Claims embedded extension.
///
/// # Examples
///
/// ```
/// # use serde::{Deserialize, Serialize};
/// use openid::{Claims, CompactJson, CustomClaims, StandardClaims, Client, Discovered};
/// use openid::provider::google::Installed;
///
/// #[derive(Deserialize, Serialize)]
/// struct MyClaims {
///     my_claim: Option<String>,
///     #[serde(flatten)]
///     standard_claims: StandardClaims,
/// }
///
/// impl CustomClaims for MyClaims {
///     fn standard_claims(&self) -> &StandardClaims {
///         &self.standard_claims
///     }
/// }
///
/// impl CompactJson for MyClaims {}
///
/// let client: Client<Installed, MyClaims> = Client::new(
///     Installed,
///     String::from("CLIENT_ID"),
///     String::from("CLIENT_SECRET"),
///     Some(String::from("urn:ietf:wg:oauth:2.0:oob")),
///     reqwest::Client::new(), None,
/// );
/// ```
///
/// See full example: [openid-example:custom_claims](https://github.com/kilork/openid-example/blob/master/examples/custom_claims.rs)
pub trait CustomClaims: Serialize + DeserializeOwned {
    /// The standard claims.
    fn standard_claims(&self) -> &StandardClaims;
}

impl<T> Claims for T
where
    T: CustomClaims,
{
    fn iss(&self) -> &url::Url {
        self.standard_claims().iss()
    }
    fn sub(&self) -> &str {
        self.standard_claims().sub()
    }
    fn aud(&self) -> &crate::SingleOrMultiple<String> {
        self.standard_claims().aud()
    }
    fn exp(&self) -> i64 {
        self.standard_claims().exp()
    }
    fn iat(&self) -> i64 {
        self.standard_claims().iat()
    }
    fn auth_time(&self) -> Option<i64> {
        self.standard_claims().auth_time()
    }
    fn nonce(&self) -> Option<&String> {
        self.standard_claims().nonce()
    }
    fn at_hash(&self) -> Option<&String> {
        self.standard_claims().at_hash()
    }
    fn c_hash(&self) -> Option<&String> {
        self.standard_claims().c_hash()
    }
    fn acr(&self) -> Option<&String> {
        self.standard_claims().acr()
    }
    fn amr(&self) -> Option<&Vec<String>> {
        self.standard_claims().amr()
    }
    fn azp(&self) -> Option<&String> {
        self.standard_claims().azp()
    }
    fn userinfo(&self) -> &crate::Userinfo {
        self.standard_claims().userinfo()
    }
}
