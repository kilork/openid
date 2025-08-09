/*!
PKCE - Proof Key for Code Exchange by OAuth Public Clients

Proof Key for Code Exchange by OAuth Public Clients (PKCE) is a method for public clients to protect against authorization code interception attacks. It involves generating a random string, encoding it as a URL-safe base64 string, and sending it as a parameter in the authorization request. The client then uses the same string to generate a hash and send it as a parameter in the token request. The authorization server verifies that the hash matches the original string before issuing the access token.

See [RFC 7636](https://tools.ietf.org/html/rfc7636) for more details.
*/

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// PKCE - Proof Key for Code Exchange by OAuth Public Clients
#[derive(Debug, Clone)]
pub enum Pkce {
    /// S256 code challenge method.
    ///
    /// The S256 method uses a SHA-256 hash of the code verifier to generate the code challenge.
    S256 {
        /// A cryptographically random string that is used to correlate the
        /// authorization request to the token request.
        code_verifier: String,
        /// A challenge derived from the code verifier that is sent in the
        /// authorization request, to be verified against later.
        code_challenge: String,
    },
    /// Plain code challenge method.
    ///
    /// The Plain method uses the code verifier as the code challenge.
    Plain(String),
}

impl Pkce {
    /// Get the code verifier.
    pub fn code_verifier(&self) -> &str {
        match self {
            Pkce::S256 { code_verifier, .. } => code_verifier,
            Pkce::Plain(code_verifier) => code_verifier,
        }
    }

    /// Get the code challenge.
    pub fn code_challenge(&self) -> &str {
        match self {
            Pkce::S256 { code_challenge, .. } => code_challenge,
            Pkce::Plain(code_verifier) => code_verifier,
        }
    }

    /// Get the code challenge method.
    pub fn code_challenge_method(&self) -> &str {
        match self {
            Pkce::S256 { .. } => "S256",
            Pkce::Plain(_) => "plain",
        }
    }
}

/// Generate a PKCE code verifier and challenge.
pub fn generate_s256_pkce() -> Pkce {
    let code_verifier = generate_s256_code_verifier();
    let code_challenge = generate_s256_code_challenge(&code_verifier);
    Pkce::S256 {
        code_verifier,
        code_challenge,
    }
}

fn generate_s256_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).unwrap();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_s256_code_challenge(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(hmac_sha256::Hash::hash(code_verifier.as_bytes()))
}
