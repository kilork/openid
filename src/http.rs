use serde::de::DeserializeOwned;

use crate::error::ClientError;

/// Maximum accepted response body size for provider documents and payloads.
///
/// See issue [#95](https://github.com/kilork/openid/issues/95): provider
/// responses are untrusted, unbounded reads should not cause memory pressure.
pub(crate) const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Reads a response body and deserializes JSON, enforcing a size limit.
///
/// # Errors
///
/// - [ClientError::ResponseTooBig] if the response is larger than
///   [MAX_RESPONSE_SIZE]
/// - [ClientError::Reqwest] if reading the response fails
/// - [ClientError::Json] if the response is not a valid `T`
pub(crate) async fn json<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, ClientError> {
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_RESPONSE_SIZE {
        return Err(ClientError::ResponseTooBig {
            size: bytes.len(),
            max: MAX_RESPONSE_SIZE,
        });
    }
    serde_json::from_slice(&bytes).map_err(ClientError::Json)
}
