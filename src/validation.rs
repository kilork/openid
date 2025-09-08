use biscuit::SingleOrMultiple;
use chrono::{DateTime, Duration, Utc};

use crate::{
    error::{Error, Expiry, Mismatch, Missing, Validation},
    Claims, Config,
};

/// Validate token issuer.
pub fn validate_token_issuer<C: Claims>(claims: &C, config: &Config) -> Result<(), Error> {
    if claims.iss() != &config.issuer {
        let expected = config.issuer.as_str().to_string();
        let actual = claims.iss().as_str().to_string();
        return Err(Validation::Mismatch(Mismatch::Issuer { expected, actual }).into());
    }

    Ok(())
}

/// Validate token nonce.
pub fn validate_token_nonce<'nonce, C: Claims>(
    claims: &C,
    nonce: impl Into<Option<&'nonce str>>,
) -> Result<(), Error> {
    if let Some(expected) = nonce.into() {
        match claims.nonce() {
            Some(actual) => {
                if expected != actual {
                    let expected = expected.to_string();
                    let actual = actual.to_string();
                    return Err(Validation::Mismatch(Mismatch::Nonce { expected, actual }).into());
                }
            }
            None => return Err(Validation::Missing(Missing::Nonce).into()),
        }
    }

    Ok(())
}

/// Validate token aud.
pub fn validate_token_aud<C: Claims>(claims: &C, client_id: &str) -> Result<(), Error> {
    if !claims.aud().contains(client_id) {
        return Err(Validation::Missing(Missing::Audience).into());
    }
    // By spec, if there are multiple auds, we must have an azp
    if let SingleOrMultiple::Multiple(aud) = claims.aud() {
        if aud.len() > 1 && claims.azp().is_none() {
            return Err(Validation::Missing(Missing::AuthorizedParty).into());
        }
    }
    // If there is an authorized party, it must be our client_id
    if let Some(actual) = claims.azp() {
        if actual != client_id {
            let expected = client_id.to_string();
            let actual = actual.to_string();
            return Err(
                Validation::Mismatch(Mismatch::AuthorizedParty { expected, actual }).into(),
            );
        }
    }

    Ok(())
}

/// Validate token expiration against current time.
pub fn validate_token_exp<'max_age, C: Claims>(
    claims: &C,
    max_age: impl Into<Option<&'max_age Duration>>,
) -> Result<(), Error> {
    let now = Utc::now();
    let exp = claims.exp();
    if exp <= now.timestamp() {
        return Err(Validation::Expired(
            DateTime::from_timestamp(exp, 0)
                .map(Expiry::Expires)
                .unwrap_or_else(|| Expiry::NotUnix(exp)),
        )
        .into());
    }

    if let Some(max) = max_age.into() {
        match claims.auth_time() {
            Some(time) => {
                let age = Duration::seconds(now.timestamp() - time);
                if age >= *max {
                    return Err(Validation::Expired(Expiry::MaxAge(age)).into());
                }
            }
            None => return Err(Validation::Missing(Missing::AuthTime).into()),
        }
    }

    Ok(())
}
