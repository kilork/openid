use crate::{
    error::{Error, Expiry, Mismatch, Missing, Validation},
    Claims, Config,
};
use biscuit::SingleOrMultiple;
use chrono::{Duration, Utc};

pub fn validate_token_issuer<C: Claims>(claims: &C, config: &Config) -> Result<(), Error> {
    if claims.iss() != &config.issuer {
        let expected = config.issuer.as_str().to_string();
        let actual = claims.iss().as_str().to_string();
        return Err(Validation::Mismatch(Mismatch::Issuer { expected, actual }).into());
    }

    Ok(())
}

pub fn validate_token_nonce<C: Claims>(claims: &C, nonce: Option<&str>) -> Result<(), Error> {
    match nonce {
        Some(expected) => match claims.nonce() {
            Some(actual) => {
                if expected != actual {
                    let expected = expected.to_string();
                    let actual = actual.to_string();
                    return Err(Validation::Mismatch(Mismatch::Nonce { expected, actual }).into());
                }
            }
            None => return Err(Validation::Missing(Missing::Nonce).into()),
        },
        None => {
            if claims.nonce().is_some() {
                return Err(Validation::Missing(Missing::Nonce).into());
            }
        }
    }

    Ok(())
}

pub fn validate_token_aud<C: Claims>(claims: &C, client_id: &str) -> Result<(), Error> {
    if !claims.aud().contains(client_id) {
        return Err(Validation::Missing(Missing::Audience).into());
    }
    // By spec, if there are multiple auds, we must have an azp
    if let SingleOrMultiple::Multiple(_) = claims.aud() {
        if claims.azp().is_none() {
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

pub fn validate_token_exp<C: Claims>(claims: &C, max_age: Option<&Duration>) -> Result<(), Error> {
    let now = Utc::now();
    // Now should never be less than the time this code was written!
    if now.timestamp() < 1504758600 {
        panic!("chrono::Utc::now() can never be before this was written!")
    }
    let exp = claims.exp();
    if exp <= now.timestamp() {
        return Err(Validation::Expired(
            chrono::naive::NaiveDateTime::from_timestamp_opt(exp, 0)
                .map(Expiry::Expires)
                .unwrap_or_else(|| Expiry::NotUnix(exp)),
        )
        .into());
    }

    if let Some(max) = max_age {
        match claims.auth_time() {
            Some(time) => {
                let age = chrono::Duration::seconds(now.timestamp() - time);
                if age >= *max {
                    return Err(Validation::Expired(Expiry::MaxAge(age)).into());
                }
            }
            None => return Err(Validation::Missing(Missing::AuthTime).into()),
        }
    }

    Ok(())
}
