use crate::error::StandardClaimsSubjectMissing;

/// Standard Claims: Subject.
pub trait StandardClaimsSubject: crate::CompactJson {
    /// Subject - Identifier for the End-User at the Issuer.
    ///
    /// See [Standard Claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
    ///
    /// Errors:
    ///
    /// - [StandardClaimsSubjectMissing] if subject (sub) is missing
    fn sub(&self) -> Result<&str, StandardClaimsSubjectMissing>;
}
