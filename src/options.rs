use std::collections::HashSet;

use chrono::Duration;

use crate::{Display, Prompt, response_mode::ResponseMode};

/// Optional request parameters.
///
/// The request parameters that [OpenID specifies](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) for the auth URI.
/// Derives Default, so remember to ..Default::default() after you specify what
/// you want.
#[derive(Default, Debug)]
pub struct Options {
    /// REQUIRED. OpenID Connect requests MUST contain the `openid` scope value.
    ///
    /// If the `openid` scope value is not present, the behavior is entirely
    /// unspecified. Other scope values MAY be present. Scope values used that
    /// are not understood by an implementation SHOULD be ignored. See Sections
    /// [5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) and [11](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess) for additional scope values defined by this
    /// specification.
    pub scope: Option<String>,
    /// RECOMMENDED. Opaque value used to maintain state between the request and
    /// the callback.
    ///
    /// Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by
    /// cryptographically binding the value of this parameter with a browser
    /// cookie.
    pub state: Option<String>,
    /// OPTIONAL. String value used to associate a Client session with an ID
    /// Token, and to mitigate replay attacks.
    ///
    /// The value is passed through unmodified from the Authentication Request
    /// to the ID Token. Sufficient entropy MUST be present in the `nonce`
    /// values used to prevent attackers from guessing values. For
    /// implementation notes, see [Section 15.5.2](https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes).
    pub nonce: Option<String>,
    /// OPTIONAL. ASCII string value that specifies how the Authorization Server
    /// displays the authentication and consent user interface pages to the
    /// End-User.
    pub display: Option<Display>,
    /// OPTIONAL. Space-delimited, case-sensitive list of ASCII string values
    /// that specifies whether the Authorization Server prompts the End-User for
    /// reauthentication and consent.
    ///
    /// The `prompt` parameter can be used by the Client to make sure that the
    /// End-User is still present for the current session or to bring attention
    /// to the request. If this parameter contains none with any other value, an
    /// error is returned. If an OP receives a `prompt` value outside the
    /// set defined above that it does not understand, it MAY return an error or
    /// it MAY ignore it; in practice, not returning errors for not-understood
    /// values will help facilitate phasing in extensions using new `prompt`
    /// values.
    pub prompt: Option<HashSet<Prompt>>,
    /// OPTIONAL. Maximum Authentication Age.
    ///
    /// Specifies the allowable elapsed time in seconds since the last time the
    /// End-User was actively authenticated by the OP. If the elapsed time is
    /// greater than this value, the OP MUST attempt to actively re-authenticate
    /// the End-User. (The `max_age` request parameter corresponds to the OpenID
    /// 2.0 PAPE [OpenID.PAPE](https://openid.net/specs/openid-connect-core-1_0.html#OpenID.PAPE) `max_auth_age` request parameter.) When `max_age`
    /// is used, the ID Token returned MUST include an `auth_time` Claim Value.
    /// Note that `max_age=0` is equivalent to `prompt=login`.
    pub max_age: Option<Duration>,
    /// OPTIONAL. End-User's preferred languages and scripts for the user
    /// interface, represented as a space-separated list of BCP47 [RFC5646](https://openid.net/specs/openid-connect-core-1_0.html#RFC5646)
    /// language tag values, ordered by preference. For instance, the value
    /// "fr-CA fr en" represents a preference for French as spoken in Canada,
    /// then French (without a region designation), followed by English (without
    /// a region designation). An error SHOULD NOT result if some or all of the
    /// requested locales are not supported by the OpenID Provider.
    pub ui_locales: Option<String>,
    /// OPTIONAL. End-User's preferred languages and scripts for Claims being
    /// returned, represented as a space-separated list of BCP47 [RFC5646]
    /// language tag values, ordered by preference. An error SHOULD NOT result
    /// if some or all of the requested locales are not supported by the OpenID
    /// Provider.
    pub claims_locales: Option<String>,
    /// OPTIONAL. ID Token previously issued by the Authorization Server being
    /// passed as a hint about the End-User's current or past authenticated
    /// session with the Client.
    ///
    /// If the End-User identified by the ID Token is already logged in or is
    /// logged in as a result of the request (with the OP possibly evaluating
    /// other information beyond the ID Token in this decision), then the
    /// Authorization Server returns a positive response; otherwise, it MUST
    /// return an error, such as `login_required`. When possible, an
    /// `id_token_hint` SHOULD be present when `prompt=none` is used and an
    /// invalid_request error MAY be returned if it is not; however, the server
    /// SHOULD respond successfully when possible, even if it is not present.
    /// The Authorization Server need not be listed as an audience of the ID
    /// Token when it is used as an `id_token_hint` value. If the ID Token
    /// received by the RP from the OP is encrypted, to use it as an
    /// `id_token_hint`, the Client MUST decrypt the signed ID Token contained
    /// within the encrypted ID Token. The Client MAY re-encrypt the signed ID
    /// token to the Authentication Server using a key that enables the server
    /// to decrypt the ID Token and use the re-encrypted ID token as the
    /// `id_token_hint` value.
    pub id_token_hint: Option<String>,
    /// OPTIONAL. Hint to the Authorization Server about the login identifier
    /// the End-User might use to log in (if necessary).
    ///
    /// This hint can be used by an RP if it first asks the End-User for their
    /// e-mail address (or other identifier) and then wants to pass that value
    /// as a hint to the discovered authorization service. It is RECOMMENDED
    /// that the hint value match the value used for discovery. This value MAY
    /// also be a phone number in the format specified for the phone_number
    /// Claim. The use of this parameter is left to the OP's discretion.
    pub login_hint: Option<String>,
    /// OPTIONAL. Requested Authentication Context Class Reference values.
    ///
    /// Space-separated string that specifies the `acr` values that the
    /// Authorization Server is being requested to use for processing this
    /// Authentication Request, with the values appearing in order of
    /// preference. The Authentication Context Class satisfied by the
    /// authentication performed is returned as the `acr` Claim Value, as
    /// specified in [Section 2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken). The `acr` Claim is requested as a Voluntary
    /// Claim by this parameter.
    pub acr_values: Option<String>,
    /// OPTIONAL. Informs the Authorization Server of the mechanism to be used
    /// for returning parameters from the Authorization Endpoint.
    ///
    /// This parameter is defined in [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
    /// This use of this parameter is NOT RECOMMENDED when the Response Mode
    /// that would be requested is the default mode specified for the Response Type.
    pub response_mode: Option<ResponseMode>,
}
