//! CAPTCHA verification boundary (docs/02: ingress reputation escalates to
//! "CAPTCHA" before a moderator-review cohort). Cue doesn't implement a
//! CAPTCHA itself — that's an external provider (hCaptcha, Turnstile, or
//! similar), integrated behind this trait. Wiring a real provider in is a
//! follow-up, not something this Phase 1 slice ships.

pub trait CaptchaVerifier: Send + Sync {
    fn verify(&self, token: &str) -> bool;
}

/// Accepts any non-empty token. This makes the registration flow
/// exercisable end to end before a real provider is wired in. Never use
/// outside tests or a local dev Node — it verifies nothing.
pub struct NullCaptchaVerifier;

impl CaptchaVerifier for NullCaptchaVerifier {
    fn verify(&self, token: &str) -> bool {
        !token.is_empty()
    }
}
