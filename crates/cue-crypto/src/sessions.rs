//! PQXDH + Double Ratchet 1:1 sessions (docs/03). Lands in Phase 1 (docs/11)
//! wrapping `libsignal-protocol`; this module is intentionally empty until
//! then rather than half-wired against a dependency nothing else uses yet.

use crate::CryptoError;

pub fn establish_session() -> Result<(), CryptoError> {
    Err(CryptoError::NotImplemented("sessions::establish_session"))
}
