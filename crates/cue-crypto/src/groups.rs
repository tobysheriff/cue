//! MLS group sessions via `openmls` (docs/03, ADR-0003). Lands in Phase 2
//! (docs/11) alongside the anonymous membership credentials in
//! `crate::credentials` that keep the Node blind to who is in a group.

use crate::CryptoError;

pub fn create_group() -> Result<(), CryptoError> {
    Err(CryptoError::NotImplemented("groups::create_group"))
}
