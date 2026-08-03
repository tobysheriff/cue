//! Blind token issuance and verification, credential rotation (docs/04 #4,
//! docs/05). Must never be able to link an issued token to the account
//! that later spends it — that link is the entire point of sealed sender,
//! and this module is where it would leak if issuance and spend were ever
//! correlatable.
