//! TLS termination, IP stripping, ingress-bucket tokens, OHTTP gateway
//! (docs/04 #5, docs/05). Must never forward a client IP address past this
//! layer, and must never write a request-level access log — both are
//! explicit non-goals, not oversights, and access logging must stay
//! disabled rather than merely rotated.
