//! Upload lifecycle primitives (HTTP-free).
//!
//! Moved from `http_api::upload_state` per ADR-010 (closes KI-07): the signed
//! upload-state token codec has no HTTP dependency and belongs to the core layer.

pub mod state;
