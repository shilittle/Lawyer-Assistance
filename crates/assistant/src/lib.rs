//! Provider-agnostic contracts for the bounded legal assistant orchestrator.
//!
//! This crate deliberately contains no database, filesystem, HTTP, Tauri, or
//! credential access. Callers resolve ownership and local legal citations,
//! build a [`ValidationContext`], and only then accept structured model output.

mod capability;
mod case_change;
mod document;
mod error;
mod map;
mod protocol;
pub mod render;
mod validation;

pub use capability::*;
pub use case_change::*;
pub use document::*;
pub use error::*;
pub use map::*;
pub use protocol::*;
pub use render::*;
pub use validation::ValidationContext;

/// Schema version shared by the envelope and the Stage 8 structured specs.
pub const CONTRACT_SCHEMA_VERSION: u16 = 1;
