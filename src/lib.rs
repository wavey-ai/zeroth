//! Zeroth facade crate.
//!
//! The facade re-exports the generic crates used by a deployment such as
//! `wavey-id`.

pub use zeroth_core as core;
pub use zeroth_oidc as oidc;
pub use zeroth_providers as providers;
pub use zeroth_server as server;
pub use zeroth_storage as storage;

#[cfg(feature = "ui")]
pub use zeroth_ui as ui;
