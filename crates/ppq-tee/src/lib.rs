//! Attested, end-to-end encrypted in-process client for PPQ.AI TEE models.

pub mod attest;
pub mod client;
pub mod ehbp;
pub mod models;

pub use client::{PpqClient, PpqClientBuilder};
pub use models::{enclave_model_id, Pricing, PrivateModel};

/// Every failure mode in this crate. There are no warn-and-continue paths.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("attestation failed: {0}")]
    Attestation(String),
    #[error("ehbp protocol error: {0}")]
    Ehbp(String),
    /// A non-2xx response that arrived without `Ehbp-Response-Nonce`, i.e. it
    /// never reached the enclave. The body is attacker-forgeable diagnostics
    /// and must never be treated as enclave output.
    #[error("unauthenticated upstream error (HTTP {status}): {body}")]
    UnauthenticatedUpstream { status: u16, body: String },
    /// The enclave returned an authenticated error response. The body is
    /// decrypted and trustworthy — unlike `UnauthenticatedUpstream`.
    #[error("enclave returned HTTP {status}: {body}")]
    Enclave { status: u16, body: String },
}

pub type Result<T> = std::result::Result<T, Error>;
