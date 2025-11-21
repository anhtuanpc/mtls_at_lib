//! Error types for the mtls_at_lib library
//!
//! This module defines all error types used throughout the library,
//! using `thiserror` for ergonomic error handling.

use thiserror::Error;

/// Errors that can occur during CSR (Certificate Signing Request) operations
#[derive(Error, Debug)]
pub enum CsrError {
    /// Invalid subject distinguished name format
    #[error("Invalid subject name: {0}")]
    InvalidSubjectName(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Encoding error (ASN.1 DER encoding)
    #[error("Encoding error: {0}")]
    EncodingError(String),
}

/// Errors that can occur during certificate operations
#[derive(Error, Debug)]
pub enum CertError {
    /// Invalid subject or issuer name
    #[error("Invalid name: {0}")]
    InvalidName(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Certificate signing failed
    #[error("Certificate signing failed: {0}")]
    SigningError(String),

    /// Serial number generation failed
    #[error("Serial number generation failed: {0}")]
    SerialNumberError(String),

    /// Public key mismatch error
    #[error("Public key mismatch: {0}")]
    PublicKeyMismatch(String),
}