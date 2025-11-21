//! # mtls_at_lib
//!
//! A safe, memory-safe Rust library for mTLS operations with comprehensive certificate management.
//!
//! This library provides fail-safe utilities for:
//! - X.509 Certificate Signing Request (CSR) generation with Key Usage and Extended Key Usage extensions
//! - Certificate issuance (both CA-signed and self-signed)
//! - Certificate Revocation List (CRL) generation and validation
//! - Certificate chain verification with CRL Distribution Point (CDP) support
//! - Mutual TLS (mTLS) connections with comprehensive validation
//!
//! ## Design Principles
//!
//! - **Memory Safety**: 100% safe Rust with minimal FFI usage
//! - **Type Safety**: Leverage Rust's type system to prevent misuse
//! - **Fail-Safe Defaults**: Secure by default, explicit opt-in for weaker security
//! - **Comprehensive Validation**: All certificates validated for expiry, revocation, key usage, and signatures
//!
//! ## Quick Start
//!
//! ### Creating a Certificate Signing Request
//!
//! ```rust
//! use mtls_at_lib::csr::CsrBuilder;
//! use mtls_at_lib::types::{KeyUsage, ExtendedKeyUsage};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a CSR for a server certificate
//! let csr = CsrBuilder::new()
//!     .subject("CN=example.com,O=Example Corp,C=US")?
//!     .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
//!     .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH])
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Creating a Self-Signed CA Certificate
//!
//! ```rust
//! use mtls_at_lib::cert::CertificateBuilder;
//! use mtls_at_lib::csr::CsrBuilder;
//! use mtls_at_lib::types::KeyUsage;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a CSR for root CA certificate
//! let ca_csr = CsrBuilder::new()
//!     .subject("CN=Root CA,O=Example Corp,C=US")?
//!     .is_ca(true)
//!     .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
//!     .build()?;
//!
//! // Create self-signed certificate from CSR
//! let ca_cert = CertificateBuilder::new()
//!     .from_csr(ca_csr.to_der())?
//!     .signing_key(ca_csr.private_key_pem().to_string())
//!     .build_self_signed()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! - `cdp-fetch`: Enable CRL fetching from distribution points (requires network access)
//!
//! ## Safety Guarantees
//!
//! All cryptographic operations use pure Rust implementations:
//! - `rustls` for TLS 1.3
//! - `rcgen` for certificate generation
//! - `x509-parser` for certificate parsing
//!
//! No unsafe code in the public API surface. Any FFI usage is:
//! - Minimal and well-documented
//! - Memory-safety verified
//! - Thoroughly tested

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
pub mod error;
pub mod types;
pub mod csr;
pub mod cert;
pub mod crl;

pub use error::*;
pub use types::*;
pub use crl::*;