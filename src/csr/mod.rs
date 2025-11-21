//! Certificate Signing Request (CSR) generation module
//!
//! This module provides functionality for creating X.509 Certificate Signing Requests
//! with support for Key Usage and Extended Key Usage extensions.

pub mod builder;

pub use builder::CsrBuilder;

use rcgen::KeyPair;

/// Represents a Certificate Signing Request
///
/// This structure holds both the CSR and the associated private key.
/// The private key is needed for signing the CSR and later for creating
/// certificates from this CSR.
///
/// # Security
///
/// The private key is stored in memory and should be handled carefully.
/// Consider using secure memory wiping when the key is no longer needed.
#[derive(Debug)]
pub struct Csr {
    /// The certificate signing request in DER format
    csr_der: Vec<u8>,
    
    /// The private key associated with this CSR
    key_pair: KeyPair,
}

impl Csr {
    /// Creates a new CSR from DER bytes and key pair
    pub(crate) fn new(csr_der: Vec<u8>, key_pair: KeyPair) -> Self {
        Self { csr_der, key_pair }
    }
    
    /// Returns the CSR in DER format
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::csr::CsrBuilder;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let csr = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .build()?;
    ///     
    /// let der = csr.to_der();
    /// assert!(!der.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_der(&self) -> &[u8] {
        &self.csr_der
    }
    
    /// Returns the CSR in PEM format
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::csr::CsrBuilder;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let csr = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .build()?;
    ///     
    /// let pem = csr.to_pem();
    /// assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_pem(&self) -> String {
        use pem::Pem;
        
        let pem_obj = Pem::new("CERTIFICATE REQUEST", self.csr_der.clone());
        pem::encode(&pem_obj)
    }
    
    /// Returns a reference to the private key
    ///
    /// # Security Warning
    ///
    /// The private key should be kept secure and never transmitted or logged.
    pub fn private_key(&self) -> &KeyPair {
        &self.key_pair
    }
    
    /// Serializes the private key to PKCS#8 DER format
    ///
    /// # Security Warning
    ///
    /// This exports the private key. Use only when necessary and ensure
    /// the output is properly protected.
    pub fn private_key_der(&self) -> Vec<u8> {
        self.key_pair.serialize_der()
    }
    
    /// Serializes the private key to PKCS#8 PEM format
    ///
    /// # Security Warning
    ///
    /// This exports the private key. Use only when necessary and ensure
    /// the output is properly protected.
    pub fn private_key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }
}
