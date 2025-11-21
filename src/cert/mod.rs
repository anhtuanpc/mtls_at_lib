//! Certificate generation and management module
//!
//! This module provides functionality for creating X.509 certificates,
//! supporting both self-signed certificates and CA-signed certificates from CSRs.

pub mod builder;

pub use builder::CertificateBuilder;

use rcgen::KeyPair;

/// Represents an X.509 certificate
///
/// This structure holds the certificate in DER format and optionally the private key.
#[derive(Debug)]
pub struct Certificate {
    /// The certificate in DER format
    cert_der: Vec<u8>,
    
    /// The private key in PKCS#8 PEM format (only for self-signed certs)
    key_pem: Option<String>,
}

impl Certificate {
    /// Creates a new certificate
    pub(crate) fn new(cert_der: Vec<u8>, key_pem: Option<String>) -> Self {
        Self { cert_der, key_pem }
    }
    
    /// Returns the certificate in DER format
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::cert::CertificateBuilder;
    /// use mtls_at_lib::csr::CsrBuilder;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let csr = CsrBuilder::new()
    ///     .subject("CN=Test CA")?
    ///     .build()?;
    ///
    /// let cert = CertificateBuilder::new()
    ///     .from_csr(csr.to_der())?
    ///     .signing_key(csr.private_key_pem().to_string())
    ///     .build_self_signed()?;
    ///     
    /// let der = cert.to_der();
    /// assert!(!der.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_der(&self) -> &[u8] {
        &self.cert_der
    }
    
    /// Returns the certificate in PEM format
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::cert::CertificateBuilder;
    /// use mtls_at_lib::csr::CsrBuilder;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let csr = CsrBuilder::new()
    ///     .subject("CN=Test CA")?
    ///     .build()?;
    ///
    /// let cert = CertificateBuilder::new()
    ///     .from_csr(csr.to_der())?
    ///     .signing_key(csr.private_key_pem().to_string())
    ///     .build_self_signed()?;
    ///     
    /// let pem = cert.to_pem();
    /// assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_pem(&self) -> String {
        use pem::Pem;
        
        let pem_obj = Pem::new("CERTIFICATE", self.cert_der.clone());
        pem::encode(&pem_obj)
    }
    
    /// Returns the private key in PKCS#8 DER format (if available)
    pub fn private_key_der(&self) -> Option<Vec<u8>> {
        self.key_pem.as_ref().and_then(|pem| {
            KeyPair::from_pem(pem).ok().map(|kp| kp.serialize_der())
        })
    }
    
    /// Returns the private key in PKCS#8 PEM format (if available)
    pub fn private_key_pem(&self) -> Option<&str> {
        self.key_pem.as_deref()
    }
}
