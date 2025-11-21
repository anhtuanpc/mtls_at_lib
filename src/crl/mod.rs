//! Builder for creating Certificate Revocation Lists (CRLs)
pub mod builder;

pub use builder::{CrlBuilder, RevokedCertificate};

/// Represents a Certificate Revocation List
///
/// This structure holds the CRL in DER format.
#[derive(Debug, Clone)]
pub struct Crl {
    /// The CRL in DER format
    crl_der: Vec<u8>,
}

impl Crl {
    /// Creates a new CRL
    pub(crate) fn new(crl_der: Vec<u8>) -> Self {
        Self { crl_der }
    }
    
    /// Returns the CRL in DER format
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::crl::CrlBuilder;
    /// use mtls_at_lib::cert::CertificateBuilder;
    /// use mtls_at_lib::csr::CsrBuilder;
    /// use mtls_at_lib::types::KeyUsage;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Create a CA
    /// let ca_csr = CsrBuilder::new()
    ///     .subject("CN=Test CA")?
    ///     .is_ca(true)
    ///     .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
    ///     .build()?;
    ///
    /// let ca = CertificateBuilder::new()
    ///     .from_der(ca_csr.to_der())?
    ///     .signing_key(ca_csr.private_key_pem().to_string())
    ///     .build_self_signed()?;
    ///     
    /// // Generate CRL
    /// let crl = CrlBuilder::new()
    ///     .issuer_key_from_pem(ca.private_key_pem().unwrap())?
    ///     .build()?;
    ///     
    /// let der = crl.to_der();
    /// assert!(!der.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_der(&self) -> &[u8] {
        &self.crl_der
    }
    
    /// Returns the CRL in PEM format
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::crl::CrlBuilder;
    /// use mtls_at_lib::cert::CertificateBuilder;
    /// use mtls_at_lib::csr::CsrBuilder;
    /// use mtls_at_lib::types::KeyUsage;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let ca_csr = CsrBuilder::new()
    ///     .subject("CN=Test CA")?
    ///     .is_ca(true)
    ///     .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
    ///     .build()?;
    ///
    /// let ca = CertificateBuilder::new()
    ///     .from_der(ca_csr.to_der())?
    ///     .signing_key(ca_csr.private_key_pem().to_string())
    ///     .build_self_signed()?;
    ///     
    /// let crl = CrlBuilder::new()
    ///     .issuer_key_from_pem(ca.private_key_pem().unwrap())?
    ///     .build()?;
    ///     
    /// let pem = crl.to_pem();
    /// assert!(pem.starts_with("-----BEGIN X509 CRL-----"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_pem(&self) -> String {
        use pem::Pem;
        
        let pem_obj = Pem::new("X509 CRL", self.crl_der.clone());
        pem::encode(&pem_obj)
    }
}