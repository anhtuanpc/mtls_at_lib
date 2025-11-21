//! Certificate Builder for constructing X.509 certificates
//!
//! This module provides a type-safe builder API for creating both self-signed
//! certificates and CA-signed certificates from CSRs.

use crate::error::CertError;
use super::Certificate;

use rcgen::{
    CertificateParams, CertificateSigningRequestParams, Issuer, KeyPair, PublicKeyData
};

/// Builder for creating certificates from CSRs
///
/// This builder allows creating either self-signed certificates or CA-signed certificates
/// from Certificate Signing Requests (CSRs). The builder maintains CSR parameters and
/// signing key information.
#[derive(Debug)]
pub struct CertificateBuilder {
    /// PEM-encoded private key used for signing the certificate
    signing_key: Option<String>,
    /// Parsed CSR parameters
    csr_params: Option<CertificateSigningRequestParams>,
    /// Not Before timestamp (certificate validity start time)
    not_before: Option<std::time::SystemTime>,
    /// Not After timestamp (certificate validity end time)
    not_after: Option<std::time::SystemTime>,
    /// CRL Distribution Points URIs
    crl_distribution_points: Vec<String>,
}

impl CertificateBuilder {
    /// Creates a builder for a certificate from a CSR
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::cert::CertificateBuilder;
    /// use mtls_at_lib::csr::CsrBuilder;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let csr = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .build()?;
    ///
    /// let cert = CertificateBuilder::new()
    ///     .from_csr(csr.to_der())?
    ///     .signing_key(csr.private_key_pem().to_string())
    ///     .build_self_signed()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Self {
        Self {
            signing_key: None,
            csr_params: None,
            not_before: None,
            not_after: None,
            crl_distribution_points: Vec::new(),
        }
    }
    
    /// Loads certificate parameters from a CSR in DER format
    ///
    /// # Arguments
    ///
    /// * `csr_der` - The CSR in DER format
    pub fn from_der(mut self, csr_der: &[u8]) -> Result<Self, CertError> {
        let csr_der_ref = csr_der.into();
        let csr_params = CertificateSigningRequestParams::from_der(&csr_der_ref)
            .map_err(|e| CertError::InvalidName(format!("Failed to parse CSR DER: {}", e)))?;
        
        self.csr_params = Some(csr_params);
        Ok(self)
    }
    
    /// Loads certificate parameters from a CSR in PEM format
    ///
    /// # Arguments
    ///
    /// * `csr_pem` - The CSR in PEM format
    pub fn from_pem(self, csr_pem: &str) -> Result<Self, CertError> {
        // Parse PEM to get DER
        let pem_data = pem::parse(csr_pem)
            .map_err(|e| CertError::InvalidName(format!("Failed to parse CSR PEM: {}", e)))?;
        
        self.from_der(&pem_data.contents())
    }
    
    /// Convenience method for from_der
    ///
    /// # Arguments
    ///
    /// * `csr_der` - The CSR in DER format
    pub fn from_csr(self, csr_der: &[u8]) -> Result<Self, CertError> {
        self.from_der(csr_der)
    }
    
    /// Sets the signing key for the certificate
    ///
    /// # Arguments
    ///
    /// * `key_pem` - The private key in PKCS#8 PEM format
    pub fn signing_key(mut self, key_pem: String) -> Self {
        self.signing_key = Some(key_pem);
        self
    }
    
    /// Sets the Not Before timestamp (certificate validity start time)
    ///
    /// # Arguments
    ///
    /// * `not_before` - SystemTime when the certificate becomes valid
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::cert::CertificateBuilder;
    /// use mtls_at_lib::csr::CsrBuilder;
    /// use std::time::SystemTime;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let csr = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .build()?;
    ///
    /// let now = SystemTime::now();
    /// let builder = CertificateBuilder::new()
    ///     .from_csr(csr.to_der())?
    ///     .signing_key(csr.private_key_pem().to_string())
    ///     .not_before(now);
    /// # Ok(())
    /// # }
    /// ```
    pub fn not_before(mut self, not_before: std::time::SystemTime) -> Self {
        self.not_before = Some(not_before);
        self
    }
    
    /// Sets the Not After timestamp (certificate validity end time)
    ///
    /// # Arguments
    ///
    /// * `not_after` - SystemTime when the certificate expires
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::cert::CertificateBuilder;
    /// use mtls_at_lib::csr::CsrBuilder;
    /// use std::time::{SystemTime, Duration};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let csr = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .build()?;
    ///
    /// let expiry = SystemTime::now() + Duration::from_secs(365 * 24 * 60 * 60);
    /// let builder = CertificateBuilder::new()
    ///     .from_csr(csr.to_der())?
    ///     .signing_key(csr.private_key_pem().to_string())
    ///     .not_after(expiry);
    /// # Ok(())
    /// # }
    /// ```
    pub fn not_after(mut self, not_after: std::time::SystemTime) -> Self {
        self.not_after = Some(not_after);
        self
    }
    
    /// Sets the validity period using a duration from now
    ///
    /// This is a convenience method that sets both not_before (to now) and
    /// not_after (to now + duration).
    ///
    /// # Arguments
    ///
    /// * `duration` - How long the certificate should be valid
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::cert::CertificateBuilder;
    /// use mtls_at_lib::csr::CsrBuilder;
    /// use std::time::Duration;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let csr = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .build()?;
    ///
    /// let builder = CertificateBuilder::new()
    ///     .from_csr(csr.to_der())?
    ///     .signing_key(csr.private_key_pem().to_string())
    ///     .validity_duration(Duration::from_secs(365 * 24 * 60 * 60)); // 1 year
    /// # Ok(())
    /// # }
    /// ```
    pub fn validity_duration(mut self, duration: std::time::Duration) -> Self {
        let now = std::time::SystemTime::now();
        self.not_before = Some(now);
        self.not_after = Some(now + duration);
        self
    }
    
    /// Adds a CRL Distribution Point URI
    ///
    /// CRL Distribution Points specify where to obtain CRLs for checking
    /// certificate revocation status.
    ///
    /// # Arguments
    ///
    /// * `uri` - URI of the CRL distribution point (e.g., "http://crl.example.com/ca.crl")
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::cert::CertificateBuilder;
    /// use mtls_at_lib::csr::CsrBuilder;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let csr = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .build()?;
    ///
    /// let builder = CertificateBuilder::new()
    ///     .from_csr(csr.to_der())?
    ///     .signing_key(csr.private_key_pem().to_string())
    ///     .add_crl_distribution_point("http://crl.example.com/ca.crl")
    ///     .add_crl_distribution_point("ldap://ldap.example.com/cn=CA,dc=example,dc=com");
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_crl_distribution_point(mut self, uri: impl Into<String>) -> Self {
        self.crl_distribution_points.push(uri.into());
        self
    }
    
    /// Sets multiple CRL Distribution Point URIs
    ///
    /// # Arguments
    ///
    /// * `uris` - Vector of CRL distribution point URIs
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::cert::CertificateBuilder;
    /// use mtls_at_lib::csr::CsrBuilder;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let csr = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .build()?;
    ///
    /// let builder = CertificateBuilder::new()
    ///     .from_csr(csr.to_der())?
    ///     .signing_key(csr.private_key_pem().to_string())
    ///     .crl_distribution_points(vec![
    ///         "http://crl.example.com/ca.crl".to_string(),
    ///         "http://backup-crl.example.com/ca.crl".to_string(),
    ///     ]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn crl_distribution_points(mut self, uris: Vec<String>) -> Self {
        self.crl_distribution_points = uris;
        self
    }
    
    /// Builds a self-signed certificate
    ///
    /// For self-signed certificates, the public key in the CSR and the public key
    /// extracted from the signing key must be identical.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - CSR parameters are not loaded
    /// - Signing key is not provided
    /// - Public keys don't match
    pub fn build_self_signed(self) -> Result<Certificate, CertError> {
        // Extract fields before consuming self
        let not_before = self.not_before;
        let not_after = self.not_after;
        let crl_dps = self.crl_distribution_points.clone();
        
        let (mut csr_params, signing_key_pem) = self.validate_and_extract()?;
        let signing_key_pair = Self::parse_key(&signing_key_pem)?;
        
        // Apply validity period if specified
        if let Some(nb) = not_before {
            csr_params.params.not_before = Self::time_to_offset_datetime(nb)?;
        }
        if let Some(na) = not_after {
            csr_params.params.not_after = Self::time_to_offset_datetime(na)?;
        }
        
        // Apply CRL Distribution Points if specified
        if !crl_dps.is_empty() {
            use rcgen::CrlDistributionPoint;
            csr_params.params.crl_distribution_points = crl_dps.iter()
                .map(|uri| CrlDistributionPoint { uris: vec![uri.clone()] })
                .collect();
        }
        
        // Note: For self-signed certificates, the caller must ensure that the signing_key
        // provided is the same key that was used to create the CSR. The CSR contains
        // the public key, and the signing_key must have the matching private key.
        // rcgen will use the CSR's public key in the certificate.
        
        // Create issuer with the same DN as the subject (self-signed)
        let mut issuer_params = CertificateParams::default();
        issuer_params.distinguished_name = csr_params.params.distinguished_name.clone();
        let issuer = Issuer::new(issuer_params, &signing_key_pair);
        if Self::is_identical_pubkey(&csr_params.public_key, &signing_key_pair) == false {
            return Err(CertError::PublicKeyMismatch(
                "Public key in CSR does not match signing key".to_string()
            ));
        }
        
        // Sign the certificate
        let cert_der = csr_params.signed_by(&issuer)
            .map_err(|e| CertError::SigningError(e.to_string()))?
            .der().to_vec();
        
        // Return certificate with the private key
        Ok(Certificate::new(cert_der, Some(signing_key_pem)))
    }
    
    /// Builds a CA-signed or ICA-signed certificate
    ///
    /// For CA/ICA-signed certificates, the public key in the CSR and the public key
    /// extracted from the CA/ICA signing key must be different.
    ///
    /// # Arguments
    ///
    /// * `ca_issuer_dn` - The issuer Distinguished Name (from CA certificate)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - CSR parameters are not loaded
    /// - Signing key is not provided
    /// - Public keys are identical (would be self-signed)
    pub fn build_ca_signed(self, ca_issuer_dn: &str) -> Result<Certificate, CertError> {
        // Extract fields before consuming self
        let not_before = self.not_before;
        let not_after = self.not_after;
        let crl_dps = self.crl_distribution_points.clone();
        
        let (mut csr_params, signing_key_pem) = self.validate_and_extract()?;
        let ca_signing_key_pair = Self::parse_key(&signing_key_pem)?;
        
        // Apply validity period if specified
        if let Some(nb) = not_before {
            csr_params.params.not_before = Self::time_to_offset_datetime(nb)?;
        }
        if let Some(na) = not_after {
            csr_params.params.not_after = Self::time_to_offset_datetime(na)?;
        }
        
        // Apply CRL Distribution Points if specified
        if !crl_dps.is_empty() {
            use rcgen::CrlDistributionPoint;
            csr_params.params.crl_distribution_points = crl_dps.iter()
                .map(|uri| CrlDistributionPoint { uris: vec![uri.clone()] })
                .collect();
        }
        
        // For CA-signed certificates, the CSR's public key should be different from CA's key
        // Since rcgen doesn't expose direct public key comparison from CSR, we rely on
        // the signing process which will use the CSR's embedded public key
        
        // Parse CA's distinguished name and create issuer
        let mut issuer_params = CertificateParams::default();
        issuer_params.distinguished_name = Self::parse_dn_string(ca_issuer_dn)?;
        let issuer = Issuer::new(issuer_params, &ca_signing_key_pair);
        if Self::is_identical_pubkey(&csr_params.public_key, &ca_signing_key_pair) {
            return Err(CertError::PublicKeyMismatch(
                "Public key in CSR matches CA signing key; expected different keys for CA-signed cert".to_string()
            ));
        }
        
        // Sign the certificate with CA's key
        let cert_der = csr_params.signed_by(&issuer)
            .map_err(|e| CertError::SigningError(e.to_string()))?
            .der().to_vec();
        
        // Return certificate without private key (it stays with CSR creator)
        Ok(Certificate::new(cert_der, None))
    }

    fn is_identical_pubkey(k1: &impl PublicKeyData, k2: &impl PublicKeyData) -> bool {
        let pk1 = k1.der_bytes();
        let pk2 = k2.der_bytes();
        pk1 == pk2
    }
    
    /// Validates required fields and extracts CSR params and signing key
    fn validate_and_extract(self) -> Result<(CertificateSigningRequestParams, String), CertError> {
        let csr_params = self.csr_params
            .ok_or_else(|| CertError::MissingField("CSR parameters required".to_string()))?;
        
        let signing_key_pem = self.signing_key
            .ok_or_else(|| CertError::MissingField("Signing key required".to_string()))?;
        
        Ok((csr_params, signing_key_pem))
    }
    
    /// Parses a PEM-encoded private key
    fn parse_key(key_pem: &str) -> Result<KeyPair, CertError> {
        KeyPair::from_pem(key_pem)
            .map_err(|e| CertError::SigningError(format!("Invalid signing key: {}", e)))
    }
    
    /// Helper function to convert SystemTime to OffsetDateTime for rcgen
    fn time_to_offset_datetime(time: std::time::SystemTime) -> Result<time::OffsetDateTime, CertError> {
        use time::OffsetDateTime;
        
        let duration = time.duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CertError::SigningError(format!("Time before UNIX epoch: {}", e)))?;
        
        OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64)
            .map_err(|e| CertError::SigningError(format!("Invalid timestamp: {}", e)))
    }
    
    /// Helper function to parse DN string into rcgen format
    fn parse_dn_string(dn_str: &str) -> Result<rcgen::DistinguishedName, CertError> {
        use rcgen::{DistinguishedName as RcgenDn, DnType};
        
        let mut rcgen_dn = RcgenDn::new();
        
        for part in dn_str.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                
                match key {
                    "CN" => rcgen_dn.push(DnType::CommonName, value),
                    "O" => rcgen_dn.push(DnType::OrganizationName, value),
                    "OU" => rcgen_dn.push(DnType::OrganizationalUnitName, value),
                    "C" => rcgen_dn.push(DnType::CountryName, value),
                    "ST" | "S" => rcgen_dn.push(DnType::StateOrProvinceName, value),
                    "L" => rcgen_dn.push(DnType::LocalityName, value),
                    _ => {},
                }
            }
        }
        
        Ok(rcgen_dn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csr::CsrBuilder;
    use x509_parser::prelude::*;
    
    /// Helper function to create a test CSR with its key
    fn create_test_csr() -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
        let csr = CsrBuilder::new()
            .subject("CN=test.example.com,O=Test Org,C=US")?
            .build()?;
        
        Ok((csr.to_der().to_vec(), csr.private_key_pem().to_string(), csr.to_pem()))
    }
    
    /// Helper function to create a CA certificate and key
    fn create_ca_cert() -> Result<(String, String), Box<dyn std::error::Error>> {
        let ca_csr = CsrBuilder::new()
            .subject("CN=Test CA,O=Test CA Org,C=US")?
            .build()?;
        
        let ca_cert = CertificateBuilder::new()
            .from_csr(ca_csr.to_der())?
            .signing_key(ca_csr.private_key_pem().to_string())
            .build_self_signed()?;
        
        Ok((ca_csr.private_key_pem().to_string(), ca_cert.to_pem()))
    }
    
    /// Helper function to parse certificate DER
    fn parse_cert(der: &[u8]) -> X509Certificate<'_> {
        let (_, cert) = X509Certificate::from_der(der).expect("Failed to parse certificate");
        cert
    }
    
    #[test]
    fn test_new_builder() {
        let builder = CertificateBuilder::new();
        assert!(builder.signing_key.is_none());
        assert!(builder.csr_params.is_none());
    }
    
    #[test]
    fn test_from_der_valid() {
        let (csr_der, _, _) = create_test_csr().unwrap();
        
        let builder = CertificateBuilder::new()
            .from_der(&csr_der);
        
        assert!(builder.is_ok());
        let builder = builder.unwrap();
        assert!(builder.csr_params.is_some());
    }
    
    #[test]
    fn test_from_der_invalid() {
        let invalid_der = vec![0x00, 0x01, 0x02, 0x03];
        
        let result = CertificateBuilder::new()
            .from_der(&invalid_der);
        
        assert!(result.is_err());
        match result {
            Err(CertError::InvalidName(msg)) => {
                assert!(msg.contains("Failed to parse CSR DER"));
            }
            _ => panic!("Expected InvalidName error"),
        }
    }
    
    #[test]
    fn test_from_pem_valid() {
        let (_, _, csr_pem) = create_test_csr().unwrap();
        
        let builder = CertificateBuilder::new()
            .from_pem(&csr_pem);
        
        assert!(builder.is_ok());
        let builder = builder.unwrap();
        assert!(builder.csr_params.is_some());
    }
    
    #[test]
    fn test_from_pem_invalid() {
        let invalid_pem = "-----BEGIN CERTIFICATE REQUEST-----\nInvalidData\n-----END CERTIFICATE REQUEST-----";
        
        let result = CertificateBuilder::new()
            .from_pem(invalid_pem);
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_from_csr_valid() {
        let (csr_der, _, _) = create_test_csr().unwrap();
        
        let builder = CertificateBuilder::new()
            .from_csr(&csr_der);
        
        assert!(builder.is_ok());
        assert!(builder.unwrap().csr_params.is_some());
    }
    
    #[test]
    fn test_signing_key() {
        let test_key = "test_key_pem".to_string();
        let builder = CertificateBuilder::new()
            .signing_key(test_key.clone());
        
        assert_eq!(builder.signing_key, Some(test_key));
    }
    
    #[test]
    fn test_build_self_signed_success() {
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .build_self_signed();
        
        assert!(cert.is_ok());
        let cert = cert.unwrap();
        
        // Verify the certificate has a private key (self-signed includes private key)
        assert!(cert.private_key_pem().is_some());
        
        // Verify we can get PEM and DER formats
        assert!(!cert.to_pem().is_empty());
        assert!(!cert.to_der().is_empty());
        
        // Parse certificate and validate DN matches input
        let parsed = parse_cert(cert.to_der());
        let subject = parsed.subject();
        
        // Verify subject DN contains expected values
        let cn = subject.iter_common_name().next().unwrap().as_str().unwrap();
        assert_eq!(cn, "test.example.com");
        
        let o = subject.iter_organization().next().unwrap().as_str().unwrap();
        assert_eq!(o, "Test Org");
        
        let c = subject.iter_country().next().unwrap().as_str().unwrap();
        assert_eq!(c, "US");
    }
    
    #[test]
    fn test_build_self_signed_missing_csr() {
        let key_pair = KeyPair::generate().unwrap();
        let key_pem = key_pair.serialize_pem();
        
        let result = CertificateBuilder::new()
            .signing_key(key_pem)
            .build_self_signed();
        
        assert!(result.is_err());
        match result {
            Err(CertError::MissingField(msg)) => {
                assert!(msg.contains("CSR parameters required"));
            }
            _ => panic!("Expected MissingField error"),
        }
    }
    
    #[test]
    fn test_build_self_signed_missing_key() {
        let (csr_der, _, _) = create_test_csr().unwrap();
        
        let result = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .build_self_signed();
        
        assert!(result.is_err());
        match result {
            Err(CertError::MissingField(msg)) => {
                assert!(msg.contains("Signing key required"));
            }
            _ => panic!("Expected MissingField error"),
        }
    }
    
    #[test]
    fn test_build_self_signed_key_mismatch() {
        let (csr_der, _, _) = create_test_csr().unwrap();
        
        // Generate a different key
        let different_key = KeyPair::generate().unwrap();
        let different_key_pem = different_key.serialize_pem();
        
        let result = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(different_key_pem)
            .build_self_signed();
        
        assert!(result.is_err());
        match result {
            Err(CertError::PublicKeyMismatch(msg)) => {
                assert!(msg.contains("Public key in CSR does not match signing key"));
            }
            _ => panic!("Expected PublicKeyMismatch error, got: {:?}", result),
        }
    }
    
    #[test]
    fn test_build_self_signed_invalid_key() {
        let (csr_der, _, _) = create_test_csr().unwrap();
        
        let result = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key("invalid_key".to_string())
            .build_self_signed();
        
        assert!(result.is_err());
        match result {
            Err(CertError::SigningError(msg)) => {
                assert!(msg.contains("Invalid signing key"));
            }
            _ => panic!("Expected SigningError"),
        }
    }
    
    #[test]
    fn test_build_ca_signed_success() {
        let (csr_der, _, _) = create_test_csr().unwrap();
        let (ca_key_pem, _) = create_ca_cert().unwrap();
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(ca_key_pem)
            .build_ca_signed("CN=Test CA,O=Test CA Org,C=US");
        
        assert!(cert.is_ok());
        let cert = cert.unwrap();
        
        // CA-signed cert should not include the private key
        assert!(cert.private_key_pem().is_none());
        
        // Verify we can get PEM and DER formats
        assert!(!cert.to_pem().is_empty());
        assert!(!cert.to_der().is_empty());
    }
    
    #[test]
    fn test_build_ca_signed_missing_csr() {
        let key_pair = KeyPair::generate().unwrap();
        let key_pem = key_pair.serialize_pem();
        
        let result = CertificateBuilder::new()
            .signing_key(key_pem)
            .build_ca_signed("CN=Test CA");
        
        assert!(result.is_err());
        match result {
            Err(CertError::MissingField(msg)) => {
                assert!(msg.contains("CSR parameters required"));
            }
            _ => panic!("Expected MissingField error"),
        }
    }
    
    #[test]
    fn test_build_ca_signed_missing_key() {
        let (csr_der, _, _) = create_test_csr().unwrap();
        
        let result = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .build_ca_signed("CN=Test CA");
        
        assert!(result.is_err());
        match result {
            Err(CertError::MissingField(msg)) => {
                assert!(msg.contains("Signing key required"));
            }
            _ => panic!("Expected MissingField error"),
        }
    }
    
    #[test]
    fn test_build_ca_signed_same_key_error() {
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        // Try to sign with the same key (should fail)
        let result = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .build_ca_signed("CN=Test CA,O=Test Org,C=US");
        
        assert!(result.is_err());
        match result {
            Err(CertError::PublicKeyMismatch(msg)) => {
                assert!(msg.contains("Public key in CSR matches CA signing key"));
            }
            _ => panic!("Expected PublicKeyMismatch error, got: {:?}", result),
        }
    }
    
    #[test]
    fn test_parse_dn_string_simple() {
        let dn_str = "CN=test.example.com";
        let result = CertificateBuilder::parse_dn_string(dn_str);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_parse_dn_string_complex() {
        let dn_str = "CN=test.example.com,O=Test Org,OU=IT Department,C=US,ST=California,L=San Francisco";
        let result = CertificateBuilder::parse_dn_string(dn_str);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_parse_dn_string_with_spaces() {
        let dn_str = "CN = test.example.com , O = Test Org , C = US";
        let result = CertificateBuilder::parse_dn_string(dn_str);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_parse_dn_string_empty() {
        let dn_str = "";
        let result = CertificateBuilder::parse_dn_string(dn_str);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_parse_key_valid() {
        let key_pair = KeyPair::generate().unwrap();
        let key_pem = key_pair.serialize_pem();
        
        let result = CertificateBuilder::parse_key(&key_pem);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_parse_key_invalid() {
        let invalid_key = "not a valid key";
        let result = CertificateBuilder::parse_key(invalid_key);
        
        assert!(result.is_err());
        match result {
            Err(CertError::SigningError(msg)) => {
                assert!(msg.contains("Invalid signing key"));
            }
            _ => panic!("Expected SigningError"),
        }
    }
    
    #[test]
    fn test_is_identical_pubkey_same() {
        let key_pair = KeyPair::generate().unwrap();
        let key_pem = key_pair.serialize_pem();
        let key_pair2 = KeyPair::from_pem(&key_pem).unwrap();
        
        assert!(CertificateBuilder::is_identical_pubkey(&key_pair, &key_pair2));
    }
    
    #[test]
    fn test_is_identical_pubkey_different() {
        let key_pair1 = KeyPair::generate().unwrap();
        let key_pair2 = KeyPair::generate().unwrap();
        
        assert!(!CertificateBuilder::is_identical_pubkey(&key_pair1, &key_pair2));
    }
    
    #[test]
    fn test_builder_chain() {
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        // Test chaining methods
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .build_self_signed();
        
        assert!(cert.is_ok());
    }
    
    #[test]
    fn test_from_pem_and_from_der_equivalence() {
        let (csr_der, _, csr_pem) = create_test_csr().unwrap();
        
        let builder_from_der = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap();
        
        let builder_from_pem = CertificateBuilder::new()
            .from_pem(&csr_pem)
            .unwrap();
        
        // Both should have CSR params loaded
        assert!(builder_from_der.csr_params.is_some());
        assert!(builder_from_pem.csr_params.is_some());
    }
    
    #[test]
    fn test_validate_and_extract_success() {
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        let builder = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem.clone());
        
        let result = builder.validate_and_extract();
        assert!(result.is_ok());
        
        let (csr_params, extracted_key) = result.unwrap();
        assert_eq!(extracted_key, key_pem);
        // CSR params should be valid
        assert!(!csr_params.params.distinguished_name.iter().collect::<Vec<_>>().is_empty());
    }
    
    #[test]
    fn test_certificate_pem_format() {
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .build_self_signed()
            .unwrap();
        
        let pem = cert.to_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }
    
    #[test]
    fn test_certificate_der_format() {
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .build_self_signed()
            .unwrap();
        
        let der = cert.to_der();
        assert!(!der.is_empty());
        // DER format typically starts with 0x30 (SEQUENCE tag)
        assert_eq!(der[0], 0x30);
    }
    
    #[test]
    fn test_certificate_private_key_der() {
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        // Test self-signed cert (should have private key)
        let self_signed_cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem.clone())
            .build_self_signed()
            .unwrap();
        
        let private_key_der = self_signed_cert.private_key_der();
        assert!(private_key_der.is_some(), "Self-signed cert should have private key DER");
        
        let der = private_key_der.unwrap();
        assert!(!der.is_empty(), "Private key DER should not be empty");
        
        // DER private keys typically start with 0x30 (SEQUENCE tag)
        assert_eq!(der[0], 0x30, "Private key DER should start with SEQUENCE tag");
        
        // Test CA-signed cert (should NOT have private key)
        let (ca_key_pem, _) = create_ca_cert().unwrap();
        let ca_signed_cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(ca_key_pem)
            .build_ca_signed("CN=Test CA,O=Test CA Org,C=US")
            .unwrap();
        
        assert!(ca_signed_cert.private_key_der().is_none(), "CA-signed cert should not have private key DER");
    }
    
    #[test]
    fn test_not_before_setter() {
        use std::time::SystemTime;
        
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        let now = SystemTime::now();
        
        let builder = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .not_before(now);
        
        assert!(builder.not_before.is_some());
    }
    
    #[test]
    fn test_not_after_setter() {
        use std::time::{SystemTime, Duration};
        
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        let expiry = SystemTime::now() + Duration::from_secs(365 * 24 * 60 * 60);
        
        let builder = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .not_after(expiry);
        
        assert!(builder.not_after.is_some());
    }
    
    #[test]
    fn test_validity_duration_setter() {
        use std::time::Duration;
        
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        let ninety_days = Duration::from_secs(90 * 24 * 60 * 60);
        
        let builder = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .validity_duration(ninety_days);
        
        assert!(builder.not_before.is_some());
        assert!(builder.not_after.is_some());
    }
    
    #[test]
    fn test_add_crl_distribution_point() {
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        let builder = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .add_crl_distribution_point("http://crl.example.com/ca.crl");
        
        assert_eq!(builder.crl_distribution_points.len(), 1);
        assert_eq!(builder.crl_distribution_points[0], "http://crl.example.com/ca.crl");
    }
    
    #[test]
    fn test_multiple_crl_distribution_points() {
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        let builder = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .add_crl_distribution_point("http://crl1.example.com/ca.crl")
            .add_crl_distribution_point("http://crl2.example.com/ca.crl")
            .add_crl_distribution_point("ldap://ldap.example.com/cn=CA");
        
        assert_eq!(builder.crl_distribution_points.len(), 3);
    }
    
    #[test]
    fn test_crl_distribution_points_vector() {
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        let uris = vec![
            "http://crl1.example.com/ca.crl".to_string(),
            "http://crl2.example.com/ca.crl".to_string(),
        ];
        
        let builder = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .crl_distribution_points(uris.clone());
        
        assert_eq!(builder.crl_distribution_points, uris);
    }
    
    #[test]
    fn test_self_signed_cert_with_validity_period() {
        use std::time::{SystemTime, Duration};
        
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        let now = SystemTime::now();
        let one_year_later = now + Duration::from_secs(365 * 24 * 60 * 60);
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .not_before(now)
            .not_after(one_year_later)
            .build_self_signed();
        
        assert!(cert.is_ok());
        let cert = cert.unwrap();
        assert!(!cert.to_pem().is_empty());
        assert!(!cert.to_der().is_empty());
    }
    
    #[test]
    fn test_self_signed_cert_with_validity_duration() {
        use std::time::Duration;
        
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        let ninety_days = Duration::from_secs(90 * 24 * 60 * 60);
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .validity_duration(ninety_days)
            .build_self_signed();
        
        assert!(cert.is_ok());
        let cert = cert.unwrap();
        assert!(cert.private_key_pem().is_some());
    }
    
    #[test]
    fn test_self_signed_cert_with_crl_distribution_points() {
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .add_crl_distribution_point("http://crl.example.com/ca.crl")
            .add_crl_distribution_point("http://backup-crl.example.com/ca.crl")
            .build_self_signed();
        
        assert!(cert.is_ok());
        let cert = cert.unwrap();
        assert!(!cert.to_pem().is_empty());
    }
    
    #[test]
    fn test_ca_signed_cert_with_validity_period() {
        use std::time::{SystemTime, Duration};
        
        let (csr_der, _, _) = create_test_csr().unwrap();
        let (ca_key_pem, _) = create_ca_cert().unwrap();
        
        let now = SystemTime::now();
        let two_years_later = now + Duration::from_secs(2 * 365 * 24 * 60 * 60);
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(ca_key_pem)
            .not_before(now)
            .not_after(two_years_later)
            .build_ca_signed("CN=Test CA,O=Test CA Org,C=US");
        
        assert!(cert.is_ok());
        let cert = cert.unwrap();
        assert!(cert.private_key_pem().is_none());
        assert!(!cert.to_der().is_empty());
    }
    
    #[test]
    fn test_ca_signed_cert_with_crl_distribution_points() {
        let (csr_der, _, _) = create_test_csr().unwrap();
        let (ca_key_pem, _) = create_ca_cert().unwrap();
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(ca_key_pem)
            .add_crl_distribution_point("http://ca-crl.example.com/ca.crl")
            .add_crl_distribution_point("ldap://ldap.example.com/cn=CA,dc=example,dc=com")
            .build_ca_signed("CN=Test CA,O=Test CA Org,C=US");
        
        assert!(cert.is_ok());
        let cert = cert.unwrap();
        assert!(!cert.to_pem().is_empty());
    }
    
    #[test]
    fn test_cert_with_all_new_features() {
        use std::time::{SystemTime, Duration};
        
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        let now = SystemTime::now();
        let expiry = now + Duration::from_secs(365 * 24 * 60 * 60);
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .not_before(now)
            .not_after(expiry)
            .add_crl_distribution_point("http://crl.example.com/ca.crl")
            .add_crl_distribution_point("http://backup-crl.example.com/ca.crl")
            .add_crl_distribution_point("ldap://ldap.example.com/cn=CA,dc=example,dc=com")
            .build_self_signed();
        
        assert!(cert.is_ok());
        let cert = cert.unwrap();
        assert!(cert.private_key_pem().is_some());
        assert!(!cert.to_pem().is_empty());
        assert!(!cert.to_der().is_empty());
    }
    
    #[test]
    fn test_ca_cert_with_long_validity_and_crl() {
        use std::time::Duration;
        
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        let ten_years = Duration::from_secs(10 * 365 * 24 * 60 * 60);
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .validity_duration(ten_years)
            .add_crl_distribution_point("http://root-ca.example.com/root.crl")
            .build_self_signed();
        
        assert!(cert.is_ok());
        let cert = cert.unwrap();
        assert!(!cert.to_der().is_empty());
    }
    
    #[test]
    fn test_short_lived_certificate() {
        use std::time::Duration;
        
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        let seven_days = Duration::from_secs(7 * 24 * 60 * 60);
        
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .validity_duration(seven_days)
            .build_self_signed();
        
        assert!(cert.is_ok());
    }
    
    #[test]
    fn test_builder_method_chaining_with_new_fields() {
        use std::time::Duration;
        
        let (csr_der, key_pem, _) = create_test_csr().unwrap();
        
        // Test that all methods can be chained fluently
        let cert = CertificateBuilder::new()
            .from_der(&csr_der)
            .unwrap()
            .signing_key(key_pem)
            .validity_duration(Duration::from_secs(365 * 24 * 60 * 60))
            .add_crl_distribution_point("http://crl1.example.com/ca.crl")
            .add_crl_distribution_point("http://crl2.example.com/ca.crl")
            .build_self_signed();
        
        assert!(cert.is_ok());
    }
}
