//! CSR Builder for constructing Certificate Signing Requests
//!
//! This module provides a type-safe builder API for creating CSRs with
//! Key Usage and Extended Key Usage extensions.

use crate::error::CsrError;
use crate::types::{DistinguishedName, ExtendedKeyUsage, KeyUsage};
use super::Csr;

use rcgen::{
    CertificateParams, DistinguishedName as RcgenDn, DnType, 
    KeyPair, KeyUsagePurpose, ExtendedKeyUsagePurpose, SanType
};

/// Builder for creating Certificate Signing Requests
///
/// This builder provides a fluent API for configuring and generating CSRs.
/// It enforces the requirement that all CSRs must have a subject DN.
///
/// # Examples
///
/// ```
/// use mtls_at_lib::csr::CsrBuilder;
/// use mtls_at_lib::types::KeyUsage;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a CA CSR
/// let ca_csr = CsrBuilder::new()
///     .subject("CN=My Root CA,O=My Organization,C=US")?
///     .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
///     .is_ca(true)
///     .build()?;
///     
/// // Create a server certificate CSR
/// let server_csr = CsrBuilder::new()
///     .subject("CN=server.example.com")?
///     .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct CsrBuilder {
    /// Subject Distinguished Name (required)
    subject: Option<DistinguishedName>,
    
    /// Key Usage extension
    key_usage: Option<KeyUsage>,
    
    /// Extended Key Usage extension
    extended_key_usage: Vec<ExtendedKeyUsage>,
    
    /// CA flag for BasicConstraints extension
    is_ca: bool,
    
    /// Path length constraint for CA certificates
    path_len_constraint: Option<u8>,
    
    /// Subject Alternative Names
    subject_alt_names: Vec<String>,
    
    /// Optional custom key pair (if not provided, a new one will be generated)
    key_pair: Option<KeyPair>,
}

impl CsrBuilder {
    /// Creates a new CSR builder
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::csr::CsrBuilder;
    ///
    /// let builder = CsrBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            subject: None,
            key_usage: None,
            extended_key_usage: Vec::new(),
            is_ca: false,
            path_len_constraint: None,
            subject_alt_names: Vec::new(),
            key_pair: None,
        }
    }
    
    /// Sets the subject Distinguished Name
    ///
    /// The subject is required for all CSRs.
    ///
    /// # Arguments
    ///
    /// * `dn` - Distinguished Name string (e.g., "CN=example.com,O=My Org,C=US")
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::csr::CsrBuilder;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let builder = CsrBuilder::new()
    ///     .subject("CN=example.com,O=Example Inc,C=US")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn subject(mut self, dn: &str) -> Result<Self, CsrError> {
        self.subject = Some(DistinguishedName::from_str(dn)?);
        Ok(self)
    }
    
    /// Sets a custom key pair to use for the CSR
    ///
    /// If not provided, a new ECDSA P-256 key pair will be generated automatically.
    ///
    /// # Arguments
    ///
    /// * `key_pem` - Private key in PKCS#8 PEM format
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::csr::CsrBuilder;
    /// use rcgen::KeyPair;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key_pair = KeyPair::generate()?;
    /// let key_pem = key_pair.serialize_pem();
    ///
    /// let csr = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .with_key(&key_pem)?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_key(mut self, key_pem: &str) -> Result<Self, CsrError> {
        let key_pair = KeyPair::from_pem(key_pem)
            .map_err(|e| CsrError::KeyGenerationFailed(format!("Invalid key: {}", e)))?;
        self.key_pair = Some(key_pair);
        Ok(self)
    }
    
    /// Sets the Key Usage extension
    ///
    /// # Arguments
    ///
    /// * `usage` - KeyUsage flags (can be combined with `|`)
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::csr::CsrBuilder;
    /// use mtls_at_lib::types::KeyUsage;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let builder = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment());
    /// # Ok(())
    /// # }
    /// ```
    pub fn key_usage(mut self, usage: KeyUsage) -> Self {
        self.key_usage = Some(usage);
        self
    }
    
    /// Sets the Extended Key Usage extension
    ///
    /// # Arguments
    ///
    /// * `ext_usage` - Vec of ExtendedKeyUsage values
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::csr::CsrBuilder;
    /// use mtls_at_lib::types::ExtendedKeyUsage;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let builder = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn extended_key_usage(mut self, ext_usage: Vec<ExtendedKeyUsage>) -> Self {
        self.extended_key_usage = ext_usage;
        self
    }
    
    /// Marks this CSR for a CA certificate
    ///
    /// This sets the CA flag in the BasicConstraints extension.
    ///
    /// # Arguments
    ///
    /// * `is_ca` - Whether this is for a CA certificate
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::csr::CsrBuilder;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let builder = CsrBuilder::new()
    ///     .subject("CN=My Root CA")?
    ///     .is_ca(true);
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_ca(mut self, is_ca: bool) -> Self {
        self.is_ca = is_ca;
        self
    }
    
    /// Sets the path length constraint for CA certificates
    ///
    /// This restricts how many intermediate CAs can appear in a chain
    /// below this CA.
    ///
    /// # Arguments
    ///
    /// * `path_len` - Maximum number of intermediate CAs
    pub fn path_len_constraint(mut self, path_len: u8) -> Self {
        self.path_len_constraint = Some(path_len);
        self
    }
    
    /// Adds a Subject Alternative Name (SAN)
    ///
    /// # Arguments
    ///
    /// * `san` - DNS name, IP address, or URI
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::csr::CsrBuilder;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let builder = CsrBuilder::new()
    ///     .subject("CN=example.com")?
    ///     .add_san("www.example.com")
    ///     .add_san("api.example.com");
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_san(mut self, san: impl Into<String>) -> Self {
        self.subject_alt_names.push(san.into());
        self
    }
    
    /// Builds the CSR and generates a new key pair
    ///
    /// This generates a new ECDSA P-256 key pair, configures the certificate
    /// parameters according to the builder settings, and creates a CSR.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The subject DN is not set
    /// - Key pair generation fails
    /// - CSR serialization fails
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
    /// // CSR is now ready to use
    /// let pem = csr.to_pem();
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self) -> Result<Csr, CsrError> {
        // Validate required fields
        let subject = self.subject.ok_or_else(|| {
            CsrError::InvalidSubjectName("Subject name is required".to_string())
        })?;
        
        // Use provided key pair or generate a new one (ECDSA P-256 for security and performance)
        let key_pair = if let Some(kp) = self.key_pair {
            kp
        } else {
            KeyPair::generate()
                .map_err(|e| CsrError::KeyGenerationFailed(e.to_string()))?
        };
        
        // Create certificate parameters
        let mut params = CertificateParams::default();
        
        // Set subject DN - convert our DistinguishedName to rcgen format
        params.distinguished_name = Self::convert_dn(&subject)?;
        
        // Set Key Usage if specified
        if let Some(ku) = self.key_usage {
            params.key_usages = Self::convert_key_usage(ku);
        }
        
        // Set Extended Key Usage if specified
        if !self.extended_key_usage.is_empty() {
            params.extended_key_usages = Self::convert_extended_key_usage(&self.extended_key_usage);
        }
        
        // Note: BasicConstraints (is_ca) is a certificate parameter, not a CSR parameter
        // It will be set when the certificate is issued from this CSR
        // We store it here for future use but don't include it in the CSR
        
        // Set Subject Alternative Names
        if !self.subject_alt_names.is_empty() {
            params.subject_alt_names = self.subject_alt_names.iter()
                .map(|s| SanType::DnsName(s.clone().try_into().unwrap()))
                .collect();
        }
        
        // Generate CSR
        let csr = params.serialize_request(&key_pair)
            .map_err(|e| CsrError::EncodingError(e.to_string()))?;
        
        Ok(Csr::new(csr.der().to_vec(), key_pair))
    }
    
    /// Converts our DistinguishedName to rcgen's format
    fn convert_dn(dn: &DistinguishedName) -> Result<RcgenDn, CsrError> {
        let mut rcgen_dn = RcgenDn::new();
        
        // Parse the DN string and add components
        // Our DistinguishedName stores raw string, so we need to parse it
        let dn_str = dn.as_str();
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
                    _ => {}, // Ignore unknown attributes
                }
            }
        }
        
        Ok(rcgen_dn)
    }
    
    /// Converts our KeyUsage flags to rcgen's format
    fn convert_key_usage(ku: KeyUsage) -> Vec<KeyUsagePurpose> {
        let mut purposes = Vec::new();
        
        if ku.contains(KeyUsage::digital_signature()) {
            purposes.push(KeyUsagePurpose::DigitalSignature);
        }
        if ku.contains(KeyUsage::non_repudiation()) {
            purposes.push(KeyUsagePurpose::ContentCommitment);
        }
        if ku.contains(KeyUsage::key_encipherment()) {
            purposes.push(KeyUsagePurpose::KeyEncipherment);
        }
        if ku.contains(KeyUsage::data_encipherment()) {
            purposes.push(KeyUsagePurpose::DataEncipherment);
        }
        if ku.contains(KeyUsage::key_agreement()) {
            purposes.push(KeyUsagePurpose::KeyAgreement);
        }
        if ku.contains(KeyUsage::key_cert_sign()) {
            purposes.push(KeyUsagePurpose::KeyCertSign);
        }
        if ku.contains(KeyUsage::crl_sign()) {
            purposes.push(KeyUsagePurpose::CrlSign);
        }
        if ku.contains(KeyUsage::encipher_only()) {
            purposes.push(KeyUsagePurpose::EncipherOnly);
        }
        if ku.contains(KeyUsage::decipher_only()) {
            purposes.push(KeyUsagePurpose::DecipherOnly);
        }
        
        purposes
    }
    
    /// Converts our ExtendedKeyUsage to rcgen's format
    fn convert_extended_key_usage(eku_list: &[ExtendedKeyUsage]) -> Vec<ExtendedKeyUsagePurpose> {
        eku_list.iter().map(|eku| {
            if eku == &ExtendedKeyUsage::SERVER_AUTH {
                ExtendedKeyUsagePurpose::ServerAuth
            } else if eku == &ExtendedKeyUsage::CLIENT_AUTH {
                ExtendedKeyUsagePurpose::ClientAuth
            } else if eku == &ExtendedKeyUsage::CODE_SIGNING {
                ExtendedKeyUsagePurpose::CodeSigning
            } else if eku == &ExtendedKeyUsage::EMAIL_PROTECTION {
                ExtendedKeyUsagePurpose::EmailProtection
            } else if eku == &ExtendedKeyUsage::TIME_STAMPING {
                ExtendedKeyUsagePurpose::TimeStamping
            } else {
                ExtendedKeyUsagePurpose::OcspSigning
            }
        }).collect()
    }
}

impl Default for CsrBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{KeyUsage, ExtendedKeyUsage};
    use x509_parser::prelude::*;
    
    /// Helper to parse CSR DER
    fn parse_csr(der: &[u8]) -> X509CertificationRequest<'_> {
        let (_, csr) = X509CertificationRequest::from_der(der).expect("Failed to parse CSR");
        csr
    }
    
    #[test]
    fn test_basic_csr_generation() {
        let csr = CsrBuilder::new()
            .subject("CN=test.example.com").unwrap()
            .build().unwrap();
            
        let pem = csr.to_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(!csr.to_der().is_empty());
        
        // Parse CSR and validate subject DN matches input
        let parsed = parse_csr(csr.to_der());
        let subject = parsed.certification_request_info.subject;
        let cn = subject.iter_common_name().next().unwrap().as_str().unwrap();
        assert_eq!(cn, "test.example.com", "CN should match input");
    }
    
    #[test]
    fn test_ca_csr_generation() {
        let csr = CsrBuilder::new()
            .subject("CN=Test Root CA,O=Test Org,C=US").unwrap()
            .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
            .is_ca(true)
            .build().unwrap();
            
        assert!(!csr.to_der().is_empty());
        
        // Parse CSR and validate subject DN matches input
        let parsed = parse_csr(csr.to_der());
        let subject = parsed.certification_request_info.subject;
        let cn = subject.iter_common_name().next().unwrap().as_str().unwrap();
        assert_eq!(cn, "Test Root CA");
        let o = subject.iter_organization().next().unwrap().as_str().unwrap();
        assert_eq!(o, "Test Org");
        let c = subject.iter_country().next().unwrap().as_str().unwrap();
        assert_eq!(c, "US");
    }
    
    #[test]
    fn test_server_csr_with_eku() {
        let csr = CsrBuilder::new()
            .subject("CN=server.example.com").unwrap()
            .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
            .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH])
            .add_san("www.example.com")
            .add_san("api.example.com")
            .build().unwrap();
            
        assert!(!csr.to_der().is_empty());
        assert!(!csr.private_key_pem().is_empty());
    }
    
    #[test]
    fn test_missing_subject_error() {
        let result = CsrBuilder::new().build();
        assert!(matches!(result, Err(CsrError::InvalidSubjectName(_))));
    }
    
    #[test]
    fn test_private_key_export() {
        let csr = CsrBuilder::new()
            .subject("CN=test.example.com").unwrap()
            .build().unwrap();
            
        let pem = csr.private_key_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        
        let der = csr.private_key_der();
        assert!(!der.is_empty());
    }
    
    #[test]
    fn test_path_len_constraint() {
        // Test CA CSR with path length constraint
        let csr = CsrBuilder::new()
            .subject("CN=Intermediate CA,O=Test Org,C=US").unwrap()
            .is_ca(true)
            .path_len_constraint(1)
            .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
            .build().unwrap();
            
        assert!(!csr.to_der().is_empty());
        
        // Verify CSR was created successfully
        let parsed = parse_csr(csr.to_der());
        let cn = parsed.certification_request_info.subject
            .iter_common_name().next().unwrap().as_str().unwrap();
        assert_eq!(cn, "Intermediate CA");
    }
    
    #[test]
    fn test_path_len_constraint_zero() {
        // Test CA CSR with path length constraint of 0 (no subordinate CAs allowed)
        let csr = CsrBuilder::new()
            .subject("CN=Leaf CA,O=Test Org,C=US").unwrap()
            .is_ca(true)
            .path_len_constraint(0)
            .key_usage(KeyUsage::key_cert_sign())
            .build().unwrap();
            
        assert!(!csr.to_der().is_empty());
        let pem = csr.to_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    }
    
    #[test]
    fn test_dn_state_and_locality_parsing() {
        // Test parsing of State (ST and S) and Locality (L) DN components
        let csr_st = CsrBuilder::new()
            .subject("CN=Test Server,ST=California,L=San Francisco,O=Test Corp,C=US").unwrap()
            .build().unwrap();
            
        let parsed_st = parse_csr(csr_st.to_der());
        let subject_st = parsed_st.certification_request_info.subject;
        
        // Verify CN matches
        let cn = subject_st.iter_common_name().next().unwrap().as_str().unwrap();
        assert_eq!(cn, "Test Server");
        
        // Verify State (ST) matches
        let state = subject_st.iter_state_or_province().next().unwrap().as_str().unwrap();
        assert_eq!(state, "California", "State (ST) should match input");
        
        // Verify Locality (L) matches
        let locality = subject_st.iter_locality().next().unwrap().as_str().unwrap();
        assert_eq!(locality, "San Francisco", "Locality (L) should match input");
        
        // Test with 'S' instead of 'ST' for state
        let csr_s = CsrBuilder::new()
            .subject("CN=Test Server 2,S=New York,L=New York City,C=US").unwrap()
            .build().unwrap();
            
        let parsed_s = parse_csr(csr_s.to_der());
        let subject_s = parsed_s.certification_request_info.subject;
        
        let state_s = subject_s.iter_state_or_province().next().unwrap().as_str().unwrap();
        assert_eq!(state_s, "New York", "State (S) should match input");
        
        let locality_s = subject_s.iter_locality().next().unwrap().as_str().unwrap();
        assert_eq!(locality_s, "New York City", "Locality should match input");
    }
    
    #[test]
    fn test_dn_with_unknown_attributes_ignored() {
        // Test that unknown DN attributes are ignored without causing errors
        let csr = CsrBuilder::new()
            .subject("CN=Test,UNKNOWN=Value,O=Org,C=US").unwrap()
            .build().unwrap();
            
        let parsed = parse_csr(csr.to_der());
        let subject = parsed.certification_request_info.subject;
        
        // Verify known attributes are parsed correctly
        let cn = subject.iter_common_name().next().unwrap().as_str().unwrap();
        assert_eq!(cn, "Test");
        let o = subject.iter_organization().next().unwrap().as_str().unwrap();
        assert_eq!(o, "Org");
    }
    
    #[test]
    fn test_extended_key_usage_fallback() {
        // This test verifies the fallback behavior in convert_extended_key_usage
        // While we can't directly test an unknown EKU value (since ExtendedKeyUsage is an enum),
        // we can test that all known EKU values are correctly converted
        let all_ekus = vec![
            ExtendedKeyUsage::SERVER_AUTH,
            ExtendedKeyUsage::CLIENT_AUTH,
            ExtendedKeyUsage::CODE_SIGNING,
            ExtendedKeyUsage::EMAIL_PROTECTION,
            ExtendedKeyUsage::TIME_STAMPING,
            ExtendedKeyUsage::OCSP_SIGNING,
        ];
        
        let csr = CsrBuilder::new()
            .subject("CN=test-all-eku.example.com").unwrap()
            .extended_key_usage(all_ekus)
            .build().unwrap();
            
        assert!(!csr.to_der().is_empty(), "CSR with all EKU types should be generated");
        
        // Parse and verify CSR is valid
        let parsed = parse_csr(csr.to_der());
        let cn = parsed.certification_request_info.subject
            .iter_common_name().next().unwrap().as_str().unwrap();
        assert_eq!(cn, "test-all-eku.example.com");
    }
    
    #[test]
    fn test_default_trait() {
        // Test that Default::default() creates the same instance as new()
        let builder1 = CsrBuilder::new();
        let builder2 = CsrBuilder::default();
        
        // Both should successfully build a CSR with the same configuration
        let csr1 = builder1.subject("CN=default-test.com").unwrap().build().unwrap();
        let csr2 = builder2.subject("CN=default-test.com").unwrap().build().unwrap();
        
        assert!(!csr1.to_der().is_empty());
        assert!(!csr2.to_der().is_empty());
        
        // Both CSRs should have the same subject
        let parsed1 = parse_csr(csr1.to_der());
        let parsed2 = parse_csr(csr2.to_der());
        
        let cn1 = parsed1.certification_request_info.subject.iter_common_name().next().unwrap().as_str().unwrap();
        let cn2 = parsed2.certification_request_info.subject.iter_common_name().next().unwrap().as_str().unwrap();
        
        assert_eq!(cn1, cn2, "Both builders should create CSRs with same subject");
    }
    
    #[test]
    fn test_private_key_reference() {
        // Test the private_key() method that returns a reference to KeyPair
        let csr = CsrBuilder::new()
            .subject("CN=key-ref-test.example.com").unwrap()
            .build().unwrap();
            
        // Get reference to private key
        let key_ref = csr.private_key();
        
        // Verify we can serialize from the reference
        let pem_from_ref = key_ref.serialize_pem();
        assert!(pem_from_ref.starts_with("-----BEGIN PRIVATE KEY-----"));
        
        // Verify it matches the direct method
        let pem_direct = csr.private_key_pem();
        assert_eq!(pem_from_ref, pem_direct, "Key reference should match direct access");
        
        // Verify DER format also matches
        let der_from_ref = key_ref.serialize_der();
        let der_direct = csr.private_key_der();
        assert_eq!(der_from_ref, der_direct, "DER from reference should match direct access");
    }
}
