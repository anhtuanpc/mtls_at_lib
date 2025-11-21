//! RevokedCertificate struct is used to build the list of revoked certificates
//! in a Certificate Revocation List (CRL).
//! CrlBuilder provides a type-safe builder API for creating CRLs with
//! revoked certificates, issuer key, and validity periods.
//!
//! This module provides the following main components:
//! - `RevokedCertificate`: Represents a single revoked certificate entry in a CRL 
//! - `CrlBuilder`: Builder for creating CRLs with revoked certificates
//! - `Crl`: Represents the generated CRL in DER format
//! 
use rcgen::{CertificateRevocationListParams, Issuer, KeyIdMethod, KeyPair, RevokedCertParams, SerialNumber};
use time::OffsetDateTime;

use crate::CrlError;
use crate::types::RevocationReason;

use super::Crl;

/// A revoked certificate entry in a CRL
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    /// Serial number of the revoked certificate
    pub serial_number: SerialNumber,
    
    /// Time when the certificate was revoked
    pub revocation_time: OffsetDateTime,
    
    /// Reason for revocation
    pub reason: Option<RevocationReason>,
}

impl RevokedCertificate {
    /// Creates a new revoked certificate entry
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::crl::RevokedCertificate;
    /// use mtls_at_lib::types::RevocationReason;
    /// use rcgen::SerialNumber;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let serial = SerialNumber::from(12345u64);
    /// let revoked = RevokedCertificate::new(serial)
    ///     .with_reason(RevocationReason::KEY_COMPROMISE);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(serial_number: SerialNumber) -> Self {
        Self {
            serial_number,
            revocation_time: OffsetDateTime::now_utc(),
            reason: None,
        }
    }
    
    /// Sets the revocation time
    pub fn with_time(mut self, time: OffsetDateTime) -> Self {
        self.revocation_time = time;
        self
    }
    
    /// Sets the revocation reason
    pub fn with_reason(mut self, reason: RevocationReason) -> Self {
        self.reason = Some(reason);
        self
    }
}

/// Builder for creating Certificate Revocation Lists
///
/// # Examples
///
/// ```
/// use mtls_at_lib::crl::{CrlBuilder, RevokedCertificate};
/// use mtls_at_lib::cert::CertificateBuilder;
/// use mtls_at_lib::csr::CsrBuilder;
/// use mtls_at_lib::types::{KeyUsage, RevocationReason};
/// use rcgen::SerialNumber;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a CA
/// let ca_csr = CsrBuilder::new()
///     .subject("CN=Test CA,O=Example Corp,C=US")?
///     .is_ca(true)
///     .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
///     .build()?;
///
/// let ca = CertificateBuilder::new()
///     .from_der(ca_csr.to_der())?
///     .signing_key(ca_csr.private_key_pem().to_string())
///     .build_self_signed()?;
///
/// // Create revoked certificate entries
/// let serial1 = SerialNumber::from(12345u64);
/// let revoked1 = RevokedCertificate::new(serial1)
///     .with_reason(RevocationReason::KEY_COMPROMISE);
///
/// // Generate CRL
/// let crl = CrlBuilder::new()
///     .issuer_key_from_pem(ca.private_key_pem().unwrap())?
///     .add_revoked_cert(revoked1)
///     .validity_days(7)
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct CrlBuilder {
    issuer_keypair: Option<KeyPair>,
    revoked_certs: Vec<RevokedCertificate>,
    this_update: Option<OffsetDateTime>,
    next_update_days: u32,
}

impl CrlBuilder {
    /// Creates a new CRL builder
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::crl::CrlBuilder;
    ///
    /// let builder = CrlBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            issuer_keypair: None,
            revoked_certs: Vec::new(),
            this_update: None,
            next_update_days: 7, // Default to 7 days
        }
    }
    
    /// Sets the issuer's private key from PEM format (required)
    ///
    /// # Arguments
    ///
    /// * `issuer_key_pem` - The issuer CA's private key in PKCS#8 PEM format
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM key cannot be parsed
    pub fn issuer_key_from_pem(mut self, issuer_key_pem: &str) -> Result<Self, CrlError> {
        let keypair = KeyPair::from_pem(issuer_key_pem)
            .map_err(|e| CrlError::SigningError(format!("Invalid issuer key PEM: {}", e)))?;
        self.issuer_keypair = Some(keypair);
        Ok(self)
    }
    
    /// Sets the issuer's private key from DER format (required)
    ///
    /// # Arguments
    ///
    /// * `issuer_key_der` - The issuer CA's private key in PKCS#8 DER format
    ///
    /// # Errors
    ///
    /// Returns an error if the DER key cannot be parsed
    pub fn issuer_key_from_der(mut self, issuer_key_der: &[u8]) -> Result<Self, CrlError> {
        // Convert DER bytes to PEM and then parse
        let pem_str = pem::encode(&pem::Pem::new("PRIVATE KEY", issuer_key_der.to_vec()));
        let keypair = KeyPair::from_pem(&pem_str)
            .map_err(|e| CrlError::SigningError(format!("Invalid issuer key DER: {}", e)))?;
        self.issuer_keypair = Some(keypair);
        Ok(self)
    }
    
    /// Adds a revoked certificate to the CRL
    ///
    /// # Arguments
    ///
    /// * `revoked` - The revoked certificate entry
    pub fn add_revoked_cert(mut self, revoked: RevokedCertificate) -> Self {
        self.revoked_certs.push(revoked);
        self
    }
    
    /// Adds multiple revoked certificates to the CRL
    ///
    /// # Arguments
    ///
    /// * `revoked_list` - A vector of revoked certificate entries
    pub fn add_revoked_certs(mut self, revoked_list: Vec<RevokedCertificate>) -> Self {
        self.revoked_certs.extend(revoked_list);
        self
    }
    
    /// Sets the "This Update" time (defaults to now)
    ///
    /// # Arguments
    ///
    /// * `time` - The time when this CRL was issued
    pub fn this_update(mut self, time: OffsetDateTime) -> Self {
        self.this_update = Some(time);
        self
    }
    
    /// Sets the validity period in days (time until next CRL update)
    ///
    /// # Arguments
    ///
    /// * `days` - Number of days until the next CRL should be issued
    pub fn validity_days(mut self, days: u32) -> Self {
        self.next_update_days = days;
        self
    }
    
    /// Builds the CRL
    ///
    /// # Errors
    ///
    /// Returns an error if the issuer key is missing or CRL generation fails.
    pub fn build(self) -> Result<Crl, CrlError> {
        // Validate required fields
        let issuer_key = self.issuer_keypair.ok_or_else(|| {
            CrlError::MissingField("Issuer key is required".to_string())
        })?;
        
        // Set update times
        let this_update = self.this_update.unwrap_or_else(OffsetDateTime::now_utc);
        let next_update = this_update + time::Duration::days(self.next_update_days as i64);
        
        // Create CRL parameters
        let params = CertificateRevocationListParams {
            this_update,
            next_update,
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: self.revoked_certs.iter().map(|revoked| {
                RevokedCertParams {
                    serial_number: SerialNumber::from(revoked.serial_number.to_bytes().to_vec()),
                    revocation_time: revoked.revocation_time,
                    reason_code: revoked.reason.as_ref().map(Self::convert_reason),
                    invalidity_date: None,
                }
            }).collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        
        // Create issuer - use default params since we only need the key
        let issuer_params = rcgen::CertificateParams::default();
        let issuer = Issuer::new(issuer_params, &issuer_key);
        
        // Generate CRL
        let crl_der = params.signed_by(&issuer)
            .map_err(|e| CrlError::SigningError(e.to_string()))?
            .der().to_vec();
        
        Ok(Crl::new(crl_der))
    }
    
    /// Converts our RevocationReason to rcgen format
    fn convert_reason(reason: &RevocationReason) -> rcgen::RevocationReason {
        match reason {
            RevocationReason::Unspecified => rcgen::RevocationReason::Unspecified,
            RevocationReason::KeyCompromise => rcgen::RevocationReason::KeyCompromise,
            RevocationReason::CaCompromise => rcgen::RevocationReason::CaCompromise,
            RevocationReason::AffiliationChanged => rcgen::RevocationReason::AffiliationChanged,
            RevocationReason::Superseded => rcgen::RevocationReason::Superseded,
            RevocationReason::CessationOfOperation => rcgen::RevocationReason::CessationOfOperation,
            RevocationReason::CertificateHold => rcgen::RevocationReason::CertificateHold,
            RevocationReason::RemoveFromCrl => rcgen::RevocationReason::RemoveFromCrl,
            RevocationReason::PrivilegeWithdrawn => rcgen::RevocationReason::PrivilegeWithdrawn,
            RevocationReason::AaCompromise => rcgen::RevocationReason::AaCompromise,
        }
    }
}

impl Default for CrlBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{CrlBuilder, RevokedCertificate};
    use crate::cert::CertificateBuilder;
    use crate::csr::CsrBuilder;
    use crate::types::{KeyUsage, RevocationReason};
    use crate::CrlError;
    use rcgen::SerialNumber;
    use x509_parser::prelude::*;

    fn create_test_ca() -> crate::cert::Certificate {
        let csr = CsrBuilder::new()
            .subject("CN=Test CA").unwrap()
            .is_ca(true)
            .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
            .build().unwrap();
        
        CertificateBuilder::new()
            .from_der(csr.to_der()).unwrap()
            .signing_key(csr.private_key_pem().to_string())
            .build_self_signed().unwrap()
    }

    fn parse_crl(der: &[u8]) -> CertificateRevocationList<'_> {
        let (_, crl) = CertificateRevocationList::from_der(der).unwrap();
        crl
    }

    #[test]
    fn test_revoked_certificate_fields() {
        // Input: serial, reason
        let input_serial = SerialNumber::from(12345u64);
        let input_reason = RevocationReason::KEY_COMPROMISE;
        
        // Output: RevokedCertificate
        let revoked = RevokedCertificate::new(input_serial.clone())
            .with_reason(input_reason);
        
        // Validate: fields match input
        assert_eq!(revoked.serial_number.to_bytes(), input_serial.to_bytes());
        assert_eq!(revoked.reason, Some(input_reason));
    }

    #[test]
    fn test_revoked_certificate_time() {
        // Input: custom time
        use ::time::{OffsetDateTime, Duration};
        let input_time = OffsetDateTime::now_utc() - Duration::days(7);
        
        // Output: RevokedCertificate
        let revoked = RevokedCertificate::new(SerialNumber::from(1u64))
            .with_time(input_time);
        
        // Validate: time matches input
        assert_eq!(revoked.revocation_time, input_time);
    }

    #[test]
    fn test_empty_crl() {
        // Input: CA key, validity days = 7
        let ca = create_test_ca();
        let input_validity_days = 7u32;
        
        // Output: CRL with no revoked certs
        let crl = CrlBuilder::new()
            .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
            .validity_days(input_validity_days)
            .build().unwrap();
        
        // Validate: Parse CRL and check it contains 0 revoked certs
        let parsed = parse_crl(crl.to_der());
        assert_eq!(parsed.iter_revoked_certificates().count(), 0);
    }

    #[test]
    fn test_crl_with_single_revoked_cert() {
        // Input: serial 12345, reason KEY_COMPROMISE
        let ca = create_test_ca();
        let input_serial = 12345u64;
        let input_reason = RevocationReason::KEY_COMPROMISE;
        
        // Output: CRL with 1 revoked cert
        let crl = CrlBuilder::new()
            .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
            .add_revoked_cert(
                RevokedCertificate::new(SerialNumber::from(input_serial)).with_reason(input_reason)
            )
            .build().unwrap();
        
        // Validate: Parse CRL and verify serial matches input
        let parsed = parse_crl(crl.to_der());
        let revoked_certs: Vec<_> = parsed.iter_revoked_certificates().collect();
        assert_eq!(revoked_certs.len(), 1);
        
        let revoked_cert = &revoked_certs[0];
        let serial_in_crl = &revoked_cert.user_certificate.to_bytes_be();
        let expected_serial = input_serial.to_be_bytes();
        // Compare as BigUint (handles leading zeros)
        assert_eq!(serial_in_crl, &expected_serial[expected_serial.iter().position(|&b| b != 0).unwrap_or(expected_serial.len() - 1)..]);
    }

    #[test]
    fn test_crl_with_multiple_revoked_certs() {
        // Input: serials 1, 2, 3
        let ca = create_test_ca();
        let input_serials = vec![1u64, 2u64, 3u64];
        let revoked_list: Vec<_> = input_serials.iter()
            .map(|&i| RevokedCertificate::new(SerialNumber::from(i)))
            .collect();
        
        // Output: CRL with 3 revoked certs
        let crl = CrlBuilder::new()
            .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
            .add_revoked_certs(revoked_list)
            .build().unwrap();
        
        // Validate: Parse CRL and verify all serials are present
        let parsed = parse_crl(crl.to_der());
        let revoked_certs: Vec<_> = parsed.iter_revoked_certificates().collect();
        assert_eq!(revoked_certs.len(), input_serials.len());
        
        for (i, revoked_cert) in revoked_certs.iter().enumerate() {
            let serial_in_crl = &revoked_cert.user_certificate.to_bytes_be();
            let expected = input_serials[i].to_be_bytes();
            // Compare as BigUint (strips leading zeros)
            let expected_stripped = &expected[expected.iter().position(|&b| b != 0).unwrap_or(expected.len() - 1)..];
            assert_eq!(serial_in_crl.as_slice(), expected_stripped);
        }
    }

    #[test]
    fn test_crl_pem_format() {
        // Input: CA key + 1 revoked cert
        let ca = create_test_ca();
        let input_serial = 999u64;
        
        // Output: CRL PEM
        let crl = CrlBuilder::new()
            .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
            .add_revoked_cert(RevokedCertificate::new(SerialNumber::from(input_serial)))
            .build().unwrap();
        
        let pem = crl.to_pem();
        
        // Validate: PEM format correct and can parse back
        assert!(pem.starts_with("-----BEGIN X509 CRL-----"));
        assert!(pem.contains("-----END X509 CRL-----"));
        
        // Verify CRL contains the revoked cert
        let parsed = parse_crl(crl.to_der());
        assert_eq!(parsed.iter_revoked_certificates().count(), 1);
    }

    #[test]
    fn test_crl_der_format() {
        // Input: CA key + 2 revoked certs
        let ca = create_test_ca();
        let input_serials = vec![111u64, 222u64];
        
        // Output: CRL DER
        let crl = CrlBuilder::new()
            .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
            .add_revoked_certs(vec![
                RevokedCertificate::new(SerialNumber::from(input_serials[0])),
                RevokedCertificate::new(SerialNumber::from(input_serials[1])),
            ])
            .build().unwrap();
        let der = crl.to_der();
        
        // Validate: DER format correct (starts with SEQUENCE tag)
        assert_eq!(der[0], 0x30);
        assert!(!der.is_empty());
        
        // Validate: Parse DER and verify revoked certs
        let parsed = parse_crl(der);
        assert_eq!(parsed.iter_revoked_certificates().count(), input_serials.len());
    }

    #[test]
    fn test_crl_all_revocation_reasons() {
        // Input: 10 revoked certs with all reason codes
        let ca = create_test_ca();
        let input_count = 10;
        let input_reasons = vec![
            RevocationReason::UNSPECIFIED,
            RevocationReason::KEY_COMPROMISE,
            RevocationReason::CA_COMPROMISE,
            RevocationReason::AFFILIATION_CHANGED,
            RevocationReason::SUPERSEDED,
            RevocationReason::CESSATION_OF_OPERATION,
            RevocationReason::CERTIFICATE_HOLD,
            RevocationReason::REMOVE_FROM_CRL,
            RevocationReason::PRIVILEGE_WITHDRAWN,
            RevocationReason::AA_COMPROMISE,
        ];
        
        let mut builder = CrlBuilder::new()
            .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap();
        
        for (i, reason) in input_reasons.iter().enumerate() {
            builder = builder.add_revoked_cert(
                RevokedCertificate::new(SerialNumber::from(i as u64 + 1))
                    .with_reason(*reason)
            );
        }
        
        // Output: CRL with all reason types
        let crl = builder.build().unwrap();
        
        // Validate: Parse CRL and verify count matches input
        let parsed = parse_crl(crl.to_der());
        let revoked_certs: Vec<_> = parsed.iter_revoked_certificates().collect();
        assert_eq!(revoked_certs.len(), input_count);
    }

    #[test]
    fn test_error_missing_issuer_key() {
        // Input: No issuer key
        // Output: Error
        let result = CrlBuilder::new().build();
        
        // Validate: MissingField error
        assert!(matches!(result, Err(CrlError::MissingField(_))));
    }

    #[test]
    fn test_error_invalid_issuer_key_pem() {
        // Input: Invalid PEM key
        // Output: Error
        let result = CrlBuilder::new()
            .issuer_key_from_pem("invalid");
        
        // Validate: SigningError
        assert!(matches!(result, Err(CrlError::SigningError(_))));
    }
    
    #[test]
    fn test_error_invalid_issuer_key_der() {
        // Input: Invalid DER key
        // Output: Error
        let invalid_der = vec![0x00, 0x01, 0x02, 0x03];
        let result = CrlBuilder::new()
            .issuer_key_from_der(&invalid_der);
        
        // Validate: SigningError
        assert!(matches!(result, Err(CrlError::SigningError(_))));
    }
    
    #[test]
    fn test_issuer_key_from_pem_valid() {
        // Input: Valid PEM key from CA
        let ca = create_test_ca();
        let ca_key_pem = ca.private_key_pem().unwrap();
        
        // Output: Builder with keypair set
        let builder = CrlBuilder::new()
            .issuer_key_from_pem(ca_key_pem);
        
        // Validate: Success and keypair is set
        assert!(builder.is_ok());
        let builder = builder.unwrap();
        assert!(builder.issuer_keypair.is_some());
    }
    
    #[test]
    fn test_issuer_key_from_der_valid() {
        // Input: Valid DER key from CA
        let ca = create_test_ca();
        let ca_key_der = ca.private_key_der().unwrap();
        
        // Output: Builder with keypair set
        let builder = CrlBuilder::new()
            .issuer_key_from_der(&ca_key_der);
        
        // Validate: Success and keypair is set
        assert!(builder.is_ok());
        let builder = builder.unwrap();
        assert!(builder.issuer_keypair.is_some());
    }
    
    #[test]
    fn test_crl_from_der_key() {
        // Input: CA DER key + 1 revoked cert
        let ca = create_test_ca();
        let ca_key_der = ca.private_key_der().unwrap();
        let input_serial = 54321u64;
        
        // Output: CRL built with DER key
        let crl = CrlBuilder::new()
            .issuer_key_from_der(&ca_key_der).unwrap()
            .add_revoked_cert(RevokedCertificate::new(SerialNumber::from(input_serial)))
            .build().unwrap();
        
        // Validate: Parse CRL and verify serial
        let parsed = parse_crl(crl.to_der());
        let revoked_certs: Vec<_> = parsed.iter_revoked_certificates().collect();
        assert_eq!(revoked_certs.len(), 1);
        
        let revoked_cert = &revoked_certs[0];
        let serial_in_crl = &revoked_cert.user_certificate.to_bytes_be();
        let expected_serial = input_serial.to_be_bytes();
        assert_eq!(serial_in_crl, &expected_serial[expected_serial.iter().position(|&b| b != 0).unwrap_or(expected_serial.len() - 1)..]);
    }

    #[test]
    fn test_builder_defaults() {
        // Output: Default builder
        let builder = CrlBuilder::default();
        
        // Validate: Default values
        assert!(builder.issuer_keypair.is_none());
        assert_eq!(builder.revoked_certs.len(), 0);
        assert_eq!(builder.next_update_days, 7);
    }
}