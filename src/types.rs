//! Common types used throughout the library
//!
//! This module defines type-safe wrappers for cryptographic concepts
//! like Key Usage, Extended Key Usage, Distinguished Names, and Serial Numbers.

use std::fmt;

/// Key Usage extension flags (RFC 5280, Section 4.2.1.3)
///
/// Defines the cryptographic operations for which a certificate's public key may be used.
/// This is a critical extension for CA certificates.
///
/// # Examples
///
/// ```
/// use mtls_at_lib::types::KeyUsage;
///
/// // For a server certificate
/// let server_usage = KeyUsage::digital_signature() | KeyUsage::key_encipherment();
///
/// // For a CA certificate
/// let ca_usage = KeyUsage::key_cert_sign() | KeyUsage::crl_sign();
///
/// // Check if a specific usage is set
/// assert!(server_usage.contains(KeyUsage::digital_signature()));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage(u16);

impl KeyUsage {
    /// Digital signature (bit 0)
    ///
    /// Used for verifying digital signatures (excluding certificates and CRLs).
    /// Required for TLS client and server authentication.
    pub const fn digital_signature() -> Self {
        KeyUsage(1 << 0)
    }

    /// Non-repudiation / Content commitment (bit 1)
    ///
    /// Used for non-repudiation services which protect against false denial of actions.
    pub const fn non_repudiation() -> Self {
        KeyUsage(1 << 1)
    }

    /// Key encipherment (bit 2)
    ///
    /// Used for encrypting keys for key transport.
    /// Required for RSA key exchange in TLS 1.2.
    pub const fn key_encipherment() -> Self {
        KeyUsage(1 << 2)
    }

    /// Data encipherment (bit 3)
    ///
    /// Used for encrypting user data (rare in practice).
    pub const fn data_encipherment() -> Self {
        KeyUsage(1 << 3)
    }

    /// Key agreement (bit 4)
    ///
    /// Used for key agreement protocols like ECDH.
    pub const fn key_agreement() -> Self {
        KeyUsage(1 << 4)
    }

    /// Key certificate sign (bit 5)
    ///
    /// **Required for CA certificates** to sign other certificates.
    /// Must be marked as critical.
    pub const fn key_cert_sign() -> Self {
        KeyUsage(1 << 5)
    }

    /// CRL sign (bit 6)
    ///
    /// Required for certificates that sign Certificate Revocation Lists.
    /// Typically used by CA certificates.
    pub const fn crl_sign() -> Self {
        KeyUsage(1 << 6)
    }

    /// Encipher only (bit 7)
    ///
    /// Only used with keyAgreement. Key is only used for enciphering data.
    pub const fn encipher_only() -> Self {
        KeyUsage(1 << 7)
    }

    /// Decipher only (bit 8)
    ///
    /// Only used with keyAgreement. Key is only used for deciphering data.
    pub const fn decipher_only() -> Self {
        KeyUsage(1 << 8)
    }

    /// Checks if this KeyUsage contains the specified usage
    ///
    /// # Examples
    ///
    /// ```
    /// use mtls_at_lib::types::KeyUsage;
    ///
    /// let usage = KeyUsage::digital_signature() | KeyUsage::key_encipherment();
    /// assert!(usage.contains(KeyUsage::digital_signature()));
    /// assert!(!usage.contains(KeyUsage::key_cert_sign()));
    /// ```
    pub const fn contains(self, other: KeyUsage) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns the raw bit flags
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Creates KeyUsage from raw bits
    pub const fn from_bits(bits: u16) -> Self {
        KeyUsage(bits)
    }
}

// Implement bitwise OR for combining key usage flags
impl std::ops::BitOr for KeyUsage {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        KeyUsage(self.0 | rhs.0)
    }
}

/// Extended Key Usage extension (RFC 5280, Section 4.2.1.12)
///
/// Specifies the purposes for which the certified public key may be used.
/// This provides more specific usage restrictions than Key Usage.
///
/// # Examples
///
/// ```
/// use mtls_at_lib::types::ExtendedKeyUsage;
///
/// // For a server certificate
/// let server_eku = vec![ExtendedKeyUsage::SERVER_AUTH];
///
/// // For a client certificate
/// let client_eku = vec![ExtendedKeyUsage::CLIENT_AUTH];
///
/// // For both client and server
/// let both_eku = vec![
///     ExtendedKeyUsage::SERVER_AUTH,
///     ExtendedKeyUsage::CLIENT_AUTH,
/// ];
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedKeyUsage {
    oid: &'static str,
    name: &'static str,
}

impl ExtendedKeyUsage {
    /// TLS server authentication (OID: 1.3.6.1.5.5.7.3.1)
    ///
    /// Required for TLS server certificates.
    pub const SERVER_AUTH: Self = Self {
        oid: "1.3.6.1.5.5.7.3.1",
        name: "serverAuth",
    };

    /// TLS client authentication (OID: 1.3.6.1.5.5.7.3.2)
    ///
    /// Required for TLS client certificates in mTLS.
    pub const CLIENT_AUTH: Self = Self {
        oid: "1.3.6.1.5.5.7.3.2",
        name: "clientAuth",
    };

    /// Code signing (OID: 1.3.6.1.5.5.7.3.3)
    pub const CODE_SIGNING: Self = Self {
        oid: "1.3.6.1.5.5.7.3.3",
        name: "codeSigning",
    };

    /// Email protection (OID: 1.3.6.1.5.5.7.3.4)
    ///
    /// Used for S/MIME email encryption and signing.
    pub const EMAIL_PROTECTION: Self = Self {
        oid: "1.3.6.1.5.5.7.3.4",
        name: "emailProtection",
    };

    /// Time stamping (OID: 1.3.6.1.5.5.7.3.8)
    pub const TIME_STAMPING: Self = Self {
        oid: "1.3.6.1.5.5.7.3.8",
        name: "timeStamping",
    };

    /// OCSP signing (OID: 1.3.6.1.5.5.7.3.9)
    pub const OCSP_SIGNING: Self = Self {
        oid: "1.3.6.1.5.5.7.3.9",
        name: "ocspSigning",
    };

    /// Returns the OID string
    pub fn oid(&self) -> &str {
        self.oid
    }

    /// Returns the human-readable name
    pub fn name(&self) -> &str {
        self.name
    }
}

impl fmt::Display for ExtendedKeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.oid)
    }
}

/// X.509 Distinguished Name
///
/// Represents an X.500 Distinguished Name used in certificate subjects and issuers.
///
/// # Examples
///
/// ```
/// use mtls_at_lib::types::DistinguishedName;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dn = DistinguishedName::from_str("CN=example.com,O=Example Corp,C=US")?;
/// assert_eq!(dn.common_name(), Some("example.com"));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistinguishedName {
    // Internal representation - to be implemented
    raw: String,
}

impl DistinguishedName {
    /// Parses a Distinguished Name from string format
    ///
    /// # Format
    ///
    /// The string should be in the format: "CN=name,O=org,C=country"
    ///
    /// Supported attributes:
    /// - CN: Common Name
    /// - O: Organization
    /// - OU: Organizational Unit
    /// - C: Country
    /// - ST: State/Province
    /// - L: Locality
    ///
    /// # Errors
    ///
    /// Returns error if the DN string is malformed.
    pub fn from_str(s: &str) -> Result<Self, crate::error::CsrError> {
        // Basic validation - detailed parsing to be implemented
        if s.is_empty() {
            return Err(crate::error::CsrError::InvalidSubjectName(
                "Distinguished name cannot be empty".to_string(),
            ));
        }

        Ok(DistinguishedName {
            raw: s.to_string(),
        })
    }

    /// Returns the Common Name (CN) if present
    pub fn common_name(&self) -> Option<&str> {
        // Simplified extraction - to be properly implemented
        self.raw
            .split(',')
            .find(|part| part.trim().starts_with("CN="))
            .and_then(|cn_part| cn_part.split('=').nth(1))
            .map(|s| s.trim())
    }

    /// Returns the raw DN string
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}


/// Revocation reason codes (RFC 5280, Section 5.3.1)
///
/// Indicates why a certificate was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    /// Unspecified reason (0)
    Unspecified = 0,
    
    /// Private key has been compromised (1)
    ///
    /// **Critical**: Immediate revocation required.
    /// Past signatures may be suspect.
    KeyCompromise = 1,
    
    /// CA key has been compromised (2)
    ///
    /// **Critical**: All certificates issued by this CA are suspect.
    CaCompromise = 2,
    
    /// Subject's affiliation has changed (3)
    AffiliationChanged = 3,
    
    /// Certificate has been superseded (4)
    Superseded = 4,
    
    /// Certificate is no longer needed (5)
    CessationOfOperation = 5,
    
    /// Certificate is temporarily suspended (6)
    ///
    /// May be un-revoked later with removeFromCRL.
    CertificateHold = 6,
    
    /// Remove from CRL (8)
    ///
    /// Un-revoke a certificate that was on hold.
    RemoveFromCrl = 8,
    
    /// Privilege has been withdrawn (9)
    PrivilegeWithdrawn = 9,
    
    /// Attribute Authority key compromised (10)
    AaCompromise = 10,
}

impl RevocationReason {
    /// Unspecified revocation reason
    pub const UNSPECIFIED: Self = Self::Unspecified;
    
    /// Private key has been compromised
    pub const KEY_COMPROMISE: Self = Self::KeyCompromise;
    
    /// CA key has been compromised
    pub const CA_COMPROMISE: Self = Self::CaCompromise;
    
    /// Subject's affiliation has changed
    pub const AFFILIATION_CHANGED: Self = Self::AffiliationChanged;
    
    /// Certificate has been superseded
    pub const SUPERSEDED: Self = Self::Superseded;
    
    /// Certificate is no longer needed
    pub const CESSATION_OF_OPERATION: Self = Self::CessationOfOperation;
    
    /// Certificate is temporarily suspended
    pub const CERTIFICATE_HOLD: Self = Self::CertificateHold;
    
    /// Remove from CRL
    pub const REMOVE_FROM_CRL: Self = Self::RemoveFromCrl;
    
    /// Privilege has been withdrawn
    pub const PRIVILEGE_WITHDRAWN: Self = Self::PrivilegeWithdrawn;
    
    /// Attribute Authority key compromised
    pub const AA_COMPROMISE: Self = Self::AaCompromise;
    
    /// Returns the numeric code
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Creates from numeric code
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(RevocationReason::Unspecified),
            1 => Some(RevocationReason::KeyCompromise),
            2 => Some(RevocationReason::CaCompromise),
            3 => Some(RevocationReason::AffiliationChanged),
            4 => Some(RevocationReason::Superseded),
            5 => Some(RevocationReason::CessationOfOperation),
            6 => Some(RevocationReason::CertificateHold),
            8 => Some(RevocationReason::RemoveFromCrl),
            9 => Some(RevocationReason::PrivilegeWithdrawn),
            10 => Some(RevocationReason::AaCompromise),
            _ => None,
        }
    }
}

impl fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            RevocationReason::Unspecified => "Unspecified",
            RevocationReason::KeyCompromise => "Key Compromise",
            RevocationReason::CaCompromise => "CA Compromise",
            RevocationReason::AffiliationChanged => "Affiliation Changed",
            RevocationReason::Superseded => "Superseded",
            RevocationReason::CessationOfOperation => "Cessation of Operation",
            RevocationReason::CertificateHold => "Certificate Hold",
            RevocationReason::RemoveFromCrl => "Remove from CRL",
            RevocationReason::PrivilegeWithdrawn => "Privilege Withdrawn",
            RevocationReason::AaCompromise => "AA Compromise",
        };
        write!(f, "{}", name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KeyUsage tests
    #[test]
    fn test_key_usage_bits() {
        // Test that bits() returns the correct raw value
        let ku = KeyUsage::digital_signature();
        assert_eq!(ku.bits(), 1, "digital_signature should have bit value 1");

        let ku = KeyUsage::key_cert_sign();
        assert_eq!(ku.bits(), 32, "key_cert_sign should have bit value 32 (1 << 5)");

        let combined = KeyUsage::digital_signature() | KeyUsage::key_encipherment();
        assert_eq!(combined.bits(), 5, "Combined flags should have value 5 (1 | 4)");
    }

    #[test]
    fn test_key_usage_from_bits() {
        // Test creating KeyUsage from raw bits
        let ku = KeyUsage::from_bits(1);
        assert_eq!(ku.bits(), 1, "from_bits(1) should create digital_signature");
        assert!(ku.contains(KeyUsage::digital_signature()));

        let ku = KeyUsage::from_bits(32);
        assert_eq!(ku.bits(), 32, "from_bits(32) should create key_cert_sign");
        assert!(ku.contains(KeyUsage::key_cert_sign()));

        // Test combined bits
        let ku = KeyUsage::from_bits(5); // digital_signature | key_encipherment
        assert!(ku.contains(KeyUsage::digital_signature()));
        assert!(ku.contains(KeyUsage::key_encipherment()));
        assert!(!ku.contains(KeyUsage::crl_sign()));
    }

    #[test]
    fn test_key_usage_bits_roundtrip() {
        // Test that bits() and from_bits() are inverses
        let original = KeyUsage::digital_signature() | KeyUsage::key_cert_sign() | KeyUsage::crl_sign();
        let bits = original.bits();
        let reconstructed = KeyUsage::from_bits(bits);
        
        assert_eq!(original.bits(), reconstructed.bits(), "Roundtrip should preserve bits");
        assert!(reconstructed.contains(KeyUsage::digital_signature()));
        assert!(reconstructed.contains(KeyUsage::key_cert_sign()));
        assert!(reconstructed.contains(KeyUsage::crl_sign()));
    }

    #[test]
    fn test_key_usage_all_flags_bits() {
        // Test all individual flag bit values
        assert_eq!(KeyUsage::digital_signature().bits(), 1);
        assert_eq!(KeyUsage::non_repudiation().bits(), 2);
        assert_eq!(KeyUsage::key_encipherment().bits(), 4);
        assert_eq!(KeyUsage::data_encipherment().bits(), 8);
        assert_eq!(KeyUsage::key_agreement().bits(), 16);
        assert_eq!(KeyUsage::key_cert_sign().bits(), 32);
        assert_eq!(KeyUsage::crl_sign().bits(), 64);
        assert_eq!(KeyUsage::encipher_only().bits(), 128);
        assert_eq!(KeyUsage::decipher_only().bits(), 256);
    }

    // ExtendedKeyUsage tests
    #[test]
    fn test_extended_key_usage_oid() {
        // Test that oid() returns the correct OID string
        assert_eq!(ExtendedKeyUsage::SERVER_AUTH.oid(), "1.3.6.1.5.5.7.3.1");
        assert_eq!(ExtendedKeyUsage::CLIENT_AUTH.oid(), "1.3.6.1.5.5.7.3.2");
        assert_eq!(ExtendedKeyUsage::CODE_SIGNING.oid(), "1.3.6.1.5.5.7.3.3");
        assert_eq!(ExtendedKeyUsage::EMAIL_PROTECTION.oid(), "1.3.6.1.5.5.7.3.4");
        assert_eq!(ExtendedKeyUsage::TIME_STAMPING.oid(), "1.3.6.1.5.5.7.3.8");
        assert_eq!(ExtendedKeyUsage::OCSP_SIGNING.oid(), "1.3.6.1.5.5.7.3.9");
    }

    #[test]
    fn test_extended_key_usage_name() {
        // Test that name() returns the correct human-readable name
        assert_eq!(ExtendedKeyUsage::SERVER_AUTH.name(), "serverAuth");
        assert_eq!(ExtendedKeyUsage::CLIENT_AUTH.name(), "clientAuth");
        assert_eq!(ExtendedKeyUsage::CODE_SIGNING.name(), "codeSigning");
        assert_eq!(ExtendedKeyUsage::EMAIL_PROTECTION.name(), "emailProtection");
        assert_eq!(ExtendedKeyUsage::TIME_STAMPING.name(), "timeStamping");
        assert_eq!(ExtendedKeyUsage::OCSP_SIGNING.name(), "ocspSigning");
    }

    #[test]
    fn test_extended_key_usage_display() {
        // Test the Display trait implementation
        let server_auth = ExtendedKeyUsage::SERVER_AUTH;
        let display_str = format!("{}", server_auth);
        assert_eq!(display_str, "serverAuth (1.3.6.1.5.5.7.3.1)");

        let client_auth = ExtendedKeyUsage::CLIENT_AUTH;
        let display_str = format!("{}", client_auth);
        assert_eq!(display_str, "clientAuth (1.3.6.1.5.5.7.3.2)");

        let code_signing = ExtendedKeyUsage::CODE_SIGNING;
        let display_str = format!("{}", code_signing);
        assert_eq!(display_str, "codeSigning (1.3.6.1.5.5.7.3.3)");
    }

    #[test]
    fn test_extended_key_usage_all_types_display() {
        // Test Display for all EKU types
        assert_eq!(format!("{}", ExtendedKeyUsage::SERVER_AUTH), "serverAuth (1.3.6.1.5.5.7.3.1)");
        assert_eq!(format!("{}", ExtendedKeyUsage::CLIENT_AUTH), "clientAuth (1.3.6.1.5.5.7.3.2)");
        assert_eq!(format!("{}", ExtendedKeyUsage::CODE_SIGNING), "codeSigning (1.3.6.1.5.5.7.3.3)");
        assert_eq!(format!("{}", ExtendedKeyUsage::EMAIL_PROTECTION), "emailProtection (1.3.6.1.5.5.7.3.4)");
        assert_eq!(format!("{}", ExtendedKeyUsage::TIME_STAMPING), "timeStamping (1.3.6.1.5.5.7.3.8)");
        assert_eq!(format!("{}", ExtendedKeyUsage::OCSP_SIGNING), "ocspSigning (1.3.6.1.5.5.7.3.9)");
    }

    // DistinguishedName tests
    #[test]
    fn test_distinguished_name_common_name() {
        // Test extracting common name from DN
        let dn = DistinguishedName::from_str("CN=example.com,O=Example Corp,C=US")
            .expect("Failed to parse DN");
        assert_eq!(dn.common_name(), Some("example.com"));

        // Test with spaces
        let dn = DistinguishedName::from_str("CN=test.example.com, O=Test Org, C=US")
            .expect("Failed to parse DN");
        assert_eq!(dn.common_name(), Some("test.example.com"));

        // Test with only CN
        let dn = DistinguishedName::from_str("CN=simple.com")
            .expect("Failed to parse DN");
        assert_eq!(dn.common_name(), Some("simple.com"));
    }

    #[test]
    fn test_distinguished_name_common_name_missing() {
        // Test DN without CN
        let dn = DistinguishedName::from_str("O=Example Corp,C=US")
            .expect("Failed to parse DN");
        assert_eq!(dn.common_name(), None, "DN without CN should return None");
    }

    #[test]
    fn test_distinguished_name_common_name_with_complex_dn() {
        // Test with full DN including state and locality
        let dn = DistinguishedName::from_str("CN=server.example.com,OU=IT,O=Example Corp,L=San Francisco,ST=California,C=US")
            .expect("Failed to parse DN");
        assert_eq!(dn.common_name(), Some("server.example.com"));
    }

    #[test]
    fn test_distinguished_name_display() {
        // Test the Display trait implementation
        let dn = DistinguishedName::from_str("CN=example.com,O=Example Corp,C=US")
            .expect("Failed to parse DN");
        let display_str = format!("{}", dn);
        assert_eq!(display_str, "CN=example.com,O=Example Corp,C=US");

        // Test with different DN format
        let dn = DistinguishedName::from_str("CN=test.com")
            .expect("Failed to parse DN");
        assert_eq!(format!("{}", dn), "CN=test.com");
    }

    #[test]
    fn test_distinguished_name_display_preserves_format() {
        // Test that Display preserves the original format
        let original = "CN=server.example.com,OU=Engineering,O=Tech Corp,L=New York,ST=NY,C=US";
        let dn = DistinguishedName::from_str(original)
            .expect("Failed to parse DN");
        assert_eq!(format!("{}", dn), original, "Display should preserve original format");
    }

    // RevocationReason tests
    #[test]
    fn test_revocation_reason_code() {
        // Test that code() returns the correct numeric code
        assert_eq!(RevocationReason::Unspecified.code(), 0);
        assert_eq!(RevocationReason::KeyCompromise.code(), 1);
        assert_eq!(RevocationReason::CaCompromise.code(), 2);
        assert_eq!(RevocationReason::AffiliationChanged.code(), 3);
        assert_eq!(RevocationReason::Superseded.code(), 4);
        assert_eq!(RevocationReason::CessationOfOperation.code(), 5);
        assert_eq!(RevocationReason::CertificateHold.code(), 6);
        assert_eq!(RevocationReason::RemoveFromCrl.code(), 8);
        assert_eq!(RevocationReason::PrivilegeWithdrawn.code(), 9);
        assert_eq!(RevocationReason::AaCompromise.code(), 10);
    }

    #[test]
    fn test_revocation_reason_from_code() {
        // Test creating RevocationReason from code
        assert_eq!(RevocationReason::from_code(0), Some(RevocationReason::Unspecified));
        assert_eq!(RevocationReason::from_code(1), Some(RevocationReason::KeyCompromise));
        assert_eq!(RevocationReason::from_code(2), Some(RevocationReason::CaCompromise));
        assert_eq!(RevocationReason::from_code(3), Some(RevocationReason::AffiliationChanged));
        assert_eq!(RevocationReason::from_code(4), Some(RevocationReason::Superseded));
        assert_eq!(RevocationReason::from_code(5), Some(RevocationReason::CessationOfOperation));
        assert_eq!(RevocationReason::from_code(6), Some(RevocationReason::CertificateHold));
        assert_eq!(RevocationReason::from_code(8), Some(RevocationReason::RemoveFromCrl));
        assert_eq!(RevocationReason::from_code(9), Some(RevocationReason::PrivilegeWithdrawn));
        assert_eq!(RevocationReason::from_code(10), Some(RevocationReason::AaCompromise));

        // Test invalid codes
        assert_eq!(RevocationReason::from_code(7), None, "Code 7 is not defined");
        assert_eq!(RevocationReason::from_code(11), None, "Code 11 is not defined");
        assert_eq!(RevocationReason::from_code(255), None, "Invalid code should return None");
    }

    #[test]
    fn test_revocation_reason_code_roundtrip() {
        // Test that code() and from_code() are inverses
        let reasons = vec![
            RevocationReason::Unspecified,
            RevocationReason::KeyCompromise,
            RevocationReason::CaCompromise,
            RevocationReason::AffiliationChanged,
            RevocationReason::Superseded,
            RevocationReason::CessationOfOperation,
            RevocationReason::CertificateHold,
            RevocationReason::RemoveFromCrl,
            RevocationReason::PrivilegeWithdrawn,
            RevocationReason::AaCompromise,
        ];

        for reason in reasons {
            let code = reason.code();
            let reconstructed = RevocationReason::from_code(code);
            assert_eq!(reconstructed, Some(reason), "Roundtrip should preserve reason");
        }
    }

    #[test]
    fn test_revocation_reason_display() {
        // Test the Display trait implementation
        assert_eq!(format!("{}", RevocationReason::Unspecified), "Unspecified");
        assert_eq!(format!("{}", RevocationReason::KeyCompromise), "Key Compromise");
        assert_eq!(format!("{}", RevocationReason::CaCompromise), "CA Compromise");
        assert_eq!(format!("{}", RevocationReason::AffiliationChanged), "Affiliation Changed");
        assert_eq!(format!("{}", RevocationReason::Superseded), "Superseded");
        assert_eq!(format!("{}", RevocationReason::CessationOfOperation), "Cessation of Operation");
        assert_eq!(format!("{}", RevocationReason::CertificateHold), "Certificate Hold");
        assert_eq!(format!("{}", RevocationReason::RemoveFromCrl), "Remove from CRL");
        assert_eq!(format!("{}", RevocationReason::PrivilegeWithdrawn), "Privilege Withdrawn");
        assert_eq!(format!("{}", RevocationReason::AaCompromise), "AA Compromise");
    }

    #[test]
    fn test_revocation_reason_constants() {
        // Test that the constant aliases match their enum values
        assert_eq!(RevocationReason::UNSPECIFIED, RevocationReason::Unspecified);
        assert_eq!(RevocationReason::KEY_COMPROMISE, RevocationReason::KeyCompromise);
        assert_eq!(RevocationReason::CA_COMPROMISE, RevocationReason::CaCompromise);
        assert_eq!(RevocationReason::AFFILIATION_CHANGED, RevocationReason::AffiliationChanged);
        assert_eq!(RevocationReason::SUPERSEDED, RevocationReason::Superseded);
        assert_eq!(RevocationReason::CESSATION_OF_OPERATION, RevocationReason::CessationOfOperation);
        assert_eq!(RevocationReason::CERTIFICATE_HOLD, RevocationReason::CertificateHold);
        assert_eq!(RevocationReason::REMOVE_FROM_CRL, RevocationReason::RemoveFromCrl);
        assert_eq!(RevocationReason::PRIVILEGE_WITHDRAWN, RevocationReason::PrivilegeWithdrawn);
        assert_eq!(RevocationReason::AA_COMPROMISE, RevocationReason::AaCompromise);
    }
}