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

/// X.509 Certificate Serial Number
///
/// A unique positive integer assigned to each certificate by the CA.
/// Must be unique within the CA's scope and should be unpredictable.
///
/// # Examples
///
/// ```
/// use mtls_at_lib::types::SerialNumber;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate a random serial number
/// let serial = SerialNumber::generate()?;
///
/// // Create from bytes
/// let serial = SerialNumber::from_bytes(&[0x01, 0x02, 0x03]);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialNumber {
    bytes: Vec<u8>,
}

impl SerialNumber {
    /// Generates a cryptographically secure random serial number
    ///
    /// The serial number is:
    /// - 20 bytes (160 bits) as per RFC 5280 maximum
    /// - Positive (high bit cleared)
    /// - Cryptographically random
    ///
    /// # Security
    ///
    /// Uses a cryptographically secure random number generator.
    /// Serial numbers are unpredictable to prevent enumeration attacks.
    pub fn generate() -> Result<Self, crate::error::CertError> {
        use sha2::{Digest, Sha256};

        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                crate::error::CertError::SerialNumberError(format!("Time error: {}", e))
            })?
            .as_secs();

        // Generate random bytes
        let random_bytes: [u8; 16] = rand::random();

        // Combine timestamp and random bytes, then hash
        let mut hasher = Sha256::new();
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&random_bytes);
        let hash = hasher.finalize();

        // Take first 20 bytes
        let mut serial = hash[..20].to_vec();

        // Ensure positive (clear high bit)
        serial[0] &= 0x7F;

        Ok(SerialNumber { bytes: serial })
    }

    /// Creates a serial number from bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw bytes of the serial number
    ///
    /// # Note
    ///
    /// The serial number should be positive. If the high bit is set,
    /// it will be interpreted as negative in ASN.1 encoding.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        SerialNumber {
            bytes: bytes.to_vec(),
        }
    }

    /// Returns the serial number as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the serial number as a hex string
    pub fn to_hex(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}

impl fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}