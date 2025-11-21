//! E2E tests for CRL module - validates input/output data

use mtls_at_lib::cert::{Certificate, CertificateBuilder};
use mtls_at_lib::crl::{CrlBuilder, RevokedCertificate};
use mtls_at_lib::csr::CsrBuilder;
use mtls_at_lib::types::{KeyUsage, RevocationReason};
use rcgen::SerialNumber;
use x509_parser::prelude::*;

fn create_test_ca() -> Certificate {
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
fn test_empty_crl() {
    // Input: CA key, no revoked certs
    let ca = create_test_ca();
    
    // Output: Empty CRL
    let crl = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
        .validity_days(7)
        .build().unwrap();
    
    // Validate: Parse CRL and verify it contains 0 revoked certs
    let parsed = parse_crl(crl.to_der());
    assert_eq!(parsed.iter_revoked_certificates().count(), 0);
    
    let pem = crl.to_pem();
    assert!(pem.starts_with("-----BEGIN X509 CRL-----"));
}

#[test]
fn test_crl_with_single_revoked_cert() {
    // Input: serial 12345 with reason KEY_COMPROMISE
    let ca = create_test_ca();
    let input_serial = 12345u64;
    let input_reason = RevocationReason::KEY_COMPROMISE;
    
    let revoked = RevokedCertificate::new(SerialNumber::from(input_serial))
        .with_reason(input_reason);
    
    // Output: CRL with revoked cert
    let crl = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
        .add_revoked_cert(revoked)
        .validity_days(7)
        .build().unwrap();
    
    // Validate: Parse CRL and verify serial matches input
    let parsed = parse_crl(crl.to_der());
    let revoked_certs: Vec<_> = parsed.iter_revoked_certificates().collect();
    assert_eq!(revoked_certs.len(), 1);
    
    let serial_in_crl = revoked_certs[0].user_certificate.to_bytes_be();
    let expected = input_serial.to_be_bytes();
    let expected_stripped = &expected[expected.iter().position(|&b| b != 0).unwrap_or(expected.len() - 1)..];
    assert_eq!(serial_in_crl.as_slice(), expected_stripped);
}

#[test]
fn test_crl_with_multiple_revoked_certs() {
    // Input: 4 serials (100, 200, 300, 400) with different reasons
    let ca = create_test_ca();
    let inputs = vec![
        (100u64, RevocationReason::KEY_COMPROMISE),
        (200u64, RevocationReason::SUPERSEDED),
        (300u64, RevocationReason::AFFILIATION_CHANGED),
        (400u64, RevocationReason::CESSATION_OF_OPERATION),
    ];
    
    let mut builder = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap();
    
    for (serial, reason) in &inputs {
        builder = builder.add_revoked_cert(
            RevokedCertificate::new(SerialNumber::from(*serial)).with_reason(*reason)
        );
    }
    
    // Output: CRL with 4 revoked certs
    let crl = builder.validity_days(30).build().unwrap();
    
    // Validate: Parse CRL and verify all 4 serials are present
    let parsed = parse_crl(crl.to_der());
    let revoked_certs: Vec<_> = parsed.iter_revoked_certificates().collect();
    assert_eq!(revoked_certs.len(), inputs.len());
    
    for (i, revoked_cert) in revoked_certs.iter().enumerate() {
        let serial_in_crl = revoked_cert.user_certificate.to_bytes_be();
        let expected = inputs[i].0.to_be_bytes();
        let expected_stripped = &expected[expected.iter().position(|&b| b != 0).unwrap_or(expected.len() - 1)..];
        assert_eq!(serial_in_crl.as_slice(), expected_stripped);
    }
}

#[test]
fn test_crl_all_revocation_reasons() {
    // Input: 10 certs with all 10 revocation reason types
    let ca = create_test_ca();
    let reasons = vec![
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
    
    for (i, reason) in reasons.iter().enumerate() {
        builder = builder.add_revoked_cert(
            RevokedCertificate::new(SerialNumber::from((i + 1) as u64)).with_reason(*reason)
        );
    }
    
    // Output: CRL with all reason types
    let crl = builder.build().unwrap();
    
    // Validate: Parse CRL and verify all 10 certs are present
    let parsed = parse_crl(crl.to_der());
    assert_eq!(parsed.iter_revoked_certificates().count(), reasons.len());
}

#[test]
fn test_crl_custom_validity() {
    // Input: CA key + custom validity period (90 days)
    let ca = create_test_ca();
    let input_validity = 90u32;
    let input_this_update = ::time::OffsetDateTime::now_utc();
    
    let revoked = RevokedCertificate::new(SerialNumber::from(999u64))
        .with_reason(RevocationReason::KEY_COMPROMISE);
    
    // Output: CRL with 90-day validity
    let crl = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
        .add_revoked_cert(revoked)
        .this_update(input_this_update)
        .validity_days(input_validity)
        .build().unwrap();
    
    // Validate: CRL generated
    assert!(!crl.to_der().is_empty());
}

#[test]
fn test_crl_batch_revoked_certs() {
    // Input: CA key + 20 revoked certs
    let ca = create_test_ca();
    let input_count = 20;
    
    let revoked_list: Vec<_> = (1..=input_count)
        .map(|i| RevokedCertificate::new(SerialNumber::from(i))
            .with_reason(RevocationReason::KEY_COMPROMISE))
        .collect();
    
    // Output: CRL with 20 revoked certs
    let crl = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
        .add_revoked_certs(revoked_list)
        .validity_days(14)
        .build().unwrap();
    
    // Validate: CRL generated
    assert!(!crl.to_der().is_empty());
}

#[test]
fn test_crl_custom_revocation_times() {
    // Input: 3 revoked certs with different revocation times
    let ca = create_test_ca();
    let now = ::time::OffsetDateTime::now_utc();
    
    let inputs = vec![
        (1001u64, now - ::time::Duration::days(1)),
        (1002u64, now - ::time::Duration::days(7)),
        (1003u64, now - ::time::Duration::days(30)),
    ];
    
    let mut builder = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap();
    
    for (serial, time) in inputs {
        builder = builder.add_revoked_cert(
            RevokedCertificate::new(SerialNumber::from(serial))
                .with_time(time)
                .with_reason(RevocationReason::KEY_COMPROMISE)
        );
    }
    
    // Output: CRL with custom revocation times
    let crl = builder.build().unwrap();
    
    // Validate: CRL generated
    assert!(!crl.to_der().is_empty());
}

#[test]
fn test_crl_without_reasons() {
    // Input: 3 revoked certs without reasons
    let ca = create_test_ca();
    
    let revoked_list = vec![
        RevokedCertificate::new(SerialNumber::from(5001u64)),
        RevokedCertificate::new(SerialNumber::from(5002u64)),
        RevokedCertificate::new(SerialNumber::from(5003u64)),
    ];
    
    // Output: CRL without revocation reasons
    let crl = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
        .add_revoked_certs(revoked_list)
        .build().unwrap();
    
    // Validate: CRL generated
    assert!(!crl.to_der().is_empty());
}

#[test]
fn test_crl_short_validity() {
    // Input: 1-day validity
    let ca = create_test_ca();
    let input_validity = 1u32;
    
    // Output: Short-lived CRL
    let crl = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
        .add_revoked_cert(
            RevokedCertificate::new(SerialNumber::from(9001u64))
                .with_reason(RevocationReason::KEY_COMPROMISE)
        )
        .validity_days(input_validity)
        .build().unwrap();
    
    // Validate: CRL generated
    assert!(!crl.to_der().is_empty());
}

#[test]
fn test_crl_long_validity() {
    // Input: 180-day validity
    let ca = create_test_ca();
    let input_validity = 180u32;
    
    // Output: Long-lived CRL
    let crl = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
        .add_revoked_cert(
            RevokedCertificate::new(SerialNumber::from(9002u64))
                .with_reason(RevocationReason::SUPERSEDED)
        )
        .validity_days(input_validity)
        .build().unwrap();
    
    // Validate: CRL generated
    assert!(!crl.to_der().is_empty());
}

#[test]
fn test_crl_default_builder() {
    // Input: Default builder settings
    let ca = create_test_ca();
    
    // Output: CRL with defaults
    let crl = CrlBuilder::default()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
        .build().unwrap();
    
    // Validate: CRL generated with defaults
    assert!(!crl.to_der().is_empty());
}

#[test]
fn test_error_missing_issuer_key() {
    // Input: No issuer key
    // Output: Error
    let result = CrlBuilder::new().validity_days(7).build();
    
    // Validate: MissingField error
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, mtls_at_lib::error::CrlError::MissingField(_)));
}

#[test]
fn test_error_invalid_issuer_key() {
    // Input: Invalid key string
    // Output: Error
    let result = CrlBuilder::new()
        .issuer_key_from_pem("invalid key data");
    
    // Validate: SigningError
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, mtls_at_lib::error::CrlError::SigningError(_)));
}

#[test]
fn test_crl_pem_der_formats() {
    // Input: CA key
    let ca = create_test_ca();
    
    // Output: CRL in both formats
    let crl = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
        .add_revoked_cert(
            RevokedCertificate::new(SerialNumber::from(8888u64))
                .with_reason(RevocationReason::KEY_COMPROMISE)
        )
        .build().unwrap();
    
    // Validate: Both formats are valid
    let pem = crl.to_pem();
    let der = crl.to_der();
    
    assert!(pem.starts_with("-----BEGIN X509 CRL-----"));
    assert!(pem.contains("-----END X509 CRL-----"));
    assert_eq!(der[0], 0x30); // SEQUENCE tag
    assert!(!der.is_empty());
}

#[test]
fn test_crl_update_scenario() {
    // Input: Initial CRL with 1 cert, then updated with 3 certs
    let ca = create_test_ca();
    
    // Initial CRL
    let initial_crl = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
        .add_revoked_cert(
            RevokedCertificate::new(SerialNumber::from(2001u64))
                .with_reason(RevocationReason::KEY_COMPROMISE)
        )
        .build().unwrap();
    
    // Updated CRL
    let update_time = ::time::OffsetDateTime::now_utc() + ::time::Duration::hours(24);
    let updated_crl = CrlBuilder::new()
        .issuer_key_from_pem(ca.private_key_pem().unwrap()).unwrap()
        .add_revoked_certs(vec![
            RevokedCertificate::new(SerialNumber::from(2001u64))
                .with_reason(RevocationReason::KEY_COMPROMISE),
            RevokedCertificate::new(SerialNumber::from(2002u64))
                .with_reason(RevocationReason::SUPERSEDED),
            RevokedCertificate::new(SerialNumber::from(2003u64))
                .with_reason(RevocationReason::AFFILIATION_CHANGED),
        ])
        .this_update(update_time)
        .build().unwrap();
    
    // Validate: Both CRLs generated
    assert!(!initial_crl.to_der().is_empty());
    assert!(!updated_crl.to_der().is_empty());
}
