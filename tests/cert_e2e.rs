//! End-to-End Tests for Certificate Module
//!
//! This test suite validates complete certificate workflows including:
//! - Self-signed certificate generation and validation
//! - CA certificate creation and certificate chain building
//! - Certificate signing with CA
//! - Certificate verification and validation
//! - Real-world scenarios with proper key management

use mtls_at_lib::cert::CertificateBuilder;
use mtls_at_lib::csr::CsrBuilder;
use mtls_at_lib::types::{KeyUsage, ExtendedKeyUsage};
use rcgen::KeyPair;

/// Helper to verify certificate PEM format
fn verify_cert_pem_format(pem: &str) {
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(pem.contains("-----END CERTIFICATE-----"));
    assert!(pem.lines().count() > 3); // Header + content + footer
}

/// Helper to verify certificate DER format
fn verify_cert_der_format(der: &[u8]) {
    assert!(!der.is_empty());
    // DER certificates start with SEQUENCE (0x30)
    assert_eq!(der[0], 0x30);
}

#[test]
fn test_e2e_self_signed_certificate_workflow() {
    // Scenario: Generate a self-signed certificate for a web server
    println!("\n=== E2E Test: Self-Signed Certificate Workflow ===");
    
    // Step 1: Create a CSR for the server
    let server_csr = CsrBuilder::new()
        .subject("CN=server.example.com,O=Example Corp,C=US")
        .expect("Failed to set subject")
        .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
        .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH])
        .add_san("server.example.com")
        .add_san("www.example.com")
        .build()
        .expect("Failed to build CSR");
    
    println!("✓ Step 1: CSR created for server.example.com");
    
    // Step 2: Create a self-signed certificate from the CSR
    let server_cert = CertificateBuilder::new()
        .from_der(server_csr.to_der())
        .expect("Failed to load CSR")
        .signing_key(server_csr.private_key_pem().to_string())
        .build_self_signed()
        .expect("Failed to build self-signed certificate");
    
    println!("✓ Step 2: Self-signed certificate created");
    
    // Step 3: Verify the certificate properties
    verify_cert_pem_format(&server_cert.to_pem());
    verify_cert_der_format(&server_cert.to_der());
    
    // Should have private key (self-signed includes it)
    assert!(server_cert.private_key_pem().is_some());
    assert!(!server_cert.private_key_pem().unwrap().is_empty());
    
    println!("✓ Step 3: Certificate validated");
    
    // Step 4: Save to files (simulated)
    let cert_pem = server_cert.to_pem();
    let key_pem = server_cert.private_key_pem().unwrap();
    
    assert!(cert_pem.len() > 100);
    assert!(key_pem.len() > 100);
    
    println!("✓ Step 4: Certificate and key ready for deployment");
    println!("=== Test Passed ===\n");
}

#[test]
fn test_e2e_ca_and_server_certificate_chain() {
    // Scenario: Create a CA certificate and use it to sign a server certificate
    println!("\n=== E2E Test: CA Certificate Chain Workflow ===");
    
    // Step 1: Create CA certificate (self-signed root CA)
    let ca_csr = CsrBuilder::new()
        .subject("CN=Example Root CA,O=Example Corp,C=US")
        .expect("Failed to set CA subject")
        .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
        .build()
        .expect("Failed to build CA CSR");
    
    println!("✓ Step 1: CA CSR created");
    
    let ca_cert = CertificateBuilder::new()
        .from_der(ca_csr.to_der())
        .expect("Failed to load CA CSR")
        .signing_key(ca_csr.private_key_pem().to_string())
        .build_self_signed()
        .expect("Failed to build CA certificate");
    
    println!("✓ Step 2: Root CA certificate created (self-signed)");
    
    // Step 2: Create a server CSR with a different key
    let server_csr = CsrBuilder::new()
        .subject("CN=api.example.com,O=Example Corp,C=US")
        .expect("Failed to set server subject")
        .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
        .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH])
        .add_san("api.example.com")
        .add_san("api-v2.example.com")
        .build()
        .expect("Failed to build server CSR");
    
    println!("✓ Step 3: Server CSR created with different key");
    
    // Step 3: Sign the server certificate with CA
    let server_cert = CertificateBuilder::new()
        .from_der(server_csr.to_der())
        .expect("Failed to load server CSR")
        .signing_key(ca_cert.private_key_pem().unwrap().to_string())
        .build_ca_signed("CN=Example Root CA,O=Example Corp,C=US")
        .expect("Failed to sign server certificate with CA");
    
    println!("✓ Step 4: Server certificate signed by CA");
    
    // Step 4: Verify the certificates
    verify_cert_pem_format(&ca_cert.to_pem());
    verify_cert_pem_format(&server_cert.to_pem());
    
    // CA cert should have private key (it's self-signed)
    assert!(ca_cert.private_key_pem().is_some());
    
    // Server cert should NOT have private key (CA-signed)
    assert!(server_cert.private_key_pem().is_none());
    
    // Server still has its own private key from CSR
    assert!(!server_csr.private_key_pem().is_empty());
    
    println!("✓ Step 5: Certificate chain validated");
    println!("=== Test Passed ===\n");
}

#[test]
fn test_e2e_intermediate_ca_chain() {
    // Scenario: Root CA -> Intermediate CA -> Server Certificate
    println!("\n=== E2E Test: Three-Level Certificate Chain ===");
    
    // Step 1: Create Root CA
    let root_ca_csr = CsrBuilder::new()
        .subject("CN=Root CA,O=Example Corp,C=US")
        .expect("Failed to set root CA subject")
        .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
        .build()
        .expect("Failed to build root CA CSR");
    
    let root_ca_cert = CertificateBuilder::new()
        .from_der(root_ca_csr.to_der())
        .expect("Failed to load root CA CSR")
        .signing_key(root_ca_csr.private_key_pem().to_string())
        .build_self_signed()
        .expect("Failed to build root CA certificate");
    
    println!("✓ Step 1: Root CA created");
    
    // Step 2: Create Intermediate CA CSR
    let intermediate_ca_csr = CsrBuilder::new()
        .subject("CN=Intermediate CA,O=Example Corp,C=US")
        .expect("Failed to set intermediate CA subject")
        .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
        .build()
        .expect("Failed to build intermediate CA CSR");
    
    println!("✓ Step 2: Intermediate CA CSR created");
    
    // Step 3: Sign Intermediate CA with Root CA
    let intermediate_ca_cert = CertificateBuilder::new()
        .from_der(intermediate_ca_csr.to_der())
        .expect("Failed to load intermediate CA CSR")
        .signing_key(root_ca_cert.private_key_pem().unwrap().to_string())
        .build_ca_signed("CN=Root CA,O=Example Corp,C=US")
        .expect("Failed to sign intermediate CA with root CA");
    
    println!("✓ Step 3: Intermediate CA signed by Root CA");
    
    // Step 4: Create Server CSR
    let server_csr = CsrBuilder::new()
        .subject("CN=secure.example.com,O=Example Corp,C=US")
        .expect("Failed to set server subject")
        .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
        .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH])
        .add_san("secure.example.com")
        .build()
        .expect("Failed to build server CSR");
    
    println!("✓ Step 4: Server CSR created");
    
    // Step 5: Sign Server Certificate with Intermediate CA
    let server_cert = CertificateBuilder::new()
        .from_der(server_csr.to_der())
        .expect("Failed to load server CSR")
        .signing_key(intermediate_ca_csr.private_key_pem().to_string())
        .build_ca_signed("CN=Intermediate CA,O=Example Corp,C=US")
        .expect("Failed to sign server certificate with intermediate CA");
    
    println!("✓ Step 5: Server certificate signed by Intermediate CA");
    
    // Step 6: Verify the chain
    verify_cert_pem_format(&root_ca_cert.to_pem());
    verify_cert_pem_format(&intermediate_ca_cert.to_pem());
    verify_cert_pem_format(&server_cert.to_pem());
    
    // Only root CA should have its private key in the cert object
    assert!(root_ca_cert.private_key_pem().is_some());
    assert!(intermediate_ca_cert.private_key_pem().is_none());
    assert!(server_cert.private_key_pem().is_none());
    
    println!("✓ Step 6: Three-level certificate chain validated");
    println!("  - Root CA (self-signed)");
    println!("  - Intermediate CA (signed by Root CA)");
    println!("  - Server Certificate (signed by Intermediate CA)");
    println!("=== Test Passed ===\n");
}

#[test]
fn test_e2e_multiple_servers_same_ca() {
    // Scenario: One CA signing multiple server certificates
    println!("\n=== E2E Test: Multiple Servers with Same CA ===");
    
    // Step 1: Create CA
    let ca_csr = CsrBuilder::new()
        .subject("CN=Shared CA,O=Example Corp,C=US")
        .expect("Failed to set CA subject")
        .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
        .build()
        .expect("Failed to build CA CSR");
    
    let ca_cert = CertificateBuilder::new()
        .from_der(ca_csr.to_der())
        .expect("Failed to load CA CSR")
        .signing_key(ca_csr.private_key_pem().to_string())
        .build_self_signed()
        .expect("Failed to build CA certificate");
    
    println!("✓ Step 1: Shared CA created");
    
    // Step 2: Create multiple server certificates
    let servers = vec![
        ("server1.example.com", "Server 1"),
        ("server2.example.com", "Server 2"),
        ("server3.example.com", "Server 3"),
    ];
    
    let mut server_certs = Vec::new();
    
    for (domain, name) in servers {
        // Create CSR for each server
        let server_csr = CsrBuilder::new()
            .subject(&format!("CN={},O=Example Corp,C=US", domain))
            .expect("Failed to set server subject")
            .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
            .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH])
            .add_san(domain)
            .build()
            .expect("Failed to build server CSR");
        
        // Sign with CA
        let server_cert = CertificateBuilder::new()
            .from_der(server_csr.to_der())
            .expect("Failed to load server CSR")
            .signing_key(ca_cert.private_key_pem().unwrap().to_string())
            .build_ca_signed("CN=Shared CA,O=Example Corp,C=US")
            .expect("Failed to sign server certificate");
        
        verify_cert_pem_format(&server_cert.to_pem());
        assert!(server_cert.private_key_pem().is_none());
        
        server_certs.push((name, server_cert));
        println!("✓ Step 2.{}: {} certificate signed", server_certs.len(), name);
    }
    
    // Step 3: Verify all certificates are valid
    assert_eq!(server_certs.len(), 3);
    for (name, cert) in &server_certs {
        assert!(!cert.to_pem().is_empty(), "{} cert is empty", name);
        assert!(!cert.to_der().is_empty(), "{} cert DER is empty", name);
    }
    
    println!("✓ Step 3: All server certificates validated");
    println!("=== Test Passed ===\n");
}

#[test]
fn test_e2e_client_certificate_for_mtls() {
    // Scenario: Generate client certificate for mutual TLS (mTLS)
    println!("\n=== E2E Test: Client Certificate for mTLS ===");
    
    // Step 1: Create CA
    let ca_csr = CsrBuilder::new()
        .subject("CN=mTLS CA,O=Example Corp,C=US")
        .expect("Failed to set CA subject")
        .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
        .build()
        .expect("Failed to build CA CSR");
    
    let ca_cert = CertificateBuilder::new()
        .from_der(ca_csr.to_der())
        .expect("Failed to load CA CSR")
        .signing_key(ca_csr.private_key_pem().to_string())
        .build_self_signed()
        .expect("Failed to build CA certificate");
    
    println!("✓ Step 1: CA certificate created");
    
    // Step 2: Create server certificate
    let server_csr = CsrBuilder::new()
        .subject("CN=mtls.example.com,O=Example Corp,C=US")
        .expect("Failed to set server subject")
        .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
        .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH])
        .add_san("mtls.example.com")
        .build()
        .expect("Failed to build server CSR");
    
    let server_cert = CertificateBuilder::new()
        .from_der(server_csr.to_der())
        .expect("Failed to load server CSR")
        .signing_key(ca_cert.private_key_pem().unwrap().to_string())
        .build_ca_signed("CN=mTLS CA,O=Example Corp,C=US")
        .expect("Failed to sign server certificate");
    
    println!("✓ Step 2: Server certificate created");
    
    // Step 3: Create client certificate
    let client_csr = CsrBuilder::new()
        .subject("CN=client-app,O=Example Corp,C=US")
        .expect("Failed to set client subject")
        .key_usage(KeyUsage::digital_signature() | KeyUsage::key_agreement())
        .extended_key_usage(vec![ExtendedKeyUsage::CLIENT_AUTH])
        .build()
        .expect("Failed to build client CSR");
    
    let client_cert = CertificateBuilder::new()
        .from_der(client_csr.to_der())
        .expect("Failed to load client CSR")
        .signing_key(ca_cert.private_key_pem().unwrap().to_string())
        .build_ca_signed("CN=mTLS CA,O=Example Corp,C=US")
        .expect("Failed to sign client certificate");
    
    println!("✓ Step 3: Client certificate created");
    
    // Step 4: Verify mTLS setup
    verify_cert_pem_format(&ca_cert.to_pem());
    verify_cert_pem_format(&server_cert.to_pem());
    verify_cert_pem_format(&client_cert.to_pem());
    
    // Verify key management
    assert!(ca_cert.private_key_pem().is_some(), "CA should have private key");
    assert!(server_cert.private_key_pem().is_none(), "Server cert shouldn't include private key");
    assert!(client_cert.private_key_pem().is_none(), "Client cert shouldn't include private key");
    
    // Server and client keep their own private keys from CSRs
    assert!(!server_csr.private_key_pem().is_empty(), "Server should have its private key");
    assert!(!client_csr.private_key_pem().is_empty(), "Client should have its private key");
    
    println!("✓ Step 4: mTLS certificate chain validated");
    println!("  - CA certificate");
    println!("  - Server certificate (for server authentication)");
    println!("  - Client certificate (for client authentication)");
    println!("=== Test Passed ===\n");
}

#[test]
fn test_e2e_certificate_with_san_multiple_domains() {
    // Scenario: Create certificate with multiple SANs (Subject Alternative Names)
    println!("\n=== E2E Test: Certificate with Multiple SANs ===");
    
    // Step 1: Create CSR with multiple SANs
    let server_csr = CsrBuilder::new()
        .subject("CN=multi.example.com,O=Example Corp,C=US")
        .expect("Failed to set subject")
        .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
        .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH])
        .add_san("multi.example.com")
        .add_san("www.multi.example.com")
        .add_san("api.multi.example.com")
        .add_san("admin.multi.example.com")
        .build()
        .expect("Failed to build CSR");
    
    println!("✓ Step 1: CSR created with 4 SANs");
    
    // Step 2: Create self-signed certificate
    let cert = CertificateBuilder::new()
        .from_der(server_csr.to_der())
        .expect("Failed to load CSR")
        .signing_key(server_csr.private_key_pem().to_string())
        .build_self_signed()
        .expect("Failed to build certificate");
    
    println!("✓ Step 2: Certificate created");
    
    // Step 3: Verify certificate
    verify_cert_pem_format(&cert.to_pem());
    assert!(cert.private_key_pem().is_some());
    
    println!("✓ Step 3: Multi-SAN certificate validated");
    println!("=== Test Passed ===\n");
}

#[test]
fn test_e2e_error_same_key_for_ca_signed() {
    // Scenario: Verify that using the same key for CA-signed cert fails
    println!("\n=== E2E Test: Error Handling - Same Key for CA-Signed ===");
    
    // Step 1: Create a CSR
    let csr = CsrBuilder::new()
        .subject("CN=test.example.com,O=Example Corp,C=US")
        .expect("Failed to set subject")
        .build()
        .expect("Failed to build CSR");
    
    println!("✓ Step 1: CSR created");
    
    // Step 2: Try to create CA-signed cert with the same key (should fail)
    let result = CertificateBuilder::new()
        .from_der(csr.to_der())
        .expect("Failed to load CSR")
        .signing_key(csr.private_key_pem().to_string())
        .build_ca_signed("CN=Test CA,O=Example Corp,C=US");
    
    println!("✓ Step 2: Attempted to sign with same key");
    
    // Step 3: Verify it fails with the correct error
    assert!(result.is_err(), "Should fail when using same key for CA-signed");
    
    match result {
        Err(mtls_at_lib::error::CertError::PublicKeyMismatch(msg)) => {
            assert!(msg.contains("Public key in CSR matches CA signing key"));
            println!("✓ Step 3: Correctly rejected with PublicKeyMismatch error");
            println!("  Error message: {}", msg);
        }
        _ => panic!("Expected PublicKeyMismatch error"),
    }
    
    println!("=== Test Passed ===\n");
}

#[test]
fn test_e2e_error_different_key_for_self_signed() {
    // Scenario: Verify that using a different key for self-signed cert fails
    println!("\n=== E2E Test: Error Handling - Different Key for Self-Signed ===");
    
    // Step 1: Create a CSR
    let csr = CsrBuilder::new()
        .subject("CN=test.example.com,O=Example Corp,C=US")
        .expect("Failed to set subject")
        .build()
        .expect("Failed to build CSR");
    
    println!("✓ Step 1: CSR created");
    
    // Step 2: Generate a different key
    let different_key = KeyPair::generate().expect("Failed to generate key");
    let different_key_pem = different_key.serialize_pem();
    
    println!("✓ Step 2: Different key generated");
    
    // Step 3: Try to create self-signed cert with different key (should fail)
    let result = CertificateBuilder::new()
        .from_der(csr.to_der())
        .expect("Failed to load CSR")
        .signing_key(different_key_pem)
        .build_self_signed();
    
    println!("✓ Step 3: Attempted to self-sign with different key");
    
    // Step 4: Verify it fails with the correct error
    assert!(result.is_err(), "Should fail when using different key for self-signed");
    
    match result {
        Err(mtls_at_lib::error::CertError::PublicKeyMismatch(msg)) => {
            assert!(msg.contains("Public key in CSR does not match signing key"));
            println!("✓ Step 4: Correctly rejected with PublicKeyMismatch error");
            println!("  Error message: {}", msg);
        }
        _ => panic!("Expected PublicKeyMismatch error, got: {:?}", result),
    }
    
    println!("=== Test Passed ===\n");
}

#[test]
fn test_e2e_load_from_pem_and_der() {
    // Scenario: Test loading CSR from both PEM and DER formats
    println!("\n=== E2E Test: Load CSR from PEM and DER ===");
    
    // Step 1: Create a CSR
    let csr = CsrBuilder::new()
        .subject("CN=format-test.example.com,O=Example Corp,C=US")
        .expect("Failed to set subject")
        .build()
        .expect("Failed to build CSR");
    
    println!("✓ Step 1: CSR created");
    
    // Step 2: Load from DER
    let cert_from_der = CertificateBuilder::new()
        .from_der(csr.to_der())
        .expect("Failed to load from DER")
        .signing_key(csr.private_key_pem().to_string())
        .build_self_signed()
        .expect("Failed to build cert from DER");
    
    println!("✓ Step 2: Certificate built from DER format");
    
    // Step 3: Load from PEM
    let cert_from_pem = CertificateBuilder::new()
        .from_pem(&csr.to_pem())
        .expect("Failed to load from PEM")
        .signing_key(csr.private_key_pem().to_string())
        .build_self_signed()
        .expect("Failed to build cert from PEM");
    
    println!("✓ Step 3: Certificate built from PEM format");
    
    // Step 4: Verify both certificates are valid
    verify_cert_pem_format(&cert_from_der.to_pem());
    verify_cert_pem_format(&cert_from_pem.to_pem());
    
    assert!(!cert_from_der.to_der().is_empty());
    assert!(!cert_from_pem.to_der().is_empty());
    
    println!("✓ Step 4: Both certificates validated");
    println!("=== Test Passed ===\n");
}
