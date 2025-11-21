//! Integration tests for CSR generation
//!
//! These tests verify that CSR generation meets all qualification requirements.

use mtls_at_lib::csr::CsrBuilder;
use mtls_at_lib::types::{ExtendedKeyUsage, KeyUsage};
use x509_parser::prelude::*;

/// Helper to parse CSR DER
fn parse_csr(der: &[u8]) -> X509CertificationRequest<'_> {
    let (_, csr) = X509CertificationRequest::from_der(der).expect("Failed to parse CSR");
    csr
}

#[test]
fn test_csr_generation_with_ku_and_eku_for_ca() {
    // Qualification requirement 1.1: Create X509 CSR with KU and EKU extensions (CA)
    let ca_csr = CsrBuilder::new()
        .subject("CN=Test Root CA,O=Test Organization,C=US")
        .expect("Failed to set subject")
        .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
        .is_ca(true)
        .build()
        .expect("Failed to generate CA CSR");

    // Verify CSR was generated
    let der = ca_csr.to_der();
    assert!(!der.is_empty(), "CSR DER should not be empty");

    // Verify PEM encoding
    let pem = ca_csr.to_pem();
    assert!(
        pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"),
        "PEM should start with CSR header"
    );
    assert!(
        pem.contains("-----END CERTIFICATE REQUEST-----"),
        "PEM should contain CSR footer"
    );

    // Verify private key was generated
    let private_key_der = ca_csr.private_key_der();
    assert!(
        !private_key_der.is_empty(),
        "Private key DER should not be empty"
    );

    let private_key_pem = ca_csr.private_key_pem();
    assert!(
        private_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"),
        "Private key PEM should start with key header"
    );
    
    // Parse CSR and validate subject DN matches input
    let parsed = parse_csr(&der);
    let subject = parsed.certification_request_info.subject;
    let cn = subject.iter_common_name().next().unwrap().as_str().unwrap();
    assert_eq!(cn, "Test Root CA", "CN should match input");
    let o = subject.iter_organization().next().unwrap().as_str().unwrap();
    assert_eq!(o, "Test Organization", "Organization should match input");
    let c = subject.iter_country().next().unwrap().as_str().unwrap();
    assert_eq!(c, "US", "Country should match input");

    println!("✓ CA CSR generated successfully with Key Usage extensions and validated DN");
}

#[test]
fn test_csr_generation_with_ku_and_eku_for_standard_cert() {
    // Qualification requirement 1.2: Create X509 CSR with KU and EKU extensions (standard)
    let server_csr = CsrBuilder::new()
        .subject("CN=server.example.com,O=Example Corp,C=US")
        .expect("Failed to set subject")
        .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
        .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH])
        .add_san("www.example.com")
        .add_san("api.example.com")
        .build()
        .expect("Failed to generate server CSR");

    // Verify CSR was generated
    let der = server_csr.to_der();
    assert!(!der.is_empty(), "CSR DER should not be empty");

    // Verify PEM encoding
    let pem = server_csr.to_pem();
    assert!(
        pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"),
        "PEM should start with CSR header"
    );

    // Verify private key
    assert!(
        !server_csr.private_key_der().is_empty(),
        "Private key should be generated"
    );
    
    // Parse CSR and validate subject DN matches input
    let parsed = parse_csr(server_csr.to_der());
    let subject = parsed.certification_request_info.subject;
    let cn = subject.iter_common_name().next().unwrap().as_str().unwrap();
    assert_eq!(cn, "server.example.com", "CN should match input");
    let o = subject.iter_organization().next().unwrap().as_str().unwrap();
    assert_eq!(o, "Example Corp", "Organization should match input");
    let c = subject.iter_country().next().unwrap().as_str().unwrap();
    assert_eq!(c, "US", "Country should match input");

    println!("✓ Server CSR generated successfully with Key Usage and Extended Key Usage, DN validated");
}

#[test]
fn test_csr_generation_for_client_auth() {
    // Create a client authentication CSR
    let client_csr = CsrBuilder::new()
        .subject("CN=client.example.com,O=Example Corp,C=US")
        .expect("Failed to set subject")
        .key_usage(KeyUsage::digital_signature())
        .extended_key_usage(vec![ExtendedKeyUsage::CLIENT_AUTH])
        .build()
        .expect("Failed to generate client CSR");

    // Verify CSR was generated
    assert!(!client_csr.to_der().is_empty(), "Client CSR should be generated");

    println!("✓ Client CSR generated successfully for mTLS client authentication");
}

#[test]
fn test_csr_generation_without_optional_extensions() {
    // Generate a basic CSR without Key Usage or Extended Key Usage
    let basic_csr = CsrBuilder::new()
        .subject("CN=basic.example.com")
        .expect("Failed to set subject")
        .build()
        .expect("Failed to generate basic CSR");

    // Verify CSR was generated
    assert!(!basic_csr.to_der().is_empty(), "Basic CSR should be generated");
    assert!(
        basic_csr.to_pem().contains("CERTIFICATE REQUEST"),
        "Should be a valid CSR"
    );

    println!("✓ Basic CSR generated successfully without extensions");
}

#[test]
fn test_csr_generation_with_multiple_eku() {
    // Generate CSR with multiple Extended Key Usage values
    let multi_eku_csr = CsrBuilder::new()
        .subject("CN=multi.example.com")
        .expect("Failed to set subject")
        .extended_key_usage(vec![
            ExtendedKeyUsage::SERVER_AUTH,
            ExtendedKeyUsage::CLIENT_AUTH,
        ])
        .build()
        .expect("Failed to generate multi-EKU CSR");

    assert!(!multi_eku_csr.to_der().is_empty(), "Multi-EKU CSR should be generated");

    println!("✓ CSR generated successfully with multiple Extended Key Usage values");
}

#[test]
fn test_csr_missing_subject_returns_error() {
    // Verify that CSR generation fails without a subject
    let result = CsrBuilder::new().build();

    assert!(result.is_err(), "CSR generation should fail without subject");
    if let Err(e) = result {
        println!("✓ Error correctly returned for missing subject: {}", e);
    }
}

#[test]
fn test_csr_invalid_subject_returns_error() {
    // Verify that invalid subject format returns an error
    let result = CsrBuilder::new().subject("");

    assert!(result.is_err(), "Empty subject should return an error");
    if let Err(e) = result {
        println!("✓ Error correctly returned for empty subject: {}", e);
    }
}

#[test]
fn test_key_pair_is_different_for_each_csr() {
    // Generate two CSRs and verify they have different key pairs
    let csr1 = CsrBuilder::new()
        .subject("CN=test1.example.com")
        .expect("Failed to set subject")
        .build()
        .expect("Failed to generate CSR 1");

    let csr2 = CsrBuilder::new()
        .subject("CN=test2.example.com")
        .expect("Failed to set subject")
        .build()
        .expect("Failed to generate CSR 2");

    // Verify that the private keys are different
    assert_ne!(
        csr1.private_key_der(),
        csr2.private_key_der(),
        "Each CSR should have a unique private key"
    );

    println!("✓ Each CSR generates a unique key pair");
}

#[test]
fn test_csr_with_all_key_usage_flags() {
    // Test CSR with all Key Usage flags set
    let all_ku = KeyUsage::digital_signature()
        | KeyUsage::non_repudiation()
        | KeyUsage::key_encipherment()
        | KeyUsage::data_encipherment()
        | KeyUsage::key_agreement()
        | KeyUsage::key_cert_sign()
        | KeyUsage::crl_sign()
        | KeyUsage::encipher_only()
        | KeyUsage::decipher_only();

    let csr = CsrBuilder::new()
        .subject("CN=all-ku.example.com")
        .expect("Failed to set subject")
        .key_usage(all_ku)
        .build()
        .expect("Failed to generate CSR with all KU flags");

    assert!(!csr.to_der().is_empty(), "CSR with all KU flags should be generated");

    println!("✓ CSR generated successfully with all Key Usage flags");
}

#[test]
fn test_csr_with_all_extended_key_usage_types() {
    // Test CSR with all Extended Key Usage types individually
    
    // Test SERVER_AUTH
    let server_csr = CsrBuilder::new()
        .subject("CN=server-auth.example.com")
        .expect("Failed to set subject")
        .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH])
        .build()
        .expect("Failed to generate CSR with SERVER_AUTH");
    assert!(!server_csr.to_der().is_empty(), "SERVER_AUTH CSR should be generated");
    println!("✓ CSR generated with SERVER_AUTH");

    // Test CLIENT_AUTH
    let client_csr = CsrBuilder::new()
        .subject("CN=client-auth.example.com")
        .expect("Failed to set subject")
        .extended_key_usage(vec![ExtendedKeyUsage::CLIENT_AUTH])
        .build()
        .expect("Failed to generate CSR with CLIENT_AUTH");
    assert!(!client_csr.to_der().is_empty(), "CLIENT_AUTH CSR should be generated");
    println!("✓ CSR generated with CLIENT_AUTH");

    // Test CODE_SIGNING
    let code_signing_csr = CsrBuilder::new()
        .subject("CN=code-signing.example.com")
        .expect("Failed to set subject")
        .extended_key_usage(vec![ExtendedKeyUsage::CODE_SIGNING])
        .build()
        .expect("Failed to generate CSR with CODE_SIGNING");
    assert!(!code_signing_csr.to_der().is_empty(), "CODE_SIGNING CSR should be generated");
    println!("✓ CSR generated with CODE_SIGNING");

    // Test EMAIL_PROTECTION
    let email_csr = CsrBuilder::new()
        .subject("CN=email-protection.example.com")
        .expect("Failed to set subject")
        .extended_key_usage(vec![ExtendedKeyUsage::EMAIL_PROTECTION])
        .build()
        .expect("Failed to generate CSR with EMAIL_PROTECTION");
    assert!(!email_csr.to_der().is_empty(), "EMAIL_PROTECTION CSR should be generated");
    println!("✓ CSR generated with EMAIL_PROTECTION");

    // Test TIME_STAMPING
    let time_stamping_csr = CsrBuilder::new()
        .subject("CN=time-stamping.example.com")
        .expect("Failed to set subject")
        .extended_key_usage(vec![ExtendedKeyUsage::TIME_STAMPING])
        .build()
        .expect("Failed to generate CSR with TIME_STAMPING");
    assert!(!time_stamping_csr.to_der().is_empty(), "TIME_STAMPING CSR should be generated");
    println!("✓ CSR generated with TIME_STAMPING");

    // Test OCSP_SIGNING
    let ocsp_csr = CsrBuilder::new()
        .subject("CN=ocsp-signing.example.com")
        .expect("Failed to set subject")
        .extended_key_usage(vec![ExtendedKeyUsage::OCSP_SIGNING])
        .build()
        .expect("Failed to generate CSR with OCSP_SIGNING");
    assert!(!ocsp_csr.to_der().is_empty(), "OCSP_SIGNING CSR should be generated");
    println!("✓ CSR generated with OCSP_SIGNING");

    // Test combination of all EKU types
    let all_eku_csr = CsrBuilder::new()
        .subject("CN=all-eku.example.com")
        .expect("Failed to set subject")
        .extended_key_usage(vec![
            ExtendedKeyUsage::SERVER_AUTH,
            ExtendedKeyUsage::CLIENT_AUTH,
            ExtendedKeyUsage::CODE_SIGNING,
            ExtendedKeyUsage::EMAIL_PROTECTION,
            ExtendedKeyUsage::TIME_STAMPING,
            ExtendedKeyUsage::OCSP_SIGNING,
        ])
        .build()
        .expect("Failed to generate CSR with all EKU types");
    assert!(!all_eku_csr.to_der().is_empty(), "CSR with all EKU types should be generated");
    println!("✓ CSR generated successfully with all Extended Key Usage types combined");
}

#[test]
fn test_csr_with_custom_key() {
    use rcgen::KeyPair;
    
    // Generate a key pair first
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let key_pem = key_pair.serialize_pem();
    
    // Create a CSR using the custom key
    let csr = CsrBuilder::new()
        .subject("CN=custom-key.example.com")
        .expect("Failed to set subject")
        .with_key(&key_pem)
        .expect("Failed to set custom key")
        .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
        .build()
        .expect("Failed to generate CSR with custom key");
    
    // Verify the CSR was created
    assert!(!csr.to_der().is_empty(), "CSR with custom key should be generated");
    
    // Verify the private key matches the one we provided
    let csr_key_pem = csr.private_key_pem();
    assert_eq!(key_pem, csr_key_pem, "CSR private key should match the provided key");
    
    println!("✓ CSR generated successfully with custom key pair");
}

#[test]
fn test_csr_with_invalid_key_returns_error() {
    // Try to create a CSR with an invalid key
    let result = CsrBuilder::new()
        .subject("CN=invalid-key.example.com")
        .expect("Failed to set subject")
        .with_key("invalid key format");
    
    assert!(result.is_err(), "CSR with invalid key should return error");
    println!("✓ Invalid key correctly rejected");
}

#[test]
fn test_multiple_csrs_with_same_key() {
    use rcgen::KeyPair;
    
    // Generate a single key pair
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let key_pem = key_pair.serialize_pem();
    
    // Create two CSRs using the same key
    let csr1 = CsrBuilder::new()
        .subject("CN=first.example.com")
        .expect("Failed to set subject")
        .with_key(&key_pem)
        .expect("Failed to set custom key")
        .build()
        .expect("Failed to generate first CSR");
    
    let csr2 = CsrBuilder::new()
        .subject("CN=second.example.com")
        .expect("Failed to set subject")
        .with_key(&key_pem)
        .expect("Failed to set custom key")
        .build()
        .expect("Failed to generate second CSR");
    
    // Verify both CSRs were created
    assert!(!csr1.to_der().is_empty(), "First CSR should be generated");
    assert!(!csr2.to_der().is_empty(), "Second CSR should be generated");
    
    // Verify both CSRs use the same key
    assert_eq!(csr1.private_key_pem(), csr2.private_key_pem(), 
               "Both CSRs should use the same private key");
    
    println!("✓ Multiple CSRs created successfully with the same key pair");
}

#[test]
fn test_csr_with_path_len_constraint() {
    // Test intermediate CA CSR with path length constraint of 1
    let intermediate_csr = CsrBuilder::new()
        .subject("CN=Intermediate CA,O=Test Organization,OU=PKI,C=US")
        .expect("Failed to set subject")
        .is_ca(true)
        .path_len_constraint(1)
        .key_usage(KeyUsage::key_cert_sign() | KeyUsage::crl_sign())
        .build()
        .expect("Failed to generate intermediate CA CSR with path_len_constraint");
    
    // Verify CSR was generated
    let der = intermediate_csr.to_der();
    assert!(!der.is_empty(), "Intermediate CA CSR should be generated");
    
    // Parse and validate subject
    let parsed = parse_csr(&der);
    let subject = parsed.certification_request_info.subject;
    let cn = subject.iter_common_name().next().unwrap().as_str().unwrap();
    assert_eq!(cn, "Intermediate CA", "CN should match input");
    
    // Test leaf CA with path length constraint of 0 (no subordinate CAs)
    let leaf_ca_csr = CsrBuilder::new()
        .subject("CN=Leaf CA,O=Test Organization,C=US")
        .expect("Failed to set subject")
        .is_ca(true)
        .path_len_constraint(0)
        .key_usage(KeyUsage::key_cert_sign())
        .build()
        .expect("Failed to generate leaf CA CSR");
    
    assert!(!leaf_ca_csr.to_der().is_empty(), "Leaf CA CSR should be generated");
    
    println!("✓ CSRs with path_len_constraint generated successfully");
}

#[test]
fn test_csr_with_state_and_locality() {
    // Test CSR with State (ST) and Locality (L) DN components
    let csr_st = CsrBuilder::new()
        .subject("CN=Regional Server,ST=California,L=San Francisco,O=Tech Corp,C=US")
        .expect("Failed to set subject")
        .key_usage(KeyUsage::digital_signature() | KeyUsage::key_encipherment())
        .extended_key_usage(vec![ExtendedKeyUsage::SERVER_AUTH])
        .build()
        .expect("Failed to generate CSR with ST and L");
    
    // Parse and validate all DN components
    let parsed = parse_csr(csr_st.to_der());
    let subject = parsed.certification_request_info.subject;
    
    let cn = subject.iter_common_name().next().unwrap().as_str().unwrap();
    assert_eq!(cn, "Regional Server", "CN should match");
    
    let state = subject.iter_state_or_province().next().unwrap().as_str().unwrap();
    assert_eq!(state, "California", "State should match");
    
    let locality = subject.iter_locality().next().unwrap().as_str().unwrap();
    assert_eq!(locality, "San Francisco", "Locality should match");
    
    let org = subject.iter_organization().next().unwrap().as_str().unwrap();
    assert_eq!(org, "Tech Corp", "Organization should match");
    
    // Test with 'S' instead of 'ST'
    let csr_s = CsrBuilder::new()
        .subject("CN=Another Server,S=New York,L=Manhattan,O=Finance Corp,C=US")
        .expect("Failed to set subject")
        .build()
        .expect("Failed to generate CSR with S and L");
    
    let parsed_s = parse_csr(csr_s.to_der());
    let subject_s = parsed_s.certification_request_info.subject;
    
    let state_s = subject_s.iter_state_or_province().next().unwrap().as_str().unwrap();
    assert_eq!(state_s, "New York", "State (S) should match");
    
    let locality_s = subject_s.iter_locality().next().unwrap().as_str().unwrap();
    assert_eq!(locality_s, "Manhattan", "Locality should match");
    
    println!("✓ CSRs with State and Locality DN components validated successfully");
}

#[test]
fn test_csr_private_key_reference() {
    use rcgen::KeyPair;
    
    // Generate a CSR
    let csr = CsrBuilder::new()
        .subject("CN=key-reference-test.example.com")
        .expect("Failed to set subject")
        .build()
        .expect("Failed to generate CSR");
    
    // Get reference to the private key
    let key_ref = csr.private_key();
    
    // Verify we can use the reference to serialize the key
    let pem_from_ref = key_ref.serialize_pem();
    assert!(pem_from_ref.starts_with("-----BEGIN PRIVATE KEY-----"), 
            "Key from reference should serialize to valid PEM");
    
    // Verify it matches the direct method
    let pem_direct = csr.private_key_pem();
    assert_eq!(pem_from_ref, pem_direct, 
               "Key reference should provide same data as direct method");
    
    // Test DER format too
    let der_from_ref = key_ref.serialize_der();
    let der_direct = csr.private_key_der();
    assert_eq!(der_from_ref, der_direct, 
               "DER from reference should match direct access");
    
    // Verify we can create another key from the PEM and they're equivalent
    let key_pair_reconstructed = KeyPair::from_pem(&pem_from_ref)
        .expect("Should be able to reconstruct key from PEM");
    let reconstructed_pem = key_pair_reconstructed.serialize_pem();
    assert_eq!(pem_from_ref, reconstructed_pem, 
               "Reconstructed key should match original");
    
    println!("✓ private_key() reference method works correctly");
}