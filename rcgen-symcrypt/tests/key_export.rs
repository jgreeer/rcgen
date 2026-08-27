//! End-to-end test of SymCrypt private-key export: generate a key, serialize it to PKCS#8,
//! reload it through the provider, and confirm the reloaded key matches and can issue a cert.
//!
//! Requires `libsymcrypt` at run time.

use rcgen::{CertificateParams, PublicKeyData, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384};
use rcgen_symcrypt::{SymCryptKeyPair, SymCryptProvider};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

#[test]
fn generated_key_exports_and_reloads() {
	for alg in [&PKCS_ECDSA_P256_SHA256, &PKCS_ECDSA_P384_SHA384] {
		let key = SymCryptKeyPair::generate(alg).expect("generate key pair");

		// Export to PKCS#8 DER and reload it through the provider's loader.
		let der = key.serialize_der();
		let reloaded = SymCryptKeyPair::from_der(
			&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.clone())),
			alg,
		)
		.expect("reload exported key");

		// The reloaded key derives the same public key, proving the private scalar survived the
		// PKCS#8 round-trip (SymCrypt re-derives the public key from the reloaded private key).
		assert_eq!(key.der_bytes(), reloaded.der_bytes());

		// The exported PEM is a PKCS#8 `PRIVATE KEY` block.
		let pem = key.serialize_pem();
		assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
		assert!(pem.contains("-----END PRIVATE KEY-----"));

		// The reloaded key can still issue a certificate through SymCrypt.
		let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
		params
			.self_signed_with_provider(&reloaded, &SymCryptProvider)
			.expect("self-sign with the reloaded key");
	}
}
