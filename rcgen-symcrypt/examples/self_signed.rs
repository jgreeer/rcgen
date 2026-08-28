//! Generate a self-signed certificate whose key generation, signing, and hashing all run
//! on SymCrypt, then export the private key as PKCS#8 PEM.
//!
//! Run with `cargo run --example self_signed` (requires `libsymcrypt` installed).

use rcgen::{CertificateParams, ExportableKey, PKCS_ECDSA_P256_SHA256};
use rcgen_symcrypt::{SymCryptKeyPair, SymCryptProvider};

fn main() {
	// Generate the key pair with SymCrypt. `SymCryptKeyPair` is concrete (unlike the boxed
	// `SigningKey` a provider hands back), so its private key can be exported.
	let key = SymCryptKeyPair::generate(&PKCS_ECDSA_P256_SHA256)
		.expect("generate a P-256 key pair with SymCrypt");

	let params = CertificateParams::new(vec!["localhost".to_string(), "example.com".to_string()])
		.expect("valid subject alt names");
	let cert = params
		.self_signed_with_provider(&key, &SymCryptProvider)
		.expect("self-sign the certificate with SymCrypt");

	println!("{}", cert.pem());
	// Export the private key too — e.g. to hand the same key to rustls.
	print!("{}", key.serialize_pem());
}
