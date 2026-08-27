//! Generate a self-signed certificate whose key generation, signing, and hashing all run
//! on SymCrypt.
//!
//! Run with `cargo run --example self_signed` (requires `libsymcrypt` installed).

use rcgen::{generate_simple_self_signed_with_provider, CertifiedKey};
use rcgen_symcrypt::SymCryptProvider;

fn main() {
	let CertifiedKey { cert, signing_key: _ } = generate_simple_self_signed_with_provider(
		vec!["localhost".to_string(), "example.com".to_string()],
		&SymCryptProvider,
	)
	.expect("generate a self-signed certificate with SymCrypt");

	println!("{}", cert.pem());
}
