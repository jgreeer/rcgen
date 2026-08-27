# rcgen-symcrypt

A [`CryptoProvider`] for [rcgen] backed by Microsoft's [SymCrypt] cryptographic library.

It lets you generate X.509 certificates, CSRs, and CRLs with rcgen while performing the
underlying key generation, signing, and hashing with SymCrypt instead of the built-in
`ring` / `aws-lc-rs` backends.

## Usage

```rust
use rcgen::{generate_simple_self_signed_with_provider, CertifiedKey};
use rcgen_symcrypt::SymCryptProvider;

let CertifiedKey { cert, signing_key } = generate_simple_self_signed_with_provider(
    vec!["localhost".to_string()],
    &SymCryptProvider,
)?;
println!("{}", cert.pem());
```

`SymCryptProvider` plugs into any of rcgen's `*_with_provider` APIs, for example
`CertificateParams::self_signed_with_provider` and `signed_by_with_provider`.

Because the provider supplies all of the cryptography rcgen needs, you can depend on rcgen
with `default-features = false` — no `ring` or `aws-lc-rs` is compiled in.

## Requirements

`symcrypt` dynamically links the system `libsymcrypt`, which must be installed at **build
and run time**. See the [rust-symcrypt install guide][rust-symcrypt].

## Supported algorithms

| Algorithm | Status |
|---|---|
| ECDSA P-256 (`PKCS_ECDSA_P256_SHA256`) | ✅ |
| ECDSA P-384 (`PKCS_ECDSA_P384_SHA384`) | ✅ |
| Ed25519 | ❌ (SymCrypt has no Ed25519) |
| RSA / ECDSA P-521 | ❌ (not wired up yet) |

## License

Licensed under either of Apache-2.0 or MIT at your option.

[rcgen]: https://github.com/rustls/rcgen
[SymCrypt]: https://github.com/microsoft/SymCrypt
[rust-symcrypt]: https://github.com/microsoft/rust-symcrypt
[`CryptoProvider`]: https://docs.rs/rcgen/latest/rcgen/trait.CryptoProvider.html
