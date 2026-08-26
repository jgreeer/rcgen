use pki_types::PrivateKeyDer;

#[cfg(feature = "crypto")]
use crate::ring_like::digest;
use crate::{Error, SignatureAlgorithm, SigningKey};

/// A hash algorithm used by a [`CryptoProvider`] to derive key identifiers and
/// default serial numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
	/// SHA-256
	Sha256,
	/// SHA-384
	Sha384,
	/// SHA-512
	Sha512,
}

/// A pluggable cryptography backend.
///
/// A `CryptoProvider` supplies every cryptographic operation rcgen performs itself:
/// generating key pairs, loading key pairs from DER, and hashing public keys to derive
/// key identifiers and default serial numbers. Signing is performed by the
/// [`SigningKey`] values a provider produces (or that you supply directly), so a
/// provider and its keys together cover everything rcgen needs from a backend.
///
/// Only [`hash`](Self::hash) is required. [`generate_key`](Self::generate_key) and
/// [`load_key`](Self::load_key) default to returning an error, so a provider that only
/// needs to override hashing (for example alongside externally-provided keys) can
/// implement just `hash`.
///
/// When the `crypto` feature is enabled, [`DefaultCryptoProvider`] implements all of
/// these using the crate's built-in backend (`ring` or `aws-lc-rs`).
pub trait CryptoProvider {
	/// Compute the digest of `data` using `alg`.
	fn hash(&self, alg: HashAlgorithm, data: &[u8]) -> Vec<u8>;

	/// Generate a new key pair for the given signature algorithm.
	///
	/// Defaults to returning [`Error::KeyGenerationUnavailable`].
	fn generate_key(&self, alg: &'static SignatureAlgorithm) -> Result<Box<dyn SigningKey>, Error> {
		let _ = alg;
		Err(Error::KeyGenerationUnavailable)
	}

	/// Load a key pair from a DER-encoded private key, for the given signature algorithm.
	///
	/// Defaults to returning [`Error::KeyLoadingUnavailable`].
	fn load_key(
		&self,
		key: &PrivateKeyDer<'_>,
		alg: &'static SignatureAlgorithm,
	) -> Result<Box<dyn SigningKey>, Error> {
		let _ = (key, alg);
		Err(Error::KeyLoadingUnavailable)
	}
}

impl<P: CryptoProvider + ?Sized> CryptoProvider for &P {
	fn hash(&self, alg: HashAlgorithm, data: &[u8]) -> Vec<u8> {
		(*self).hash(alg, data)
	}

	fn generate_key(&self, alg: &'static SignatureAlgorithm) -> Result<Box<dyn SigningKey>, Error> {
		(*self).generate_key(alg)
	}

	fn load_key(
		&self,
		key: &PrivateKeyDer<'_>,
		alg: &'static SignatureAlgorithm,
	) -> Result<Box<dyn SigningKey>, Error> {
		(*self).load_key(key, alg)
	}
}

/// The built-in [`CryptoProvider`], backed by the crate's cryptography backend
/// (`ring` or `aws-lc-rs`).
///
/// This is the provider used by the convenience methods (such as
/// [`CertificateParams::self_signed`](crate::CertificateParams::self_signed)) that don't
/// take a provider explicitly.
#[cfg(feature = "crypto")]
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultCryptoProvider;

#[cfg(feature = "crypto")]
impl CryptoProvider for DefaultCryptoProvider {
	fn hash(&self, alg: HashAlgorithm, data: &[u8]) -> Vec<u8> {
		let algorithm = match alg {
			HashAlgorithm::Sha256 => &digest::SHA256,
			HashAlgorithm::Sha384 => &digest::SHA384,
			HashAlgorithm::Sha512 => &digest::SHA512,
		};
		digest::digest(algorithm, data).as_ref().to_vec()
	}

	fn generate_key(&self, alg: &'static SignatureAlgorithm) -> Result<Box<dyn SigningKey>, Error> {
		Ok(Box::new(crate::KeyPair::generate_for(alg)?))
	}

	fn load_key(
		&self,
		key: &PrivateKeyDer<'_>,
		alg: &'static SignatureAlgorithm,
	) -> Result<Box<dyn SigningKey>, Error> {
		Ok(Box::new(crate::KeyPair::from_der_and_sign_algo(key, alg)?))
	}
}
