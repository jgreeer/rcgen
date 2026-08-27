//! A [`CryptoProvider`] for [`rcgen`] backed by Microsoft's [SymCrypt] library.
//!
//! This crate lets you generate X.509 certificates, CSRs, and CRLs with `rcgen` while
//! performing all of the underlying cryptography with SymCrypt instead of the built-in
//! `ring`/`aws-lc-rs` backends. Pair it with `rcgen`'s `*_with_provider` APIs:
//!
//! ```no_run
//! use rcgen::{generate_simple_self_signed_with_provider, CertifiedKey};
//! use rcgen_symcrypt::SymCryptProvider;
//!
//! let CertifiedKey { cert, signing_key } = generate_simple_self_signed_with_provider(
//!     vec!["localhost".to_string()],
//!     &SymCryptProvider,
//! )
//! .unwrap();
//! # let _ = (cert, signing_key);
//! ```
//!
//! # Requirements
//!
//! `symcrypt` dynamically links the system `libsymcrypt`, which must be present at build
//! and run time. See the [rust-symcrypt] install guide.
//!
//! # Supported algorithms
//!
//! ECDSA P-256 ([`PKCS_ECDSA_P256_SHA256`]) and P-384 ([`PKCS_ECDSA_P384_SHA384`]).
//! SymCrypt has no Ed25519, so `PKCS_ED25519` is intentionally unsupported; RSA and
//! P-521 are not wired up here yet.
//!
//! [SymCrypt]: https://github.com/microsoft/SymCrypt
//! [rust-symcrypt]: https://github.com/microsoft/rust-symcrypt
//! [`PKCS_ECDSA_P256_SHA256`]: rcgen::PKCS_ECDSA_P256_SHA256
//! [`PKCS_ECDSA_P384_SHA384`]: rcgen::PKCS_ECDSA_P384_SHA384

use rcgen::{
	CryptoProvider, Error, HashAlgorithm, PublicKeyData, SignatureAlgorithm, SigningKey,
	PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
};
use rustls_pki_types::PrivateKeyDer;
use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
use symcrypt::hash::{sha256, sha384, sha512};

/// An [`rcgen::CryptoProvider`] that performs all cryptography with SymCrypt.
///
/// This is a zero-sized type; pass `&SymCryptProvider` to any of rcgen's
/// `*_with_provider` methods.
#[derive(Debug, Default, Clone, Copy)]
pub struct SymCryptProvider;

impl CryptoProvider for SymCryptProvider {
	fn hash(&self, alg: HashAlgorithm, data: &[u8]) -> Vec<u8> {
		match alg {
			HashAlgorithm::Sha256 => sha256(data).to_vec(),
			HashAlgorithm::Sha384 => sha384(data).to_vec(),
			HashAlgorithm::Sha512 => sha512(data).to_vec(),
			// `HashAlgorithm` is `#[non_exhaustive]`; rcgen only ever requests the above.
			_ => unimplemented!("unsupported hash algorithm: {alg:?}"),
		}
	}

	fn generate_key(&self, alg: &'static SignatureAlgorithm) -> Result<Box<dyn SigningKey>, Error> {
		let curve = curve_for(alg).ok_or(Error::KeyGenerationUnavailable)?;
		let key = EcKey::generate_key_pair(curve, EcKeyUsage::EcDsa)
			.map_err(|_| Error::KeyGenerationUnavailable)?;
		Ok(Box::new(SymCryptEcdsaKey::new(key, alg)?))
	}

	fn load_key(
		&self,
		key: &PrivateKeyDer<'_>,
		alg: &'static SignatureAlgorithm,
	) -> Result<Box<dyn SigningKey>, Error> {
		let curve = curve_for(alg).ok_or(Error::KeyLoadingUnavailable)?;
		let scalar = ec_private_scalar(key).ok_or(Error::KeyLoadingUnavailable)?;
		let key = EcKey::set_key_pair(curve, &scalar, None, EcKeyUsage::EcDsa)
			.map_err(|_| Error::KeyLoadingUnavailable)?;
		Ok(Box::new(SymCryptEcdsaKey::new(key, alg)?))
	}
}

/// A SymCrypt ECDSA key together with the rcgen algorithm it signs with.
struct SymCryptEcdsaKey {
	key: EcKey,
	alg: &'static SignatureAlgorithm,
	/// SEC1 uncompressed point (`0x04 || X || Y`), as it appears in a SubjectPublicKeyInfo.
	spki_public_key: Vec<u8>,
}

impl SymCryptEcdsaKey {
	fn new(key: EcKey, alg: &'static SignatureAlgorithm) -> Result<Self, Error> {
		// SymCrypt exports the raw affine point `X || Y`; X.509 wants the SEC1 uncompressed
		// encoding, which prefixes `0x04`.
		let raw = key.export_public_key().map_err(|_| Error::RemoteKeyError)?;
		let mut spki_public_key = Vec::with_capacity(raw.len() + 1);
		spki_public_key.push(0x04);
		spki_public_key.extend_from_slice(&raw);
		Ok(Self {
			key,
			alg,
			spki_public_key,
		})
	}
}

impl PublicKeyData for SymCryptEcdsaKey {
	fn der_bytes(&self) -> &[u8] {
		&self.spki_public_key
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.alg
	}
}

impl SigningKey for SymCryptEcdsaKey {
	fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
		let digest = if self.alg == &PKCS_ECDSA_P256_SHA256 {
			sha256(msg).to_vec()
		} else if self.alg == &PKCS_ECDSA_P384_SHA384 {
			sha384(msg).to_vec()
		} else {
			return Err(Error::RemoteKeyError);
		};

		// SymCrypt returns a fixed-width `r || s`; X.509 signatures are the ASN.1 DER
		// `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`.
		let raw = self.key.ecdsa_sign(&digest).map_err(|_| Error::RemoteKeyError)?;
		Ok(der_encode_ecdsa_signature(&raw))
	}
}

fn curve_for(alg: &SignatureAlgorithm) -> Option<CurveType> {
	if alg == &PKCS_ECDSA_P256_SHA256 {
		Some(CurveType::NistP256)
	} else if alg == &PKCS_ECDSA_P384_SHA384 {
		Some(CurveType::NistP384)
	} else {
		None
	}
}

/// DER-encode a fixed-width `r || s` ECDSA signature as `SEQUENCE { INTEGER r, INTEGER s }`.
fn der_encode_ecdsa_signature(raw: &[u8]) -> Vec<u8> {
	let (r, s) = raw.split_at(raw.len() / 2);
	let mut body = der_integer(r);
	body.extend(der_integer(s));

	let mut out = Vec::with_capacity(body.len() + 4);
	out.push(0x30); // SEQUENCE
	der_push_len(&mut out, body.len());
	out.extend(body);
	out
}

/// Encode `bytes` (a big-endian magnitude) as a DER positive `INTEGER`.
fn der_integer(bytes: &[u8]) -> Vec<u8> {
	// Trim leading zero bytes, keeping at least one byte.
	let mut start = 0;
	while start + 1 < bytes.len() && bytes[start] == 0 {
		start += 1;
	}
	let magnitude = &bytes[start..];

	let mut value = Vec::with_capacity(magnitude.len() + 1);
	// Prefix 0x00 so the high bit isn't read as a sign bit.
	if magnitude[0] & 0x80 != 0 {
		value.push(0x00);
	}
	value.extend_from_slice(magnitude);

	let mut out = Vec::with_capacity(value.len() + 2);
	out.push(0x02); // INTEGER
	der_push_len(&mut out, value.len());
	out.extend(value);
	out
}

/// Append a DER length (definite form) to `out`.
fn der_push_len(out: &mut Vec<u8>, len: usize) {
	if len < 0x80 {
		out.push(len as u8);
	} else {
		let mut tmp = Vec::new();
		let mut l = len;
		while l > 0 {
			tmp.push((l & 0xff) as u8);
			l >>= 8;
		}
		tmp.reverse();
		out.push(0x80 | tmp.len() as u8);
		out.extend(tmp);
	}
}

/// Extract the raw EC private scalar from a PKCS#8 or SEC1 DER private key.
fn ec_private_scalar(key: &PrivateKeyDer<'_>) -> Option<Vec<u8>> {
	match key {
		PrivateKeyDer::Sec1(k) => scalar_from_ec_private_key(k.secret_sec1_der()),
		PrivateKeyDer::Pkcs8(k) => {
			// PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm SEQUENCE, privateKey OCTET STRING }
			let seq = der_read(k.secret_pkcs8_der(), 0x30)?;
			let (_version, rest) = der_next(seq, 0x02)?;
			let (_alg, rest) = der_next(rest, 0x30)?;
			let (ec_private_key, _rest) = der_next(rest, 0x04)?;
			scalar_from_ec_private_key(ec_private_key)
		},
		_ => None,
	}
}

/// ECPrivateKey ::= SEQUENCE { version INTEGER, privateKey OCTET STRING, ... }
fn scalar_from_ec_private_key(der: &[u8]) -> Option<Vec<u8>> {
	let seq = der_read(der, 0x30)?;
	let (_version, rest) = der_next(seq, 0x02)?;
	let (scalar, _rest) = der_next(rest, 0x04)?;
	Some(scalar.to_vec())
}

/// Read one DER TLV, returning `(tag, value, remaining)`.
fn der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
	if input.len() < 2 {
		return None;
	}
	let tag = input[0];
	let first = input[1];
	let (len, header) = if first < 0x80 {
		(first as usize, 2)
	} else {
		let n = (first & 0x7f) as usize;
		if n == 0 || n > 4 || input.len() < 2 + n {
			return None;
		}
		let mut l = 0usize;
		for &b in &input[2..2 + n] {
			l = (l << 8) | b as usize;
		}
		(l, 2 + n)
	};
	let end = header.checked_add(len)?;
	if end > input.len() {
		return None;
	}
	Some((tag, &input[header..end], &input[end..]))
}

/// Read the value of the first TLV if it has `tag`.
fn der_read(input: &[u8], tag: u8) -> Option<&[u8]> {
	let (t, value, _rest) = der_tlv(input)?;
	(t == tag).then_some(value)
}

/// Read the value and remainder of the first TLV if it has `tag`.
fn der_next(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
	let (t, value, rest) = der_tlv(input)?;
	(t == tag).then_some((value, rest))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn der_integer_adds_sign_byte_when_high_bit_set() {
		assert_eq!(der_integer(&[0x80, 0x01]), vec![0x02, 0x03, 0x00, 0x80, 0x01]);
		assert_eq!(der_integer(&[0x7f, 0x01]), vec![0x02, 0x02, 0x7f, 0x01]);
		// Leading zeros are trimmed.
		assert_eq!(der_integer(&[0x00, 0x00, 0x2a]), vec![0x02, 0x01, 0x2a]);
	}

	#[test]
	fn der_encodes_ecdsa_signature_sequence() {
		// r = 0x01, s = 0x02 (2-byte raw signature).
		let sig = der_encode_ecdsa_signature(&[0x01, 0x02]);
		assert_eq!(sig, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
	}

	#[test]
	fn parses_sec1_scalar() {
		// SEQUENCE { INTEGER 1, OCTET STRING 0xdeadbeef }
		let der = [
			0x30, 0x09, 0x02, 0x01, 0x01, 0x04, 0x04, 0xde, 0xad, 0xbe, 0xef,
		];
		assert_eq!(
			scalar_from_ec_private_key(&der),
			Some(vec![0xde, 0xad, 0xbe, 0xef])
		);
	}
}
