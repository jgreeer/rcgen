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

use pem::Pem;
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
		Ok(Box::new(SymCryptKeyPair::generate(alg)?))
	}

	fn load_key(
		&self,
		key: &PrivateKeyDer<'_>,
		alg: &'static SignatureAlgorithm,
	) -> Result<Box<dyn SigningKey>, Error> {
		Ok(Box::new(SymCryptKeyPair::from_der(key, alg)?))
	}
}

/// A SymCrypt ECDSA key pair together with the rcgen algorithm it signs with.
///
/// This is the SymCrypt analog of [`rcgen::KeyPair`]: a concrete, exportable key type. Use it
/// directly (rather than the boxed [`SigningKey`] a provider hands back) when you need the
/// generated private key — for example to hand the same key to rustls — via
/// [`serialize_der`](Self::serialize_der) or [`serialize_pem`](Self::serialize_pem).
///
/// [`SymCryptProvider`] produces these internally, erased as `Box<dyn SigningKey>`.
pub struct SymCryptKeyPair {
	key: EcKey,
	alg: &'static SignatureAlgorithm,
	/// SEC1 uncompressed point (`0x04 || X || Y`), as it appears in a SubjectPublicKeyInfo.
	spki_public_key: Vec<u8>,
	/// The key pair (including the private key) encoded as PKCS#8 DER.
	pkcs8_der: Vec<u8>,
}

impl SymCryptKeyPair {
	/// Generate a new SymCrypt key pair for `alg`.
	///
	/// Supports [`PKCS_ECDSA_P256_SHA256`] and [`PKCS_ECDSA_P384_SHA384`]; any other algorithm
	/// returns [`Error::KeyGenerationUnavailable`].
	pub fn generate(alg: &'static SignatureAlgorithm) -> Result<Self, Error> {
		let curve = curve_for(alg).ok_or(Error::KeyGenerationUnavailable)?;
		let key = EcKey::generate_key_pair(curve, EcKeyUsage::EcDsa)
			.map_err(|_| Error::KeyGenerationUnavailable)?;
		Self::new(key, alg)
	}

	/// Load a SymCrypt key pair from a PKCS#8 or SEC1 DER private key for `alg`.
	///
	/// Any algorithm other than [`PKCS_ECDSA_P256_SHA256`] / [`PKCS_ECDSA_P384_SHA384`], or a key
	/// that can't be parsed, returns [`Error::KeyLoadingUnavailable`].
	pub fn from_der(
		key: &PrivateKeyDer<'_>,
		alg: &'static SignatureAlgorithm,
	) -> Result<Self, Error> {
		let curve = curve_for(alg).ok_or(Error::KeyLoadingUnavailable)?;
		let scalar = ec_private_scalar(key).ok_or(Error::KeyLoadingUnavailable)?;
		let key = EcKey::set_key_pair(curve, &scalar, None, EcKeyUsage::EcDsa)
			.map_err(|_| Error::KeyLoadingUnavailable)?;
		Self::new(key, alg)
	}

	/// Serialize the key pair (including the private key) as PKCS#8 DER.
	///
	/// The result is a valid [`rustls_pki_types::PrivateKeyDer`] PKCS#8 document, so it can be
	/// handed straight to rustls, e.g. `PrivatePkcs8KeyDer::from(pair.serialize_der())`.
	pub fn serialize_der(&self) -> Vec<u8> {
		self.pkcs8_der.clone()
	}

	/// Serialize the key pair (including the private key) as PKCS#8 PEM (a `PRIVATE KEY` block).
	pub fn serialize_pem(&self) -> String {
		pem::encode(&Pem::new("PRIVATE KEY", self.pkcs8_der.clone()))
	}

	fn new(key: EcKey, alg: &'static SignatureAlgorithm) -> Result<Self, Error> {
		// SymCrypt exports the raw affine point `X || Y`; X.509 wants the SEC1 uncompressed
		// encoding, which prefixes `0x04`.
		let raw = key.export_public_key().map_err(|_| Error::RemoteKeyError)?;
		let mut spki_public_key = Vec::with_capacity(raw.len() + 1);
		spki_public_key.push(0x04);
		spki_public_key.extend_from_slice(&raw);

		// Cache the PKCS#8 encoding up front so `serialize_der`/`serialize_pem` stay cheap and
		// infallible, mirroring `rcgen::KeyPair`.
		let scalar = key
			.export_private_key()
			.map_err(|_| Error::RemoteKeyError)?;
		let pkcs8_der = ec_private_key_pkcs8_der(alg, &scalar, &spki_public_key);

		Ok(Self {
			key,
			alg,
			spki_public_key,
			pkcs8_der,
		})
	}
}

impl PublicKeyData for SymCryptKeyPair {
	fn der_bytes(&self) -> &[u8] {
		&self.spki_public_key
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.alg
	}
}

impl SigningKey for SymCryptKeyPair {
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
		let raw = self
			.key
			.ecdsa_sign(&digest)
			.map_err(|_| Error::RemoteKeyError)?;
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

/// DER-encoded OID for id-ecPublicKey (1.2.840.10045.2.1), tag and length included.
const OID_ID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// DER-encoded OID for the P-256 named curve, prime256v1 (1.2.840.10045.3.1.7).
const OID_NAMED_CURVE_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// DER-encoded OID for the P-384 named curve, secp384r1 (1.3.132.0.34).
const OID_NAMED_CURVE_P384: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

/// Encode an EC key pair as a PKCS#8 (RFC 5958) `PrivateKeyInfo` DER document.
///
/// `scalar` is the fixed-width private key; `sec1_public_key` is the `0x04 || X || Y` point.
fn ec_private_key_pkcs8_der(
	alg: &SignatureAlgorithm,
	scalar: &[u8],
	sec1_public_key: &[u8],
) -> Vec<u8> {
	// AlgorithmIdentifier ::= SEQUENCE { id-ecPublicKey, namedCurve }
	let mut algorithm = Vec::new();
	algorithm.extend_from_slice(OID_ID_EC_PUBLIC_KEY);
	algorithm.extend_from_slice(named_curve_oid(alg));
	let algorithm = der_tlv_encode(0x30, &algorithm);

	// ECPrivateKey ::= SEQUENCE { version(1), privateKey OCTET STRING, [1] publicKey BIT STRING }
	let mut public_key_bits = Vec::with_capacity(sec1_public_key.len() + 1);
	public_key_bits.push(0x00); // number of unused bits in the final byte
	public_key_bits.extend_from_slice(sec1_public_key);
	let mut ec_private_key = vec![0x02, 0x01, 0x01]; // INTEGER 1
	ec_private_key.extend(der_tlv_encode(0x04, scalar));
	ec_private_key.extend(der_tlv_encode(
		0xA1,
		&der_tlv_encode(0x03, &public_key_bits),
	)); // [1] BIT STRING
	let ec_private_key = der_tlv_encode(0x30, &ec_private_key);

	// PrivateKeyInfo ::= SEQUENCE { version(0), privateKeyAlgorithm, privateKey OCTET STRING }
	let mut private_key_info = vec![0x02, 0x01, 0x00]; // INTEGER 0
	private_key_info.extend(algorithm);
	private_key_info.extend(der_tlv_encode(0x04, &ec_private_key));
	der_tlv_encode(0x30, &private_key_info)
}

/// The DER-encoded named-curve OID for `alg` (only P-256/P-384 reach here).
fn named_curve_oid(alg: &SignatureAlgorithm) -> &'static [u8] {
	if alg == &PKCS_ECDSA_P384_SHA384 {
		OID_NAMED_CURVE_P384
	} else {
		OID_NAMED_CURVE_P256
	}
}

/// Encode a single DER TLV: `tag || length || contents`.
fn der_tlv_encode(tag: u8, contents: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(contents.len() + 4);
	out.push(tag);
	der_push_len(&mut out, contents.len());
	out.extend_from_slice(contents);
	out
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
		assert_eq!(
			der_integer(&[0x80, 0x01]),
			vec![0x02, 0x03, 0x00, 0x80, 0x01]
		);
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

	#[test]
	fn pkcs8_is_well_formed_and_preserves_scalar() {
		// A P-256-sized scalar and SEC1 uncompressed point (contents are arbitrary here; the
		// point is to check the PKCS#8 framing round-trips back through the scalar parser).
		let scalar = [0x11u8; 32];
		let mut public_key = vec![0x04];
		public_key.extend_from_slice(&[0x22u8; 64]);

		let der = ec_private_key_pkcs8_der(&PKCS_ECDSA_P256_SHA256, &scalar, &public_key);
		let parsed = ec_private_scalar(&PrivateKeyDer::Pkcs8(der.into())).expect("PKCS#8 parses");
		assert_eq!(parsed, scalar);
	}
}
