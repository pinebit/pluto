//! # BLST implementation
//!
//! Implementation of threshold BLS signatures using the blst library.
//! This implementation is compatible with the Herumi BLS library used in the Go
//! implementation.

use std::collections::HashMap;

use blst::{
    BLST_ERROR,
    min_pk::{PublicKey as BlstPublicKey, SecretKey as BlstSecretKey, Signature as BlstSignature},
};
use rand_core::{CryptoRng, RngCore};

use crypto_primitives::{crypto_bigint_const_monty::F256, crypto_bigint_uint::Uint};
use num_traits::identities::One;

use crate::{
    tbls::Tbls,
    types::{BlsError, Error, Index, MathError, PrivateKey, PublicKey, Signature},
};

/// Domain Separation Tag for Ethereum 2.0 BLS signatures
const ETH2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

// NOTE(alex): Here we're using crypto-bigint backend, but ark-ff is also
// supported
crypto_bigint::const_monty_params!(
    Bls12_381r,
    crypto_bigint::U256,
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
);

type F = F256<Bls12_381r>;

fn to_f(value: &blst::blst_scalar) -> F {
    let int = Uint::new(crypto_bigint::Uint::from_le_slice(&value.b));
    F::from(int)
}

fn from_f(value: &F) -> blst::blst_scalar {
    let b = value.inner().retrieve().to_le_bytes();
    blst::blst_scalar { b }
}

/// BLST implementation of threshold BLS signatures.
///
/// This implementation is compatible with the Herumi BLS library used in
/// the Go implementation of Charon.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct BlstImpl;

impl Tbls for BlstImpl {
    fn generate_secret_key(&self, mut rng: impl RngCore + CryptoRng) -> Result<PrivateKey, Error> {
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let sk = BlstSecretKey::key_gen(&ikm, &[])
            .map_err(|_| Error::InvalidSecretKey(BlsError::KeyGeneration))?;

        Ok(sk.to_bytes())
    }

    fn generate_insecure_secret(
        &self,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<PrivateKey, Error> {
        // For insecure/test key generation, we just use random bytes directly
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        // Validate it's a valid secret key
        let _ = BlstSecretKey::from_bytes(&bytes)?;

        Ok(bytes)
    }

    fn secret_to_public_key(&self, secret_key: &PrivateKey) -> Result<PublicKey, Error> {
        let sk = BlstSecretKey::from_bytes(secret_key)?;
        let pk = sk.sk_to_pk();
        Ok(pk.to_bytes())
    }

    fn threshold_split_insecure(
        &self,
        secret_key: &PrivateKey,
        total: Index,
        threshold: Index,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<HashMap<Index, PrivateKey>, Error> {
        if threshold <= 1 || threshold > total {
            return Err(Error::InvalidThreshold { threshold, total });
        }

        let sk = BlstSecretKey::from_bytes(secret_key)?;
        let sk = to_f((&sk).into());

        // Create polynomial coefficients: a_0 = secret, a_1..a_{t-1} = random
        let mut poly = Vec::with_capacity(threshold as usize);
        poly.push(sk);

        for _ in 1..threshold {
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);
            let coeff = BlstSecretKey::key_gen(&ikm, &[])
                .map_err(|_| Error::InvalidSecretKey(BlsError::KeyGeneration))?;
            poly.push(to_f((&coeff).into()));
        }

        // Evaluate polynomial at points 1..total to create shares
        let mut shares = HashMap::new();
        for i in 1..=total {
            let share = evaluate_polynomial(&poly, i)?;
            let share = from_f(&share);
            let share: &BlstSecretKey = (&share).try_into()?;
            shares.insert(
                i.checked_sub(1).ok_or(MathError::IntegerUnderflow)?,
                share.to_bytes(),
            );
        }

        Ok(shares)
    }

    fn threshold_split(
        &self,
        secret_key: &PrivateKey,
        total: Index,
        threshold: Index,
    ) -> Result<HashMap<Index, PrivateKey>, Error> {
        // Use OsRng for secure random number generation
        use rand::rngs::OsRng;
        self.threshold_split_insecure(secret_key, total, threshold, OsRng)
    }

    fn recover_secret(&self, shares: HashMap<Index, PrivateKey>) -> Result<PrivateKey, Error> {
        if shares.is_empty() {
            return Err(Error::InvalidThreshold {
                threshold: 0,
                total: 0,
            });
        }

        // Convert share indices to 1-indexed (shares are stored 0-indexed, but
        // evaluated at 1-indexed points)
        let share_points: Vec<Index> = shares
            .keys()
            .map(|&k| k.checked_add(1).ok_or(MathError::IntegerOverflow))
            .collect::<Result<Vec<_>, _>>()?;

        let share_secrets: Vec<F> = shares
            .values()
            .map(|bytes| {
                BlstSecretKey::from_bytes(bytes).map_err(|e| Error::InvalidSecretKey(e.into()))
            })
            .map(|sk_res| sk_res.map(|sk| to_f((&sk).into())))
            .collect::<Result<Vec<_>, _>>()?;

        // Lagrange interpolation at x=0
        let recovered = lagrange_interpolate_secret(&share_points, &share_secrets)?;
        let recovered = from_f(&recovered);
        let recovered: &BlstSecretKey = (&recovered).try_into()?;
        Ok(recovered.to_bytes())
    }

    fn aggregate(&self, signatures: Vec<Signature>) -> Result<Signature, Error> {
        if signatures.is_empty() {
            return Err(Error::EmptySignatureArray);
        }

        if signatures.len() == 1 {
            return Ok(signatures[0]);
        }

        // Use blst's aggregation
        let parsed_sigs: Vec<BlstSignature> = signatures
            .iter()
            .map(|sig_bytes| {
                BlstSignature::from_bytes(sig_bytes).map_err(|e| Error::InvalidSignature(e.into()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let sigs: Vec<&BlstSignature> = parsed_sigs.iter().collect();

        let agg = blst::min_pk::AggregateSignature::aggregate(&sigs[..], true)
            .map_err(|e| Error::AggregationFailed(e.into()))?;

        Ok(signature_to_bytes(&agg.to_signature()))
    }

    fn threshold_aggregate(
        &self,
        partial_signatures_by_idx: HashMap<Index, Signature>,
    ) -> Result<Signature, Error> {
        if partial_signatures_by_idx.is_empty() {
            return Err(Error::EmptySignatureArray);
        }

        // Convert indices to 1-indexed points (shares are 0-indexed, evaluated at
        // 1-indexed points)
        let indices: Vec<Index> = partial_signatures_by_idx
            .keys()
            .map(|&k| k.checked_add(1).ok_or(MathError::IntegerOverflow))
            .collect::<Result<Vec<_>, _>>()?;

        let signatures: Vec<BlstSignature> = partial_signatures_by_idx
            .values()
            .map(|sig_bytes| {
                BlstSignature::from_bytes(sig_bytes).map_err(|e| Error::InvalidSignature(e.into()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Perform Lagrange interpolation on signatures at x=0
        let recovered_sig = lagrange_interpolate_signature(&indices, &signatures)?;
        Ok(signature_to_bytes(&recovered_sig))
    }

    fn verify(
        &self,
        public_key: &PublicKey,
        data: &[u8],
        raw_signature: &Signature,
    ) -> Result<(), Error> {
        let pk =
            BlstPublicKey::from_bytes(public_key).map_err(|e| Error::InvalidPublicKey(e.into()))?;

        let sig = BlstSignature::from_bytes(raw_signature)
            .map_err(|e| Error::InvalidSignature(e.into()))?;

        let result = sig.verify(true, data, ETH2_DST, &[], &pk, true);

        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(Error::VerificationFailed(result.into()))
        }
    }

    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Signature, Error> {
        let sk = BlstSecretKey::from_bytes(private_key)?;
        let sig = sk.sign(data, ETH2_DST, &[]);
        Ok(signature_to_bytes(&sig))
    }

    fn verify_aggregate(
        &self,
        public_keys: Vec<PublicKey>,
        signature: Signature,
        data: &[u8],
    ) -> Result<(), Error> {
        if public_keys.is_empty() {
            return Err(Error::EmptySignatureArray);
        }

        let pks: Vec<BlstPublicKey> = public_keys
            .iter()
            .map(|pk_bytes| {
                BlstPublicKey::from_bytes(pk_bytes).map_err(|e| Error::InvalidPublicKey(e.into()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let sig =
            BlstSignature::from_bytes(&signature).map_err(|e| Error::InvalidSignature(e.into()))?;

        // Aggregate public keys using blst point addition
        let agg_pk = aggregate_public_keys(&pks)?;

        let result = sig.verify(true, data, ETH2_DST, &[], &agg_pk, true);

        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(Error::VerificationFailed(result.into()))
        }
    }
}

/// Aggregate public keys
fn aggregate_public_keys(pks: &[BlstPublicKey]) -> Result<BlstPublicKey, Error> {
    if pks.is_empty() {
        return Err(Error::EmptySignatureArray);
    }

    let mut agg = blst::blst_p1::default();

    unsafe {
        // Convert first key to projective form
        let first_compressed = pks[0].compress();
        let mut first_affine = blst::blst_p1_affine::default();
        blst::blst_p1_uncompress(&mut first_affine, first_compressed.as_ptr());
        blst::blst_p1_from_affine(&mut agg, &first_affine);

        for pk in pks.iter().skip(1) {
            let compressed = pk.compress();
            let mut pk_affine = blst::blst_p1_affine::default();
            blst::blst_p1_uncompress(&mut pk_affine, compressed.as_ptr());
            blst::blst_p1_add_or_double_affine(&mut agg, &agg, &pk_affine);
        }

        // Convert back to affine
        let mut agg_affine = blst::blst_p1_affine::default();
        blst::blst_p1_to_affine(&mut agg_affine, &agg);
        Ok(BlstPublicKey::from(agg_affine))
    }
}

/// Evaluate polynomial at point x
/// poly(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n
#[allow(clippy::arithmetic_side_effects)] // Field arithmetic cannot overflow
fn evaluate_polynomial(poly: &[F], x: Index) -> Result<F, Error> {
    if poly.is_empty() {
        return Err(Error::InvalidThreshold {
            threshold: 0,
            total: 0,
        });
    }
    let x = F::from(x);

    // Start with the constant term
    let mut result = poly[0];

    // Compute powers of x and accumulate
    let mut x_power = x;

    for coeff in poly.iter().skip(1) {
        result += coeff * x_power;

        // x_power *= x for next iteration
        if poly.len() > 2 {
            x_power *= x;
        }
    }

    Ok(result)
}

/// Lagrange interpolation of secret keys at x=0
/// Recovers f(0) from points (x_i, y_i) where y_i are secret keys
#[allow(clippy::arithmetic_side_effects)] // Field arithmetic cannot overflow
fn lagrange_interpolate_secret(indices: &[Index], shares: &[F]) -> Result<F, Error> {
    if indices.len() != shares.len() || indices.is_empty() {
        return Err(Error::InvalidThreshold {
            threshold: 0,
            total: 0,
        });
    }

    // Compute Lagrange coefficients and interpolate
    let coeffs = compute_lagrange_coefficients(indices)?;

    let result = shares
        .iter()
        .zip(coeffs.iter())
        .map(|(share, coeff)| share * coeff)
        .sum();

    Ok(result)
}

/// Lagrange interpolation of signatures at x=0
/// Recovers f(0) from points (x_i, σ_i) where σ_i are signatures
fn lagrange_interpolate_signature(
    indices: &[Index],
    signatures: &[BlstSignature],
) -> Result<BlstSignature, Error> {
    if indices.len() != signatures.len() || indices.is_empty() {
        return Err(Error::EmptySignatureArray);
    }

    // Compute Lagrange coefficients
    let coeffs = compute_lagrange_coefficients(indices)?;
    let coeffs = coeffs.iter().map(from_f).collect::<Vec<_>>();

    // Multiply each signature by its Lagrange coefficient and aggregate
    let first_sig_scaled = signature_mult(&signatures[0], &coeffs[0])?;
    let mut result_p2 = blst::blst_p2::default();

    unsafe {
        // Convert first scaled signature to projective
        let first_compressed = first_sig_scaled.compress();
        let mut first_affine = blst::blst_p2_affine::default();
        blst::blst_p2_uncompress(&mut first_affine, first_compressed.as_ptr());
        blst::blst_p2_from_affine(&mut result_p2, &first_affine);

        for i in 1..signatures.len() {
            let sig_scaled = signature_mult(&signatures[i], &coeffs[i])?;
            let compressed = sig_scaled.compress();
            let mut sig_affine = blst::blst_p2_affine::default();
            blst::blst_p2_uncompress(&mut sig_affine, compressed.as_ptr());
            blst::blst_p2_add_or_double_affine(&mut result_p2, &result_p2, &sig_affine);
        }

        // Convert back to affine
        let mut result_affine = blst::blst_p2_affine::default();
        blst::blst_p2_to_affine(&mut result_affine, &result_p2);
        Ok(BlstSignature::from(result_affine))
    }
}

/// Compute Lagrange coefficients for interpolation at x=0
/// λ_i = ∏_{j≠i} (0 - x_j) / (x_i - x_j) = ∏_{j≠i} x_j / (x_j - x_i)
#[allow(clippy::arithmetic_side_effects)] // Field arithmetic cannot overflow
fn compute_lagrange_coefficients(indices: &[Index]) -> Result<Vec<F>, Error> {
    let mut coeffs = Vec::with_capacity(indices.len());

    for (i, &x_i) in indices.iter().enumerate() {
        let mut numerator = F::one();
        let mut denominator = F::one();

        for (j, &x_j) in indices.iter().enumerate() {
            if i == j {
                continue;
            }

            numerator *= F::from(x_j);

            // denominator *= (x_j - x_i)
            let mut diff = F::from(x_i.abs_diff(x_j));
            if x_j < x_i {
                diff = -diff;
            };

            denominator *= diff;
        }

        // Compute numerator / denominator = numerator * denominator^{-1}
        let coeff = numerator / denominator;
        coeffs.push(coeff);
    }

    Ok(coeffs)
}

/// Multiply signature by scalar
fn signature_mult(sig: &BlstSignature, scalar: &blst::blst_scalar) -> Result<BlstSignature, Error> {
    let compressed = sig.compress();
    let mut sig_proj = blst::blst_p2::default();
    let mut result_p2 = blst::blst_p2::default();
    let mut result_affine = blst::blst_p2_affine::default();

    unsafe {
        let mut sig_affine = blst::blst_p2_affine::default();
        blst::blst_p2_uncompress(&mut sig_affine, compressed.as_ptr());
        // Convert affine to projective
        blst::blst_p2_from_affine(&mut sig_proj, &sig_affine);
        // Multiply
        blst::blst_p2_mult(&mut result_p2, &sig_proj, scalar.b.as_ptr(), 255);
        // Convert back to affine
        blst::blst_p2_to_affine(&mut result_affine, &result_p2);
    }

    Ok(BlstSignature::from(result_affine))
}

/// Convert signature to bytes
fn signature_to_bytes(sig: &BlstSignature) -> Signature {
    sig.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> BlstImpl {
        BlstImpl
    }

    #[test]
    fn test_verify_aggregate_from_data() {
        let blst = setup();
        let data = b"hello obol!";

        // Decode the secret key from hex
        let secret_bytes =
            hex::decode("7356c7dab0220088158a8bba45894b164c04cf7de83149e2c4fab381e765ff38")
                .unwrap();
        assert_eq!(secret_bytes.len(), 32);

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);
        assert!(!secret.is_empty());

        // Split the secret into shares (total=5, threshold=3)
        let shares = blst.threshold_split(&secret, 5, 3).unwrap();
        assert_eq!(shares.len(), 5);

        // Create signatures for each share
        let mut signatures = HashMap::new();
        for (idx, key) in shares.iter() {
            let signature = blst.sign(key, data).unwrap();
            signatures.insert(*idx, signature);
        }

        // Aggregate the threshold signatures
        let total_sig = blst.threshold_aggregate(signatures).unwrap();

        // Expected signature from the Go implementation
        let expected_sig = hex::decode("b46736c3a1fb5d7977acc6abf3cb3a10fd1a5aed301437022f28cf616326186654d747fda7cd530c2bf18c640e4c024b01d7ba38d90e4abe0cc5356ef63b8e20f717ef0a1f68c3292bd62b4f891345ecafa89a8604f8f6c3ce193dc239215adf").unwrap();

        // Compare the aggregated signature with the expected one
        assert_eq!(
            expected_sig,
            &total_sig[..],
            "Aggregated signature does not match expected signature from Go implementation"
        );
    }

    #[test]
    fn test_generate_and_derive_key() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();
        assert_eq!(sk.len(), 32);

        let pk = blst.secret_to_public_key(&sk).unwrap();
        assert_eq!(pk.len(), 48);
    }

    #[test]
    fn test_sign_and_verify() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();
        let pk = blst.secret_to_public_key(&sk).unwrap();
        let data = b"test message";

        let sig = blst.sign(&sk, data).unwrap();
        assert_eq!(sig.len(), 96);

        let result = blst.verify(&pk, data, &sig);
        assert!(result.is_ok());
    }

    #[test]
    fn test_threshold_split_and_recover() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();
        let threshold = 3;
        let total = 5;

        let shares = blst.threshold_split(&sk, total, threshold).unwrap();
        assert_eq!(shares.len(), total as usize);

        // Take exactly threshold shares
        let subset: HashMap<Index, PrivateKey> = shares
            .iter()
            .take(threshold as usize)
            .map(|(k, v)| (*k, *v))
            .collect();

        let recovered_sk = blst.recover_secret(subset).unwrap();
        assert_eq!(sk, recovered_sk);
    }

    #[test]
    fn test_recover_secret_with_all_shares() {
        use rand::rngs::OsRng;

        let blst = setup();
        let secret = blst.generate_secret_key(OsRng).unwrap();
        let threshold = 3;
        let total = 5;

        let shares = blst.threshold_split(&secret, total, threshold).unwrap();
        assert_eq!(shares.len(), total as usize);

        // Recover using all shares
        let recovered = blst.recover_secret(shares).unwrap();
        assert_eq!(
            secret, recovered,
            "Secret recovered from all shares should match original"
        );
    }

    #[test]
    fn test_threshold_aggregate_matches_direct_sign() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"hello obol!";

        let secret = blst.generate_secret_key(OsRng).unwrap();

        // Sign directly with the secret
        let direct_sig = blst.sign(&secret, data).unwrap();

        // Split into shares and sign with each
        let shares = blst.threshold_split(&secret, 5, 3).unwrap();
        let mut signatures = HashMap::new();
        for (idx, key) in shares.iter() {
            let signature = blst.sign(key, data).unwrap();
            signatures.insert(*idx, signature);
        }

        // Aggregate threshold signatures
        let aggregated_sig = blst.threshold_aggregate(signatures).unwrap();

        // Both signatures should be identical
        assert_eq!(
            direct_sig, aggregated_sig,
            "Threshold aggregated signature should match direct signature"
        );
    }

    #[test]
    fn test_verify_with_correct_signature() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"hello obol!";

        let secret = blst.generate_secret_key(OsRng).unwrap();
        let pubkey = blst.secret_to_public_key(&secret).unwrap();
        let signature = blst.sign(&secret, data).unwrap();

        let result = blst.verify(&pubkey, data, &signature);
        assert!(
            result.is_ok(),
            "Verification should succeed with correct signature"
        );
    }

    #[test]
    fn test_verify_fails_with_wrong_message() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data1 = b"hello obol!";
        let data2 = b"goodbye obol!";

        let secret = blst.generate_secret_key(OsRng).unwrap();
        let pubkey = blst.secret_to_public_key(&secret).unwrap();
        let signature = blst.sign(&secret, data1).unwrap();

        let result = blst.verify(&pubkey, data2, &signature);
        assert!(
            result.is_err(),
            "Verification should fail with wrong message"
        );
    }

    #[test]
    fn test_verify_fails_with_wrong_public_key() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"hello obol!";

        let secret1 = blst.generate_secret_key(OsRng).unwrap();
        let secret2 = blst.generate_secret_key(OsRng).unwrap();
        let pubkey2 = blst.secret_to_public_key(&secret2).unwrap();
        let signature1 = blst.sign(&secret1, data).unwrap();

        let result = blst.verify(&pubkey2, data, &signature1);
        assert!(
            result.is_err(),
            "Verification should fail with wrong public key"
        );
    }

    #[test]
    fn test_verify_aggregate_success() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"hello obol!";

        // Generate 10 key pairs
        let mut keys = Vec::new();
        for _ in 0..10 {
            let secret = blst.generate_secret_key(OsRng).unwrap();
            let pubkey = blst.secret_to_public_key(&secret).unwrap();
            keys.push((secret, pubkey));
        }

        // Sign with each key
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        for (secret, pubkey) in &keys {
            let sig = blst.sign(secret, data).unwrap();
            signatures.push(sig);
            public_keys.push(*pubkey);
        }

        // Aggregate signatures
        let aggregated_sig = blst.aggregate(signatures).unwrap();

        // Verify aggregate
        let result = blst.verify_aggregate(public_keys, aggregated_sig, data);
        assert!(result.is_ok(), "Aggregate verification should succeed");
    }

    #[test]
    fn test_verify_aggregate_fails_with_wrong_data() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data1 = b"hello obol!";
        let data2 = b"goodbye obol!";

        // Generate 5 key pairs
        let mut keys = Vec::new();
        for _ in 0..5 {
            let secret = blst.generate_secret_key(OsRng).unwrap();
            let pubkey = blst.secret_to_public_key(&secret).unwrap();
            keys.push((secret, pubkey));
        }

        // Sign with each key using data1
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        for (secret, pubkey) in &keys {
            let sig = blst.sign(secret, data1).unwrap();
            signatures.push(sig);
            public_keys.push(*pubkey);
        }

        // Aggregate signatures
        let aggregated_sig = blst.aggregate(signatures).unwrap();

        // Verify with data2 (wrong data)
        let result = blst.verify_aggregate(public_keys, aggregated_sig, data2);
        assert!(
            result.is_err(),
            "Aggregate verification should fail with wrong data"
        );
    }

    #[test]
    fn test_aggregate_single_signature() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"test message";

        let sk = blst.generate_secret_key(OsRng).unwrap();
        let sig = blst.sign(&sk, data).unwrap();

        let aggregated = blst.aggregate(vec![sig]).unwrap();
        assert_eq!(
            sig, aggregated,
            "Aggregating single signature should return the same signature"
        );
    }

    #[test]
    fn test_aggregate_multiple_signatures() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"test message";

        // Generate 3 signatures
        let mut signatures = Vec::new();
        for _ in 0..3 {
            let sk = blst.generate_secret_key(OsRng).unwrap();
            let sig = blst.sign(&sk, data).unwrap();
            signatures.push(sig);
        }

        let aggregated = blst.aggregate(signatures).unwrap();
        assert_eq!(
            aggregated.len(),
            96,
            "Aggregated signature should be 96 bytes"
        );
    }

    #[test]
    fn test_threshold_split_minimum_threshold() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();

        // Minimum valid threshold is 2
        let shares = blst.threshold_split(&sk, 3, 2).unwrap();
        assert_eq!(shares.len(), 3);

        // Recover with exactly 2 shares
        let subset: HashMap<Index, PrivateKey> =
            shares.iter().take(2).map(|(k, v)| (*k, *v)).collect();

        let recovered = blst.recover_secret(subset).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_threshold_split_invalid_threshold() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();

        // Threshold of 1 is invalid
        let result = blst.threshold_split(&sk, 5, 1);
        assert!(result.is_err(), "Threshold of 1 should be rejected");

        // Threshold greater than total is invalid
        let result = blst.threshold_split(&sk, 3, 5);
        assert!(result.is_err(), "Threshold > total should be rejected");
    }

    #[test]
    fn test_different_keys_produce_different_signatures() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"test message";

        let sk1 = blst.generate_secret_key(OsRng).unwrap();
        let sk2 = blst.generate_secret_key(OsRng).unwrap();

        let sig1 = blst.sign(&sk1, data).unwrap();
        let sig2 = blst.sign(&sk2, data).unwrap();

        assert_ne!(
            sig1, sig2,
            "Different keys should produce different signatures"
        );
    }

    #[test]
    fn test_same_key_produces_same_signature() {
        use rand::rngs::OsRng;

        let blst = setup();
        let data = b"test message";

        let sk = blst.generate_secret_key(OsRng).unwrap();

        let sig1 = blst.sign(&sk, data).unwrap();
        let sig2 = blst.sign(&sk, data).unwrap();

        assert_eq!(
            sig1, sig2,
            "Same key should produce same signature for same data"
        );
    }

    #[test]
    fn test_empty_aggregate_fails() {
        let blst = setup();

        let result = blst.aggregate(vec![]);
        assert!(
            result.is_err(),
            "Aggregating empty signature list should fail"
        );
    }

    #[test]
    fn test_public_key_is_deterministic() {
        use rand::rngs::OsRng;

        let blst = setup();
        let sk = blst.generate_secret_key(OsRng).unwrap();

        let pk1 = blst.secret_to_public_key(&sk).unwrap();
        let pk2 = blst.secret_to_public_key(&sk).unwrap();

        assert_eq!(pk1, pk2, "Public key derivation should be deterministic");
    }

    #[test]
    fn test_different_secrets_produce_different_public_keys() {
        use rand::rngs::OsRng;

        let blst = setup();

        let sk1 = blst.generate_secret_key(OsRng).unwrap();
        let sk2 = blst.generate_secret_key(OsRng).unwrap();

        let pk1 = blst.secret_to_public_key(&sk1).unwrap();
        let pk2 = blst.secret_to_public_key(&sk2).unwrap();

        assert_ne!(
            pk1, pk2,
            "Different secrets should produce different public keys"
        );
    }
}
