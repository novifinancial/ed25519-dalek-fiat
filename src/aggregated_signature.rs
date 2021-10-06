//! Non-Interactive Aggregate Signatures

use crate::{errors::*, public::*, signature::*};
use curve25519_dalek::constants;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use ed25519::Signature;

use sha2::{
    digest::generic_array::typenum::U64, digest::generic_array::GenericArray, Sha256, Sha512,
};
use std::convert::TryFrom;
use std::vec::Vec;

/// Size of the random Scalars used in aggregation
pub enum ScalarSize {
    /// 128 bits
    Half,
    /// 256 bits
    Full,
    /// 512 bits
    Double,
}

/// Aggregated Signature Method 1 (Fiat-Shamir based)
#[derive(Clone, Debug)]
pub struct AggregatedSignature {
    pub(crate) r_terms: Vec<CompressedEdwardsY>,
    pub(crate) s: Scalar,
}

#[inline]
fn set_initial_hash<'a, D: sha2::Digest>(hrams: &Vec<GenericArray<u8, U64>>) -> D {
    let mut h: D = D::new();
    for bits in hrams {
        h.update(&bits);
    }
    h
}

#[inline]
fn compute_hrams<'a>(
    m_k: &[(&[u8], &PublicKey)],
    sigs: impl Iterator<Item = &'a CompressedEdwardsY>,
) -> Vec<GenericArray<u8, U64>> {
    let mut h: Sha512 = Sha512::default();
    // Compute H(R || A || M) for each (signature, public_key, message) triplet
    sigs.enumerate()
        .map(|(i, sig)| {
            h.update(sig.as_bytes());
            h.update(m_k[i].1.as_bytes());
            h.update(&m_k[i].0);
            h.finalize_reset()
        })
        .collect()
}

impl AggregatedSignature {
    /// Aggregate from individual signatures
    pub fn aggregate(
        msg_and_keys: &[(&[u8], &PublicKey)],
        sigs: &[Signature],
        scalar_size: ScalarSize,
    ) -> Result<AggregatedSignature, SignatureError> {
        let signatures = check_slice_size(sigs, msg_and_keys.len(), "sigs")?
            .iter()
            .map(InternalSignature::try_from)
            .collect::<Result<Vec<InternalSignature>, _>>()?;

        let raw_hrams = compute_hrams(msg_and_keys, signatures.iter().map(|s| &s.R));

        let zs: Vec<Scalar> = match scalar_size {
            ScalarSize::Half => {
                let initial_hash: Sha256 = set_initial_hash(&raw_hrams);
                (0usize..signatures.len())
                    .map(|i| {
                        let mut h = initial_hash.clone(); // hash of sum already included
                        h.update(i.to_le_bytes());
                        let mut half_scalar_bytes = [0u8; 16];
                        half_scalar_bytes.copy_from_slice(&h.finalize()[..16]);
                        Scalar::from(u128::from_le_bytes(half_scalar_bytes))
                    })
                    .collect()
            }
            ScalarSize::Full => {
                let initial_hash: Sha256 = set_initial_hash(&raw_hrams);

                (0usize..signatures.len())
                    .map(|i| {
                        let mut h = initial_hash.clone(); // hash of sum already included
                        h.update(i.to_le_bytes());
                        Scalar::from_bytes_mod_order(h.finalize().into())
                    })
                    .collect()
            }
            ScalarSize::Double => {
                let initial_hash: Sha512 = set_initial_hash(&raw_hrams);
                (0usize..signatures.len())
                    .map(|i| {
                        let mut h = initial_hash.clone(); // hash of sum already included
                        h.update(i.to_le_bytes());
                        Scalar::from_hash(h)
                    })
                    .collect()
            }
        };

        let s = signatures
            .iter()
            .zip(zs)
            .fold(Scalar::zero(), |acc, (sig, h)| acc + sig.s * h);

        let r_terms = signatures.iter().map(|sig| sig.R).collect::<Vec<_>>();
        Ok(AggregatedSignature { r_terms, s })
    }

    /// verify an aggregated signature
    pub fn verify(
        msg_and_keys: &[(&[u8], &PublicKey)],
        sig: &AggregatedSignature,
        scalar_size: ScalarSize,
    ) -> Result<(), SignatureError> {
        let m_k = check_slice_size(msg_and_keys, sig.r_terms.len(), "msg_and_keys")?;

        let decompressed_r_terms: Vec<EdwardsPoint> = sig
            .r_terms
            .iter()
            .map(|r| r.decompress().ok_or(InternalError::PointDecompressionError))
            .collect::<Result<Vec<_>, _>>()?;

        let raw_hrams = compute_hrams(m_k, sig.r_terms.iter());

        let zs: Vec<Scalar> = match scalar_size {
            ScalarSize::Half => {
                let initial_hash: Sha256 = set_initial_hash(&raw_hrams);
                (0usize..m_k.len())
                    .map(|i| {
                        let mut h = initial_hash.clone(); // hash of sum already included
                        h.update(i.to_le_bytes());
                        let mut half_scalar_bytes = [0u8; 16];
                        half_scalar_bytes.copy_from_slice(&h.finalize()[..16]);
                        Scalar::from(u128::from_le_bytes(half_scalar_bytes))
                    })
                    .collect()
            }
            ScalarSize::Full => {
                let initial_hash: Sha256 = set_initial_hash(&raw_hrams);

                (0usize..m_k.len())
                    .map(|i| {
                        let mut h = initial_hash.clone(); // hash of sum already included
                        h.update(i.to_le_bytes());
                        Scalar::from_bytes_mod_order(h.finalize().into())
                    })
                    .collect()
            }
            ScalarSize::Double => {
                let initial_hash: Sha512 = set_initial_hash(&raw_hrams);
                (0usize..m_k.len())
                    .map(|i| {
                        let mut h = initial_hash.clone(); // hash of sum already included
                        h.update(i.to_le_bytes());
                        Scalar::from_hash(h)
                    })
                    .collect()
            }
        };

        let hrams: Vec<Scalar> = raw_hrams
            .iter()
            .map(|ga| {
                let mut bits = [0u8; 64];
                bits.copy_from_slice(&ga);
                Scalar::from_bytes_mod_order_wide(&bits)
            })
            .collect();

        let zhrams = hrams.iter().zip(zs.iter()).map(|(hram, z)| hram * z);

        let left_hand = EdwardsPoint::optional_multiscalar_mul(
            zs.iter().cloned().chain(zhrams),
            decompressed_r_terms
                .iter()
                .cloned()
                .map(Some)
                .chain(m_k.iter().map(|(_, a)| Some(a.1))),
        )
        .ok_or(InternalError::VerifyError)?;

        let right_hand = &sig.s * &constants::ED25519_BASEPOINT_TABLE;

        if right_hand.compress() == left_hand.compress() {
            Ok(())
        } else {
            Err(InternalError::VerifyError.into())
        }
    }
}

pub(crate) fn check_slice_size<'a, T>(
    slice: &'a [T],
    expected_len: usize,
    arg_name: &'static str,
) -> Result<&'a [T], InternalError> {
    if slice.len() != expected_len {
        return Err(InternalError::BytesLengthError {
            name: arg_name,
            length: expected_len,
        });
    }
    Ok(slice)
}

fn log_2(x: usize) -> usize {
    x.next_power_of_two().trailing_zeros() as usize
}

const LAMBDA: usize = 128;

fn l(r: usize, n: usize) -> usize {
    LAMBDA / r + log_2(n)
}

/// Aggregated Signature method #2 (Fischlin transform based)
#[derive(Clone, Debug)]
pub struct QuasiAggregatedSignature {
    pub(crate) r_terms: Vec<CompressedEdwardsY>,
    pub(crate) e_terms: Vec<Scalar>,
    pub(crate) z_terms: Vec<Scalar>,
}

fn uninit_vector<T: Default + Clone>(length: usize) -> Vec<T> {
    let mut vector = Vec::with_capacity(length);
    vector.resize(length, T::default());
    vector
}

#[allow(clippy::many_single_char_names)]
impl QuasiAggregatedSignature {
    /// Aggregate from individual signatures
    pub fn aggregate(
        r: usize,
        msg_and_keys: &[(&[u8], &PublicKey)],
        sigs: &[Signature],
    ) -> Result<QuasiAggregatedSignature, SignatureError> {
        let n = msg_and_keys.len();

        let signatures = check_slice_size(sigs, n, "sigs")?
            .iter()
            .map(InternalSignature::try_from)
            .collect::<Result<Vec<InternalSignature>, _>>()?;

        let r_terms = signatures.iter().map(|sig| sig.R).collect::<Vec<_>>();

        let ha: &[u8] = {
            let mut hash: Sha256 = Sha256::new();
            r_terms
                .iter()
                .for_each(|r_term| hash.update(r_term.as_bytes()));
            &hash.finalize()
        };
        let init_hash: Sha256 = {
            let mut h = Sha256::new();
            h.update(ha);
            h
        };

        let mut e_terms = uninit_vector::<Scalar>(r);

        let mut z_terms = uninit_vector::<Scalar>(r);

        let mut j: usize = 0;
        let mut e: Scalar = Scalar::one();

        while j < r {
            let z: Scalar = signatures
                .iter()
                .map(|sig| sig.s)
                .rev()
                .reduce(|acc, sig_scalar| (acc * e + sig_scalar))
                .unwrap();
            let mut h = init_hash.clone(); // ha is already contained in h
            h.update(j.to_le_bytes());
            h.update(e.to_bytes());
            h.update(z.to_bytes());

            let mut h_bytes = [0u8; 4];
            h_bytes.clone_from_slice(&h.finalize()[28..]);

            if (u32::from_be_bytes(h_bytes)).trailing_zeros() >= l(r, n) as u32 {
                e_terms[j] = e;
                z_terms[j] = z;
                j += 1;
                e = Scalar::one();
            } else {
                e += Scalar::one();
            }
        }

        Ok(QuasiAggregatedSignature {
            r_terms,
            e_terms,
            z_terms,
        })
    }

    /// Verify an agg sig
    pub fn verify(
        r: usize,
        msg_and_keys: &[(&[u8], &PublicKey)],
        sig: &QuasiAggregatedSignature,
    ) -> Result<(), SignatureError> {
        let n = msg_and_keys.len();
        let m_k = check_slice_size(msg_and_keys, sig.r_terms.len(), "msg_and_keys")?;
        let e_terms = check_slice_size(&sig.e_terms, sig.z_terms.len(), "e_terms")?;

        let ha: &[u8] = {
            let mut h: Sha256 = Sha256::new();
            sig.r_terms.iter().for_each(|r| h.update(r.as_bytes()));
            &h.finalize()
        };

        let init_hash: Sha256 = {
            let mut h = Sha256::new();
            h.update(ha);
            h
        };

        let cond1 = sig
            .z_terms
            .iter()
            .zip(e_terms)
            .enumerate()
            .map(|(j, (z, e))| {
                let mut h = init_hash.clone(); // ha is already contained in h
                h.update(j.to_le_bytes());
                h.update(e.to_bytes());
                h.update(z.to_bytes());
                h.finalize()
            })
            .all(|hh| {
                let mut h_bytes = [0u8; 4];
                h_bytes.copy_from_slice(&hh[28..]);

                u32::from_be_bytes(h_bytes).trailing_zeros() >= l(r, n) as u32
            });

        let decompressed_r_terms: Vec<EdwardsPoint> = sig
            .r_terms
            .iter()
            .map(|r| r.decompress().ok_or(InternalError::PointDecompressionError))
            .collect::<Result<Vec<_>, _>>()?;

        let hrams: Vec<Scalar> = compute_hrams(m_k, sig.r_terms.iter())
            .iter()
            .map(|ga| {
                let mut bits = [0u8; 64];
                bits.copy_from_slice(&ga);
                Scalar::from_bytes_mod_order_wide(&bits)
            })
            .collect();

        let sums = e_terms
            .iter()
            .zip(&sig.z_terms)
            .map::<Result<_, InternalError>, _>(|(e_j, z_j)| {
                let es: Vec<Scalar> = decompressed_r_terms
                    .iter()
                    .scan(Scalar::one(), |state, _| {
                        let coeff = state.clone();
                        *state *= e_j;
                        Some(coeff)
                    })
                    .collect();

                let ehrams: Vec<Scalar> = hrams
                    .iter()
                    .cloned()
                    .zip(es.iter().cloned())
                    .map(|(hram, e)| hram * e)
                    .collect();

                let left_hand: EdwardsPoint = EdwardsPoint::optional_multiscalar_mul(
                    es.into_iter().chain(ehrams),
                    decompressed_r_terms
                        .iter()
                        .cloned()
                        .map(Some)
                        .chain(m_k.iter().map(|(_, a)| Some(a.1))),
                )
                .ok_or(InternalError::VerifyError)?;

                let right_hand = z_j * &constants::ED25519_BASEPOINT_TABLE;
                Ok(left_hand == right_hand)
            })
            .collect::<Result<Vec<bool>, _>>()?;

        let cond2 = sums.iter().all(|x| *core::convert::identity(x));

        if cond1 && cond2 {
            Ok(())
        } else {
            Err(InternalError::VerifyError.into())
        }
    }
}
