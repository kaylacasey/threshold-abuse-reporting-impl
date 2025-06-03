//! EPID with subset-based threshold non-membership proofs

use blstrs::{G1Projective, G2Projective, Gt, Scalar as BlsScalar, pairing};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use group::{Group, GroupEncoding};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

pub type G1Element = G1Projective;
pub type G2Element = G2Projective;
pub type G3Element = RistrettoPoint;
pub type GTElement = Gt;

// gpk 
pub struct GroupPublicKey {
    pub g1: G1Element,
    pub g2: G2Element,
    pub g3: G3Element,
    pub h1: G1Element,
    pub h2: G1Element,
    pub w: G2Element, // g2^gamma
}

// isk
pub struct IssuerSecretKey {
    pub gamma: Scalar,
}

// sk
pub struct EPIDKey {
    pub A: G1Element,
    pub x: Scalar,
    pub y: Scalar,
    pub f: Scalar,
}

// sigma_0
pub struct SignatureBase {
    pub B: G3Element,
    pub K: G3Element,
    pub T: G1Element,
    pub c: Scalar,
    pub sx: Scalar,
    pub sf: Scalar,
    pub sa: Scalar,
    pub sb: Scalar,
}

// sigma
pub struct EPIDSignature {
    pub base: SignatureBase,
    pub subset_proofs: Vec<ZKSubsetProof>,
    pub kh: Option<Scalar>,
}

// zkp placeholder
pub struct ZKSubsetProof {
    pub subset: Vec<(CompressedRistretto, CompressedRistretto)>,
    pub proof_bytes: Vec<u8>, // abstract for now
}

pub fn setup() -> (GroupPublicKey, IssuerSecretKey) {
    let g1 = G1Element::generator();
    let g2 = G2Element::generator();
    let g3 = G3Element::random(&mut OsRng);

    let h1 = g1;
    let h2 = g1;
    let gamma = Scalar::random(&mut OsRng);
    let w = g2 * BlsScalar::from_bytes(&gamma.to_bytes()).unwrap();

    (
        GroupPublicKey { g1, g2, g3, h1, h2, w },
        IssuerSecretKey { gamma },
    )
}

pub fn join_user(gpk: &GroupPublicKey) -> (Scalar, G1Element) {
    let f = Scalar::random(&mut OsRng);
    let _y_prime = Scalar::random(&mut OsRng);
    let T = gpk.h1 + gpk.h2;
    (f, T)
}

pub fn join_issuer(
    f: &Scalar,
    T: &G1Element,
    _gpk: &GroupPublicKey,
    _isk: &IssuerSecretKey,
) -> EPIDKey {
    let x = Scalar::random(&mut OsRng);
    let y = Scalar::random(&mut OsRng);
    let A = *T;

    EPIDKey { A, x, y, f: *f }
}

pub fn sign(
    sk: &EPIDKey,
    sig_rl: &Vec<(CompressedRistretto, CompressedRistretto)>,
    t: usize,
    session_hash: Option<Scalar>,
) -> EPIDSignature {
    let B = G3Element::random(&mut OsRng);
    let B_session = if let Some(kh) = session_hash {
        B * kh
    } else {
        B
    };
    let K = B_session * sk.f;

    let _a = Scalar::random(&mut OsRng);
    let _b = sk.y + _a * sk.x;
    let T = sk.A;

    let c = Scalar::random(&mut OsRng);
    let sx = Scalar::random(&mut OsRng);
    let sf = Scalar::random(&mut OsRng);
    let sa = Scalar::random(&mut OsRng);
    let sb = Scalar::random(&mut OsRng);

    let mut subset_proofs = vec![];
    let subsets = sig_rl.chunks(t);
    for chunk in subsets {
        let proof = ZKSubsetProof {
            subset: chunk.to_vec(),
            proof_bytes: vec![0u8; 64],
        };
        subset_proofs.push(proof);
    }

    EPIDSignature {
        base: SignatureBase { B, K, T, c, sx, sf, sa, sb },
        subset_proofs,
        kh: session_hash,
    }
}

pub fn verify(
    sig: &EPIDSignature,
    sig_rl: &Vec<(CompressedRistretto, CompressedRistretto)>,
    t: usize,
) -> bool {
    let valid_base = true;
    let valid_subsets = sig.subset_proofs.iter().all(|proof| {
        proof.subset.len() == t && proof.proof_bytes.len() == 64
    });

    valid_base && valid_subsets
}