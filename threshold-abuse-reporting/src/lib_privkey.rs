//! Method 1: Fully Linkable Public Key Threshold Blocking

use std::collections::{HashMap, HashSet};
use rand::Rng;
use crate::crypto::*; // will later pick packages for Sign, AEAD, HMAC, DHKE, BlindSig, Hash, etc...

pub type PublicKey = Vec<u8>;
pub type PrivateKey = Vec<u8>;
pub type Cert = Vec<u8>;
pub type CipherText = Vec<u8>;
pub type Mac = Vec<u8>;
pub type SessionKey = Vec<u8>;
pub type HashVal = Vec<u8>;

pub struct PlatformKeys {
    pub sk_ca: PrivateKey,
    pub pk_ca: PublicKey,
    pub kp: PrivateKey,
    pub pk_ctr: HashMap<PublicKey, usize>,
    pub pk_rl: HashSet<PublicKey>,
    pub kh_rl: HashSet<HashVal>,
}

pub struct UserKeys {
    pub sks: PrivateKey,
    pub pks: PublicKey,
    pub skr: PrivateKey,
    pub pkr: PublicKey,
    pub cert: Cert,
}

pub fn platform_setup() -> (PublicKey, PlatformKeys) {
    let (sk_ca, pk_ca) = siggen();
    let (kp, _) = siggen(); // kp is secret only
    let keys = PlatformKeys {
        sk_ca,
        pk_ca: pk_ca.clone(),
        kp,
        pk_ctr: HashMap::new(),
        pk_rl: HashSet::new(),
        kh_rl: HashSet::new(),
    };
    (pk_ca, keys)
}

pub fn join(pk_ca: &PublicKey, sk_ca: &PrivateKey) -> UserKeys {
    let (sks, pks) = siggen();
    let (skr, pkr) = siggen();
    let r = rand_bytes();
    let sigma_blind = blind_sign(&pks, &r, sk_ca);
    let cert = unblind(&sigma_blind, &r);
    UserKeys { sks, pks, skr, pkr, cert }
}

pub fn session_setup(pk_a: &PublicKey, sk_a: &PrivateKey, pk_b: &PublicKey) -> HashVal {
    let k_ab = dhke(sk_a, pk_b);
    hash(&k_ab)
}

pub fn session_init(skr: &PrivateKey, pks: &PublicKey, cert: &Cert, kr: &SessionKey, kh: &HashVal) -> (CipherText, Mac) {
    let sigma = sign(skr, kh);
    let kf = rand_bytes();
    let mut mac_input = sigma.clone();
    mac_input.extend(pks);
    mac_input.extend(cert);
    mac_input.extend(kh);
    let c2 = hmac(&kf, &mac_input);
    let mut enc_input = mac_input.clone();
    enc_input.extend(kf);
    let c1 = aead_encrypt(kr, &enc_input);
    (c1, c2)
}

pub fn commit(kp: &PrivateKey, c2: &Mac, metadata: &[u8]) -> Mac {
    let mut input = c2.clone();
    //input.extend(metadata);  probably wont add metadata
    hmac(kp, &input)
}

pub fn session_verify(
    a: &Mac,
    (c1, c2): (&CipherText, &Mac),
    metadata: &[u8],
    kr: &SessionKey,
    kh: &HashVal,
    pk_rl: &HashSet<PublicKey>,
    pk_ca: &PublicKey,
) -> bool {
    let plaintext = match aead_decrypt(kr, c1) {
        Some(pt) => pt,
        None => return false,
    };

    let (sigma, pks, cert, kh_prime, kf) = parse_decrypted_payload(&plaintext);
    if &kh_prime != kh || pk_rl.contains(&pks) {
        return false;
    }

    let mut mac_input = sigma.clone();
    mac_input.extend(&pks);
    mac_input.extend(&cert);
    mac_input.extend(&kh_prime);
    if hmac(&kf, &mac_input) != *c2 {
        return false;
    }

    verify_signature(&cert, &pk_ca) && verify_signature(&sigma, &pks)
}

pub fn report(pks: &PublicKey, sigma: &Vec<u8>, a: &Mac, c2: &Mac, kh: &HashVal) -> (PublicKey, Vec<u8>, Mac, Mac, HashVal) {
    (pks.clone(), sigma.clone(), a.clone(), c2.clone(), kh.clone())
}

pub fn moderate(
    report: (PublicKey, Vec<u8>, Mac, Mac, HashVal),
    platform: &mut PlatformKeys,
    t: usize,
) -> Result<(), ()> {
    let (pks, sigma, a, c2, kh) = report;
    let mut mac_input = c2.clone();
    //let metadata = b""; // or a timestamp
    //mac_input.extend(metadata);

    if hmac(&platform.kp, &mac_input) != a {
        return Err(());
    }

    if !verify_signature(&sigma, &pks) {
        return Err(());
    }

    if platform.pk_rl.contains(&pks) {
        return Err(());
    }

    let count = platform.pk_ctr.entry(pks.clone()).or_insert(0);
    if !platform.kh_rl.contains(&kh) && *count < t {
        platform.kh_rl.insert(kh.clone());
        *count += 1;
    }

    if *count >= t {
        platform.pk_rl.insert(pks);
    } else {
        return Err(());
    }

    Ok(())
}

// helper functions to later be implemented with crypto fns and design specifics

fn siggen() -> (PrivateKey, PublicKey) {
    (rand_bytes(), rand_bytes())
}

fn blind_sign(m: &PublicKey, r: &Vec<u8>, sk: &PrivateKey) -> Vec<u8> {
    vec![]
}

fn unblind(sigma: &Vec<u8>, r: &Vec<u8>) -> Vec<u8> {
    sigma.clone()
}

fn sign(sk: &PrivateKey, m: &HashVal) -> Vec<u8> {
    vec![]
}

fn verify_signature(sig: &Vec<u8>, pk: &PublicKey) -> bool {
    true
}

fn aead_encrypt(key: &SessionKey, msg: &Vec<u8>) -> CipherText {
    msg.clone()
}

fn aead_decrypt(key: &SessionKey, ct: &CipherText) -> Option<Vec<u8>> {
    Some(ct.clone())
}

fn hmac(key: &Vec<u8>, msg: &Vec<u8>) -> Mac {
    vec![0; 32]
}

fn hash(data: &Vec<u8>) -> HashVal {
    vec![1; 32]
}

fn dhke(sk: &PrivateKey, pk: &PublicKey) -> SessionKey {
    vec![9; 32]
}

fn rand_bytes() -> Vec<u8> {
    rand::thread_rng().gen::<[u8; 32]>().to_vec()
}