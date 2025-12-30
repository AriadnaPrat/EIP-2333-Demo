//Reference -> //https://www.rfc-editor.org/rfc/rfc5869 

use hmac::{Hmac, Mac};
use sha2::Sha256;
use num_bigint::BigUint;

pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &BigUint) -> Vec<u8> {
    const HASH_LEN: usize = 32;

    let salt = salt.unwrap_or(&[0u8; HASH_LEN]);

    let mut mac = Hmac::<Sha256>::new_from_slice(salt)
        .expect("HMAC can take key of any size");

    let ikm_bytes = ikm.to_bytes_be();
    mac.update(&ikm_bytes);

    let result = mac.finalize();
    let prk = result.into_bytes();

    prk.to_vec()
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], l: usize) -> Vec<u8> {
    const HASH_LEN: usize = 32; // SHA-256

    assert_eq!(prk.len(), HASH_LEN, "PRK must be HashLen bytes");


    let n = (l + HASH_LEN - 1) / HASH_LEN;
    assert!(n <= 255, "HKDF-Expand: n must be <= 255");

    let mut okm = Vec::with_capacity(n * HASH_LEN);
    let mut t_prev: Vec<u8> = Vec::new();

    for i in 1..=n {
        let mut mac = Hmac::<Sha256>::new_from_slice(prk)
            .expect("HMAC key error");

        mac.update(&t_prev);     // T(i-1)
        mac.update(info);        // info
        mac.update(&[i as u8]);  // counter

        t_prev = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&t_prev);
    }

    okm.truncate(l);
    okm
}
