use crate::constants::{K, L};
use crate::hkdf_test::{hkdf_extract, hkdf_expand};
use crate::utils::bytes_split;
use crate::i2osp_test::{i2osp, os2ip};
use crate::utils::flip_bits;
use sha2::{Sha256, Digest};
use num_bigint::BigUint;

pub fn ikm_to_lamport_sk(ikm: &BigUint, salt: &[u8]) -> Vec<Vec<u8>>{

    /*  
    Inputs:
     - IKM, a secret octet string 
     - salt, an octet string

    Outputs: 
     - lamport_SK, an array of 255 32-octet strings 
    */

    let prk = hkdf_extract(Some(&salt), ikm);
    let okm = hkdf_expand(&prk, b"" , L as usize);
    let lamport_sk = bytes_split(&okm, K as usize).unwrap();

    lamport_sk
}

pub fn parent_sk_to_lamport_pk(
    parent_sk: &BigUint,
    index: &BigUint,
) -> Result<Vec<u8>, &'static str> {

    if parent_sk.to_bytes_be().len() != 32 {
        return Err("parent_sk must be 32 bytes");
    }

    let salt = i2osp(index, 4).unwrap();
    let ikm = i2osp(parent_sk, 32).unwrap(); 
    let not_ikm = &flip_bits(&ikm);

    let lamport_0 = ikm_to_lamport_sk(&BigUint::from_bytes_be(&ikm), &salt);
    let lamport_1 = ikm_to_lamport_sk(&not_ikm, &salt);

    let mut lamport_pk = Vec::with_capacity(255 * 2 * 32); 
    for i in 0..255 {
        let h = Sha256::digest(&lamport_0[i]);
        lamport_pk.extend_from_slice(&h);
    }

    for i in 0..255 {
        let h = Sha256::digest(&lamport_1[i]);
        lamport_pk.extend_from_slice(&h);
    }

    let result = Sha256::digest(&lamport_pk);

    Ok(result.to_vec())

}

pub fn hkdf_mod_r(ikm: &[u8], key_info: Option<&str>) -> BigUint {
    let mut salt = b"BLS-SIG-KEYGEN-SALT-".to_vec();
    let r = BigUint::parse_bytes(
        b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
        10
    ).unwrap();
    let l_prev = (3 * r.bits() + 15) / 16;
    let mut sk = BigUint::from(0u32);

    while sk == BigUint::from(0u32) {
        let mut sha = Sha256::new();
        sha.update(&salt);
        salt = sha.finalize().to_vec();

        let i2osp1 = i2osp(&BigUint::from(0u32), 1).expect("i2osp failed");
        let x = [ikm, &i2osp1].concat();
        let prk = hkdf_extract(Some(&salt), &BigUint::from_bytes_be(&x));  //TODO: Change type

        let i2osp2 = i2osp(&BigUint::from(l_prev), 2).expect("i2osp failed");
        let key_bytes = key_info.map(|s| s.as_bytes().to_vec()).unwrap_or_default();
        let y: Vec<u8> = [key_bytes.as_slice(), &i2osp2].concat();

        let okm = hkdf_expand(&prk, &y, l_prev as usize);

        sk = os2ip(&okm) % &r;
    }

    sk
}


pub fn derive_child_sk(parent_sk: &BigUint, index:&BigUint) -> BigUint{
    let compressed_lamport_pk = parent_sk_to_lamport_pk(parent_sk, index).unwrap();
    let sk = hkdf_mod_r(&compressed_lamport_pk, None);
    sk
}


pub fn derive_master_sk(seed: Vec<u8>) -> Result< BigUint, &'static str>{
    /*
    Inputs:
    - seed, the source entropy for the entire tree, a octet string >= 256 bits in length
    Outputs:
    - SK, the secret key of master node within the tree, a big endian encoded integer
    */

    if seed.len() < 32 {
    return Err("Seed must be at least 32 bytes");
    }

    let sk = hkdf_mod_r(&seed, None);
    Ok(sk)
}
