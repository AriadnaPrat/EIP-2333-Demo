use crate::constants::{K, L};
use crate::HKDF_functions::{hkdf_extract, hkdf_expand};
use crate::utils::bytes_split;

pub fn IKM_to_lamport_SK(ikm: &[u8], salt: &[u8]) -> Vec<Vec<u8>>{
    /*  
    Inputs:
     - IKM, a secret octet string 
     - salt, an octet string

    Outputs: 
     - lamport_SK, an array of 255 32-octet strings 
    */

    let prk = hkdf_extract(Some(&salt), &ikm);
    let okm = hkdf_expand(&prk, b"" , L.try_into().unwrap());
    let lamport_SK = bytes_split(okm, K);

    lamport_SK
}

pub fn lamport_SK_to_lamport_PK(){
    //TODO
}

pub fn HKDF_mod_r(){
    //TODO
}

pub fn derive_child_SK(){
    //TODO
}

pub fn derive_master_SK(){
    //TODO
}
