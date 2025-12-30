use crate::constants::{K};
use num_bigint::BigUint;
use num_traits::Zero;

pub fn bytes_split(input: &[u8], chunk_size: usize) -> Result<Vec<Vec<u8>>, &'static str> {
    if input.len() % chunk_size != 0 {
        return Err("input length not divisible by chunk size");
    }

    assert!(input.len() % K == 0);

    Ok(input
        .chunks(chunk_size)
        .map(|c| c.to_vec())
        .collect())
}

//Returns bitwise negation of input
pub fn flip_bits(input: &[u8]) -> BigUint {
    let x = BigUint::from_bytes_be(input);
    let bit_len = input.len() * 8;

    let mut result = BigUint::zero();

    for i in 0..bit_len {
        if !x.bit(i as u64) {
            result.set_bit(i as u64, true);
        }
    }

    result
}

