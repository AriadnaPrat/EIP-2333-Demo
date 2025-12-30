//https://www.rfc-editor.org/rfc/rfc3447

use num_bigint::BigUint;

pub fn i2osp(x: &BigUint, x_len: usize) -> Result<Vec<u8>, &'static str> {
    let mut x_bytes = x.to_bytes_be();

    if x_bytes.len() > x_len {
        return Err("integer too large");
    }

    let mut result = vec![0u8; x_len - x_bytes.len()];
    result.append(&mut x_bytes);

    Ok(result)
}

pub fn os2ip(x: &[u8]) -> BigUint{
    x.iter().fold(BigUint::default(), |acc, &b| acc * 256u32 + b)
}