use eip_2333_testing::HKDF_functions::hkdf_extract;
use eip_2333_testing::HKDF_functions::hkdf_expand;
use eip_2333_testing::functions::IKM_to_lamport_SK;

fn main() {
    let ikm = b"super secret IKM";
    let salt = b"random salt";

    let lamport_sk = IKM_to_lamport_SK(ikm, salt);

    println!("Lamport SK has {} blocks:", lamport_sk.len());
    for (i, block) in lamport_sk.iter().enumerate() {
        println!("Block {}: {:02x?}", i + 1, block);
    }
}


