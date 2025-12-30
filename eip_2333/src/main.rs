use eip_2333_testing::functions::{derive_child_sk, derive_master_sk};
use eip_2333_testing::i2osp_test::{i2osp};
use num_bigint::BigUint;

fn main() {
    // ===============================
    // Test vector 0
    // ===============================

    let seed_hex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531\
                    f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

    let expected_master_sk = BigUint::parse_bytes(
        b"6083874454709270928345386274498605044986640685124978867557563392430687146096",
        10
    ).unwrap();

    let expected_child_sk = BigUint::parse_bytes(
        b"20397789859736650942317412262472558107875392172444076792671091975210932703118",
        10
    ).unwrap();

    let child_index = BigUint::from(0u32);

    // ===============================
    // Convert seed hex → Vec<u8>
    // ===============================

    let seed = hex::decode(seed_hex).expect("Invalid hex seed");

    // ===============================
    // Derive master SK
    // ===============================

    let master_sk = derive_master_sk(seed.clone()).expect("Failed to derive master SK");

    println!("Derived master SK  = {}", master_sk);
    println!("Expected master SK = {}", expected_master_sk);

    assert_eq!(master_sk, expected_master_sk);
    println!("✔ Master SK matches");

    // ===============================
    // Derive child SK
    // ===============================

    let master_sk_bytes = i2osp(&master_sk, 32).unwrap();
    let child_sk = derive_child_sk(&BigUint::from_bytes_be(&master_sk_bytes), &child_index);

    println!("Derived child SK  = {}", child_sk);
    println!("Expected child SK = {}", expected_child_sk);

    assert_eq!(child_sk, expected_child_sk);
    println!("✔ Child SK matches");

    println!("\n✅ All tests passed!");

    //TODO: Adding more tests
    
}



