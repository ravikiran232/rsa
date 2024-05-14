use base64::{engine::general_purpose, Engine as _};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One};
use rand::prelude::*;
use std::fs::File;
use std::io::{Read, Write};
use sha3::{Digest, Sha3_256};

pub fn generate_primes(key_length: u64) -> BigUint {
    let prime_length: u64 = key_length / 2;
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..prime_length / 8).map(|_| rng.gen::<u8>()).collect();
    let mut p = BigUint::from_bytes_be(&random_bytes);
    p = p | BigUint::one();
    p
}

pub fn calculate_hash(content:&[u8]) -> BigUint {
    let mut hasher = Sha3_256::new();
    hasher.update(content);
    BigUint::from_bytes_be(&hasher.finalize())

}

pub fn write_file(signed_hash: &BigUint, n: BigUint, e: u64, file: &String) -> () {
    let s = format!(
        "{}\nend\n{}\nend\n{}\nend\n",
        base64_encoding(signed_hash),
        base64_encoding(&n),
        base64_encoding(&BigUint::from_i64(e as i64).expect("error in conversion"))
    );
    let mut file = File::create(file).unwrap();
    file.write_all(s.as_bytes()).unwrap();
}

pub fn read_file(file: &str) -> Vec<BigUint> {
    let mut file = File::open(file).unwrap();
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();
    let mut out = Vec::new();
    let mut i = 0;
    let mut j = 0;
    while i < buffer.len() {
        if &buffer[i..i + 5] != "\nend\n" {
            i += 1;
        } else {
            out.push(BigUint::from_bytes_be(
                &general_purpose::STANDARD.decode(&buffer[j..i]).unwrap(),
            ));
            i += 5;
            j = i;
        }
    }
    return out;
}

fn base64_encoding(value: &BigUint) -> String {
    let bytes_array = value.to_bytes_be();
    general_purpose::STANDARD.encode(bytes_array)
}
