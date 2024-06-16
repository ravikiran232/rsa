
use rand;
use num_bigint::{BigUint,RandBigInt};
use num_traits::{FromPrimitive, One};
// use rand::rngs::OsRng;
use rand::thread_rng;
use sha3::{Digest, Sha3_256};
use crate::oaep::Error;

pub fn generate_primes(key_length: u64) -> BigUint {
    let prime_length: u64 = key_length / 2;
    let mut rng = thread_rng();
    // let random_bytes: Vec<u8> = (0..prime_length / 8).map(|_| rng.gen::<u8>()).collect();
    // let mut p = BigUint::from_bytes_be(&random_bytes);
    // p = p | BigUint::one();
    let lower_bound = BigUint::from(1u8) << (prime_length-1); // 2^1023
    let upper_bound = BigUint::from(1u8) << prime_length; // 2^1024
    let mut p= rng.gen_biguint_range(&lower_bound,&upper_bound);
    p= p | BigUint::one();
    p
}

pub fn calculate_hash(content: &[u8]) -> BigUint {
    let mut hasher = Sha3_256::new();
    hasher.update(content);
    BigUint::from_bytes_be(&hasher.finalize())
}

pub fn calculate_hash_u8(content: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(content);
    hasher.finalize().to_vec()
}

pub fn i2osp(x: &BigUint, x_len: usize) -> Result<Vec<u8>,Error> {
    let x_bytes = x.to_bytes_be();
    if x_bytes.len() > x_len {
        //panic!("I2OSP: integer too large");
        return Err(Error::IntegerTooLarge);
    }
    let mut result = vec![0; x_len];
    result.splice(x_len - x_bytes.len()..x_len, x_bytes.iter().cloned());
    Ok(result)
}

pub fn os2ip(x: &[u8]) -> BigUint {
    BigUint::from_bytes_be(x)
}



pub fn mgf(seed: &[u8], mask_len: usize,blen:u64) -> Result<Vec<u8>,Error> {
    if mask_len > 2usize.pow(32)*(blen as usize){ // 2^32 is the maximum length of the mask
        panic!("mask too long");
    }
    // let mut hasher= Sha3_256::new();
    let mut t:Vec<u8>=Vec::new();
    for i in 0..((mask_len).div_ceil(blen as usize)){
        let c= i2osp(&BigUint::from_i128(i as i128).unwrap(),4)?;
        let finalhash= calculate_hash_u8(&[seed,&c].concat());
        t.extend(finalhash);
    }

    Ok(t[0..mask_len].to_vec())

}

