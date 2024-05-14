use crate::utilities;
use large_primes::fermat as prime_test;
use num_bigint::BigUint;
use num_traits::FromPrimitive;

#[derive(Debug)]
pub enum KeyType {
    RSAPublicKey { n: BigUint, e: u64 },
    RSAPrivateKey { d: BigUint },
}

#[derive(Debug)]
pub struct Key {
    pub rsaprivate_key: KeyType,
    pub rsapublic_key: KeyType,
}

impl Key {
    pub fn validate_from_file(file_path: &str, content_hash: &BigUint) -> bool {
        let values = utilities::read_file(file_path);
        let new_value = values[0].modpow(&values[2], &values[1]);
        if new_value == *content_hash {
            return true;
        }
        false
    }

    pub fn generte_rsa_keys(key_length: u64, e: Option<u64>) -> Key {
        let mut p = utilities::generate_primes(key_length);
        while prime_test(&p) != true {
            p = utilities::generate_primes(key_length);
        }
        let mut q = utilities::generate_primes(key_length);
        while prime_test(&q) != true {
            q = utilities::generate_primes(key_length);
        }
        let n = &p * &q;

        let e = e.unwrap_or(65537);
        let phi = (p - BigUint::from_i8(1).expect("")) * (q - BigUint::from_i8(1).expect(""));
        let d = BigUint::from_i64(e as i64)
            .expect("")
            .modinv(&phi)
            .expect("error in d");
        Key {
            rsaprivate_key: KeyType::RSAPrivateKey { d: d },
            rsapublic_key: KeyType::RSAPublicKey { n: n, e: e },
        }
    }

    pub fn get_d(&self) -> Option<BigUint> {
        match &self.rsaprivate_key {
            KeyType::RSAPrivateKey { d } => Some(d.clone()),
            _ => None,
        }
    }

    pub fn get_e(&self) -> Option<u64> {
        match &self.rsapublic_key {
            KeyType::RSAPublicKey { n: _, e } => Some(*e),
            _ => None,
        }
    }

    pub fn get_n(&self) -> Option<BigUint> {
        match &self.rsapublic_key {
            KeyType::RSAPublicKey { n, e: _ } => Some(n.clone()),
            _ => None,
        }
    }

    pub fn sign(&self, content_hash: BigUint) -> BigUint {
        let d = self.get_d().unwrap();
        let n = self.get_n().unwrap();
        content_hash.modpow(&d, &n)
    }

    pub fn validate(&self, content_hash: BigUint, sign_value: BigUint) -> bool {
        let e = self.get_e().unwrap();
        let n = self.get_n().unwrap();
        let new_value = sign_value.modpow(
            &BigUint::from_i64(e as i64).expect("unable to convert e to BU"),
            &n,
        );
        if new_value == content_hash {
            return true;
        }
        false
    }

    pub fn save_to_file(&self, signed_hash: &BigUint, file_name: &String) -> () {
        let n = self.get_n().unwrap();
        let e = self.get_e().unwrap();
        utilities::write_file(&signed_hash, n, e, file_name);
    }
}
