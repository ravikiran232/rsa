use crate::utilities;
use large_primes::fermat as prime_test;
use num_bigint::BigUint;
use num_traits::FromPrimitive;

#[derive(Debug)]
pub enum KeyType {
    RSAPublicKey { n: BigUint, e: u64 },
    RSAPrivateKey { d: BigUint, n: BigUint },
}

#[derive(Debug)]
pub struct Key {
    pub rsaprivate_key: KeyType,
    pub rsapublic_key: KeyType,
}

impl KeyType {
    pub fn validate(&self, content_hash: &BigUint, sign_value: &BigUint) -> bool {
        let (n, e) = match self {
            KeyType::RSAPublicKey { n, e } => (Some(n), Some(e)),
            _ => (None, None),
        };
        let (n, e) = (n.unwrap(), e.unwrap());
        let new_value = sign_value.modpow(
            &BigUint::from_i64(*e as i64).expect("BigUint conversion failed"),
            &n,
        );
        if new_value == *content_hash {
            return true;
        }
        false
    }

    pub fn sign(&self, content_hash: &BigUint) -> BigUint {
        let (d, n) = match self {
            KeyType::RSAPrivateKey { d, n } => (Some(d), Some(n)),
            _ => (None, None),
        };
        let (d, n) = (d.unwrap(), n.unwrap());
        content_hash.modpow(&d, &n)
    }
}

impl Key {
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
        let phi = &p * &q - (p + q) + BigUint::from_i8(1).expect("BigUint conversion failed");
        let d = BigUint::from_i64(e as i64)
            .expect("BigUint conversion failed")
            .modinv(&phi)
            .expect("change the e value(odd)");
        Key {
            rsaprivate_key: KeyType::RSAPrivateKey { d: d, n: n.clone() },
            rsapublic_key: KeyType::RSAPublicKey { n: n, e: e },
        }
    }

    pub fn get_d(&self) -> Option<BigUint> {
        match &self.rsaprivate_key {
            KeyType::RSAPrivateKey { d, n: _ } => Some(d.clone()),
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
}
