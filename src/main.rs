use std::io::Read;

use crate::{decrypt::Decryption, encrypt::Encryption, keygen::{Key, KeyType}};

mod keygen;
mod utilities;
mod encrypt;
mod decrypt;
mod oaep;
fn main() {
    let keys = Key::generte_rsa_keys(3072, None);

    let mut file1 = std::fs::File::open("src/encrypt.rs").unwrap();
    let mut file2 = std::fs::File::open("src/encrypt.rs").unwrap();

    let mut str1 = String::new();
    let mut str2 = String::new();

    file1.read_to_string(&mut str1).unwrap();
    file2.read_to_string(&mut str2).unwrap();

    let hash1 = utilities::calculate_hash(str1.as_bytes());
    let hash2 = utilities::calculate_hash(str2.as_bytes());

    println!("{:?}", hash1);
    println!("{:?}", hash2);

    // example for signing and validation
    // no padding is used for signing, so use it with caution

    let signing = keys.rsaprivate_key.sign(&hash1);
    println!("{:?}", keys.rsapublic_key.validate(&hash2, &signing));

    // If you don't have the full Key you can use publickey(n,e) for validation and privatekey(d,n) for signing
    // example
    let privatekey = KeyType::RSAPrivateKey {
        d: keys.get_d().unwrap(),
        n: keys.get_n().unwrap(),
    };
    let publickey = KeyType::RSAPublicKey {
        n: keys.get_n().unwrap(),
        e: keys.get_e().unwrap(),
    };
    let new_sign = privatekey.sign(&hash1);
    println!("{:?}", publickey.validate(&hash2, &new_sign));


    //example for encryption and decryption using OAEP padding
    // you get the encrypted message in base64 format
    // base64 encoded message will be given as input to decrypt function
    // encryption should be done using public key otherwise it will throw an InvalidKeyTypeError
    // decryption should be done using private key otherwise it will throw an InvalidKeyTypeError
    // if wrong key is used for decryption it will throw DecryptionFailed error or DecodingError
    // if wrongly generated public key is used for encryption error will be thrown

    for _ in 0..6{
    let encrypted = keys.rsapublic_key.encrypt("Remember the emoji 😊".as_bytes());
    println!("{:?}",encrypted);
    let decrypted = keys.rsaprivate_key.decrypt(&encrypted.unwrap());
    println!("{:?}",decrypted);}

}
