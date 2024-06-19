
# RSA- Rust

A Rust library for generating RSA key pairs, and performing encryption and decryption using OAEP encoding. Additionally, it supports signing but padding is not implemented.




## Demo

```rust 
    let keys = Key::generte_rsa_keys(3072, None); // length of the key

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

    // Example for signing and validation
    // Note: No padding is used for signing, use it with caution

    let signing = keys.rsaprivate_key.sign(&hash1);
    println!("{:?}", keys.rsapublic_key.validate(&hash2, &signing));

    // If you don't have the full Key, you can use publickey(n,e) for validation and privatekey(d,n) for signing
    // Example:
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


    // Example for encryption and decryption using OAEP padding
    // You get the encrypted message in base64 format
    // The base64 encoded message will be given as input to the decrypt function
    // Encryption should be done using the public key, otherwise it will throw an InvalidKeyTypeError
    // Decryption should be done using the private key, otherwise it will throw an InvalidKeyTypeError
    // If the wrong key is used for decryption, it will throw a DecryptionFailed error or DecodingError
    // If a wrongly generated public key is used for encryption, an error will be thrown

    for _ in 0..6{
    let encrypted = keys.rsapublic_key.encrypt("Remember the emoji 😊".as_bytes());
    println!("{:?}",encrypted);
    let decrypted = keys.rsaprivate_key.decrypt(&encrypted.unwrap());
    println!("{:?}",decrypted);}

```


## License

[MIT](https://choosealicense.com/licenses/mit/)


## Contributing

Contributions are always welcome! If you find anything or want to contribute, please add it in the issues section.

