
use std::io::Read;

use crate::key_gen::Key;

mod key_gen;
mod utilities;
fn main() {
    let keys = Key::generte_rsa_keys(2048, None);

    let mut file1=std::fs::File::open("signed_hash").unwrap();
    let mut file2=std::fs::File::open("signed_hash").unwrap();

    let mut str1 = String::new();
    let mut str2 = String::new();

    file1.read_to_string(&mut str1).unwrap();
    file2.read_to_string(&mut str2).unwrap();

    let hash1 = utilities::calculate_hash(str1.as_bytes());
    let hash2 = utilities::calculate_hash(str2.as_bytes());

    println!("{:?}", hash1);
    println!("{:?}", hash2);

    // let m1 = BigUint::from_i128(hash1 as i128).expect("error");
    // let m2 = BigUint::from_i128(hash2 as i128).expect("error");

    println!("enter the file name");
    let mut file_name = String::new();
    std::io::stdin()
        .read_line(&mut file_name)
        .expect("error in reading the input");
    file_name = file_name.trim().to_string();
    let signing = keys.sign(hash1);
    keys.save_to_file(&signing, &file_name);

    println!("{:?}", Key::validate_from_file(&file_name, &hash2));
    println!("{:?}", keys.validate(hash2, signing));
}
