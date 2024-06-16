

use num_bigint::BigUint;
use rand::{rngs::OsRng, Rng};

use crate::utilities::{calculate_hash_u8,os2ip,mgf};

#[derive(Debug)]
pub enum Error {
    MessageTooLong,
    DecodingError,
    InvalidKeyTypeError,
    IntegerTooLarge,
    DecryptionFailed,
}

pub fn oaep_encoding(x:&[u8],key_length: usize,p:&[u8])->Result<BigUint,Error>{
    
    let x_hash= calculate_hash_u8(x);
    
    let b_len= x_hash.len();
    if (x.len()+2*b_len+1)>(key_length/8-1){
        //panic!("Message too long");
        return Err(Error::MessageTooLong);
    }

    // no input limitation for sha3 hash function

    let mut ps:String = String::new();
    for _ in 0..(key_length/8-x.len()-2*b_len-2){
        ps.push('0');
    }

    let p_hash= calculate_hash_u8(p);

    let db = [p_hash,ps.as_bytes().to_vec(),"1".as_bytes().to_vec(),x.to_vec()].concat();

    // generating random seed of length b_len
    let mut rng = OsRng;
    let seed:Vec<u8>=(0..b_len).map(|_|rng.gen::<u8>()).collect();

    let dbmask = mgf(&seed, key_length/8-b_len-1, b_len as u64)?;
    let maskeddb = db.iter().zip(dbmask.iter()).map(|(a,b)|a^b).collect::<Vec<u8>>();


    let seedmask=mgf(&maskeddb,b_len,b_len as u64)?;

    let maskedseed = seed.iter().zip(seedmask.iter()).map(|(a,b)|a^b).collect::<Vec<u8>>();

   

    let em = [maskedseed,maskeddb].concat();

    Ok(os2ip(&em))


}

pub fn oeap_decoding(encoded_message:&[u8],p:&[u8])->Result<Vec<u8>,Error>{
    let sample_hash= calculate_hash_u8("hello".as_bytes());
    let b_len= sample_hash.len();
    if encoded_message.len()<(2*b_len+1){
        //panic!("Decoding error");
        return Err(Error::DecodingError);
    }
    let maskedseed= encoded_message[0..b_len].to_vec();
    let maskeddb= encoded_message[b_len..].to_vec();    

    let seedmask=mgf(&maskeddb,b_len,b_len as u64)?;
    let seed= maskedseed.iter().zip(seedmask.iter()).map(|(a,b)|a^b).collect::<Vec<u8>>();

    let dbmask=mgf(&seed,encoded_message.len()-b_len,b_len as u64)?;

    let db= maskeddb.iter().zip(dbmask.iter()).map(|(a,b)|a^b).collect::<Vec<u8>>();

    let p_hash= calculate_hash_u8(p);

    let p_hash_db= db[0..b_len].to_vec();

    if p_hash!=p_hash_db{
        //panic!("Decoding error");
        return Err(Error::DecodingError);
    }

    let mut is_01:bool = false;
    let mut message_index=0;
    for i in b_len..db.len(){
        if db[i]==49{
            is_01=true;
            message_index=i+1;
            break;
        }
    }
    if !is_01{
        //panic!("Decoding error");
        return Err(Error::DecodingError);
    }

    let message= db[message_index..].to_vec();
    Ok(message)

}
