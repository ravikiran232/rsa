
use crate::utilities;
use crate::keygen::KeyType;
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use base64::{Engine as _, engine::general_purpose};
use crate::oaep::{oaep_encoding,Error};



pub trait Encryption {
    fn get_oaep_encoded_message(&self,content:&[u8])->Result<(BigUint,&BigUint,BigUint),Error>;
    fn encrypt(&self,content:&[u8])->Result<String,Error>;
}

impl Encryption for KeyType{
    fn get_oaep_encoded_message(&self,content:&[u8])->Result<(BigUint,&BigUint,BigUint),Error>{
        let (n,e)=match self{
            KeyType::RSAPublicKey{n,e}=>(Some(n),Some(e)),
            _=>{
                // panic!("Invalid Key Type, expected RSAPublicKey");
                return Err(Error::InvalidKeyTypeError);
            },
        };
        let (n,e)=(n.unwrap(),e.unwrap());
        let mut key_len= n.bits();
        if key_len%8!=0{
            key_len+= 8-(key_len%8);
        }
        let encoded_message=oaep_encoding(content,key_len as usize,"rsa_simple".as_bytes())?; // p is the label
        Ok((encoded_message,n,BigUint::from_i128(*e as i128).expect("BigUint conversion failed")))
    }
    
    fn encrypt(&self,content:&[u8])->Result<String,Error> {
        let (em,n,e)=self.get_oaep_encoded_message(content)?;
        let c= em.modpow(&e,n);
        let mut key_len= n.bits();
        if key_len%8!=0{
            key_len+= 8-(key_len%8);
        }
        let cipher=utilities::i2osp(&c, (key_len/8) as usize)?;
        Ok(general_purpose::STANDARD.encode(&cipher))
    }
}

