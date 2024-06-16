use crate::utilities;
use crate::keygen::KeyType;
use base64::{Engine as _, engine::general_purpose};
use crate::oaep::{oeap_decoding,Error};


pub trait Decryption {
    fn decrypt(&self, content: &str) -> Result<String,Error>;
    fn get_oaep_decoded_message(&self, content: &[u8],p:&[u8]) -> Result<Vec<u8>,Error>;
}

impl Decryption for KeyType {
    fn get_oaep_decoded_message(&self, content: &[u8],p:&[u8]) -> Result<Vec<u8>,Error> {
        oeap_decoding(content, p)
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String,Error> {
        let cipher= general_purpose::STANDARD.decode(ciphertext).unwrap();
       let c= utilities::os2ip(&cipher); 
       let (d,n)= match self{
           KeyType::RSAPrivateKey{d,n}=>(Some(d),Some(n)),
           _=>{
            //    panic!("Invalid Key Type, expected RSAPrivateKey");
            return Err(Error::InvalidKeyTypeError);
           },
       };
        let (d,n)=(d.unwrap(),n.unwrap());
        let m=c.modpow(d,n);
        let mut key_len= n.bits();
        if key_len%8!=0{
            key_len+= 8-(key_len%8);
        }
        let em = utilities::i2osp(&m, ((key_len/8)-1) as usize);
        let encodemessage=match em {
            Ok(encodedmessage) => encodedmessage,
            Err(_) => {
                // panic!("Decryption failed");
                return Err(Error::DecryptionFailed);
            }
            
        };
        let m=self.get_oaep_decoded_message(&encodemessage,"rsa_simple".as_bytes())?;  // p is the label
        Ok(String::from_utf8(m).unwrap())

}
}