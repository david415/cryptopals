
extern crate rand;
extern crate rustc_serialize as serialize;
use self::rand::Rng;
use self::rand::os::OsRng;
use self::serialize::base64::FromBase64;

use ecb::ECBAESCipher;
use ecb::BLOCK_SIZE;

pub struct EncryptionOracle {
    cipher: ECBAESCipher,
}

impl EncryptionOracle {
    pub fn new() -> EncryptionOracle {
        let mut rnd = OsRng::new().unwrap();
        let key = rnd.gen_iter::<u8>().take(BLOCK_SIZE as usize).collect::<Vec<u8>>();
        EncryptionOracle{
            cipher: ECBAESCipher::new(key.as_ref()),
        }
    }

    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let mut plaintext = vec![];
        let suffix_str = String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        let suffix = suffix_str.from_base64().unwrap();
        plaintext.extend(input);
        plaintext.extend(suffix);
        let out = self.cipher.encrypt(plaintext.as_ref());
        return out;
    }

    pub fn find_block_size(&self) -> i16 {
        let mut prev_delta = 0;
        let empty_input = vec![];
        let ciphertext = self.encrypt(empty_input.as_ref());
        let cipher_size = ciphertext.len() as i16;
        for i in 0 .. 100 {
            let input = vec![0; i];
            let output = self.encrypt(input.as_ref());
            let delta = output.len() as i16 - input.len() as i16;
            let offset = delta - prev_delta;
            if offset != cipher_size && offset+1 != 0 {
                return offset + 1;
            }
            prev_delta = delta;
        }
        return 0;
    }
}
