
extern crate crypto;

use self::crypto::symmetriccipher::BlockDecryptor;
use self::crypto::aessafe::AesSafe128Decryptor;

pub use blocks::get_blocks;

pub const BLOCK_SIZE: u8 = 16;

pub struct ECBAESCipher {
    decryptor: AesSafe128Decryptor,
}

impl ECBAESCipher {
    pub fn new(key: &[u8]) -> ECBAESCipher {
        ECBAESCipher{
            decryptor: AesSafe128Decryptor::new(key),
        }
    }

    pub fn decrypt<'a>(&self, ciphertext: &[u8]) -> Vec<u8> {
        let blocks = get_blocks(ciphertext.as_ref(), BLOCK_SIZE);
        let mut plaintext: Vec<u8> = vec![];
        for block in blocks {
            let mut out_vec: Vec<u8> = vec![0; BLOCK_SIZE as usize];
            self.decryptor.decrypt_block(block, out_vec.as_mut_slice());
            plaintext.extend(out_vec);
        }
        return plaintext;
    }
}
