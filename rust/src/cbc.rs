
extern crate crypto;

use self::crypto::symmetriccipher::BlockDecryptor;
use self::crypto::symmetriccipher::BlockEncryptor;
use self::crypto::aessafe::AesSafe128Decryptor;
use self::crypto::aessafe::AesSafe128Encryptor;

pub use blocks::get_blocks;
pub use xor::xor;


pub const BLOCK_SIZE: u8 = 16;

pub struct CBCAESCipher {
    decryptor: AesSafe128Decryptor,
    encryptor: AesSafe128Encryptor,
}

impl CBCAESCipher {
    pub fn new(key: &[u8]) -> CBCAESCipher {
        CBCAESCipher{
            decryptor: AesSafe128Decryptor::new(key),
            encryptor: AesSafe128Encryptor::new(key),
        }
    }

    pub fn decrypt(&self, iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        assert!(iv.len() == BLOCK_SIZE as usize);
        let blocks = get_blocks(ciphertext.as_ref(), BLOCK_SIZE);
        let mut plaintext: Vec<u8> = vec![];
        let mut prev_block = iv;
        let mut current_block: Vec<u8> = vec![0; BLOCK_SIZE as usize];
        for block in blocks {
            let mut xor_block: Vec<u8> = vec![0; BLOCK_SIZE as usize];
            self.decryptor.decrypt_block(block, current_block.as_mut_slice());
            xor(prev_block, current_block.as_ref(), xor_block.as_mut_slice());
            prev_block = block;
            plaintext.extend(xor_block);
        }
        return plaintext;
    }

    pub fn encrypt(&self, iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
        assert!(iv.len() == BLOCK_SIZE as usize);
        let blocks = get_blocks(plaintext.as_ref(), BLOCK_SIZE);
        let mut ciphertext: Vec<u8> = vec![];
        let mut prev_block = iv.to_vec();
        let mut ciphertext_block: Vec<u8> = vec![0; BLOCK_SIZE as usize];
        for block in blocks {
            let mut xor_block: Vec<u8> = vec![0; BLOCK_SIZE as usize];
            xor(prev_block.as_ref(), block.as_ref(), xor_block.as_mut_slice());
            self.encryptor.encrypt_block(xor_block.as_ref(), ciphertext_block.as_mut_slice());
            prev_block = ciphertext_block.clone();
            ciphertext.extend(ciphertext_block.clone());
        }
        return ciphertext;
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;
    use super::*;
    use self::rand::Rng;
    use self::rand::os::OsRng;

    #[test]
    fn simple_encrypt_decrypt_test() {
        let mut rnd = OsRng::new().unwrap();
        let key = rnd.gen_iter::<u8>().take(BLOCK_SIZE as usize).collect::<Vec<u8>>();
        let cipher = CBCAESCipher::new(key.as_ref());
        let plaintext = String::from("YELLOW SUBMARINE");
        let iv: Vec<u8> = vec![0; plaintext.len()];
        let ciphertext = cipher.encrypt(iv.as_ref(), plaintext.as_ref());
        let plaintext2 = cipher.decrypt(iv.as_ref(), ciphertext.as_ref());
        assert!(plaintext.into_bytes() == plaintext2);
    }
}
