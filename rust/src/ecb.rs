
extern crate crypto;

use self::crypto::symmetriccipher::BlockDecryptor;
use self::crypto::aessafe::AesSafe128Decryptor;
use self::crypto::symmetriccipher::BlockEncryptor;
use self::crypto::aessafe::AesSafe128Encryptor;

use blocks::get_blocks;
use padding::{pkcs7_pad, pkcs7_unpad};

pub const BLOCK_SIZE: u8 = 16;

pub struct ECBAESCipher {
    decryptor: AesSafe128Decryptor,
    encryptor: AesSafe128Encryptor,
}

impl ECBAESCipher {
    pub fn new(key: &[u8]) -> ECBAESCipher {
        assert!(key.len() == BLOCK_SIZE as usize);
        ECBAESCipher{
            decryptor: AesSafe128Decryptor::new(key),
            encryptor: AesSafe128Encryptor::new(key),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let blocks = get_blocks(ciphertext.as_ref(), BLOCK_SIZE);
        let mut plaintext: Vec<u8> = vec![];
        for i in 0 .. blocks.len() {
            let mut out_vec: Vec<u8> = vec![0; BLOCK_SIZE as usize];
            self.decryptor.decrypt_block(blocks[i], out_vec.as_mut_slice());
            assert!(out_vec.len() == BLOCK_SIZE as usize);
            if i == blocks.len() - 1 {
                let unpadded = pkcs7_unpad(&out_vec, BLOCK_SIZE);
                if unpadded.len() != 0 {
                    plaintext.extend(unpadded);
                }
            } else {
                plaintext.extend(out_vec);
            }
        }
        return plaintext;
    }

    pub fn encrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let blocks = get_blocks(ciphertext.as_ref(), BLOCK_SIZE);
        let mut plaintext: Vec<u8> = vec![];
        for i in 0 .. blocks.len() {
            if i == blocks.len() - 1 {
                let padded_block = pkcs7_pad(blocks[i], BLOCK_SIZE);
                let padded_blocks = get_blocks(padded_block.as_ref(), BLOCK_SIZE);
                for j in 0 .. padded_blocks.len() {
                    let mut out_vec: Vec<u8> = vec![0; BLOCK_SIZE as usize];
                    self.encryptor.encrypt_block(padded_blocks[j].as_ref(), out_vec.as_mut_slice());
                    plaintext.extend(out_vec);
                }
            } else {
                let mut out_vec: Vec<u8> = vec![0; BLOCK_SIZE as usize];
                self.encryptor.encrypt_block(blocks[i], out_vec.as_mut_slice());
                plaintext.extend(out_vec);
            }
        }
        return plaintext;
    }
}
