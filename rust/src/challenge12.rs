
extern crate rand;
extern crate rustc_serialize as serialize;
use self::rand::Rng;
use self::rand::os::OsRng;
use self::serialize::base64::FromBase64;

use ecb::ECBAESCipher;
use ecb::BLOCK_SIZE;
use blocks::{get_nth_block, get_blocks};
use padding::pkcs7_pad;

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
}

/// given a block cipher encryption oracle which appends
/// an unknown string to the input before encrypting...
/// find the block size
pub fn find_block_size(oracle: &EncryptionOracle) -> i16 {
    let mut prev_delta = 0;
    let empty_input = vec![];
    let ciphertext = oracle.encrypt(empty_input.as_ref());
    let cipher_size = ciphertext.len() as i16;
    for i in 0 .. 100 {
        let input = vec![0; i];
        let output = oracle.encrypt(input.as_ref());
        let delta = output.len() as i16 - input.len() as i16;
        let offset = delta - prev_delta;
        if offset != cipher_size && offset+1 != 0 {
            return offset + 1;
        }
        prev_delta = delta;
    }
    return 0;
}

/// create_retrieval_data is used to create an input to the oracle so that we can
/// retrieve  ciphertext to break via our reverse hashmap
pub fn create_retrieval_data(block_size: u8, block_offset: u8) -> Vec<u8> {
    return vec![0x41; (block_size as usize - (block_offset as usize + 1))];
}

// create_trial_data is used to generate oracle input for generating our reverse hashmap
pub fn create_trial_data(block_size: u8, block_index: u8, block_offset: u8, max_blocks: u8, plaintext: &[u8], current_block_plaintext: &[u8], last_byte: u8) -> Vec<u8> {
    let mut output = vec![];
    if block_size - (block_offset + 1) != 0 {
        output = vec![0x41; block_size as usize - (block_offset as usize + 1)];
    }
    if plaintext.len() > 0 {
        output.extend(plaintext);
    }
    if current_block_plaintext.len() > 0 {
        output.extend(current_block_plaintext);
    }
    output.push(last_byte);
    if block_index == max_blocks - 1 {
        let mut padded = vec![];
        {
            let blocks = get_blocks(&output, block_size);
            if blocks[block_index as usize].len() < block_size as usize {
                padded = pkcs7_pad(&blocks[block_index as usize], block_size);
            }
        }
        output.extend(padded);
    }
    return output;
}

pub fn break_oracle_string(max_blocks: u8, block_size: u8, oracle: &EncryptionOracle) -> Vec<u8> {
    let mut plaintext = vec![];
    for block_index in 0 .. max_blocks {
        let mut block_plaintext = vec![];
        for block_offset in 0 .. block_size {
            let mut last_map = ::std::collections::HashMap::with_capacity(500);
            for val in 0 .. 256_u16{
                let input = create_trial_data(block_size, block_index, block_offset, max_blocks, &plaintext, &block_plaintext, val as u8);
                let ciphertext = oracle.encrypt(&input);
                let block = get_nth_block(&ciphertext, block_index, block_size).unwrap();
                let map_key = block.to_owned();
                if last_map.contains_key(&map_key) {
                    return vec![]; // XXX add error handling here
                }
                last_map.insert(map_key, val as u8);
            }
            assert!(last_map.len() == 256);
            let input = create_retrieval_data(block_size, block_offset);
            let ciphertext = oracle.encrypt(&input);
            let block = get_nth_block(&ciphertext, block_index, block_size).unwrap();
            let map_key = block.to_owned();
            if !last_map.contains_key(&map_key) {
                continue
            }
            block_plaintext.push(last_map[&map_key]);
        }
        plaintext.extend(block_plaintext);
    }
    return plaintext;
}
