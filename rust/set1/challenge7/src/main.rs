
extern crate rustc_serialize as serialize;
extern crate crypto;

use crypto::symmetriccipher::BlockDecryptor;
use crypto::aessafe::AesSafe128Decryptor;
use serialize::base64::{FromBase64};
use std::io::prelude::*;
use std::fs::File;

fn get_blocks<'a>(ciphertext: &'a [u8], block_size: u16) -> Vec<&'a [u8]> {
    let mut blocks: Vec<&'a [u8]> = vec![];
    let mut i = 0;
    for j in 0..ciphertext.len() {
        if i >= ciphertext.len() {
            break
        }
        if i + block_size as usize > ciphertext.len() {
            blocks.push(&ciphertext[i ..]);
        } else {
            blocks.push(&ciphertext[i .. i + block_size as usize]);
        }
        i += block_size as usize;
    }
    return blocks;
}

fn main() {
    let mut fh = File::open("7.txt").unwrap();
    let mut content: Vec<u8> = Vec::new();
    fh.read_to_end(&mut content).unwrap();
    let ciphertext = content.from_base64().unwrap();
    let key_size = 16;
    let key_str = "YELLOW SUBMARINE";
    let mut cipher = AesSafe128Decryptor::new(key_str.as_ref());
    let blocks = get_blocks(ciphertext.as_ref(), key_size);
    for block in blocks {
        let mut out_vec = vec![0; block.len()];
        cipher.decrypt_block(block, out_vec.as_mut_slice());
        let out_str = String::from_utf8_lossy(out_vec.as_ref());
        print!("{}", out_str);
    }
}
