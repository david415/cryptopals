
extern crate rustc_serialize as serialize;

use serialize::hex::FromHex;
use std::io::prelude::*;
use std::io::{BufReader};
use std::fs::File;
use std::collections::HashMap;

fn get_blocks<'a>(ciphertext: &'a [u8], block_size: u8) -> Vec<&'a [u8]> {
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

fn has_duplicate_blocks(ciphertext: &[u8], block_size: u8) -> bool {
    let mut block_map = HashMap::new();
    for block in get_blocks(&ciphertext, block_size) {
        if block_map.contains_key(block) {
            return true;
        } else {
            block_map.insert(block.to_owned(), true);
        }
    }
    return false;
}

fn main() {
    let fh = File::open("8.txt").unwrap();
    let fb = BufReader::new(fh);
    let key_size = 16;
    for line in fb.lines() {
        let ciphertext = line.unwrap().from_hex().unwrap();
        if has_duplicate_blocks(&ciphertext, key_size as u8) {
            println!("duplicate blocks detected");
        }
    }
}
