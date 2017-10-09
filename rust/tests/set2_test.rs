
extern crate rustc_serialize as serialize;
extern crate cryptopals;

use serialize::hex::ToHex;
use serialize::base64::FromBase64;
use std::fs::File;
use std::io::prelude::*;


#[test]
fn challenge9() {
    let input = "YELLOW SUBMARINE";
    let block = cryptopals::padding::pkcs7_pad(input.as_ref(), 20);
    let out_str = String::from_utf8_lossy(block.as_ref());
    println!("{}", out_str);
    println!("{}", block.to_hex());
}

#[test]
fn challenge10() {
    let mut fh = File::open("../test_vectors/10.txt").unwrap();
    let mut content: Vec<u8> = Vec::new();
    fh.read_to_end(&mut content).unwrap();
    let ciphertext = content.from_base64().unwrap();
    let key_str = "YELLOW SUBMARINE";
    let iv = vec![0; 16];
    let cipher = cryptopals::cbc::CBCAESCipher::new(key_str.as_ref());
    let plaintext = cipher.decrypt(iv.as_ref(), ciphertext.as_ref());
    let out_str = String::from_utf8_lossy(plaintext.as_ref());
    println!("{}", out_str);
    assert!(out_str.contains("Play that funky music"));
}

#[test]
fn challenge11() {
    let plaintext = vec![12; cryptopals::ecb::BLOCK_SIZE as usize * 3];
    let ciphertext = cryptopals::challenge11::encrypt_oracle(plaintext.as_ref());
    if cryptopals::blocks::has_duplicate_blocks(ciphertext.as_ref(), cryptopals::ecb::BLOCK_SIZE) {
        println!("ECB mode detected");
    } else {
        println!("ECB mode NOT detected");
    }
}

#[test]
fn challenge12() {
    let oracle = cryptopals::challenge12::EncryptionOracle::new();
    let block_size = oracle.find_block_size();
    assert!(block_size == cryptopals::ecb::BLOCK_SIZE as i16);

    let plaintext = vec![12; cryptopals::ecb::BLOCK_SIZE as usize * 2];
    let ciphertext = oracle.encrypt(plaintext.as_ref());
    assert!(cryptopals::blocks::has_duplicate_blocks(ciphertext.as_ref(), cryptopals::ecb::BLOCK_SIZE) == true);

    let empty_input = vec![];
    let ciphertext = oracle.encrypt(empty_input.as_ref());
    let max_blocks = cryptopals::blocks::get_blocks(ciphertext.as_ref(), cryptopals::ecb::BLOCK_SIZE);

}
