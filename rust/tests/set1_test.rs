extern crate rustc_serialize as serialize;
extern crate cryptopals;

use serialize::base64::{self, FromBase64, ToBase64};
use serialize::hex::FromHex;
use serialize::hex::ToHex;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader};


#[test]
fn challenge1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let result = input.from_hex().unwrap().to_base64(base64::STANDARD);
    let out = format!("{}", result);
    assert!(out == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

#[test]
fn challenge2() {
    let input1 = "1c0111001f010100061a024b53535009181c";
    let input2 = "686974207468652062756c6c277320657965";
    let input1_bytes = input1.from_hex().unwrap();
    let input2_bytes = input2.from_hex().unwrap();
    let mut out_vec = vec![0; input1_bytes.len()];
    cryptopals::xor::xor(&input1_bytes, &input2_bytes, &mut out_vec);
    let hex_output = out_vec.to_hex();
    let out_str = format!("{}", hex_output);
    assert!(out_str == "746865206b696420646f6e277420706c6179");
}

#[test]
fn challenge3() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let input_bytes = input.from_hex().unwrap();
    let mut out_vec = vec![0; input_bytes.len()];
    let (_, single_key) = cryptopals::english::get_single_xor_score(input_bytes.as_ref());
    cryptopals::xor::xor_with_one(&input_bytes, single_key, &mut out_vec);
    let out_str = String::from_utf8_lossy(out_vec.as_ref());
    assert!(out_str == "Cooking MC's like a pound of bacon");
    println!("{}", out_str);
}

#[test]
fn challenge4() {
    let fh = File::open("../test_vectors/4.txt").expect("file not found");
    let fb = BufReader::new(fh);
    let mut high_score = 0;
    let mut plaintext = vec![];
    for line in fb.lines() {
        let input_bytes = line.unwrap().from_hex().unwrap();
        let (score, single_key) = cryptopals::english::get_single_xor_score(input_bytes.as_ref());
        if score != 0 {
            let mut out_vec = vec![0; input_bytes.len()];
            cryptopals::xor::xor_with_one(&input_bytes, single_key, &mut out_vec);
            if score > high_score {
                high_score = score;
                plaintext = out_vec;
            }
        }
    }
    let out_str = String::from_utf8_lossy(plaintext.as_ref());
    println!("{}", out_str);
    assert!(out_str == "Now that the party is jumping\n");
}

#[test]
fn challenge5() {
    let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let key_str = "ICE";
    let mut out_vec = vec![0; input.len()];
    cryptopals::xor::repeat_xor(key_str.as_ref(), input.as_ref(), out_vec.as_mut_slice());
    let hex_output = out_vec.to_hex();
    let out_str = format!("{}", hex_output);
    assert!(out_str == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
}

#[test]
fn challenge6() {
    let mut fh = File::open("../test_vectors/6.txt").unwrap();
    let mut content: Vec<u8> = Vec::new();
    fh.read_to_end(&mut content).unwrap();
    let ciphertext = content.from_base64().unwrap();
    let key_size = cryptopals::bits::estimate_key_size(ciphertext.as_ref());
    let blocks = cryptopals::blocks::get_blocks(ciphertext.as_ref(), key_size);
    let transposed = cryptopals::blocks::transpose_blocks(blocks);
    let mut key = vec![];
    for block in transposed {
        let (_, single_key) = cryptopals::english::get_single_xor_score(block.as_ref());
        key.push(single_key);
    }
    let mut out_vec = vec![0; ciphertext.len()];
    cryptopals::xor::repeat_xor(key.as_ref(), ciphertext.as_ref(), out_vec.as_mut_slice());
    let out_str = String::from_utf8_lossy(out_vec.as_ref());
    let key_str = String::from_utf8_lossy(key.as_ref());
    println!("key {}", key_str);
    println!("plaintext {}", out_str);
    assert!(out_str.contains("Let the witch doctor"));
}

#[test]
fn challenge7() {
    let mut fh = File::open("../test_vectors/7.txt").unwrap();
    let mut content: Vec<u8> = Vec::new();
    fh.read_to_end(&mut content).unwrap();
    let ciphertext = content.from_base64().unwrap();
    let key_str = "YELLOW SUBMARINE";
    let cipher = cryptopals::ecb::ECBAESCipher::new(key_str.as_ref());
    let plaintext = cipher.decrypt(ciphertext.as_ref());
    let out_str = String::from_utf8_lossy(plaintext.as_ref());
    print!("{}", out_str);
    assert!(out_str.contains("funky music"));
}

#[test]
fn challenge8() {
    let fh = File::open("../test_vectors/8.txt").unwrap();
    let fb = BufReader::new(fh);
    let key_size: u8 = 16;
    for line in fb.lines() {
        let ciphertext = line.unwrap().from_hex().unwrap();
        if cryptopals::blocks::has_duplicate_blocks(&ciphertext, key_size) {
            println!("duplicate blocks detected");
        }
    }
}
