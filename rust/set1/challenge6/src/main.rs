
extern crate rustc_serialize as serialize;

use serialize::base64::{FromBase64};
use std::io::prelude::*;
use std::fs::File;
use std::f32;
use std::cmp::Ordering;

macro_rules! map(
    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = ::std::collections::HashMap::new();
            $(
                m.insert($key, $value);
            )+
                m
        }
    };
);

struct PotentialKeySize {
    distance: f32,
    key_size: u16,
}

impl PotentialKeySize {
    /// return a new potential_key_size struct
    fn new(distance: f32, key_size: u16) -> PotentialKeySize {
        PotentialKeySize{
            distance: distance,
            key_size: key_size,
        }
    }
}

impl PartialOrd for PotentialKeySize {
    fn partial_cmp(&self, other: &PotentialKeySize) -> Option<Ordering> {
        self.distance.partial_cmp(&other.distance)
    }
}

impl PartialEq for PotentialKeySize {
    fn eq(&self, other: &PotentialKeySize) -> bool {
        self.distance == other.distance
    }
}

// return the number of bits set in the given byte
fn bit_set_count(v: u8) -> u8 {
    let mut r = v;
    r = (r & 0x55) + ((r >> 1) & 0x55);
    r = (r & 0x33) + ((r >> 2) & 0x33);
    return (r + (r >> 4)) & 0xF;
}

// return the bitwise hamming distance
fn hamming_distance(a: &[u8], b: &[u8]) -> u16 {
    assert!( a.len() == b.len() );
    let mut count = 0u16;
    for i in 0..a.len() {
        count += bit_set_count(a[i] ^ b[i]) as u16;
    }
    return count;
}

// return the estimated key size using the key corresponding to the
// smallest normalized average hamming distance
fn estimate_key_size(ciphertext: &[u8]) -> u16 {
    let mut potentials: Vec<PotentialKeySize> = vec![];
    for key_size in 2..40 {
        let mut distances: Vec<f32> = vec![];
        for i in (0..ciphertext.len()).take(key_size) {
            if key_size * (i + 3) > ciphertext.len() {
                break
            }
            let a = ciphertext.to_vec();
            let b = ciphertext.to_vec();
            let distance = hamming_distance(&a[key_size * i .. key_size * (i + 1)],
                                            &b[key_size * (i + 2) .. key_size * (i + 3)]) as f32;
            distances.push(distance);
        }
        let sum = distances.iter().fold(0_f32, |mut sum, &x| {sum += x; sum});
        let average = (sum / distances.len() as f32) / key_size as f32;
        let p = PotentialKeySize::new(average, key_size as u16);
        potentials.push(p);
    }

    let s = potentials.into_iter().fold(None, |min, x| match min {
        None => Some(x),
        Some(y) => Some(if x.distance < y.distance { x } else { y }),
    });
    return s.unwrap().key_size;
}

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

fn transpose_blocks(blocks: Vec<&[u8]>) -> Vec<Vec<u8>> {
    let mut output = vec![];
    for j in 0..(blocks[0].len()) as usize {
        output.push(vec![]);
        for i in 0..blocks.len() as usize {
            if j < blocks[i].len() {
                output[j].push(blocks[i][j])
            } else {
                break
            }
        }
    }
    return output;
}

fn xor_with_one(x: &[u8], y: u8, output: &mut [u8]) {
    assert!( x.len() == output.len() );
    for i in 0..x.len() {
        output[i] = x[i] ^ y
    }
}

fn remove_spaces(input: &str) -> String {
    let mut buf = String::with_capacity(input.len());
    for c in input.chars() {
        if !c.is_whitespace() {
            buf.push(c);
        }
    }
    return buf;
}

fn count_char(s: &str, m: char) -> usize {
    s.chars().filter(|&c| c == m).count()
}

fn percent_char(s: &str, m: char) -> f32 {
    let c = count_char(s, m);
    if c != 0 {
        return 100 as f32 / (s.len() as f32 / c as f32)
    }
    return 0 as f32
}

fn near(n: f32, exact: f32) -> bool {
    let slop = 3_f32;
    if n > 5 as f32 {
        if n > exact - slop {
            return true
        }
        return false
    } else {
        if n > exact - 0.25 {
            return true
        }
    }
    return false
}

fn english_score(s: &str) -> u8 {
    let letter_freq = map!{
        "a" => 8.167_f32,
	"b" => 1.492_f32,
	"c" => 2.782_f32,
	"d" => 4.253_f32,
	"e" => 12.702_f32,
	"f" => 2.228_f32,
	"g" => 2.015_f32,
	"h" => 6.094_f32,
	"i" => 7.294_f32,
	"j" => 0.511_f32,
	"k" => 0.456_f32,
	"l" => 2.415_f32,
	"m" => 3.826_f32,
	"n" => 2.284_f32,
	"o" => 7.631_f32,
	"p" => 4.319_f32,
	"q" => 0.222_f32,
	"r" => 2.826_f32,
	"s" => 6.686_f32,
	"t" => 15.978_f32,
	"u" => 1.183_f32,
	"v" => 0.824_f32,
	"w" => 5.497_f32,
	"x" => 0.045_f32,
	"y" => 0.763_f32,
	"z" => 0.045_f32
    };
    let mut score = 0;
    if near(percent_char(s.as_ref() as &str, " ".chars().next().unwrap()), 15 as f32) {
        score += 1
    } else {
        return 0 as u8;
    }
    let lowered = s.to_lowercase();
    let washed = remove_spaces(lowered.as_ref() as &str);
    for (letter, freq) in letter_freq {
        if near(percent_char(washed.as_ref() as &str, letter.chars().next().unwrap()), freq) {
            score += 1
        }
    }
    return score as u8;
}

fn get_single_xor_score(input: &[u8]) -> (u8, u8) {
    let mut out_vec = vec![0; input.len()];
    let mut key = 0;
    let mut high_score = 0;
    for i in 0..255 {
        xor_with_one(&input, i as u8, &mut out_vec);
        let out_str = String::from_utf8_lossy(out_vec.as_ref());
        let score = english_score(out_str.as_ref());
        if high_score < score {
            high_score = score;
            key = i as u8;
        }
    }
    return (high_score, key);
}

fn repeat_xor(key: &[u8], input: &[u8], output: &mut [u8]) {
    let mut done = false;
    let mut i = 0;
    let mut j = 0;
    while !done {
        output[i] = input[i] ^ key[j];
        if j < key.len()-1 {
            j += 1
        } else {
            j = 0
        }
        if i == output.len()-1 {
            done = true;
        }
        i += 1
    }
}

fn main() {
    let mut fh = File::open("6.txt").unwrap();
    let mut content: Vec<u8> = Vec::new();
    fh.read_to_end(&mut content).unwrap();
    let ciphertext = content.from_base64().unwrap();
    let key_size = estimate_key_size(ciphertext.as_ref());
    let blocks = get_blocks(ciphertext.as_ref(), key_size);
    let transposed = transpose_blocks(blocks);
    let mut key = vec![];
    for block in transposed {
        let (score, single_key) = get_single_xor_score(block.as_ref());
        key.push(single_key);
    }
    let mut out_vec = vec![0; ciphertext.len()];
    repeat_xor(key.as_ref(), ciphertext.as_ref(), out_vec.as_mut_slice());
    let out_str = String::from_utf8_lossy(out_vec.as_ref());
    let key_str = String::from_utf8_lossy(key.as_ref());
    println!("key {}", key_str);
    println!("plaintext {}", out_str);
}


#[cfg(test)]
mod tests {
    use super::{hamming_distance, get_blocks, transpose_blocks, english_score};
    use std::io::prelude::*;
    use std::fs::File;

    #[test]
    fn hamming_distance_test() {
        let input1 = "this is a test";
        let input2 = "wokka wokka!!!";
        let distance = hamming_distance(input1.as_ref(), input2.as_ref());
        assert_eq!(distance, 37);
    }

    #[test]
    fn english_score_test() {
        let mut fh = File::open("1984.txt").unwrap();
        let mut content: Vec<u8> = Vec::new();
        fh.read_to_end(&mut content).unwrap();
        let block_size = 7;
        let blocks = get_blocks(content.as_ref(), block_size);
        let transposed = transpose_blocks(blocks);
        for block in transposed {
            let block_str = String::from_utf8_lossy(block.as_ref());
            let score = english_score(block_str.as_ref());
            assert!(score != 0);
        }
    }
}
