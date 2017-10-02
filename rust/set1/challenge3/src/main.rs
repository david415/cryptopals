
extern crate rustc_serialize as serialize;

use std::f32;
use serialize::hex::FromHex;

fn xor_with_one(x: &[u8], y: u8, output: &mut [u8]) {
    assert!( x.len() == output.len() );
    for i in 0..x.len() {
        output[i] = x[i] ^ y
    }
}

fn count(s: &str, m: char) -> usize {
    s.chars().filter(|&c| c == m).count()
}

fn percent_char(s: &str, m: char) -> f32 {
    let c = count(s, m);
    if c != 0 {
        return 100 as f32 / (s.len() as f32 / c as f32)
    }
    return 0 as f32
}

fn is_fit(s: String) -> bool {
    let mut fit_count = 0;
    if !s.contains(" ") {
        return false
    }
    if percent_char(s.as_ref() as &str, "a".chars().next().unwrap()) >= 8 as f32{
        fit_count += 1
    }
    if percent_char(s.as_ref() as &str, "e".chars().next().unwrap()) >= 12 as f32{
        fit_count += 1
    }
    if percent_char(s.as_ref() as &str, "i".chars().next().unwrap()) >= 6 as f32{
        fit_count += 1
    }
    if percent_char(s.as_ref() as &str, "o".chars().next().unwrap()) >= 7 as f32{
        fit_count += 1
    }
    if percent_char(s.as_ref() as &str, "u".chars().next().unwrap()) >= 2 as f32{
        fit_count += 1
    }
    if percent_char(s.as_ref() as &str, "y".chars().next().unwrap()) >= 1 as f32{
        fit_count += 1
    }
    if fit_count >= 2 {
        return true
    }
    return false
}

fn main() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let input_bytes = input.from_hex().unwrap();
    let mut out_vec = vec![0; input_bytes.len()];
    for i in 0..255 {
        xor_with_one(&input_bytes, i as u8, &mut out_vec);
        let out_str = String::from_utf8_lossy(out_vec.as_ref());
        if is_fit(out_str.to_string()) {
            println!("{}\n", out_str);
        }
    }
}
