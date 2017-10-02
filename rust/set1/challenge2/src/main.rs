
extern crate rustc_serialize as serialize;

use serialize::hex::ToHex;
use serialize::hex::FromHex;


/// Simple slice xor function modified from:
/// https://github.com/DaGenix/rust-crypto/blob/master/src/scrypt.rs
pub fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    assert!( x.len() == y.len() && x.len() == output.len() );
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}

fn main() {
    let input1 = "1c0111001f010100061a024b53535009181c";
    let input2 = "686974207468652062756c6c277320657965";
    let input1_bytes = input1.from_hex().unwrap();
    let input2_bytes = input2.from_hex().unwrap();
    let mut out_vec = vec![0; input1_bytes.len()];
    xor(&input1_bytes, &input2_bytes, &mut out_vec);
    let hex_output = out_vec.to_hex();
    println!("{}", hex_output);
}
