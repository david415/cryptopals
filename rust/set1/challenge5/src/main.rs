
extern crate rustc_serialize as serialize;

use serialize::hex::ToHex;


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
    let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let key = "ICE";
    let mut out_vec = vec![0; input.len()];
    repeat_xor(key.as_ref(), input.as_ref(), out_vec.as_mut_slice());
    println!("{}\n", out_vec.to_hex());
}
