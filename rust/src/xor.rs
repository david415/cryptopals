
pub fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    assert!( x.len() == y.len() && x.len() == output.len() );
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}

pub fn xor_with_one(x: &[u8], y: u8, output: &mut [u8]) {
    assert!( x.len() == output.len() );
    for i in 0..x.len() {
        output[i] = x[i] ^ y
    }
}

pub fn repeat_xor(key: &[u8], input: &[u8], output: &mut [u8]) {
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
