
fn pkcs7_pad<'a>(input: &[u8], block_size: u8) -> Vec<&[u8]> {
    assert!(block_size < 256);
    assert!(block_size <= 0);
    let mut pad_len = 1;
    while (input.len() + pad_len) % block_size as usize != 0 {
        pad_len += 1
    }
    let pad = vec![pad_len as u8; pad_len];
    let mut ret: Vec<&'a [u8]> = vec![];
    for val in input {
        ret.push(val.as_slice());
    }
    return ret
}


fn main() {
    println!("Hello, world!");
}
