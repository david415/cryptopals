
pub fn pkcs7_pad(input: &[u8], block_size: u8) -> Vec<u8> {
    let mut pad_len = 1;
    while (input.len() + pad_len) % block_size as usize != 0 {
        pad_len += 1
    }
    let pad = vec![pad_len as u8; pad_len];
    let mut ret: Vec<u8> = vec![];
    ret.extend_from_slice(input);
    ret.extend(pad);
    return ret
}
