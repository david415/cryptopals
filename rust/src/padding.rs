
pub fn pkcs7_pad(input: &[u8], block_size: u8) -> Vec<u8> {
    assert!(input.len() <= block_size as usize);
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

// pub fn pkcs7_unpad(input: &[u8], block_size: u8) -> Vec<u8> {
//     assert!(input.len() == block_size as usize);
//     let pad_len: u8 = input[input.len()-1];
//     assert!(pad_len <= block_size);
//     assert!(pad_len != 0);
//     let pad = &input[input.len() - pad_len as usize ..];
//     for i in 0 .. pad_len {
//         assert!(pad[i] == pad_len);
//     }
//     if pad_len == block_size {
//         return vec![];
//     } else {
//         return input[0 .. input.len() - pad_len as usize].to_vec();
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic1_padding_test() {
        let input = String::from("YELLOW SUBMARINE");
        let block = pkcs7_pad(input.as_ref(), 20);
        assert!(block.len() == 20);
    }
    #[test]
    fn basic2_padding_test() {
        let input = String::from("YELLOW SUBMARINE");
        let block = pkcs7_pad(input.as_ref(), 16);
        assert!(block.len() == 32);
    }
}
