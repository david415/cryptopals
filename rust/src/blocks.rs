
use std::collections::HashMap;

pub fn get_nth_block(ciphertext: &[u8], nth: u8, block_size: u8) -> Result<&[u8], &str> {
    let nth_block = nth as usize * block_size as usize;
    if nth_block > ciphertext.len() {
        return Err("block index exceeds length of input");
    }
    if nth_block + (block_size as usize) < ciphertext.len() {
        Ok(&ciphertext[nth_block .. nth_block + block_size as usize])
    } else {
        Ok(&ciphertext[nth_block .. ciphertext.len()])
    }
}

pub fn get_blocks(ciphertext: &[u8], block_size: u8) -> Vec<&[u8]> {
    let mut blocks: Vec<&[u8]> = vec![];
    let mut i = 0;
    for _ in 0..ciphertext.len() {
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

pub fn transpose_blocks(blocks: Vec<&[u8]>) -> Vec<Vec<u8>> {
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

pub fn has_duplicate_blocks(ciphertext: &[u8], block_size: u8) -> bool {
    let mut block_map = HashMap::new();
    for block in get_blocks(&ciphertext, block_size) {
        if block_map.contains_key(block) {
            return true;
        } else {
            block_map.insert(block.to_owned(), true);
        }
    }
    return false;
}
