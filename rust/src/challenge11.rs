
extern crate rand;
use self::rand::Rng;
use self::rand::os::OsRng;

use cbc::BLOCK_SIZE;
use cbc::CBCAESCipher;
use ecb::ECBAESCipher;


pub fn encrypt_oracle(plaintext: &[u8]) -> Vec<u8> {
    let mut rnd = OsRng::new().unwrap();
    let key = rnd.gen_iter::<u8>().take(BLOCK_SIZE as usize).collect::<Vec<u8>>();
    let mode = rand::thread_rng().gen_range(0, 2);
    let ciphertext: Vec<u8>;
    if mode == 0 {
        let cipher = ECBAESCipher::new(key.as_ref());
        ciphertext = cipher.encrypt(plaintext);
    } else {
        let cipher = CBCAESCipher::new(key.as_ref());
        let iv = rnd.gen_iter::<u8>().take(BLOCK_SIZE as usize).collect::<Vec<u8>>();
        ciphertext = cipher.encrypt(iv.as_ref(), plaintext);
    }
    let prefix_len = rand::thread_rng().gen_range(5, 11);
    let suffix_len = rand::thread_rng().gen_range(5, 11);
    let prefix = vec![0; prefix_len];
    let suffix = vec![0; suffix_len];
    let mut output = vec![];
    output.extend(prefix);
    output.extend(ciphertext);
    output.extend(suffix);
    return output;
}
