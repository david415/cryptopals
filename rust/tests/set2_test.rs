
extern crate rustc_serialize as serialize;
extern crate cryptopals;

use serialize::hex::ToHex;


#[test]
fn challenge9() {
    let input = "YELLOW SUBMARINE";
    let block = cryptopals::padding::pkcs7_pad(input.as_ref(), 20);
    let out_str = String::from_utf8_lossy(block.as_ref());
    println!("{}", out_str);
    println!("{}", block.to_hex());
}
