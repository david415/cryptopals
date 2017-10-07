
use std::f32;
use std::cmp::Ordering;

pub use xor::xor_with_one;

macro_rules! map(
    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = ::std::collections::HashMap::new();
            $(
                m.insert($key, $value);
            )+
                m
        }
    };
);

fn remove_spaces(input: &str) -> String {
    let mut buf = String::with_capacity(input.len());
    for c in input.chars() {
        if !c.is_whitespace() {
            buf.push(c);
        }
    }
    return buf;
}

fn count_char(s: &str, m: char) -> usize {
    s.chars().filter(|&c| c == m).count()
}

fn percent_char(s: &str, m: char) -> f32 {
    let c = count_char(s, m);
    if c != 0 {
        return 100 as f32 / (s.len() as f32 / c as f32)
    }
    return 0 as f32
}

fn near(n: f32, exact: f32) -> bool {
    let slop = 3_f32;
    if n > 5 as f32 {
        if n > exact - slop {
            return true
        }
        return false
    } else {
        if n > exact - 0.25 {
            return true
        }
    }
    return false
}

fn english_score(s: &str) -> u8 {
    let letter_freq = map!{
        "a" => 8.167_f32,
	"b" => 1.492_f32,
	"c" => 2.782_f32,
	"d" => 4.253_f32,
	"e" => 12.702_f32,
	"f" => 2.228_f32,
	"g" => 2.015_f32,
	"h" => 6.094_f32,
	"i" => 7.294_f32,
	"j" => 0.511_f32,
	"k" => 0.456_f32,
	"l" => 2.415_f32,
	"m" => 3.826_f32,
	"n" => 2.284_f32,
	"o" => 7.631_f32,
	"p" => 4.319_f32,
	"q" => 0.222_f32,
	"r" => 2.826_f32,
	"s" => 6.686_f32,
	"t" => 15.978_f32,
	"u" => 1.183_f32,
	"v" => 0.824_f32,
	"w" => 5.497_f32,
	"x" => 0.045_f32,
	"y" => 0.763_f32,
	"z" => 0.045_f32
    };
    let mut score = 0;
    if near(percent_char(s.as_ref() as &str, " ".chars().next().unwrap()), 15 as f32) {
        score += 1
    } else {
        return 0 as u8;
    }
    let lowered = s.to_lowercase();
    let washed = remove_spaces(lowered.as_ref() as &str);
    for (letter, freq) in letter_freq {
        if near(percent_char(washed.as_ref() as &str, letter.chars().next().unwrap()), freq) {
            score += 1
        }
    }
    return score as u8;
}

pub fn get_single_xor_score(input: &[u8]) -> (u8, u8) {
    let mut out_vec = vec![0; input.len()];
    let mut key = 0;
    let mut high_score = 0;
    for i in 0..255 {
        xor_with_one(&input, i as u8, &mut out_vec);
        let out_str = String::from_utf8_lossy(out_vec.as_ref());
        let score = english_score(out_str.as_ref());
        if high_score < score {
            high_score = score;
            key = i as u8;
        }
    }
    return (high_score, key);
}
