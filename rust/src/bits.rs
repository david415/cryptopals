
use std::cmp::Ordering;

// return the number of bits set in the given byte
fn bit_set_count(v: u8) -> u8 {
    let mut r = v;
    r = (r & 0x55) + ((r >> 1) & 0x55);
    r = (r & 0x33) + ((r >> 2) & 0x33);
    return (r + (r >> 4)) & 0xF;
}

// return the bitwise hamming distance
pub fn hamming_distance(a: &[u8], b: &[u8]) -> u16 {
    assert!( a.len() == b.len() );
    let mut count = 0u16;
    for i in 0..a.len() {
        count += bit_set_count(a[i] ^ b[i]) as u16;
    }
    return count;
}

struct PotentialKeySize {
    distance: f32,
    key_size: u8,
}

impl PotentialKeySize {
    /// return a new potential_key_size struct
    fn new(distance: f32, key_size: u8) -> PotentialKeySize {
        PotentialKeySize{
            distance: distance,
            key_size: key_size,
        }
    }
}

impl PartialOrd for PotentialKeySize {
    fn partial_cmp(&self, other: &PotentialKeySize) -> Option<Ordering> {
        self.distance.partial_cmp(&other.distance)
    }
}

impl PartialEq for PotentialKeySize {
    fn eq(&self, other: &PotentialKeySize) -> bool {
        self.distance == other.distance
    }
}

// return the estimated key size using the key corresponding to the
// smallest normalized average hamming distance
pub fn estimate_key_size(ciphertext: &[u8]) -> u8 {
    let mut potentials: Vec<PotentialKeySize> = vec![];
    for key_size in 2..40 {
        let (sum, count) = (0..ciphertext.len()).skip(key_size)
            .filter(|j| key_size * (j + 3) <= ciphertext.len())
            .map(|i| hamming_distance(&ciphertext[key_size * i .. key_size * (i + 1)],
                                            &ciphertext[key_size * (i + 2) .. key_size * (i + 3)]) as f32)
            .fold((0., 0), |(sum, count), x| (sum + x, count + 1));
        let average = (sum / count as f32) / key_size as f32;
        let p = PotentialKeySize::new(average, key_size as u8);
        potentials.push(p);
    }

    let s = potentials.into_iter().fold(None, |min, x| match min {
        None => Some(x),
        Some(y) => Some(if x.distance < y.distance { x } else { y }),
    });
    return s.unwrap().key_size;
}
