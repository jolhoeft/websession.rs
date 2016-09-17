extern crate pwhash;

use std::io;
use std::io::BufRead;
use pwhash::bcrypt;

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let plaintext = line.unwrap();
        let hash = bcrypt::hash(&plaintext).unwrap();
        println!("The hash of {} is {}", plaintext, hash);
    }
}
