extern crate uuid;
extern crate crypto;

use uuid::Uuid;
use std::ops::Deref;
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;

#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct Token {
    key: String,
}

impl Token {
    // I sort of don't want this public - maybe it needs to move back into
    // lib.rs?
    pub fn new(secret: &str) -> Token {
        let mut hasher = Sha256::new();
        hasher.input_str(secret);
        hasher.input_str(Uuid::new_v4().to_string().deref());
        Token {
            key: hasher.result_str(),
        }
    }

    pub fn new_from_str(key: &str) -> Token {
        Token {
            key: key,
        }
    }
}
