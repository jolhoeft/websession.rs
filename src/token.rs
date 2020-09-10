#![forbid(unsafe_code)]

extern crate uuid;

use sha2::{Digest, Sha256};
use std::fmt;
use std::ops::Deref;
use uuid::Uuid;

#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct Token {
    key: String,
}

impl Token {
    // I sort of don't want this public - maybe it needs to move back into
    // lib.rs?
    pub fn new(secret: &str) -> Token {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(Uuid::new_v4().to_string().deref());
        Token {
            key: format!("{:x}", hasher.finalize()),
        }
    }

    pub fn new_from_str(key: &str) -> Token {
        Token {
            key: key.to_string(),
        }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.key)
    }
}
