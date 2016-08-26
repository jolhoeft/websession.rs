extern crate uuid;

use uuid::Uuid;

#[derive(Copy, Eq, PartialEq, Debug, Clone, Hash)]
pub struct Token {
    uuid: Uuid,
}

impl Token {
    // I sort of don't want this public - maybe it needs to move back into
    // lib.rs?
    pub fn new() -> Token {
        Token {
            uuid: Uuid::new_v4()
        }
    }
}
