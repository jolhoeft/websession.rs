#![forbid(unsafe_code)]

use crate::sessionpolicy::SessionPolicy;
use crate::token::Token;
use std::fmt;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnectionSignature {
    pub token: Token,
}

impl fmt::Display for ConnectionSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.token.fmt(f)
    }
}

impl ConnectionSignature {
    pub fn new(secret: &str) -> ConnectionSignature {
        ConnectionSignature {
            token: Token::new_from_str(secret),
        }
    }

    pub fn new_from_policy(policy: &SessionPolicy) -> ConnectionSignature {
        ConnectionSignature {
            token: Token::new(&policy.salt),
        }
    }

    pub fn get_token(&self) -> Token {
        self.token.clone()
    }
}
