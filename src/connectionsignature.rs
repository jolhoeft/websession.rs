#![forbid(unsafe_code)]

#[cfg(feature = "hyper")]
use hyper::header::Cookie;
#[cfg(feature = "hyper")]
use hyper::server::Request;

use sessionpolicy::SessionPolicy;
use std::fmt;
use token::Token;

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

    #[cfg(feature = "hyper")]
    pub fn new_hyper(
        req: &Request,
        cookie_name: &str,
        policy: &SessionPolicy,
    ) -> ConnectionSignature {
        // for unsecured cookies key = [0u8; 32], i.e. 32 zero bytes
        // Warning: this is untested
        match req.headers().get::<Cookie>() {
            Some(c) => match c.get(cookie_name) {
                Some(c) => ConnectionSignature { token: Token::new(c) },
                None => ConnectionSignature::new_from_policy(policy),
            },
            None => ConnectionSignature::new_from_policy(policy),
        }
    }
}
