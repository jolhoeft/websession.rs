#[cfg(feature = "hyper")]
use hyper::server::request::Request;

use token::Token;
use sessionpolicy::SessionPolicy;

#[derive(Debug, Clone, Hash)]
pub struct ConnectionSignature {
    policy: SessionPolicy,
    pub token: Token,
}

impl PartialEq for ConnectionSignature {
    fn eq(&self, other: &ConnectionSignature) -> bool {
        (self.policy == other.policy) && (self.token == other.token)
    }

    fn ne(&self, other: &ConnectionSignature) -> bool {
        (self.policy != other.policy) || (self.token != other.token)
    }
}

impl Eq for ConnectionSignature {}

impl ConnectionSignature {
    pub fn new(secret: &str, policy: &SessionPolicy) -> ConnectionSignature {
        ConnectionSignature {
            policy: policy.clone(),
            token: Token::new_from_str(secret),
        }
    }

    pub fn get_token(&self) -> Token {
        self.token.clone()
    }

    #[cfg(feature = "hyper")]
    pub fn new_hyper(_req: &Request, _cookie_name: &str, policy: &SessionPolicy) -> ConnectionSignature {
        // get cookie here
        // if cookie exists:
        // token = Token::new_from_str(cookie.value);
        // else
        // token = Token::new(policy.salt);
        ConnectionSignature {
            token: Token::new("sekrit"), // Todo: wrong, fixme!!! extract from request using cookie_name
            policy: policy.clone(),
        }
    }
}

