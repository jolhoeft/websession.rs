extern crate time;
extern crate pwhash;

#[cfg(feature = "hyper")]
extern crate hyper;

use connectionsignature::ConnectionSignature;
use token::Token;
use sessionpolicy::SessionPolicy;
use time::{Timespec, Duration};
use std::collections::HashMap;

// use std::net::SocketAddr;
// use std::net::IpAddr;
use std::sync::Mutex;

#[derive(Debug)]
pub enum SessionError {
    Unauthorized,
    BadSignature,
    Expired,
    Lost,
    // BackingStore(BackingStoreError),
    Mutex,
}

#[derive(Debug)]
struct Session {
    user: Option<String>,
    last_access: Timespec,
    signature: ConnectionSignature,
}

impl Session {
    fn new(signature: &ConnectionSignature) -> Session {
        Session {
            user: None,
            last_access: time::now().to_timespec(),
            signature: signature.clone(),
        }
    }
}

pub struct SessionManager {
    expiration: Duration,
    policy: SessionPolicy,
    // cookie_dir: String,
    sessions: Mutex<HashMap<ConnectionSignature, Session>>,
}

impl SessionManager {
    pub fn new(expiration: Duration, policy: SessionPolicy) -> SessionManager {
        SessionManager {
            expiration: expiration,
            policy: policy,
            // cookie_dir: "cookies".to_string(),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    // This makes sure that the connectionsignature matches our policy and also
    // matches the session it is being applied to.
    // It's a good idea, but I'm not sure where to glue it in right now.
    // fn valid_connection(&self, signature: &ConnectionSignature, token: &Token) -> bool {
    //     self.policy.suitable_connection(signature) && match self.sessions.get(token) {
    //         Some(sess) => sess.signature == *signature,
    //         None => false,
    //     }
    // }

    pub fn is_expired(&self, signature: &ConnectionSignature) -> Result<bool, SessionError> {
        let hashmap = try!(self.sessions.lock().map_err(|_| SessionError::Mutex));
        match hashmap.get(signature) {
            Some(sess) => if (time::now().to_timespec() - sess.last_access) >= self.expiration {
                Ok(true)
            } else {
                Ok(false)
            },
            None => Err(SessionError::Lost),
        }
    }

    // This has the same caveats as logout_all_sessions; should it be a Result?
    pub fn logout(&self, signature: &ConnectionSignature) {
        match self.sessions.lock() {
            Ok(mut hashmap) => hashmap.remove(signature),
            Err(poisoned) => poisoned.into_inner().remove(signature),
        };
    }

    // if valid, returns the session struct and possibly update cookie in
    // res; if invalid, returns None
    pub fn start(self: &Self, signature: &ConnectionSignature) -> Result<String, SessionError> {
        let mut new_sig = ConnectionSignature::new_from_signature(signature);
        let need_insert = match self.is_expired(signature) {
            Ok(true) => {
                self.logout(signature);
                true
            },
            Ok(false) => false,
            Err(SessionError::Lost) => true, // this just means it's new
            Err(e) => return Err(e),
        };

        let mut hashmap = try!(self.sessions.lock().map_err(|_| SessionError::Mutex));
        if need_insert {
            new_sig.token = Token::new(self.policy.salt.as_str());
            hashmap.insert(new_sig.clone(), Session::new(&new_sig));
        } else {
            match hashmap.get_mut(signature) {
                Some(sess) => sess.last_access = time::now().to_timespec(),
                None => return Err(SessionError::Lost),
            }
        }
        Ok(new_sig.token.to_string())
    }

    pub fn get_user(&self, signature: &ConnectionSignature) -> Result<Option<String>, SessionError> {
        match self.is_expired(signature) {
            Ok(true) => Err(SessionError::Expired),
            Err(e) => Err(e),
            Ok(false) => {
                let mut hashmap = try!(self.sessions.lock().map_err(|_| SessionError::Mutex));
                match hashmap.get_mut(signature) {
                    Some(sess) => {
                        sess.last_access = time::now().to_timespec();
                        Ok(sess.user.clone())
                    },
                    None => Err(SessionError::Lost),
                }
            }
        }
    }

    // Todo: Nickel does not give us direct access to a hyper response
    // object. We need to figure out a clean way of setting the
    // cookie, ideally w/o requiring Nickel to be compiled in.

    // Should this fail if the mutex blew up?
    // It's not supposed to break anyway.
    pub fn logout_all_sessions(&self) {
        match self.sessions.lock() {
            Ok(mut hashmap) => hashmap.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
    }
}

/*
    // Session data methods
    pub fn get_data(&self, key: &str) -> Result<Option<String>, SessionError> {
        panic!("Not implemented!");
    }

    // Session data methods
    pub fn set_data(&self, key: &str, value: &str) -> Result<(), SessionError> {
        panic!("Not implemented!");
    }

    // Session data methods
    pub fn get_persistant_data(&self, key: &str) -> Result<Option<String>, SessionError> {
        panic!("Not implemented!");
    }

    // Session data methods
    pub fn set_persistant_data(&self, key: &str, value: &str) -> Result<(), SessionError> {
        panic!("Not implemented!");
    }
}
*/

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
