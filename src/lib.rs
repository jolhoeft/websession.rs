#![crate_type = "lib"]
#![crate_name = "websession"]

extern crate time;
extern crate uuid;
extern crate pwhash;

pub mod backingstore;
pub use self::backingstore::{BackingStore, BackingStoreError};

pub mod connectionsignature;
pub use self::connectionsignature::ConnectionSignature;

mod token;
use self::token::Token;

pub mod sessionpolicy;
pub use self::sessionpolicy::SessionPolicy;

#[cfg(feature = "hyper")]
extern crate hyper;

use time::{Timespec, Duration};
use std::collections::HashMap;
use pwhash::bcrypt;
// use std::net::SocketAddr;
// use std::net::IpAddr;
use std::sync::Mutex;

#[cfg(feature = "hyper")]
use hyper::server::request::Request;

#[derive(Debug)]
pub enum SessionError {
    Unauthorized,
    BadSignature,
    Expired,
    Lost,
    BackingStore(BackingStoreError),
    Mutex
}

impl From<BackingStoreError> for SessionError {
    // Arguably, we should parse these and convert non-data-integrity errors to
    // Unauthorized errors.
    fn from(err: BackingStoreError) -> SessionError {
        SessionError::BackingStore(err)
    }
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
    // policy: SessionPolicy,
    backing_store: Box<BackingStore + Send + Sync>,
    // cookie_dir: String,
    sessions: Mutex<HashMap<Token, Session>>,
}

impl SessionManager {
    pub fn new(expiration: Duration, _: SessionPolicy, backing_store: Box<BackingStore + Send + Sync>) -> SessionManager {
        SessionManager {
            expiration: expiration,
            // policy: policy,
            backing_store: backing_store,
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

    fn is_expired(&self, token: &Token) -> Result<bool, SessionError> {
        match self.sessions.lock() {
            Ok(hashmap) => match hashmap.get(token) {
                Some(sess) => if (time::now().to_timespec() - sess.last_access) >= self.expiration {
                    Ok(true)
                } else {
                    Ok(false)
                },
                None => Err(SessionError::Lost),
            },
            Err(_) => Err(SessionError::Mutex),
        }
    }

    // This doesn't validate the signature against the session, nor does it make
    // sure the signature matches our policy requirements.  Right now, it's hard
    // for either of these to fail, because we don't have any requirements.
    pub fn login(&self, user: &str, password: &str, token: &Token) -> Result<(), SessionError> {
        match self.is_expired(token) {
            Ok(true) => {
                self.logout(token);
                Err(SessionError::Expired)
            },
            Ok(false) => if (user.trim() == user) && (user.len() > 1) {
                let pwhash = try!(self.backing_store.get_pwhash(user, true));
                if bcrypt::verify(password, pwhash.as_str()) {
                    match self.sessions.lock() {
                        Ok(mut hashmap) => match hashmap.get_mut(token) {
                            Some(sess) => {
                                sess.user = Some(user.to_string());
                                sess.last_access = time::now().to_timespec();
                                Ok(())
                            },
                            None => Err(SessionError::Lost),
                        },
                        Err(_) => Err(SessionError::Mutex),
                    }
                } else { // didn't verify
                    Err(SessionError::Unauthorized)
                }
            } else { // bad username format
                Err(SessionError::Unauthorized)
            },
            Err(e) => Err(e),
        } // is_expired
    }

    // This has the same caveats as logout_all_sessions; should it be a Result?
    pub fn logout(&self, token: &Token) {
        match self.sessions.lock() {
            Ok(mut hashmap) => hashmap.remove(token),
            Err(poisoned) => poisoned.into_inner().remove(token),
        };
    }

    #[cfg(feature = "hyper")]
    pub fn login_hyper(&self, user: &str, password: &str, req: &Request) -> Result<(), SessionError> {
        let conn = ConnectionSignature::new_hyper(req);
        let token = try!{self.start(None, &conn)};
        self.login(user, password, &token) // this is the wrong signature
    }

    // if valid, returns the session struct and possibly update cookie in
    // res; if invalid, returns None
    pub fn start(&self, token: Option<&Token>, signature: &ConnectionSignature) -> Result<Token, SessionError> {
        let cur_token = token.map_or(Token::new(), |x| *x);
        let need_insert = match self.is_expired(&cur_token) {
            Ok(true) => {
                self.logout(&cur_token);
                true
            },
            Ok(false) => false,
            Err(SessionError::Lost) => true, // this just means it's new
            Err(e) => return Err(e),
        };

        match self.sessions.lock() {
            Ok(mut hashmap) => {
                if need_insert {
                    hashmap.insert(cur_token.clone(), Session::new(signature));
                } else {
                    match hashmap.get_mut(&cur_token) {
                        Some(sess) => sess.last_access = time::now().to_timespec(),
                        None => return Err(SessionError::Lost),
                    }
                }
            },
            Err(_) => return Err(SessionError::Mutex),
        }
        Ok(cur_token.clone())
    }

    #[cfg(feature = "hyper")]
    // if valid, returns the session struct and possibly update cookie in res
    pub fn start_hyper(&self, token: Option<&Token>, req: &Request) -> Result<Token, SessionError> {
        let conn = ConnectionSignature::new_hyper(req);
        self.start(token, &conn)
    }

    pub fn get_user(&self, token: &Token) -> Result<Option<String>, SessionError> {
        match self.sessions.lock() {
            Ok(hashmap) => match hashmap.get(token) {
                Some(sess) => Ok(sess.user.clone()),
                None => Err(SessionError::Lost),
            },
            Err(_) => Err(SessionError::Mutex),
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
