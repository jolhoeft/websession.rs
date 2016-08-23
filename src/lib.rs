#![crate_type = "lib"]
#![crate_name = "websession"]

extern crate time;
extern crate uuid;
extern crate pwhash;

pub mod backingstore;
pub use self::backingstore::{BackingStore, BackingStoreError};

#[cfg(feature = "hyper")]
extern crate hyper;

use time::{Timespec, Duration};
use std::path::Path;
use std::error::Error;
use std::collections::HashMap;
use uuid::Uuid;
use pwhash::bcrypt;
// use std::net::SocketAddr;
// use std::net::IpAddr;
use std::hash::{Hash, Hasher};

#[cfg(feature = "hyper")]
use hyper::server::request::Request;
#[cfg(feature = "hyper")]
use hyper::server::response::Response;

#[derive(Debug)]
pub enum SessionError {
    Unauthorized,
    BadSignature,
    Expired,
    Lost,
    BackingStore(BackingStoreError),
}

#[derive(Copy, Eq, PartialEq, Debug, Clone, Hash)]
pub struct Token {
    uuid: Uuid,
}

impl Token {
    fn new() -> Token {
        Token {
            uuid: Uuid::new_v4()
        }
    }
}

#[derive(Debug)]
pub struct SessionPolicy {
}

impl SessionPolicy {
    pub fn new() -> SessionPolicy {
        SessionPolicy {}
    }

    fn valid_connection(&self, signature: &ConnectionSignature) -> bool {
        true
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

// XXX let's break this into more fiels so there's less hair everywhere

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionSignature;

impl ConnectionSignature {
    pub fn new() -> ConnectionSignature {
        ConnectionSignature
    }

    #[cfg(feature = "hyper")]
    pub fn new_hyper(req: &Request) -> ConnectionSignature {
        // stubbed in
        ConnectionSignature
    }
}

pub struct SessionManager {
    expiration: Duration,
    policy: SessionPolicy,
    backing_store: Box<BackingStore + Send + Sync>,
    cookie_dir: String,
    sessions: HashMap<Token, Session>
}

impl SessionManager {
    pub fn new(expiration: Duration, policy: SessionPolicy, backing_store: Box<BackingStore + Send + Sync>) -> SessionManager {
        SessionManager {
            expiration: expiration,
            policy: policy,
            backing_store: backing_store,
            cookie_dir: "cookies".to_string(),
            sessions: HashMap::new()
        }
    }

    // This makes sure that the connectionsignature matches our policy and also
    // matches the session it is being applied to
    fn valid_connection(&self, signature: &ConnectionSignature, token: &Token) -> bool {
        self.policy.valid_connection(signature) && match self.sessions.get(token) {
            Some(sess) => sess.signature == *signature,
            None => false,
        }
    }

    fn is_expired(&self, token: &Token) -> Result<bool, SessionError> {
        match self.sessions.get(token) {
            Some(sess) => if (time::now().to_timespec() - sess.last_access) >= self.expiration {
                Ok(true)
            } else {
                Ok(false)
            },
            None => return Err(SessionError::Lost),
        }
    }

    // This doesn't validate the signature against the session, nor does it make
    // sure the signature matches our policy requirements.  Right now, it's hard
    // for either of these to fail, because we don't have any requirements.
    pub fn login(&mut self, user: &String, password: &str, token: &Token) -> Result<(), SessionError> {
        match self.is_expired(token) {
            Ok(true) => {
                self.logout(token);
                Err(SessionError::Expired)
            },
            Ok(false) => if (user.trim() == user) && (user.len() > 1) {
		let pwhash = try!(self.backing_store.get_pwhash(user).map_err(SessionError::BackingStore));
		if bcrypt::verify(password, pwhash.as_str()) {
		    match self.sessions.get_mut(token) {
	    		Some(sess) => {
    			    sess.user = Some(user.clone());
			    sess.last_access = time::now().to_timespec();
			    Ok(())
			},
			None => Err(SessionError::Lost),
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

    pub fn logout(&mut self, token: &Token) {
        self.sessions.remove(token);
    }

    #[cfg(feature = "hyper")]
    pub fn login_hyper(&mut self, user: &str, password: &str, req: &Request) -> Result<Token, SessionError> {
        let conn = ConnectionSignature::new_hyper(req);
        let token = try!{self.start(None, &conn)};
        self.login(user.to_string(), password, &token) // this is the wrong signature
    }

    // if valid, returns the session struct and possibly update cookie in
    // res; if invalid, returns None
    pub fn start(self: &mut Self, token: Option<&Token>, signature: &ConnectionSignature) -> Result<Token, SessionError> {
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
        
        if need_insert {
            self.sessions.insert(cur_token.clone(), Session::new(signature));
        } else {
            match self.sessions.get_mut(&cur_token) {
                Some(sess) => sess.last_access = time::now().to_timespec(),
                None => return Err(SessionError::Lost),
            }
        }
        Ok(cur_token.clone())
    }

    #[cfg(feature = "hyper")]
    // if valid, returns the session struct and possibly update cookie in res
    pub fn start_hyper(&mut self, token: Option<&Token>, req: &Request) -> Result<Token, SessionError> {
        let conn = ConnectionSignature::new_hyper(req);
        self.start(token, &conn)
    }

    pub fn get_user(&self, token: &Token) -> Result<Option<String>, SessionError> {
        match self.sessions.get(token) {
            Some(sess) => Ok(sess.user.clone()),
            None => Err(SessionError::Lost),
        }
    }



    // Todo: Nickel does not give us direct access to a hyper response
    // object. We need to figure out a clean way of setting the
    // cookie, ideally w/o requiring Nickel to be compiled in.

    // logout all sessions
    pub fn logout_all_sessions(&mut self) {
        self.sessions.clear();
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
