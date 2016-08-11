#![crate_type = "lib"]
#![crate_name = "websession"]

extern crate time;
extern crate uuid;
extern crate pwhash;

#[cfg(feature = "hyper")]
extern crate hyper;

use time::Duration;
use std::path::Path;
use std::io::{BufReader, BufRead};
use std::fs::File;
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
    IO(String),
}

impl From<std::io::Error> for SessionError {
    fn from(err: std::io::Error) -> SessionError {
        SessionError::IO(err.description().to_string())
    }
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct SessionPolicy {
    // All sessions use username and password authentication
    // address: bool, // this used to be unreliable due to proxy farms
    // port: bool, // really only makes sense with address == true
    // useragent: bool,
}

#[derive(Debug, Copy, Clone)]
pub struct ConnectionSignature {
    uuid: Uuid,
    // sockaddr: SocketAddr,
    // useragent: String,
    // signature details here
}

impl Hash for ConnectionSignature {
    fn hash<H: Hasher>(&self, h: &mut H) { self.uuid.hash(h); }
}

impl ConnectionSignature {
    pub fn new() -> ConnectionSignature {
        ConnectionSignature {
            // sockaddr: sockaddr,
            // useragent: String,
            uuid: Uuid::new_v4()
        }
    }

    pub fn match_policy(&self, session: &Session, policy: &SessionPolicy) -> bool {
	// makes sure the penciled-in fields are present and available
	// right now, all we have is the secret cookie policy, so:
        true
    }

    #[cfg(feature = "hyper")]
    pub fn new_hyper(req: &Request) -> ConnectionSignature {
        // panic!("Not implemented!");
        ConnectionSignature::new()
    }
}

#[derive(Debug)]
pub struct SessionManager<T> {
    expiration: Duration,
    policy: SessionPolicy,
    backing_store: T,
    cookie_dir: String,
    sessions: HashMap<Uuid, Session>
}

impl <T: AsRef<Path>> SessionManager<T> {
    pub fn new(expiration: Duration, policy: SessionPolicy, backing_store: T) -> SessionManager<T> {
        SessionManager {
            expiration: expiration,
            policy: policy,
            backing_store: backing_store,
            cookie_dir: "cookies".to_string(),
            sessions: HashMap::new()
        }
    }

/*
    fn valid_policy(&self, signature: &ConnectionSignature) -> bool {
        // everything in the match goes away when
        // https://github.com/rust-lang/rust/pull/34694 makes it to stable
        // let ipv4unspec = std::net::Ipv4Addr::new(0,0,0,0);
        // match self.policy {
        //     SessionPolicy::Simple => true,
        //     SessionPolicy::AddressLock => match signature.sockaddr.ip() {
        //         IpAddr::V4(ref ip) => ip.ne(&ipv4unspec),
        //         IpAddr::V6(ref ip) => !ip.is_unspecified(),
        //     },
        //     SessionPolicy::AddressPortLock => match signature.sockaddr.ip() {
        //         IpAddr::V4(ref ip) => ip.ne(&ipv4unspec) &&
        //             signature.sockaddr.port() > 0,
        //         IpAddr::V6(ref ip) => !ip.is_unspecified() &&
        //             signature.sockaddr.port() > 0,
        //     },
        // }
        true
    }
*/

// It's always okay to log out an expired session, so don't both
    // if valid, sets session cookie in res and returns a Session
    pub fn login(self: &mut Self, user: String, password: &str,
        session: &Session) -> Result<&Session, SessionError> {
	let sig = session.signature;

	// This doesn't validate the signature against the session, nor does it
	// make sure the signature matches our policy requirements.  Right now,
	// it's pretty much impossible for either of these to fail, because we
	// don't have any requirements.

	let remove = match self.sessions.get_mut(&sig.uuid) {
            Some(cs) => if (time::now().to_timespec() - session.last_access) >= self.expiration {
                true
            } else {
                cs.update_access();
                false
            },
            None => return Err(SessionError::Lost)
	};

	if remove {
	    self.sessions.remove(&session.signature.uuid);
	    return Err(SessionError::Expired);
	}

    if (user.trim() == user) && (user.len() > 1) {
        let ref p = self.backing_store;
        let f = try!(File::open(p));
        let reader = BufReader::new(f);
        for line in reader.lines() {
            let s = try!(line);
            // Format: username:bcrypt
            let v: Vec<&str> = s.split(':').collect();
            if v[0] == user {
                println!("Found user {}!", user);
                if bcrypt::verify(password, v[1]) {
                    let replacement = Session::new(Some(&sig));
                    self.sessions.insert(sig.uuid, replacement);
                    return self.sessions.get(&sig.uuid).ok_or(SessionError::Lost)
                } else {
                    return Err(SessionError::Unauthorized);
                }
            } // else continue looking
        } // ran out of lines
	} // bad match or ran out of lines
	return Err(SessionError::Unauthorized);
    }

    pub fn logout(&mut self, session: &Session) {
	// Let's blow away the session and let them make a new anonymous session
	// on next login.
	self.sessions.remove(&session.signature.uuid);
    }

    // #[cfg(feature = "hyper")]
    // pub fn login_hyper(&self, user: &str, password: &str, req: &Request) -> Result<&Session, SessionError> {
    //     let conn = ConnectionSignature::new_hyper(req);
    //     self.login(user, password, conn)
    // }

    // if valid, returns the session struct and possibly update cookie in
    // res; if invalid, returns None
    pub fn start(self: &mut Self, signature: ConnectionSignature) -> Result<&Session, SessionError> {
	// We now think the hash has to contain our session.  Let's see if it
	// conforms to our signature.
	let need_replacement = match self.sessions.get_mut(&signature.uuid) {
	    None => true,
	    Some(sess) => if sess.match_signature(&signature) {
		if (time::now().to_timespec() - sess.last_access) <= self.expiration {
	    	    sess.update_access();
    		    false
		} else {
		    // It's expired, log them out and make a new session
		    // insert() overwrites, so we don't need to
		    // self.sessions.remove(&sess.signature.uuid);
		    true
		}
	    } else {
		// They have a valid UUID but their signature doesn't match, so:
		return Err(SessionError::Unauthorized);
	    }
	};
	if need_replacement {
	    self.sessions.insert(signature.uuid.clone(),
		Session::new(Some(&signature)));
	}
	self.sessions.get(&signature.uuid).ok_or(SessionError::Lost)
    }

    #[cfg(feature = "hyper")]
    // if valid, returns the session struct and possibly update cookie in res
    pub fn get_session_hyper(&self, req: &Request) -> Result<&Session, SessionError> {
	let conn = ConnectionSignature::new_hyper(req);
	self.get_session(conn)
    }

    // Todo: Nickel does not give us direct access to a hyper response
    // object. We need to figure out a clean way of setting the
    // cookie, ideally w/o requiring Nickel to be compiled in.

    // logout all sessions
    pub fn logout_all_sessions(&mut self) {
        self.sessions.clear();
    }
}

#[derive(Debug)]
pub struct Session {
    // sockaddr: SocketAddr,
    // useragent: String,
    user: Option<String>,
    last_access: time::Timespec,
    // kick vars up to the session manager?
    // vars: HashMap<String, String>,
    signature: ConnectionSignature,
}

impl Session {
    // need user account stuff
    // - create account
    // - change password
    // - disable account
    // - delete account
    // - set account data (real name, email, etc)

    pub fn new(signature: Option<&ConnectionSignature>) -> Session {
	Session {
	    signature: match signature {
		Some(cs) => cs.clone(),
		None => ConnectionSignature::new()
	    },
	    user: None,
	    last_access: time::now().to_timespec(),
	}
    }

    pub fn clone(self) -> Session {
	Session {
	    signature: self.signature,
	    user: self.user,
	    last_access: time::now().to_timespec(),
	}
    }

    pub fn match_signature(&self, signature: &ConnectionSignature) -> bool {
	// XXX needs to check policy to only test the relevant parts of the
	// signature
	self.signature.uuid == signature.uuid
    }

    pub fn update_access(&mut self) {
        self.last_access = time::now().to_timespec();
    }

    pub fn get_user(&self) -> Option<String> {
	self.user.clone()
    }

    pub fn get_session_id(self) -> String {
        self.signature.uuid.to_string()
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
*/
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
