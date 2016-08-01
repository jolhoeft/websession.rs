#![crate_type = "lib"]
#![crate_name = "websession"]

extern crate time;
extern crate uuid;
extern crate pwhash;

#[cfg(feature = "hyper")]
extern crate hyper;

use std::path::Path;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::error::Error;
use std::collections::HashMap;
use uuid::Uuid;
use pwhash::bcrypt;
use std::net::SocketAddr;
use std::net::IpAddr;

#[cfg(feature = "hyper")]
use hyper::server::request::Request;
#[cfg(feature = "hyper")]
use hyper::server::response::Response;

#[derive(Debug)]
pub enum SessionError {
    Unauthorized,
    BadSignature,
    Impossible(String),
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

use std::hash::Hash;
use std::hash::Hasher;
impl Hash for ConnectionSignature {
    fn hash<H: Hasher>(&self, h: &mut H) { self.uuid.hash(h); }
}

impl ConnectionSignature {
    pub fn new(sockaddr: SocketAddr) -> ConnectionSignature {
        // we may need a builder pattern here if this gets complicated
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
struct SessionManager<T> {
    expiration: u64, // in time (seconds) since last access
    policy: SessionPolicy,
    backing_store: T,
    cookie_dir: String,
    sessions: HashMap<Uuid, Session>
}

impl <T: AsRef<Path>> SessionManager<T> {
    pub fn new(expiration: u64, policy: SessionPolicy, backing_store: T) -> SessionManager<T> {
        SessionManager {
            expiration: expiration,
            policy: policy,
            backing_store: backing_store,
            cookie_dir: "cookies".to_string(),
            sessions: HashMap::new()
        }
    }

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

    // if valid, sets session cookie in res and returns a Session
    pub fn login(&mut self, user: String, password: &str,
        signature: &ConnectionSignature) -> Result<&Session, SessionError> {
        if self.valid_policy(signature) {
            return Err(SessionError::BadSignature)
        }

        if (user.trim() == user) && (user.len() > 1) {
	    let ref p = self.backing_store;
       	    let f = try!(File::open(p));
   	    let reader = BufReader::new(f);
	    for line in reader.lines() {
		let s = try!(line);
		// Format: username:bcrypt // XXX should be JSON per spec
		let v: Vec<&str> = s.split(':').collect();
		if v[0] == user {
		    println!("Found user {}!", user);
		    if bcrypt::verify(password, v[1]) {
			let session = Session {
			    session_id: signature.uuid,
			    user: Some(user),
			    // sockaddr: signature.sockaddr,
			    last_access: time::now().to_timespec(),
			    vars: HashMap::new(),
			};
			// If this is a valid login, stomp on any
			// outstanding sessions matching this ID.  (There
			// shouldn't be any, because the ID is a UUID).
			self.sessions.insert(signature.uuid, session);
			return self.sessions.get(&signature.uuid).ok_or(SessionError::Impossible("lost hash key".to_string()));
		    } else {
			return Err(SessionError::Unauthorized);
		    }
		} // else continue looking
	    } // ran out of lines
	} // bad match or ran out of lines
	return Err(SessionError::Unauthorized);
    }

    #[cfg(feature = "hyper")]
    pub fn login_hyper(&self, user: &str, password: &str, req: &Request) -> Result<&Session, SessionError> {
        let conn = ConnectionSignature::new_hyper(req);
        self.login(user, password, conn)
    }

    // if valid, returns the session struct and possibly update cookie in
    // res; if invalid, returns None
    pub fn get_session(self: &mut Self,
	signature: ConnectionSignature) -> Option<&Session> {
	// is_ok is needed because I can't give up the mutability of the result
	let is_ok = match self.sessions.get_mut(&signature.uuid) {
	    Some(sess) =>
		if signature.match_policy(sess, &self.policy) {
	    	    sess.last_access = time::now().to_timespec();
		    true
		} else {
		    false
		},
	    None => false
	};
	if is_ok {
	    self.sessions.get(&signature.uuid)
	} else {
	    None
	}
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

    // logout the user associated with this session
    pub fn logout_session(&self, session: Session) {
        panic!{"Not implemented"};
    }

    // logout all sessions
    pub fn logout_all_sessions(&mut self) {
        self.sessions.clear();
    }
}

#[derive(Debug)]
pub struct Session {
    session_id: Uuid,
    // sockaddr: SocketAddr,
    // useragent: String,
    user: Option<String>,
    last_access: time::Timespec,
    vars: HashMap<String, String>,
}

impl Session {
    // need user account stuff
    // - create account
    // - change password
    // - disable account
    // - delete account
    // - set account data (real name, email, etc)

    pub fn update_access(&mut self) {
        self.last_access = time::now().to_timespec();
    }

    pub fn get_user(&self) -> Option<String> {
	self.user.clone()
    }

    pub fn get_session_id(self) -> String {
        return self.session_id.to_string();
    }

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

    // log the user out
    pub fn logout(&self) {
        panic!("not implemented");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
