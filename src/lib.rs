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

#[cfg(feature = "hyper")]
use hyper::server::request::Request;
#[cfg(feature = "hyper")]
use hyper::server::response::Response;

#[derive(Debug)]
pub enum SessionError {
    Unauthorized,
    IO(String),
}

// impl From<std::io::Error> for SessionError {
//     fn from(err: std::io::Error) -> SessionError {
//         SessionError::IO(err.description().to_string())
//     }
// }

#[derive(Hash, Eq, PartialEq, Debug)]
pub enum SessionPolicy {
    Simple,      // check username/pw, session id for expiration
    AddressLock, // Simple plus check sessionid against original ip address
    AddressPortLock,
}

#[derive(Debug, Copy, Clone)]
pub struct ConnectionSignature {
    uuid: Option<Uuid>,
    ipv4: Option<[u8; 4]>,
    ipv6: Option<[u8; 16]>,
    port: u16
    // signature details here
}

impl PartialEq for ConnectionSignature {
    // We only compare by UUID for hashing; the library will
    // need to compare the other components; this is how we can
    // detect attempted collisions, since UUIDs are supposed to be
    // unique.
    fn eq(&self, other: &Self) -> bool { self.uuid == other.uuid }
}

impl Eq for ConnectionSignature {}

use std::hash::Hash;
use std::hash::Hasher;
impl Hash for ConnectionSignature {
    fn hash<H: Hasher>(&self, h: &mut H) { self.uuid.hash(h); }
}

impl ConnectionSignature {
    pub fn new(ipv4: Option<[u8; 4]>, ipv6: Option<[u8; 16]>, port: u16) -> ConnectionSignature {
        // we may need a builder pattern here if this gets complicated
        ConnectionSignature {
            uuid: Uuid::new_v4(),
            ipv4: ipv4,
            ipv6: ipv6,
            port: port
        }
    }

    #[cfg(feature = "hyper")]
    pub fn new_hyper(req: &Request) -> ConnectionSignature {
        // panic!("Not implemented!");
        ConnectionSignature::new()
    }
}

#[derive(Debug)]
pub struct SessionManager<T> {
    expiration: u64, // in time (seconds) since last access
    policy: SessionPolicy,
    backing_store: T,
    cookie_dir: String,
    sessions: HashMap<ConnectionSignature, Session>
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

    // if valid, sets session cookie in res and returns a Session
    // struct (or maybe a reference to a Session struct,
    // i.e. Result<Session, SessionError>)
    pub fn login(&mut self, user: String, password: &str,
        signature: ConnectionSignature) -> Result<Uuid, SessionError> {
        if user.trim() != user {
            return Err(SessionError::Unauthorized);
        }
        if user.len() < 1 {
            return Err(SessionError::Unauthorized);
        }
        if (self.policy == SessionPolicy::AddressLock) ||
            (self.policy == SessionPolicy::AddressPortLock) {
            if signature.ipv4.is_none() && signature.ipv6.is_none() {
                return Err(SessionError::Unauthorized);
            }
        }
        if self.policy == SessionPolicy::AddressPortLock {
            if signature.port == 0 {
                return Err(SessionError::Unauthorized);
            }
        }

        let session = Session {
            session_id: signature.uuid,
            user: Some(user.to_string()),
            ipv4: signature.ipv4,
            ipv6: signature.ipv6,
            port: signature.port,
            last_access: time::now().to_timespec(),
        };

        let ref p = self.backing_store;
        let f = match File::open(p) {
            Err(x) => return Err(SessionError::IO(x.description().to_string())),
            Ok(f) => f,
        };
        let reader = BufReader::new(f);
        for line in reader.lines() {
            let s = line.unwrap();
            let v: Vec<&str> = s.split(':').collect();
            // Format: username:bcrypt
            if v[0] == user {
                println!("Found user {}!", user);
                let h = bcrypt::hash(password).unwrap();
                if v[2] == h {
                    // If this is a valid login, stomp on any outstanding
                    // sessions matching this identifier
                    self.sessions.insert(signature, session);
                    return Ok(session);
                } else {
                    return Err(SessionError::Unauthorized);
                }
            }
        }
        return Err(SessionError::Unauthorized);
    }

    #[cfg(feature = "hyper")]
    pub fn login_hyper(&self, user: &str, password: &str, req: &Request) -> Result<&Session, SessionError> {
        let conn = ConnectionSignature::new_hyper(req);
        self.login(user, password, conn)
    }

    // if valid, returns the session struct and possibly update cookie in res
    pub fn get_session(&self, signature: ConnectionSignature) -> Result<&Session, SessionError> {
        let mut rv = Err(SessionError::Unauthorized);
        if self.sessions.contains_key(&signature) {
            let compare = self.sessions.get(&signature).unwrap();
            match self.policy {
                SessionPolicy::Simple => rv = Ok(compare),
                SessionPolicy::AddressLock => if
                    (signature.ipv4.is_some() && signature.ipv4.eq(&compare.ipv4)) ||
                    (signature.ipv6.is_some() && signature.ipv6.eq(&compare.ipv6)) {
                    self.sessions.get_mut(&signature).unwrap().last_access =
                        time::now().to_timespec();
                    rv = Ok(compare);
                },
                SessionPolicy::AddressPortLock => if
                    ((signature.ipv4.is_some() && signature.ipv4.eq(&compare.ipv4)) ||
                    (signature.ipv6.is_some() && signature.ipv6.eq(&compare.ipv6))) &&
                    (signature.port == compare.port) && (signature.port > 0) {
                    self.sessions.get_mut(&signature).unwrap().last_access =
                        time::now().to_timespec();
                    rv = Ok(compare);
                }
            }
        }
        rv
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
    pub fn logout_all_sessions(&self) {
        panic!{"Not implemented"};
    }
}

#[derive(Debug)]
pub struct Session {
    session_id: Uuid,
    // vars: HashMap<String, String>,
    user: Option<String>, // this isn't in the hashmap because all sessions have a user
    ipv4: Option<[u8; 4]>,
    ipv6: Option<[u8; 16]>,
    port: u16,
    last_access: time::Timespec,
}

impl Session {
    // need user account stuff
    // - create account
    // - change password
    // - disable account
    // - delete account
    // - set account data (real name, email, etc)

    pub fn get_user(&self) -> &Option<String> {
        // panic!{"Not implemented"};
        &self.user
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
