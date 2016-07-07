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
    uuid: Uuid,
    sockaddr: SocketAddr
    // signature details here
}

use std::hash::Hash;
use std::hash::Hasher;
impl Hash for ConnectionSignature {
    fn hash<H: Hasher>(&self, h: &mut H) { self.uuid.hash(h); }
}

fn is_ip_specified(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(x) => !x.is_unspecified(),
        std::net::IpAddr::V6(x) => !x.is_unspecified(),
    }
}

impl ConnectionSignature {
    pub fn new(sockaddr: SocketAddr) -> ConnectionSignature {
        // we may need a builder pattern here if this gets complicated
        ConnectionSignature {
            uuid: Uuid::new_v4(),
            sockaddr: sockaddr
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

    // if valid, sets session cookie in res and returns a Session
    // struct (or maybe a reference to a Session struct,
    // i.e. Result<Session, SessionError>)
    pub fn login(&mut self, user: String, password: &str,
        signature: ConnectionSignature) -> Result<Uuid, SessionError> {
        let mut rv = Err(SessionError::Unauthorized);
        if (user.trim() == user) && (user.len() > 1) {
            if ((self.policy == SessionPolicy::AddressLock) &&
                is_ip_specified(signature.sockaddr.ip())) ||
                ((self.policy == SessionPolicy::AddressPortLock) &&
                is_ip_specified(signature.sockaddr.ip()) &&
                (signature.sockaddr.port() > 0)) ||
                (self.policy == SessionPolicy::Simple) {
                let session = Session {
                    session_id: signature.uuid,
                    user: Some(user.to_string()),
                    sockaddr: signature.sockaddr,
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
                            self.sessions.insert(signature.uuid, session);
                            rv = Ok(signature.uuid);
                        }
                        break;
                    }
                }
            }
        }
        return rv;
    }

    #[cfg(feature = "hyper")]
    pub fn login_hyper(&self, user: &str, password: &str, req: &Request) -> Result<&Session, SessionError> {
        let conn = ConnectionSignature::new_hyper(req);
        self.login(user, password, conn)
    }

    // if valid, returns the session struct and possibly update cookie in res
    pub fn get_session(&self, signature: ConnectionSignature) -> Result<Uuid, SessionError> {
        let mut rv = Err(SessionError::Unauthorized);
        match self.sessions.contains_key(&signature.uuid) {
            true => {
                let mut compare = self.sessions.get_mut(&signature.uuid).unwrap();
                match self.policy {
                    SessionPolicy::Simple => rv = Ok(compare),
                    SessionPolicy::AddressLock => if
                        compare.sockaddr.ip() == signature.sockaddr.ip() {
                        compare.update_access();
                        rv = Ok(compare.session_id);
                    },
                    SessionPolicy::AddressPortLock => if
                        signature.sockaddr == compare.sockaddr {
                        compare.update_access();
                        rv = Ok(compare.session_id);
                    }
                }
            },
            false => { }
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
    sockaddr: SocketAddr,
    user: Option<String>, // this isn't in the hashmap because all sessions have a user
    last_access: time::Timespec,
    // vars: HashMap<String, String>,
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
