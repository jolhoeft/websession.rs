extern crate hyper;

use hyper::server::request::Request;
use hyper::server::response::Response;

pub enum SessionError {
    Unauthorized,
}

pub enum SessionPolicy {
    Simple,      // check username/pw, session id for expiration
    AddressLock, // Simple plus check sessionid against original ip address
}

pub struct SessionManager {
    expiration: u64,
    policy: SessionPolicy,
}

impl SessionManager {
    pub fn new(expiration: u64, policy: SessionPolicy) -> SessionManager {
        SessionManager{expiration: expiration, policy: policy}
    }

    // if valid, sets session cookie in res and returns a Session
    // struct (or maybe a reference to a Session struct,
    // i.e. Result<&Session, SessionError>)
    pub fn login(self, user: &str, password: &str, req: &Request, res: &mut Response) -> Result<Session, SessionError> {
        panic!("Not implemented!");
    }

    // if valid, returns the session struct and possibly update cookie in res
    pub fn get_session(self, req: &Request, res: &mut Response) -> Result<Session, SessionError> {
        panic!("Not implemented!");
    }

    // logout the user associated with this session
    pub fn logout_session(self, session: Session) {
        panic!{"Not implemented"};
    }

    // logout all sessions
    pub fn logout_all_sessions(self) {
        panic!{"Not implemented"};
    }
}

pub struct Session {
}

impl Session {
    // need user account stuff
    // - create account
    // - change password
    // - disable account
    // - delete account
    // - set account data (real name, email, etc)

    pub fn get_user(self) -> String {
        panic!{"Not implemented"};
    }

    pub fn get_session_id(self) -> String {
        panic!{"Not implemented"};
    }

    // Session data methods
    pub fn get_data(self, key: &str) -> String {
        panic!("Not implemented!");
    }

    // Session data methods
    pub fn set_data(self, key: &str, value: &str) {
        panic!("Not implemented!");
    }

    // log the user out
    pub fn logout(self) {
        panic!("not implemented");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
