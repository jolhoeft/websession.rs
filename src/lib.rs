#[cfg(feature = "hyper")]
extern crate hyper;

#[cfg(feature = "hyper")]
use hyper::server::request::Request;
#[cfg(feature = "hyper")]
use hyper::server::response::Response;

pub enum SessionError {
    Unauthorized,
}

pub enum SessionPolicy {
    Simple,      // check username/pw, session id for expiration
    AddressLock, // Simple plus check sessionid against original ip address
}

pub struct ConnectionSignature {
    // signature details here
}

impl ConnectionSignature {
    pub fn new() -> ConnectionSignature {
        // we may need a builder pattern here if this gets complicated
        ConnectionSignature{}
    }

    #[cfg(feature = "hyper")]
    pub fn new_hyper(req: &Request, res: &mut Response) -> ConnectionSignature {
        panic!("Not implemented!");
    }
}

pub struct SessionManager {
    expiration: u64, // in time (seconds) since last access
    policy: SessionPolicy,
}

impl SessionManager {
    pub fn new(expiration: u64, policy: SessionPolicy) -> SessionManager {
        SessionManager{expiration: expiration, policy: policy}
    }

    // if valid, sets session cookie in res and returns a Session
    // struct (or maybe a reference to a Session struct,
    // i.e. Result<&Session, SessionError>)
    pub fn login(self, user: &str, password: &str, signature: ConnectionSignature) -> Result<Session, SessionError> {
        panic!("Not implemented!");
    }

    #[cfg(feature = "hyper")]
    pub fn login_hyper(self, user: &str, password: &str, req: &Request, res: &mut Response) -> Result<Session, SessionError> {
        let conn = ConnectionSignature::new_hyper(req,res);
        self.login(user, password, conn)
    }

    // if valid, returns the session struct and possibly update cookie in res
    pub fn get_session(self, signature: ConnectionSignature) -> Result<Session, SessionError> {
        panic!("Not implemented!");
    }

    #[cfg(feature = "hyper")]
    // if valid, returns the session struct and possibly update cookie in res
    pub fn get_session_hyper(self, req: &Request, res: &mut Response) -> Result<Session, SessionError> {
        let conn = ConnectionSignature::new_hyper(req,res);
        self.get_session(conn)
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

    pub fn get_user(self) -> Option<String> {
        panic!{"Not implemented"};
    }

    pub fn get_session_id(self) -> String {
        panic!{"Not implemented"};
    }

    // Session data methods
    pub fn get_data(self, key: &str) -> Result<Option<String>, SessionError> {
        panic!("Not implemented!");
    }

    // Session data methods
    pub fn set_data(self, key: &str, value: &str) -> Result<(), SessionError> {
        panic!("Not implemented!");
    }

    // Session data methods
    pub fn get_persistant_data(self, key: &str) -> Result<Option<String>, SessionError> {
        panic!("Not implemented!");
    }

    // Session data methods
    pub fn set_persistant_data(self, key: &str, value: &str) -> Result<(), SessionError> {
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
