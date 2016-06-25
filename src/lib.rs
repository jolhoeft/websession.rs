#[cfg(feature = "hyper")]
extern crate hyper;

#[cfg(feature = "hyper")]
use hyper::server::request::Request;
#[cfg(feature = "hyper")]
use hyper::server::response::Response;

#[derive(Debug)]
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
    pub fn new_hyper(req: &Request) -> ConnectionSignature {
        // panic!("Not implemented!");
        ConnectionSignature::new()
    }
}

pub struct SessionManager {
    expiration: u64, // in time (seconds) since last access
    policy: SessionPolicy,
    dummy: Session, // for verifying API, Todo: replace with something like the line below
    // sessions: HashMap<ConnectionSignature, Session> // - or something like this
}

impl SessionManager {
    pub fn new(expiration: u64, policy: SessionPolicy) -> SessionManager {
        SessionManager{expiration: expiration, policy: policy, dummy: Session{user: None, session_id: "42".to_string()}}
    }

    // if valid, sets session cookie in res and returns a Session
    // struct (or maybe a reference to a Session struct,
    // i.e. Result<&Session, SessionError>)
    pub fn login(&self, user: &str, password: &str, signature: ConnectionSignature) -> Result<&Session, SessionError> {
        panic!("Not implemented!");
    }

    #[cfg(feature = "hyper")]
    pub fn login_hyper(&self, user: &str, password: &str, req: &Request) -> Result<&Session, SessionError> {
        let conn = ConnectionSignature::new_hyper(req);
        self.login(user, password, conn)
    }

    // if valid, returns the session struct and possibly update cookie in res
    pub fn get_session(&self, signature: ConnectionSignature) -> Result<&Session, SessionError> {
        // panic!("Not implemented!");
        Ok(&self.dummy)
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

pub struct Session {
    user: Option<String>,
    session_id: String,
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

    pub fn get_session_id(&self) -> &String {
        // panic!{"Not implemented"};
        &self.session_id
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
