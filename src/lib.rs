extern crate hyper;

use hyper::server::request::Request;
use hyper::server::response::Response;

pub struct Session {
}

pub enum SessionError {
    Unauthorized,
}

impl Session {
    // if valid, sets session cookie in res and returns a Session
    // struct (or maybe a reference to a Session struct,
    // i.e. Result<&Session, SessionError>)
    pub fn login(user: &str, password: &str, req: &Request, res: &mut Response) -> Result<Session, SessionError> {
        panic!("Not implemented!");
    }

    // if valid, returns the session struct and possibly update cookie in res
    pub fn get_session(req: &Request, res: &mut Response) -> Result<Session, SessionError> {
        panic!("Not implemented!");
    }

    // need user account stuff
    // - create account
    // - change password
    // - disable account
    // - delete account
    // - set account data (real name, email, etc)

    // Session data methods
    pub fn get_data(self, key: &str) -> String {
        panic!("Not implemented!");
    }

    // Session data methods
    pub fn set_data(self, key: &str, value: &str) {
        panic!("Not implemented!");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
