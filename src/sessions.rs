extern crate time;

#[cfg(feature = "hyper")]
extern crate hyper;

use connectionsignature::ConnectionSignature;
use token::Token;
use sessionpolicy::SessionPolicy;
use time::{Timespec, Duration};
use std::collections::HashMap;
use AuthError;

// use std::net::SocketAddr;
// use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};

#[derive(Debug)]
struct Session {
    last_access: Timespec,
    // We're not using this right now, but will need it when we match policies
    // signature: ConnectionSignature,
}

impl Session {
    fn new(_: &ConnectionSignature) -> Session {
        Session {
            last_access: time::now().to_timespec(),
            // signature: signature.clone(),
        }
    }
}

#[derive(Debug)]
pub struct SessionManager {
    expiration: Duration,
    policy: SessionPolicy,
    // cookie_dir: String,
    sessions: Mutex<HashMap<ConnectionSignature, Session>>,
}

impl SessionManager {
    pub fn new(expiration: Duration, policy: SessionPolicy) -> SessionManager {
        SessionManager {
            expiration,
            policy,
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

    pub fn is_expired(&self, signature: &ConnectionSignature) -> Result<bool, AuthError> {
        let mut hashmap = self.sessions.lock().map_err(|_| AuthError::Mutex)?;
        Ok(self.is_expired_locked(signature, &mut hashmap))
    }

    fn is_expired_locked(&self, signature: &ConnectionSignature, hashmap: &mut MutexGuard<HashMap<ConnectionSignature, Session>>) -> bool {
        let rv = match hashmap.get(signature) {
            Some(sess) => {
                (time::now().to_timespec() - sess.last_access) >= self.expiration
            }
            None => true
        };
        if rv {
            self.stop_locked(&signature, hashmap);
        }
        debug!("is_expired about to return {}", rv);
        rv
    }

    fn stop_locked(&self, signature: &ConnectionSignature, hashmap: &mut MutexGuard<HashMap<ConnectionSignature, Session>>) -> Option<Session> {
        hashmap.remove(signature)
    }

    // This has the same caveats as stop_all_sessions; should it be a Result?
    pub fn stop(&self, signature: &ConnectionSignature) {
        match self.sessions.lock() {
            Ok(mut hashmap) => self.stop_locked(signature, &mut hashmap),
            Err(poisoned) => poisoned.into_inner().remove(signature),
        };
    }

    pub fn start(&self, mut signature: ConnectionSignature) -> Result<ConnectionSignature, AuthError> {
        let mut hashmap = self.sessions.lock().map_err(|_| AuthError::Mutex)?;
        let need_insert = self.is_expired_locked(&signature, &mut hashmap);

        if need_insert {
            signature.token = Token::new(&self.policy.salt);
            hashmap.insert(signature.clone(), Session::new(&signature));
        } else {
            match hashmap.get_mut(&signature) {
                Some(sess) => sess.last_access = time::now().to_timespec(),
                None => return Err(AuthError::InternalConsistency), // this should be impossible
            }
        }
        Ok(signature)
    }

    // TODO: Nickel does not give us direct access to a hyper response object.
    // We need to figure out a clean way of setting the cookie, ideally w/o
    // requiring Nickel to be compiled in.

    // Should this fail if the mutex blew up?
    // It's not supposed to break anyway.
    pub fn stop_all_sessions(&self) {
        match self.sessions.lock() {
            Ok(mut hashmap) => hashmap.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
    }
}

/*
    // Session data methods
    pub fn get_data(&self, key: &str) -> Result<Option<String>, AuthError> {
        panic!("Not implemented!");
    }

    // Session data methods
    pub fn set_data(&self, key: &str, value: &str) -> Result<(), AuthError> {
        panic!("Not implemented!");
    }

    // Session data methods
    pub fn get_persistant_data(&self, key: &str) -> Result<Option<String>, AuthError> {
        panic!("Not implemented!");
    }

    // Session data methods
    pub fn set_persistant_data(&self, key: &str, value: &str) -> Result<(), AuthError> {
        panic!("Not implemented!");
    }
}
*/

/*
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
*/
