#![crate_type = "lib"]
#![crate_name = "websession"]

extern crate time;
extern crate uuid;
extern crate pwhash;

pub mod sessions;
pub mod backingstore;
pub mod connectionsignature;
pub mod token;
pub mod sessionpolicy;

use std::collections::HashMap;
use pwhash::bcrypt;
use time::Duration;
use std::sync::Mutex;
use self::backingstore::{BackingStore, BackingStoreError};
use self::connectionsignature::ConnectionSignature;
use self::sessions::{SessionManager, SessionError};
use self::sessionpolicy::SessionPolicy;

#[derive(Debug)]
pub enum AuthError {
    Expired,
    Unauthorized,
    Mutex,
    BackingStore(BackingStoreError),
    Session(SessionError),
}

impl From<BackingStoreError> for AuthError {
    fn from(err: BackingStoreError) -> AuthError {
        match err {
            BackingStoreError::NoSuchUser => AuthError::Unauthorized,
            BackingStoreError::Locked => AuthError::Unauthorized,
            BackingStoreError::UserExists => AuthError::Unauthorized,
            // not sure what else we can trap
            _ => AuthError::BackingStore(err),
        }
    }
}

pub struct Authenticator {
    sess_mgr: SessionManager,
    backing_store: Box<BackingStore + Send + Sync>,
    cookie_name: String,
    mapping: Mutex<HashMap<String, String>>,
}

impl Authenticator {
    pub fn new(backing_store: Box<BackingStore + Send + Sync>, expiration: Duration, policy: SessionPolicy, cookie_name: &str) -> Authenticator {
        Authenticator {
            sess_mgr: SessionManager::new(expiration, policy),
            backing_store: backing_store,
            cookie_name: cookie_name.to_string(),
            mapping: Mutex::new(HashMap::new()),
        }
    }

    fn verify(&self, user: &str, creds: &str) -> Result<bool, AuthError> {
        let real_creds = try!(self.backing_store.get_credentials(user, true));
        Ok(bcrypt::verify(creds, real_creds.as_str()))
    }

    // should check policy
    pub fn login(&self, user: &str, creds: &str, signature: &ConnectionSignature) -> Result<(), AuthError> {
        match self.sess_mgr.is_expired(signature) {
            Ok(true) => {
                self.sess_mgr.logout(signature);
                Err(AuthError::Expired)
            },
            Ok(false) => match self.verify(user, creds) {
                Ok(true) => {
                    try!(self.mapping.lock().map_err(|_| AuthError::Mutex))
                        .insert(signature.token.to_string(), user.to_string());
                    Ok(())
                },
                Ok(false) => Err(AuthError::Unauthorized),
                Err(e) => Err(e),
            },
            Err(e) => Err(AuthError::Session(e)),
        }
    }

    pub fn logout(&self, signature: &ConnectionSignature) {
        let id = signature.token.to_string();
        match self.mapping.lock() {
            Ok(mut hashmap) => hashmap.remove(&id),
            Err(poisoned) => poisoned.into_inner().remove(&id),
        };
        self.sess_mgr.logout(signature);
    }

    pub fn get_user(&self, signature: &ConnectionSignature) -> Result<Option<String>, AuthError> {
        match self.sess_mgr.is_expired(signature) {
            Ok(true) => Err(AuthError::Expired),
            Ok(false) => match self.mapping.lock() {
                Ok(hashmap) => Ok(hashmap.get(&signature.token.to_string())
                    .map(|s| s.clone())), // this is to unborrow the username
                Err(_) => Err(AuthError::Mutex),
            },
            Err(e) => match e {
                SessionError::Lost => Ok(None),
                _ => Err(AuthError::Session(e)),
            },
        }
    }

    pub fn run(&self, signature: &ConnectionSignature) -> Result<String, AuthError> {
        match self.sess_mgr.start(signature) {
            Ok(s) => Ok(s),
            Err(e) => Err(AuthError::Session(e)),
        }
    }
}
