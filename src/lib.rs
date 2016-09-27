#![crate_type = "lib"]
#![crate_name = "websession"]

extern crate time;
extern crate uuid;
#[cfg(feature = "hyper")]
extern crate hyper;

pub mod sessions;
pub mod backingstore;
pub mod connectionsignature;
pub mod token;
pub mod sessionpolicy;

pub use self::connectionsignature::ConnectionSignature;

use std::collections::HashMap;
use time::Duration;
use std::sync::Mutex;
use self::backingstore::{BackingStore, BackingStoreError};
use self::sessions::{SessionManager, SessionError};
pub use self::sessionpolicy::SessionPolicy;

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

impl From<SessionError> for AuthError {
    fn from(err: SessionError) -> AuthError {
        AuthError::Session(err)
    }
}

pub struct Authenticator {
    sess_mgr: SessionManager,
    backing_store: Box<BackingStore + Send + Sync>,
    // Do we need this, or does the app just hang onto this for us?
    // cookie_name: String,
    mapping: Mutex<HashMap<String, String>>,
}

impl Authenticator {
    // add `cookie_name: &str` as the last argument if we need it
    pub fn new(backing_store: Box<BackingStore + Send + Sync>, expiration: Duration, policy: SessionPolicy) -> Authenticator {
        Authenticator {
            sess_mgr: SessionManager::new(expiration, policy),
            backing_store: backing_store,
            // cookie_name: cookie_name.to_string(),
            mapping: Mutex::new(HashMap::new()),
        }
    }

    fn verify(&self, user: &str, creds: &str) -> Result<bool, AuthError> {
        self.backing_store.verify(user, creds).map_err(|e| AuthError::BackingStore(e))
    }

    // should check policy
    pub fn login(&self, user: &str, creds: &str, signature: &ConnectionSignature) -> Result<(), AuthError> {
        match self.sess_mgr.is_expired(signature) {
            Ok(true) => {
                self.sess_mgr.stop(signature);
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
        self.sess_mgr.stop(signature);
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

    // These doesn't take a ConnectionSignature because maybe we want to
    // manipulate a user other than ourself.
    pub fn lock_user(&mut self, user: &str) -> Result<(), AuthError> {
        self.backing_store.lock(user).map_err(|e| AuthError::BackingStore(e))
    }

    pub fn islocked(&self, user: &str) -> Result<bool, AuthError> {
        self.backing_store.is_locked(user).map_err(|e| AuthError::BackingStore(e))
    }

    pub fn unlock(&mut self, user: &str) -> Result<(), AuthError> {
        self.backing_store.unlock(user).map_err(|e| AuthError::BackingStore(e))
    }

    pub fn create(&mut self, user: &str, creds: &str) -> Result<(), AuthError> {
        self.backing_store.create(user, creds).map_err(|e| AuthError::BackingStore(e))
    }

    pub fn delete(&mut self, user: &str) -> Result<(), AuthError> {
        self.backing_store.delete(user).map_err(|e| AuthError::BackingStore(e))
    }

    // This is the main driver - it returns a signature tht contains
    // the current value for the cookie, or an error if something went
    // wrong. The returned signature may be different from the one
    // provided.
    pub fn run(&self, signature: &ConnectionSignature) -> Result<ConnectionSignature, AuthError> {
        self.sess_mgr.start(signature).map_err(|err| AuthError::from(err))
    }
}
