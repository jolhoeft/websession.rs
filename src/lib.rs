#![crate_type = "lib"]
#![crate_name = "websession"]

//! # Websession
//!
//! Websession provides session and user support for web
//! applications. It provides support for storing user information in
//! a plain text file or in memory. Implement the
//! [BackingStore](backingstore/index.html) trait to support other
//! storage, such as a database.
//!
//! ## Example
//!
//! Todo: working example here
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
use std::vec::IntoIter;
use self::backingstore::{BackingStore, BackingStoreError};
use self::sessions::{SessionManager, SessionError};
pub use self::sessionpolicy::SessionPolicy;

#[derive(Debug)]
pub enum AuthError {
    /// Session has expired
    Expired,
    /// User is not authorized
    Unauthorized,
    /// Internal error, mutex is poisoned
    Mutex,
    /// Internal error in the backing store
    BackingStore(BackingStoreError),
    /// Internal error in the session manager 
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

/// The Authenticator is the main interface to Websession. It is
/// responsible for tracking session IDs, and the users associated
/// with the ID, if any. It also provides pass through support to the
/// [BackingStore](backingstore/index.html) for user management.
#[derive(Debug)]
pub struct Authenticator {
    sess_mgr: SessionManager,
    backing_store: Box<BackingStore + Send + Sync>,
    // Do we need this, or does the app just hang onto this for us?
    // cookie_name: String,
    mapping: Mutex<HashMap<String, String>>,
}

impl Authenticator {
    // add `cookie_name: &str` as the last argument if we need it
    /// Create a new Authenticator. `expiration` is how long a session
    /// should live w/o activity. Activity resets the clock on a
    /// session.
    pub fn new(backing_store: Box<BackingStore + Send + Sync>, expiration: Duration, policy: SessionPolicy) -> Authenticator {
        Authenticator {
            sess_mgr: SessionManager::new(expiration, policy),
            backing_store: backing_store,
            // cookie_name: cookie_name.to_string(),
            mapping: Mutex::new(HashMap::new()),
        }
    }

    fn verify(&self, user: &str, credentials: &str) -> Result<bool, AuthError> {
        self.backing_store.verify(user, credentials).map_err(|e| AuthError::BackingStore(e))
    }

    // should check policy
    /// Verify that the provided `credentials` apply to the given
    /// `user`. If they do, associate the user with the given
    /// `signature`.
    pub fn login(&self, user: &str, credentials: &str, signature: &ConnectionSignature) -> Result<(), AuthError> {
        match self.sess_mgr.is_expired(signature) {
            Ok(true) => {
                self.sess_mgr.stop(signature);
                Err(AuthError::Expired)
            },
            Ok(false) => match self.verify(user, credentials) {
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

    /// Remove any assocation of a user to the given `signature`, and
    /// remove the session.
    pub fn logout(&self, signature: &ConnectionSignature) {
        let id = signature.token.to_string();
        match self.mapping.lock() {
            Ok(mut hashmap) => hashmap.remove(&id),
            Err(poisoned) => poisoned.into_inner().remove(&id),
        };
        self.sess_mgr.stop(signature);
    }

    /// Get the `user` associate with the session, if any.
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

    /// Update the users credentials, e.g. password.
    pub fn update_credentials(&self, user: &str, new_creds: &str) -> Result<(), AuthError> {
        self.backing_store.update_credentials(user, new_creds).map_err(|e| AuthError::BackingStore(e))
    }

    // These doesn't take a ConnectionSignature because maybe we want to
    // manipulate a user other than ourself.
    /// Disable the a user's ability to login. The password will not
    /// be changed, but all login attempts will fail.
    pub fn lock_user(&self, user: &str) -> Result<(), AuthError> {
        self.backing_store.lock(user).map_err(|e| AuthError::BackingStore(e))
    }

    /// Check if the user's account is locked.
    pub fn is_locked(&self, user: &str) -> Result<bool, AuthError> {
        self.backing_store.is_locked(user).map_err(|e| AuthError::BackingStore(e))
    }

    /// Enable the user's account. The old password will be restored.
    pub fn unlock(&self, user: &str) -> Result<(), AuthError> {
        self.backing_store.unlock(user).map_err(|e| AuthError::BackingStore(e))
    }

    /// Create a new user with the given credentials. The backing
    /// store is responsible for ensuring the credentials are stored
    /// securely.
    pub fn create(&self, user: &str, creds: &str) -> Result<(), AuthError> {
        self.backing_store.create(user, creds).map_err(|e| AuthError::BackingStore(e))
    }

    /// Delete the given user. Any stored credentials will be deleted
    /// too, and will need to be provided again if the user is
    /// re-created.
    pub fn delete(&self, user: &str) -> Result<(), AuthError> {
        self.backing_store.delete(user).map_err(|e| AuthError::BackingStore(e))
    }

    /// This is the main driver - it returns a signature that contains
    /// the current value for the cookie, or an error if something
    /// went wrong. The returned signature may be different from the
    /// one provided.
    pub fn run(&self, signature: ConnectionSignature) -> Result<ConnectionSignature, AuthError> {
        self.sess_mgr.start(signature).map_err(|err| AuthError::from(err))
    }

    /// Return a Vec of usernames
    pub fn users(&self) -> Result<Vec<String>, AuthError> {
        self.backing_store.users().map_err(|e| AuthError::BackingStore(e))
    }

    /// Return an iterator over usesrs
    pub fn users_iter(&self) -> Result<IntoIter<String>, AuthError> {
        self.backing_store.users_iter().map_err(|e| AuthError::BackingStore(e))
    }
}
