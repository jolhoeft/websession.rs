//! # BackingStore
//!
//! The BackingStore trait provides the interfaces for storing user
//! credentials. Default implementations are provided for plain text
//! file and in memory storage.

extern crate libc;
extern crate pwhash;
extern crate fs2;

use std::{io, fs};
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, BufWriter};
use std::convert::From;
use std::collections::HashMap;
use std::sync::Mutex;
use std::vec::IntoIter;
use pwhash::bcrypt;
use fs2::FileExt;

#[derive(Debug)]
pub enum BackingStoreError {
    NoSuchUser,
    MissingData,
    Locked,
    UserExists,
    IO(io::Error),
    Mutex,
    Hash(pwhash::error::Error),
}

impl PartialEq for BackingStoreError {
    fn eq(&self, other: &BackingStoreError) -> bool {
        let rv = match (self, other) {
            (&BackingStoreError::NoSuchUser,  &BackingStoreError::NoSuchUser) => true,
            (&BackingStoreError::MissingData, &BackingStoreError::MissingData) => true,
            (&BackingStoreError::Locked,      &BackingStoreError::Locked) => true,
            (&BackingStoreError::UserExists,  &BackingStoreError::UserExists) => true,
            (&BackingStoreError::IO(_),       &BackingStoreError::IO(_)) => true,
            (&BackingStoreError::Mutex,       &BackingStoreError::Mutex) => true,
            (&BackingStoreError::Hash(_),     &BackingStoreError::Hash(_)) => true,
            _ => false,
        };
        rv
    }
}

impl From<io::Error> for BackingStoreError {
    fn from(err: io::Error) -> BackingStoreError {
        BackingStoreError::IO(err)
    }
}

impl From<pwhash::error::Error> for BackingStoreError {
    fn from(err: pwhash::error::Error) -> BackingStoreError {
        BackingStoreError::Hash(err)
    }
}

/// The BackingStore doesn't know about userIDs vs usernames; the
/// consumer of websessions is responsible for being able to change
/// usernames w/o affecting userIDs.
///
/// N.B., implementors of BackingStore provide a new that gets
/// whatever is needed to connect to the store.
///
/// In general, the BackingStore will be accessed in a multi-threded
/// environment, so Mutex or RwLock will probably be needed.
pub trait BackingStore : Debug {
    /// Encrypt unencrypted credentials. For passwords this would be a
    /// sound hashing funtions. For some credentials, e.g. public
    /// keys, additional encryption may be unneeded.
    fn encrypt_credentials(&self, plain: &str) -> Result<String, BackingStoreError>;
    /// Verify the credentials for the user. Unencrypted passwords are
    /// expected, as would be provided by a user logging in.
    fn verify(&self, user: &str, plain_cred: &str) -> Result<bool, BackingStoreError>;
    /// Get the credentials for the user. For passwords, this would be
    /// the salted hashed password.
    fn get_credentials(&self, user: &str, fail_if_locked: bool) -> Result<String, BackingStoreError>;
    /// Set new credentials for the user. Credentials must be
    /// encrypted by the encrypt_credentials. If unencrypted
    /// credentials are provided, users will not be able to log in,
    /// but plain text will be stored in the backing store, creating a
    /// potential security issue.
    fn update_credentials(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError>;
    /// Convenience method calling encrypt_credentials and
    /// update_credentials. The default implementation should
    /// normally be sufficient.
    fn update_credentials_plain(&self, user: &str, plain_cred: &str) -> Result<(), BackingStoreError> {
        let enc_cred = self.encrypt_credentials(plain_cred)?;
        self.update_credentials(user, &enc_cred)
    }
    /// Lock the user to prevent logins. Locked users should never
    /// verify, but the password/credentials are not cleared and can be
    /// restored.
    fn lock(&self, user: &str) -> Result<(), BackingStoreError>;
    /// Check if the user is locked.
    fn is_locked(&self, user: &str) -> Result<bool, BackingStoreError>;
    /// Unlock the user, restoring the original password/credentials.
    fn unlock(&self, user: &str) -> Result<(), BackingStoreError>;
    /// Create a new user with the given credentials. Should return
    /// `BackingStoreError::UserExists` if the user already
    /// exists. See comment about encrypted credentials under
    /// update_credentials.
    fn create_preencrypted(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError>;
    /// Convenience method calling encrypt_credentials and create_preencrypted.
    /// The default implementation should normally be sufficient.
    fn create_plain(&self, user: &str, plain_cred: &str) -> Result<(), BackingStoreError> {
        let enc_cred = self.encrypt_credentials(plain_cred)?;
        self.create_preencrypted(user, &enc_cred)
    }
    /// Delete the user and all stored credentials and other data.
    fn delete(&self, user: &str) -> Result<(), BackingStoreError>;
    /// Return a Vec of the user names. `users_iter` may be more
    /// appropriate when there are large numbers of users. Only one of
    /// `users` or `users-iter` needs to be implemented. The default
    /// implementations will take care of the other. However there may
    /// be performace reasons to implement both.
    fn users(&self) -> Result<Vec<String>, BackingStoreError> {
        self.users_iter().map(|v| v.map(|u| u.clone()).collect())
    }
    /// Return Interator over the user names. `users` may be more
    /// convenient when there are small numbers of users. Only one of
    /// `users` or `users-iter` needs to be implemented. The default
    /// implementations will take care of the other. However there may
    /// be performace reasons to implement both.
    fn users_iter(&self) -> Result<IntoIter<String>, BackingStoreError> {
        self.users().map(|v| v.into_iter())
    }
}

#[derive(Debug)]
/// File based backing store.
pub struct FileBackingStore {
    filename: Mutex<String>,
}

impl FileBackingStore {
    /// Create a new file based backing store with the given file.
    pub fn new(filename: &str) -> FileBackingStore {
        let fname = filename.to_string();
        FileBackingStore {
            filename: Mutex::new(fname.clone()),
        }
    }

    // it would be nice if we allowed retries and/or sleep times, but that
    // breaks the API
    fn load_file(&self) -> Result<String, BackingStoreError> {
        let fname = self.filename.lock().map_err(|_| BackingStoreError::Mutex)?;
        let name = fname.clone();
        let mut buf = String::new();
        let mut f = File::open(name)?;
        f.lock_shared()?;
        f.read_to_string(&mut buf)?;
        Ok(buf)
    }

    fn line_has_user(&self, line: &str, user: &str, fail_if_locked: bool) -> Result<Option<String>, BackingStoreError> {
        let v: Vec<&str> = line.splitn(2, ':').collect();
        if v.len() < 2 { // it's not okay for users to have empty passwords
            Err(BackingStoreError::MissingData)
        } else if v[0] == user {
            if fail_if_locked && try!(self.hash_is_locked(v[1])) {
                Err(BackingStoreError::Locked)
            } else {
                Ok(Some(v[1].to_string()))
            }
        } else {
            Ok(None)
        }
    }

    fn hash_is_locked(&self, hash: &str) -> Result<bool, BackingStoreError> {
        let mut chars = hash.chars();
        match chars.next() {
            Some(c) => Ok(c == '!'),
            None => Err(BackingStoreError::MissingData),
        }
    }

    fn update_user_hash(&self, user: &str, new_creds: Option<&str>, fail_if_locked: bool) -> Result<(), BackingStoreError> {
        let mut found = false;
        let pwfile = self.load_file()?;

        let fname = self.filename.lock().map_err(|_| BackingStoreError::Mutex)?;
        let oldfn = fname.clone();
        let newfn = oldfn.to_string() + ".old";

        fs::rename(oldfn.clone(), newfn)?; // XXX modes
        let file = File::create(oldfn)?;
        file.lock_exclusive()?;
        let mut f = BufWriter::new(file);
        for line in pwfile.lines() {
            match self.line_has_user(line, user, fail_if_locked)? {
                Some(_) => match new_creds {
                    Some(newhash) => {
                        f.write_all(user.as_bytes())?;
                        f.write_all(b":")?;
                        f.write_all(newhash.as_bytes())?;
                        f.write_all(b"\n")?;
                        found = true;
                    },
                    None => found = true, // we're deleting, don't write out
                },
                None => { // no user on this line, continue
                    f.write_all(line.as_bytes())?;
                    f.write_all(b"\n")?;
                },
            }
        }

        if found {
            Ok(())
        } else {
            Err(BackingStoreError::NoSuchUser)
        }
    }
}

impl BackingStore for FileBackingStore {
    fn encrypt_credentials(&self, plain: &str) -> Result<String, BackingStoreError> {
        Ok(bcrypt::hash(plain)?)
    }

    fn get_credentials(&self, user: &str, fail_if_locked: bool) -> Result<String, BackingStoreError> {
        let pwfile = try!(self.load_file());
        for line in pwfile.lines() {
            match try!(self.line_has_user(line, user, fail_if_locked)) {
                Some(hash) => return Ok(hash),
                None => { }, // keep looking
            }
        }
        Err(BackingStoreError::NoSuchUser)
    }

    fn verify(&self, user: &str, plain_cred: &str) -> Result<bool, BackingStoreError> {
        let hash = try!(self.get_credentials(user, true));
        Ok(bcrypt::verify(plain_cred, &hash))
    }

    fn update_credentials(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError> {
        self.update_user_hash(user, Some(enc_cred), true)
    }

    fn lock(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hash = try!(self.get_credentials(user, false));
        if !try!(self.hash_is_locked(&hash)) {
            hash.insert(0, '!');
            return self.update_user_hash(user, Some(&hash), false);
        }
        // not an error to lock a locked user
        Ok(())
    }

    fn is_locked(&self, user: &str) -> Result<bool, BackingStoreError> {
        let hash = try!(self.get_credentials(user, false));
        self.hash_is_locked(&hash)
    }

    fn unlock(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hash = try!(self.get_credentials(user, false));
        if try!(self.hash_is_locked(&hash)) {
            hash.remove(0);
            return self.update_user_hash(user, Some(&hash), false);
        }
        // not an error to unlock an unlocked user
        Ok(())
    }

    fn create_preencrypted(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError> {
        // The FileBackingStore uses a : delimiter, so : in usernames is bad.
        if user.find(':').is_some() {
            Err(BackingStoreError::NoSuchUser)
        } else {
            match self.get_credentials(user, false) {
                Ok(_) => Err(BackingStoreError::UserExists),
                Err(BackingStoreError::NoSuchUser) => {
                    let fname = self.filename.lock().map_err(|_| BackingStoreError::Mutex)?;
                    let name = (*fname).clone();
                    let file = OpenOptions::new().append(true).open(name)?;
                    file.lock_exclusive()?;
                    let mut f = BufWriter::new(file);
                    f.write_all(user.as_bytes())?;
                    f.write_all(b":")?;
                    f.write_all(enc_cred.as_bytes())?;
                    f.write_all(b"\n")?;
                    Ok(())
                },
                Err(e) => Err(e),
            }
        }
    }

    fn delete(&self, user: &str) -> Result<(), BackingStoreError> {
        self.update_user_hash(user, None, false)
    }

    fn users(&self) -> Result<Vec<String>, BackingStoreError> {
        let mut users = Vec::new();
        let pwfile = try!(self.load_file());
        for line in pwfile.lines() {
            let v: Vec<&str> = line.split(':').collect();
            if v.len() == 0 {
                continue;
            } else {
                users.push(v[0].to_string());
            }
        }
        Ok(users)
    }
}

#[derive(Debug)]
struct MemoryEntry {
    credentials: String,
    locked: bool,
}

/// In memory backing store. Does not persist across restarts. Mostly
/// useful for testing.
#[derive(Debug)]
pub struct MemoryBackingStore {
    users: Mutex<HashMap<String, MemoryEntry>>,
}

impl MemoryBackingStore {
    /// Create a new in memory backing store.
    pub fn new() -> MemoryBackingStore {
        MemoryBackingStore {
            users: Mutex::new(HashMap::new()),
        }
    }

    /// Exports the contents in a format suitable for a FileBackingStore to use,
    /// if it is then written to disk as a file with suitable permissions.
    pub fn export_as_fbs(&self) -> Result<String, BackingStoreError> {
        let mut rv = String::new();
        let hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        for (key, val) in hashmap.iter() {
            rv += key;
            rv.push(':');
            if val.locked {
                rv.push('!');
            }
            // Since we're the consumer, we don't have to care about \n vs \r\n.
            rv += &val.credentials;
            rv.push('\n');
        }
        Ok(rv)
    }
}

impl BackingStore for MemoryBackingStore {
    fn encrypt_credentials(&self, plain: &str) -> Result<String, BackingStoreError> {
        Ok(bcrypt::hash(plain)?)
    }

    fn get_credentials(&self, user: &str, fail_if_locked: bool) -> Result<String, BackingStoreError> {
        let hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        match hashmap.get(user) {
            Some(entry) => if !(fail_if_locked && entry.locked) {
                Ok(entry.credentials.to_string())
            } else {
                Err(BackingStoreError::Locked)
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn verify(&self, user: &str, plain_cred: &str) -> Result<bool, BackingStoreError> {
        let creds = self.get_credentials(user, true)?;
        Ok(bcrypt::verify(plain_cred, &creds))
    }

    fn update_credentials(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError> {
        let mut hashmap =
            self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        match hashmap.get_mut(user) {
            Some(entry) => match entry.locked {
                true => Err(BackingStoreError::Locked),
                false => {
                    entry.credentials = enc_cred.to_string();
                    Ok(())
                },
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn lock(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        match hashmap.get_mut(user) {
            Some(entry) => {
                entry.locked = true;
                Ok(())
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn is_locked(&self, user: &str) -> Result<bool, BackingStoreError> {
        let hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        match hashmap.get(user) {
            Some(entry) => Ok(entry.locked),
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn unlock(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        match hashmap.get_mut(user) {
            Some(entry) => {
                entry.locked = false;
                Ok(())
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn create_preencrypted(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        if hashmap.contains_key(user) {
            Err(BackingStoreError::UserExists)
        } else if user.find(':').is_some() { // maintain compatibility with FBS
            Err(BackingStoreError::NoSuchUser)
        } else {
            hashmap.insert(user.to_string(), MemoryEntry {
                credentials: enc_cred.to_string(),
                locked: false,
            });
            Ok(())
        }
    }

    fn delete(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        match hashmap.remove(user) {
            Some(_) => Ok(()),
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn users(&self) -> Result<Vec<String>, BackingStoreError> {
        let hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        Ok(hashmap.keys().map(|k| k.clone()).collect::<Vec<String>>())
    }
}

// Note that these tests do not set permissions on the (temporary) password
// files and use hardcoded passwords which are visible in both plaintext and in
// ciphertext.  Good practices dictate minimizing the read permissions on the
// password file and not storing the password anywhere else, in plaintext or
// ciphertext.
#[cfg(test)]
mod test {
    extern crate tempdir;

    use backingstore::{BackingStore, FileBackingStore, MemoryBackingStore};
    use std::fs::File;
    use std::io::Write;

    /// Tests that usernames with : in them are illegal for the FileBackingStore
    #[test]
    fn fbs_colons_in_usernames() {
        let fullpath = tempdir::TempDir::new("fbs").unwrap();
        let tp = fullpath.path().join("fbs");
        let path = tp.to_str().unwrap();
        let _f = File::create(path);
        let fbs = FileBackingStore::new(&path);

        assert_eq!(fbs.create_plain("bad:user", "password").is_err(), true);
    }

    #[test]
    fn mbs_colons_in_usernames() {
        let mbs = MemoryBackingStore::new();
        assert_eq!(mbs.create_plain("bad:user", "password").is_err(), true);
    }

    #[test]
    fn fbs_create_user_plain() {
        let fullpath = tempdir::TempDir::new("fbs").unwrap();
        let tp = fullpath.path().join("fbs");
        let path = tp.to_str().unwrap();
        let _f = File::create(path);
        let fbs = FileBackingStore::new(&path);

        assert_eq!(fbs.create_plain("user", "password").is_ok(), true);
    }

    #[test]
    fn mbs_create_user_plain() {
        let mbs = MemoryBackingStore::new();
        assert_eq!(mbs.create_plain("user", "password").is_ok(), true);
    }

    /// Tests that locked users cannot authenticate to the FileBackingStore
    #[test]
    fn fbs_can_locked_login() {
        let fullpath = tempdir::TempDir::new("fbs").unwrap();
        let tp = fullpath.path().join("fbs");
        let path = tp.to_str().unwrap();
        let _f = File::create(path);
        let fbs = FileBackingStore::new(&path);

        assert_eq!(fbs.create_plain("user", "password").is_ok(), true);
        assert_eq!(fbs.lock("user").is_ok(), true);
        assert_eq!(fbs.verify("user", "password").is_err(), true);
    }

    /// Tests that locked users cannot authenticate to the MemoryBackingStore
    #[test]
    fn mbs_can_locked_login() {
        let mbs = MemoryBackingStore::new();
        assert_eq!(mbs.create_plain("user", "password").is_ok(), true);
        assert_eq!(mbs.verify("user", "password").is_err(), false);
        assert_eq!(mbs.lock("user").is_ok(), true);
        assert_eq!(mbs.verify("user", "password").is_err(), true);
    }

    #[test]
    fn mbs_export() {
        let mbs = MemoryBackingStore::new();
        let password = String::from("$2b$08$LOru0WKGEf49Pn26QuFC7OPIYyihiFNNjr0DBzWkLNj/rq8cg3sgq");
        let line = String::from("user:") + &password + "\n";
        assert_eq!(mbs.create_preencrypted("user", &password).is_ok(), true);
        assert_eq!(mbs.verify("user", "password").is_err(), false);
        let output = mbs.export_as_fbs();
        assert_eq!(output.is_err(), false);
        assert_eq!(output.unwrap(), line);

        let fullpath = tempdir::TempDir::new("fbs").unwrap();
        let tp = fullpath.path().join("fbs");
        let path = tp.to_str().unwrap();
        let f = File::create(path);
        // Once we've gotten here, line and output are the same, but I gave
        // output away in the assert_eq! that proved it.
        assert_eq!(f.unwrap().write_all(line.as_bytes()).is_err(), false);
        let fbs = FileBackingStore::new(&path);
        assert_eq!(fbs.verify("user", "password").is_err(), false);
    }
}
