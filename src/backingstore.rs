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

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

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
        match (self, other) {
            (&BackingStoreError::NoSuchUser, &BackingStoreError::NoSuchUser) |
            (&BackingStoreError::MissingData, &BackingStoreError::MissingData) |
            (&BackingStoreError::Locked, &BackingStoreError::Locked) |
            (&BackingStoreError::UserExists, &BackingStoreError::UserExists) |
            (&BackingStoreError::IO(_), &BackingStoreError::IO(_)) |
            (&BackingStoreError::Mutex, &BackingStoreError::Mutex) |
            (&BackingStoreError::Hash(_), &BackingStoreError::Hash(_)) => true,
            _ => false,
        }
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

/// The BackingStore doesn't know about user-IDs vs usernames: the consumer of
/// websessions is responsible for being able to change usernames w/o affecting
/// user-IDs.
///
/// N.B., implementors of BackingStore provide a `new` that gets whatever is
/// needed to connect to the store.
///
/// In general, the BackingStore will be accessed in a multi-threaded
/// environment, so Mutex or RwLock will probably be needed.
pub trait BackingStore : Debug {
    /// Encrypt unencrypted credentials.  For passwords, this would be a sound
    /// hashing function.  For some credentials, such as public keys, additional
    /// encryption may be unneeded.
    fn encrypt_credentials(&self, plain: &str) -> Result<String, BackingStoreError>;
    /// Verify the credentials for the user.  Unencrypted passwords are
    /// expected, such as would be provided by a user logging in.
    fn verify(&self, user: &str, plain_cred: &str) -> Result<bool, BackingStoreError>;
    /// Get the credentials for the user. For passwords, this would be the
    /// salted hashed password.
    fn get_credentials(&self, user: &str, fail_if_locked: bool) -> Result<String, BackingStoreError>;
    /// Set new credentials for the user.  Credentials must be encrypted by
    /// `encrypt_credentials`.  If unencrypted credentials are provided, users
    /// will not be able to log in, and plain text will be stored in the backing
    /// store, creating a potential security issue.
    fn update_credentials(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError>;
    /// Convenience method, calling encrypt_credentials and update_credentials.
    /// The default implementation should normally be sufficient.
    fn update_credentials_plain(&self, user: &str, plain_cred: &str) -> Result<(), BackingStoreError> {
        let enc_cred = self.encrypt_credentials(plain_cred)?;
        self.update_credentials(user, &enc_cred)
    }
    /// Lock the user to prevent logins.  Locked users should never verify, but
    /// the password/credentials are not cleared and can be restored.
    fn lock(&self, user: &str) -> Result<(), BackingStoreError>;
    /// Check if the user is locked.
    fn is_locked(&self, user: &str) -> Result<bool, BackingStoreError>;
    /// Unlock the user, restoring the original password/credentials.
    fn unlock(&self, user: &str) -> Result<(), BackingStoreError>;
    /// Create a new user with the given credentials.  Should return
    /// `BackingStoreError::UserExists` if the user already exists. See the
    /// comment about encrypted credentials under `update_credentials`.
    fn create_preencrypted(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError>;
    /// Convenience method calling `encrypt_credentials` and
    /// `create_preencrypted`.  The default implementation should normally be
    /// sufficient.
    fn create_plain(&self, user: &str, plain_cred: &str) -> Result<(), BackingStoreError> {
        let enc_cred = self.encrypt_credentials(plain_cred)?;
        self.create_preencrypted(user, &enc_cred)
    }
    /// Delete the user, all stored credentials, and any other data.
    fn delete(&self, user: &str) -> Result<(), BackingStoreError>;
    /// Return a Vec of the user names. `users_iter` may be more appropriate
    /// when there are large numbers of users.  Only one of `users` or
    /// `users_iter` needs to be implemented, as the default implementations
    /// will take care of the other.  However, there may be performance reasons
    /// to implement both.
    fn users(&self) -> Result<Vec<String>, BackingStoreError> {
        self.users_iter().map(|v| v.map(|u| u.clone()).collect())
    }
    /// Return an Iterator over the user names.  `users` may be more convenient
    /// when there are small numbers of users.  Only one of `users` or
    /// `users_iter` needs to be implemented, as the default implementations
    /// will take care of the other.  However, there may be performance reasons
    /// to implement both.
    fn users_iter(&self) -> Result<IntoIter<String>, BackingStoreError> {
        self.users().map(|v| v.into_iter())
    }
    /// Return whether or not the user already exists in the backing store.  May
    /// return a `BackingStoreError`, in particular,
    /// `BackingStoreError::Locked`, which means the user exists but the account
    /// is locked.
    fn check_user(&self, user: &str) -> Result<bool, BackingStoreError>;
}

#[derive(Debug)]
/// File based backing store.
pub struct FileBackingStore {
    filename: Mutex<String>,
}

impl FileBackingStore {
    /// Create a new file based backing store with the given file.  The file
    /// must already exist, and is assumed to have appropriate permissions.
    pub fn new(filename: &str) -> FileBackingStore {
        let fname = filename.to_string();
        FileBackingStore {
            filename: Mutex::new(fname.clone()),
        }
    }

    // It would be nice if we allowed retries and/or sleep times, but that
    // breaks the API.  Right now, let's go with "worse is better" and force the
    // caller to manage this.
    fn load_file(&self) -> Result<String, BackingStoreError> {
        let fname = self.filename.lock().map_err(|_| BackingStoreError::Mutex)?;
        let name = fname.clone();
        let mut buf = String::new();
        let mut f = File::open(name)?;
        f.lock_shared()?;
        f.read_to_string(&mut buf)?;
        Ok(buf)
    }

#[cfg(unix)]
    // Assumes it already called with the filename locked.
    fn replace_file(basename: &str) -> Result<File, BackingStoreError> {
        let perms = {
            let f = File::open(basename.clone())?;
            let p = f.metadata()?.permissions();
            p.mode()
            // and drop the file
        };
        let backupfn = basename.to_string() + "old";
        fs::rename(basename.clone(), backupfn)?;
        // We could depend upon the umask but that way lies easy mistakes.
        let file = OpenOptions::new().write(true).create_new(true).mode(perms)
            .open(basename)?;
        file.lock_exclusive()?;
        Ok(file)
    }

#[cfg(windows)]
    // Assumes it already called with the filename locked.
    // XXX I don't have the foggiest notion how to secure this file, especially
    // because file attributes under Windows don't have much relationship to
    // access control.
    fn replace_file(basename: &str) -> Result<File, IOError> {
        let backupfn = basename.to_string() + "old";
        fs::rename(basename.clone(), backupfn)?;
        let file = OpenOptions::new().write(true).create_new(true)
            .share_mode(0).open(basename)?;
        file.lock_exclusive()?;
        Ok(file)
    }

    fn line_has_user(line: &str, user: &str, fail_if_locked: bool) -> Result<Option<String>, BackingStoreError> {
        let v: Vec<&str> = line.splitn(2, ':').collect();
        let fixed_user = user.replace("\n", "\u{FFFD}");
        if v.len() < 2 { // it's not okay for users to have empty passwords
            Err(BackingStoreError::MissingData)
        } else if v[0] == fixed_user {
            if fail_if_locked && FileBackingStore::hash_is_locked(v[1])? {
                Err(BackingStoreError::Locked)
            } else {
                Ok(Some(v[1].to_string()))
            }
        } else {
            Ok(None)
        }
    }

    fn hash_is_locked(hash: &str) -> Result<bool, BackingStoreError> {
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
        let mut f = BufWriter::new(FileBackingStore::replace_file(&fname)?);
        for line in pwfile.lines() {
            // line_has_user corrects \n to \u{FFFD}
            match FileBackingStore::line_has_user(line, user, fail_if_locked)? {
                Some(_) => match new_creds {
                    Some(newhash) => {
                        f.write_all(user.replace("\n", "\u{FFFD}").as_bytes())?;
                        f.write_all(b":")?;
                        f.write_all(newhash.as_bytes())?;
                        f.write_all(b"\n")?;
                        found = true;
                    },
                    None => found = true, // we're deleting, don't write out
                },
                None => { // wrong user on this line, continue
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
        let pwfile = self.load_file()?;
        for line in pwfile.lines() {
            // line_has_user corrects \n to \u{FFFD}
            if let Some(hash) =
                FileBackingStore::line_has_user(line, user, fail_if_locked)? {
                return Ok(hash);
            }
            // otherwise keep looking
        }
        Err(BackingStoreError::NoSuchUser)
    }

    fn verify(&self, user: &str, plain_cred: &str) -> Result<bool, BackingStoreError> {
        // get_credentials corrects \n to \u{FFFD}
        let hash = self.get_credentials(user, true)?;
        Ok(bcrypt::verify(plain_cred, &hash))
    }

    fn update_credentials(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError> {
        // update_user_hash corrects \n to \u{FFFD}
        self.update_user_hash(user, Some(enc_cred), true)
    }

    fn lock(&self, user: &str) -> Result<(), BackingStoreError> {
        // get_credentials corrects \n to \u{FFFD}
        let mut hash = self.get_credentials(user, false)?;
        if !FileBackingStore::hash_is_locked(&hash)? {
            hash.insert(0, '!');
            // update_user_hash corrects \n to \u{FFFD}
            return self.update_user_hash(user, Some(&hash), false);
        }
        // not an error to lock a locked user
        Ok(())
    }

    fn is_locked(&self, user: &str) -> Result<bool, BackingStoreError> {
        // get_credentials corrects \n to \u{FFFD}
        let hash = self.get_credentials(user, false)?;
        FileBackingStore::hash_is_locked(&hash)
    }

    fn unlock(&self, user: &str) -> Result<(), BackingStoreError> {
        // get_credentials corrects \n to \u{FFFD}
        let mut hash = self.get_credentials(user, false)?;
        if FileBackingStore::hash_is_locked(&hash)? {
            hash.remove(0);
            // update_user_hash corrects \n to \u{FFFD}
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
            // get_credentials corrects \n to \u{FFFD}
            match self.get_credentials(user, false) {
                Ok(_) => Err(BackingStoreError::UserExists),
                Err(BackingStoreError::NoSuchUser) => {
                    let fname = self.filename.lock().map_err(|_| BackingStoreError::Mutex)?;
                    let mut f =
                        BufWriter::new(FileBackingStore::replace_file(&fname)?);
                    f.write_all(&user.replace("\n", "\u{FFFD}").as_bytes())?;
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
        let pwfile = self.load_file()?;
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

    fn check_user(&self, user: &str) -> Result<bool, BackingStoreError> {
        let pwfile = self.load_file()?;
        for line in pwfile.lines() {
            let v: Vec<&str> = line.split(':').collect();
            if v.len() > 1 {
                if v[0] == user.replace("\n", "\u{FFFD}") {
                    return match FileBackingStore::hash_is_locked(v[1])? {
                        true => Err(BackingStoreError::Locked),
                        false => Ok(true),
                    };
                }
            }
        }
        Ok(false)
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
        match hashmap.get(&user.replace("\n", "\u{FFFD}")) {
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
        match hashmap.get_mut(&user.replace("\n", "\u{FFFD}")) {
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
        let mut hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        match hashmap.get_mut(&user.replace("\n", "\u{FFFD}")) {
            Some(entry) => {
                entry.locked = true;
                Ok(())
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn is_locked(&self, user: &str) -> Result<bool, BackingStoreError> {
        let hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        match hashmap.get(&user.replace("\n", "\u{FFFD}")) {
            Some(entry) => Ok(entry.locked),
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn unlock(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        match hashmap.get_mut(&user.replace("\n", "\u{FFFD}")) {
            Some(entry) => {
                entry.locked = false;
                Ok(())
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn create_preencrypted(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        let fixed_user = &user.replace("\n", "\u{FFFD}"); // compatibility FBS
        if hashmap.contains_key(fixed_user) {
            Err(BackingStoreError::UserExists)
        } else if fixed_user.find(':').is_some() { // maintain compatibility with FBS
            Err(BackingStoreError::NoSuchUser)
        } else {
            hashmap.insert(fixed_user.to_string(), MemoryEntry {
                credentials: enc_cred.to_string(),
                locked: false,
            });
            Ok(())
        }
    }

    fn delete(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = self.users.lock().map_err(|_|
            BackingStoreError::Mutex)?;
        match hashmap.remove(&user.replace("\n", "\u{FFFD}")) {
            Some(_) => Ok(()),
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn users(&self) -> Result<Vec<String>, BackingStoreError> {
        let hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        Ok(hashmap.keys().map(|k| k.clone()).collect::<Vec<String>>())
    }

    fn check_user(&self, user: &str) -> Result<bool, BackingStoreError> {
        let hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        if let Some(u) = hashmap.get(&user.replace("\n", "\u{FFFD}")) {
            match u.locked {
                true => Err(BackingStoreError::Locked),
                false => Ok(true),
            }
        } else {
            Ok(false)
        }
    }
}

// Note that these tests do not set permissions on the (temporary) password
// files and use hardcoded passwords which are visible in both plaintext and in
// ciphertext.  Good practices dictate minimizing the read permissions on the
// production password file and not storing the password anywhere else, in
// plaintext or ciphertext.
#[cfg(test)]
mod test {
    extern crate tempdir;

    use backingstore::*;
    use std::fs::File;
    use std::io::Write;

    /// Tests that usernames with `:` in them are illegal for the
    /// `FileBackingStore`.  This concern is specific to the implementation of
    /// the `FileBackingStore`, which uses `:` as a delimiter, but is also
    /// carried across to the `MemoryBackingStore` to provide a simple
    /// conversion path from the latter to the former.
    #[test]
    fn fbs_colons_in_usernames() {
        let fullpath = tempdir::TempDir::new("fbs").unwrap();
        let tp = fullpath.path().join("fbs");
        let path = tp.to_str().unwrap();
        let _f = File::create(path);
        let fbs = FileBackingStore::new(&path);

        assert_eq!(fbs.create_plain("bad:user", "password").is_err(), true);
    }

    /// Tests that usernames with `:` in them are illegal for the
    /// `MemoryBackingStore`.  This concern is specific to the implementation of
    /// the `FileBackingStore`, which uses `:` as a delimiter, but is also
    /// carried across to the `MemoryBackingStore` to provide a simple
    /// conversion path from the latter to the former.
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

    /// Tests that locked users cannot authenticate to the `FileBackingStore`.
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

    /// Tests that locked users cannot authenticate to the `MemoryBackingStore`.
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
        assert_eq!(mbs.verify("user", "password"), Ok(true));
        assert_eq!(mbs.verify("user", "badpassword"), Ok(false));
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
        assert_eq!(fbs.verify("user", "password"), Ok(true));
        assert_eq!(fbs.verify("user", "badpassword"), Ok(false));
    }

    #[test]
    fn fbs_check_user() {
        let fullpath = tempdir::TempDir::new("fbs").unwrap();
        let tp = fullpath.path().join("fbs");
        let path = tp.to_str().unwrap();
        let _f = File::create(path);
        let fbs = FileBackingStore::new(&path);

        assert_eq!(fbs.create_plain("user", "password").is_ok(), true);
        assert_eq!(fbs.check_user("user").is_ok(), true);
        assert_eq!(fbs.check_user("user"), Ok(true));
        assert_eq!(fbs.check_user("missing"), Ok(false));
        assert_eq!(fbs.lock("user").is_ok(), true);
        assert_eq!(fbs.check_user("user"), Err(BackingStoreError::Locked));
    }

    #[test]
    fn mbs_check_user() {
        let mbs = MemoryBackingStore::new();
        assert_eq!(mbs.create_plain("user", "password").is_ok(), true);
        assert_eq!(mbs.check_user("user").is_ok(), true);
        assert_eq!(mbs.check_user("user"), Ok(true));
        assert_eq!(mbs.check_user("missing"), Ok(false));
        assert_eq!(mbs.lock("user").is_ok(), true);
        assert_eq!(mbs.check_user("user"), Err(BackingStoreError::Locked));
    }

    #[test]
    fn fbs_check_newline() {
        let fullpath = tempdir::TempDir::new("fbs").unwrap();
        let tp = fullpath.path().join("fbs");
        let path = tp.to_str().unwrap();
        let _f = File::create(path);
        let fbs = FileBackingStore::new(&path);

        assert_eq!(fbs.create_plain("user\nname", "password").is_ok(), true);
        assert_eq!(fbs.check_user("user\nname").is_ok(), true);
        assert_eq!(fbs.check_user("user\nname"), Ok(true));
        assert_eq!(fbs.check_user("user\u{FFFD}name"), Ok(true));
    }

    #[test]
    fn mbs_check_newline() {
        let mbs = MemoryBackingStore::new();

        assert_eq!(mbs.create_plain("user\nname", "password").is_ok(), true);
        assert_eq!(mbs.check_user("user\nname").is_ok(), true);
        assert_eq!(mbs.check_user("user\nname"), Ok(true));
        assert_eq!(mbs.check_user("user\u{FFFD}name"), Ok(true));
    }
}
