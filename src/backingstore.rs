//! # BackingStore
//!
//! The BackingStore trait provides the interfaces for storing user credentials. Default implementations are provided
//! for plain text files and in-memory storage.

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

/// The BackingStore doesn't know about user-IDs vs usernames: the consumer of websessions is responsible for being
/// able to change usernames w/o affecting user-IDs.
///
/// N.B., implementors of BackingStore provide a `new` that gets whatever is needed to connect to the store.
///
/// In general, the BackingStore will be accessed in a multi-threaded environment, so a Mutex or RwLock will probably
/// be needed by implementers.

pub trait BackingStore : Debug {
    /// Encrypt unencrypted credentials.  For passwords, this would be a sound hashing function.  For some credentials,
    /// such as public keys, additional encryption may be unneeded.
    fn encrypt_credentials(&self, plain: &str) -> Result<String, BackingStoreError>;

    /// Verify the credentials for the user.  Unencrypted passwords are
    /// expected, such as would be provided by a user logging in.
    fn verify(&self, user: &str, plain_cred: &str) -> Result<bool, BackingStoreError>;

    /// Get the credentials for the user. For passwords, this would be the salted hashed password.

    fn get_credentials(&self, user: &str, fail_if_locked: bool) -> Result<String, BackingStoreError>;

    /// Set new credentials for the user.  Credentials must be encrypted by `encrypt_credentials`.  If unencrypted
    /// credentials are provided, users will not be able to log in, and plain text will be stored in the backing store,
    /// creating a potential security issue.

    fn update_credentials(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError>;

    /// Convenience method, calling `encrypt_credentials` and `update_credentials`.  The default implementation should
    /// normally be sufficient.
    fn update_credentials_plain(&self, user: &str, plain_cred: &str) -> Result<(), BackingStoreError> {
        let enc_cred = self.encrypt_credentials(plain_cred)?;
        self.update_credentials(user, &enc_cred)
    }

    /// Lock the user to prevent logins.  Locked users should never verify, but the password/credentials are not cleared
    /// and can be restored.
    fn lock(&self, user: &str) -> Result<(), BackingStoreError>;

    /// Check if the user is locked.
    fn is_locked(&self, user: &str) -> Result<bool, BackingStoreError>;

    /// Unlock the user, restoring the original password/credentials.
    fn unlock(&self, user: &str) -> Result<(), BackingStoreError>;

    /// Create a new user with the given credentials.  Should return `BackingStoreError::UserExists` if the user already
    /// exists.  See the comment about encrypted credentials under `update_credentials`.
    fn create_preencrypted(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError>;

    // Convenience method calling `encrypt_credentials` and `create_preencrypted`.  The default implementation should
    /// normally be sufficient.
    fn create_plain(&self, user: &str, plain_cred: &str) -> Result<(), BackingStoreError> { let enc_cred =
        self.encrypt_credentials(plain_cred)?; self.create_preencrypted(user, &enc_cred) }

    /// Delete the user, all stored credentials, and any other data.
    fn delete(&self, user: &str) -> Result<(), BackingStoreError>;

    /// Return a Vec of the user names. `users_iter` may be more appropriate when there are large numbers of users.
    /// Only one of `users` or `users_iter` needs to be implemented, as the default implementations will take care of
    /// the other.  However, there may be performance reasons to implement both.
    fn users(&self) -> Result<Vec<String>, BackingStoreError> {
        self.users_iter().map(|v| v.map(|u| u.clone()).collect())
    }

    /// Return an Iterator over the user names.  `users` may be more convenient when there are small numbers of users.
    /// Only one of `users` or `users_iter` needs to be implemented, as the default implementations will take care of
    /// the other.  However, there may be performance reasons to implement both.
    fn users_iter(&self) -> Result<IntoIter<String>, BackingStoreError> {
        self.users().map(|v| v.into_iter())
    }

    /// Return whether or not the user already exists in the backing store.  May return a `BackingStoreError`, in
    /// particular, `BackingStoreError::Locked`, which means the user exists but the account is locked.
    fn check_user(&self, user: &str) -> Result<bool, BackingStoreError>;
}

#[derive(Debug)]
/// File based backing store.
pub struct FileBackingStore {
    filename: Mutex<String>,
}

#[cfg(unix)]
macro_rules! fbs_options {
    ($x:expr) => ($x.mode(0o600).custom_flags(libc::O_NOFOLLOW));
}

#[cfg(windows)]
macro_rules! fbs_options {
    ($x:expr) => ($x.share_mode(0));
}

impl FileBackingStore {
    /// Create a new file based backing store with the given file.  The file must already exist, and is assumed to have
    /// appropriate permissions.
    pub fn new(filename: &str) -> FileBackingStore {
        let fname = filename.to_string();
        FileBackingStore {
            filename: Mutex::new(fname.clone()),
        }
    }

    // It would be nice if we allowed retries and/or sleep times, but that breaks the API.  Right now, let's go with
    // "worse is better" and force the caller to manage this.
    fn load_file(&self) -> Result<String, BackingStoreError> {
        let fname = self.filename.lock().map_err(|_| BackingStoreError::Mutex)?;
        let name = fname.to_string();
        let mut buf = String::new();
        let mut f = File::open(name)?;
        f.lock_shared()?;
        f.read_to_string(&mut buf)?;
        Ok(buf)
    }

    fn fix_username(user: &str) -> String {
        user.replace("\n", "\u{FFFD}").replace(":", "\u{FFFFD}")
    }

    // Returns the password of the user in question, if they're found (and unlocked, when `fail_if_locked` is `true`).
    fn line_has_user(line: &str, user: &str, fail_if_locked: bool) -> Result<Option<String>, BackingStoreError> {
        let v: Vec<&str> = line.splitn(2, ':').collect();
        let fixed_user = FileBackingStore::fix_username(user);
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

    fn create_safe(filename: &str) -> Result<File, BackingStoreError> {
        let newf;

        let mut opts = OpenOptions::new();
        let o = fbs_options!(opts.create_new(true).write(true));
        loop {
            if match fs::remove_file(&filename) {
                Ok(_) => true,
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => true,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => false,
                Err(e) => return Err(BackingStoreError::IO(e)),
            } {
                match o.open(&filename) {
                    Ok(x) => {
                        newf = x;
                        break;
                    },
                    // Keep going...
                    Err(ref e) if (e.kind() == io::ErrorKind::Interrupted) || (e.kind() == io::ErrorKind::AlreadyExists) => (),
                    Err(e) => return Err(BackingStoreError::IO(e)),
                }
            }
        }
        // There might be a race here, but we should be opening the file with secure permissions, so it's probably okay.
        // N.B., ACLs (under both Linux and Windows) may not be captured properly here.
        newf.set_permissions(fs::metadata(filename)?.permissions())?;
        newf.lock_exclusive()?;
        Ok(newf)
    }

    // To make a new user, supply:                    username, Some(password), None
    // To change an existing user's password, supply: username, Some(password), Some(fail_if_locked)
    // To delete a user, supply:                      username, None,           _
    fn update_password_file(&self, username: &str, new_creds: Option<&str>, fail_if_locked: Option<bool>) -> Result<(), BackingStoreError> {
        let fixedname = FileBackingStore::fix_username(username);
        let mut user_recorded = false;

        let (create_new, change_pass, fil) = match (new_creds, fail_if_locked) {
            (Some(_), None) => (true, false, false),
            (Some(_), Some(fil)) => (false, true, fil),
            (None, Some(fil)) => (false, false, fil),
            _ => return Err(BackingStoreError::MissingData),
        };

        let basename = self.filename.lock().map_err(|_| BackingStoreError::Mutex)?;
        let oldfn = basename.to_string() + ".old";
        let newfn = basename.to_string() + ".new";

        let all = self.load_file()?;

        { // In its own block because I want to drop the backup file once it was written.
            let mut backupf = FileBackingStore::create_safe(&oldfn)?;

            backupf.write(all.as_bytes())?;
            backupf.flush()?;
        }

        { // In its own block because I want to drop the new file once it has been written.
            let mut f = BufWriter::new(FileBackingStore::create_safe(&newfn)?);

            for line in all.lines() {
                match FileBackingStore::line_has_user(line, username, fil)? {
                    Some(_) => {
                        if create_new {
                            // We found them.  That's bad.  Try to clean up.  It might not work.  That's okay.
                            let _ = fs::remove_file(&oldfn);
                            let _ = fs::remove_file(&newfn);
                            return Err(BackingStoreError::UserExists);
                        } else if change_pass {
                            if user_recorded {
                                // Don't write them more than once to the file.
                                // TODO: add logging
                                // warn!(format!("{} already found in {}; removing extra line", username, basename));
                            } else {
                                f.write_all(fixedname.as_bytes())?;
                                f.write_all(b":")?;
                                // We checked, there are new credentials here.
                                f.write_all(new_creds.unwrap().as_bytes())?;
                                f.write_all(b"\n")?;
                            }
                        } // else we're deleting them, so don't do anything
                        // Either way, we're good now.
                        user_recorded = true;
                    },
                    None => {
                        f.write_all(line.as_bytes())?;
                        f.write_all(b"\n")?;
                    },
                }
            }

            if create_new {
                f.write_all(fixedname.as_bytes())?;
                f.write_all(b":")?;
                // We already made sure there were some credentials in here.
                f.write_all(new_creds.unwrap().as_bytes())?;
                f.write_all(b"\n")?;
            } else if !user_recorded {
                // We didn't find them, but we were supposed to.  Try to clean up, but not very hard.
                let _ = fs::remove_file(&oldfn);
                let _ = fs::remove_file(&newfn);
                return Err(BackingStoreError::NoSuchUser);
            }

            f.flush()?;
        }

        // We now have a saved backup and a fully written new file.
        fs::rename(newfn, basename.to_string())?;
        Ok(())
    }
}

impl BackingStore for FileBackingStore {
    fn encrypt_credentials(&self, plain: &str) -> Result<String, BackingStoreError> {
        Ok(bcrypt::hash(plain)?)
    }

    fn get_credentials(&self, user: &str, fail_if_locked: bool) -> Result<String, BackingStoreError> {
        let pwfile = self.load_file()?;
        for line in pwfile.lines() {
            if let Some(hash) = FileBackingStore::line_has_user(line, user, fail_if_locked)? {
                return Ok(hash);
            }
            // otherwise keep looking
        }
        Err(BackingStoreError::NoSuchUser)
    }

    fn verify(&self, user: &str, plain_cred: &str) -> Result<bool, BackingStoreError> {
        let hash = self.get_credentials(user, true)?;
        Ok(bcrypt::verify(plain_cred, &hash))
    }

    fn update_credentials(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError> {
        self.update_password_file(user, Some(enc_cred), Some(true))
    }

    fn lock(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hash = self.get_credentials(user, false)?;
        if !FileBackingStore::hash_is_locked(&hash)? {
            hash.insert(0, '!');
            self.update_password_file(user, Some(&hash), Some(false))
        } else { // not an error to lock a locked user
            Ok(())
        }
    }

    fn is_locked(&self, user: &str) -> Result<bool, BackingStoreError> {
        let hash = self.get_credentials(user, false)?;
        FileBackingStore::hash_is_locked(&hash)
    }

    fn unlock(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hash = self.get_credentials(user, false)?;
        if FileBackingStore::hash_is_locked(&hash)? {
            hash.remove(0);
            self.update_password_file(user, Some(&hash), Some(false))
        } else { // not an error to unlock an unlocked user
            Ok(())
        }
    }

    fn create_preencrypted(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError> {
        self.update_password_file(user, Some(enc_cred), None)
    }

    fn delete(&self, user: &str) -> Result<(), BackingStoreError> {
        self.update_password_file(user, None, Some(false))
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

    /* The more I look at this, the less it seems to be a good idea, */
    /*
    /// Exports the contents as a string, which happens to match the format
    /// used by the FileBackingStore implementation.
    pub fn to_string(&self) -> Result<String, BackingStoreError> {
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
    */
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

    /* The more I look at this, the less it looks like a good idea. */
    /*
    #[test]
    fn mbs_export() {
        let mbs = MemoryBackingStore::new();
        let password = String::from("$2b$08$LOru0WKGEf49Pn26QuFC7OPIYyihiFNNjr0DBzWkLNj/rq8cg3sgq");
        let line = String::from("user:") + &password + "\n";
        assert_eq!(mbs.create_preencrypted("user", &password).is_ok(), true);
        assert_eq!(mbs.verify("user", "password").is_err(), false);
        assert_eq!(mbs.verify("user", "password"), Ok(true));
        assert_eq!(mbs.verify("user", "badpassword"), Ok(false));
        let output = mbs.to_string();
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
    */

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
