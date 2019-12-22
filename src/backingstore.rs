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

/// The BackingStore doesn't know about user-IDs vs usernames: the consumer of websession is responsible for being
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

    /// Convenience method calling `encrypt_credentials` and `create_preencrypted`.  The default implementation should
    /// normally be sufficient.
    fn create_plain(&self, user: &str, plain_cred: &str) -> Result<(), BackingStoreError> {
        let enc_cred = self.encrypt_credentials(plain_cred)?;
        self.create_preencrypted(user, &enc_cred)
    }

    /// Delete the user, all stored credentials, and any other data.
    fn delete(&self, user: &str) -> Result<(), BackingStoreError>;

    /// Return a Vec of the user names. `users_iter` may be more appropriate when there are large numbers of users.
    /// Only one of `users` or `users_iter` needs to be implemented, as the default implementations will take care of
    /// the other.  However, there may be performance reasons to implement both.
    fn users(&self) -> Result<Vec<String>, BackingStoreError> {
        self.users_iter().map(|v| v.collect())
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
            filename: Mutex::new(fname),
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

    /// Returns the password of the user in question, if they're found (and unlocked, when `fail_if_locked` is `true`).
    /// Returns MissingData if the password file is missing a password, or Locked if they're found but locked.
    fn line_has_user(line: &str, user: &str, fail_if_locked: bool) -> Result<Option<String>, BackingStoreError> {
        let v: Vec<&str> = line.splitn(2, ':').collect();
        let fixed_user = FileBackingStore::fix_username(user);
        if v.len() < 2 { // it's not okay for users to have empty passwords
            Err(BackingStoreError::MissingData)
        } else if v[0] == fixed_user {
            if fail_if_locked && FileBackingStore::hash_is_locked(v[1]) {
                Err(BackingStoreError::Locked)
            } else {
                Ok(Some(v[1].to_string()))
            }
        } else {
            Ok(None)
        }
    }

    fn hash_is_locked(hash: &str) -> bool {
        hash.starts_with('!')
    }

    // Fix usernames so that no illegal characters or strings enter the backing store.  I'd like all `BackingStore`
    // implementations to implement this, but I can't figure out how to do this generically while still allowing users
    // to override it, so for now, it's here as an example.
    fn fix_username(user: &str) -> String { user.replace("\n", "\u{FFFD}").replace(":", "\u{FFFFD}") }

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
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(ref e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
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
        let mut user_recorded = false;
        let fixedname = FileBackingStore::fix_username(username);

        let (create_new, change_pass, fil) = match (new_creds, fail_if_locked) {
            (Some(_), None) => (true, false, false),
            (Some(_), Some(fil)) => (false, true, fil),
            (None, Some(fil)) => (false, false, fil),
            (None, None) => (false, false, false), // It looks like they want to delete the user.
        };

        let all = self.load_file()?;
        let basename = self.filename.lock().map_err(|_| BackingStoreError::Mutex)?;
        let oldfn = basename.to_string() + ".old";
        let newfn = basename.to_string() + ".new";

        { // In its own block because I want to drop the backup file once it was written.
            let mut backupf = FileBackingStore::create_safe(&oldfn)?;

            backupf.write_all(all.as_bytes())?;
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
                                warn!("{} already found in {}; removing extra line", username, basename);
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
        // Ok(bcrypt::hash_with(bcrypt::BcryptSetup { cost: Some(12u32), ..Default::default() }, plain)?)
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
        if !FileBackingStore::hash_is_locked(&hash) {
            hash.insert(0, '!');
            self.update_password_file(user, Some(&hash), Some(false))
        } else { // not an error to lock a locked user
            Ok(())
        }
    }

    fn is_locked(&self, user: &str) -> Result<bool, BackingStoreError> {
        let hash = self.get_credentials(user, false)?;
        Ok(FileBackingStore::hash_is_locked(&hash))
    }

    fn unlock(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hash = self.get_credentials(user, false)?;
        if FileBackingStore::hash_is_locked(&hash) {
            // It must have at least 1 char or it couldn't be locked.
            hash.remove(0);
            self.update_password_file(user, Some(&hash), Some(false))
        } else { // not an error to unlock an unlocked user
            Ok(())
        }
    }

    fn create_preencrypted(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError> {
        self.update_password_file(user, Some(enc_cred), None)
    }

    /// Returns Ok(()) on deletion, Err(BackingStoreError::NoSuchUser) if they were already deleted, or IO or Mutex
    /// errors.
    fn delete(&self, user: &str) -> Result<(), BackingStoreError> {
        self.update_password_file(user, None, Some(false))
    }

    fn users(&self) -> Result<Vec<String>, BackingStoreError> {
        let mut users = Vec::new();
        let pwfile = self.load_file()?;
        for line in pwfile.lines() {
            let v: Vec<&str> = line.split(':').collect();
            if v.is_empty() {
                continue;
            } else {
                users.push(v[0].to_string());
            }
        }
        Ok(users)
    }

    fn check_user(&self, user: &str) -> Result<bool, BackingStoreError> {
        let pwfile = self.load_file()?;
        let fixeduser = FileBackingStore::fix_username(user);
        for line in pwfile.lines() {
            let v: Vec<&str> = line.split(':').collect();
            if (v.len() > 1) && (v[0] == fixeduser) {
                if FileBackingStore::hash_is_locked(v[1]) {
                    return Err(BackingStoreError::Locked);
                } else {
                    return Ok(true);
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
#[derive(Debug, Default)]
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
        // Ok(bcrypt::hash_with(bcrypt::BcryptSetup { cost: Some(12u32), ..Default::default() }, plain)?)
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
            Some(entry) => {
                if entry.locked {
                    Err(BackingStoreError::Locked)
                } else {
                    entry.credentials = enc_cred.to_string();
                    Ok(())
                }
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn lock(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        match hashmap.get_mut(user) {
            Some(entry) => {
                entry.locked = true;
                Ok(())
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn is_locked(&self, user: &str) -> Result<bool, BackingStoreError> {
        let hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        match hashmap.get(user) {
            Some(entry) => Ok(entry.locked),
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn unlock(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        match hashmap.get_mut(user) {
            Some(entry) => {
                entry.locked = false;
                Ok(())
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn create_preencrypted(&self, user: &str, enc_cred: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        if hashmap.contains_key(user) {
            Err(BackingStoreError::UserExists)
        } else {
            hashmap.insert(user.to_string(), MemoryEntry {
                credentials: enc_cred.to_string(),
                locked: false,
            });
            Ok(())
        }
    }

    fn delete(&self, user: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = self.users.lock().map_err(|_|
            BackingStoreError::Mutex)?;
        match hashmap.remove(user) {
            Some(_) => Ok(()),
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn users(&self) -> Result<Vec<String>, BackingStoreError> {
        let hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        Ok(hashmap.keys().cloned().collect::<Vec<String>>())
    }

    fn check_user(&self, user: &str) -> Result<bool, BackingStoreError> {
        let hashmap = self.users.lock().map_err(|_| BackingStoreError::Mutex)?;
        if let Some(u) = hashmap.get(user) {
            if u.locked {
                Err(BackingStoreError::Locked)
            } else {
                Ok(true)
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
    extern crate rand;

    use backingstore::*;
    use std::fs::File;
    use std::collections::HashSet;
    use backingstore::test::rand::Rng;

    fn make_filebackingstore() -> (FileBackingStore, tempdir::TempDir) {
        let fullpath = tempdir::TempDir::new("fbs").unwrap();
        let tp = fullpath.path().join("fbs");
        let path = tp.to_str().unwrap();
        let _f = File::create(path);
        (FileBackingStore::new(&path), fullpath)
    }

    /// Tests that usernames with `:` and `\n` in them are now okay for the `FileBackingStore` (because it will convert
    /// them).  This concern was specific to the implementation of the `FileBackingStore`, which uses `:` as a
    /// delimiter, but is no longer required -- with the caveat that the FileBackingStore may collide usernames that the
    /// `MemoryBackingStore` won't complain about.
    #[test]
    fn fbs_colons_in_usernames() {
        let (fbs, _temp) = make_filebackingstore();

        assert_eq!(fbs.create_plain("now:a:valid:user", "password").is_err(), false);
    }

    /// Tests that usernames with `:` and `\n` in them are now okay for the `MemoryBackingStore` (because it doesn't
    /// care).  This concern was specific to the implementation of the `FileBackingStore`, which uses `:` as a
    /// delimiter, but is no longer required -- with the caveat that the FileBackingStore may collide usernames that the
    /// `MemoryBackingStore` won't complain about.
    #[test]
    fn mbs_colons_in_usernames() {
        let mbs = MemoryBackingStore::new();
        assert_eq!(mbs.create_plain("now:a:good:user", "password").is_err(), false);
    }

    /// Tests that usernames and passwords with Unicode in them are okay.  There's no reason they shouldn't be, but
    /// let's make sure.

    #[test]
    fn fbs_unicrud() {
        let (fbs, _temp) = make_filebackingstore();

        assert_eq!(fbs.create_plain("Some\u{FFFD}", "Unicode\u{2747}").is_err(), false);
    }

    #[test]
    fn fbs_create_user_plain() {
        let (fbs, _temp) = make_filebackingstore();

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
        let (fbs, _temp) = make_filebackingstore();

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
    fn fbs_check_user() {
        let (fbs, _temp) = make_filebackingstore();

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
        let (fbs, _temp) = make_filebackingstore();

        assert_eq!(fbs.create_plain("user\nname", "password").is_ok(), true);
        assert_eq!(fbs.check_user("user\nname").is_ok(), true);
        assert_eq!(fbs.check_user("user\nname"), Ok(true));
        assert_eq!(fbs.check_user("user\u{FFFD}name"), Ok(true));
    }

    #[test]
    fn mbs_check_newline1() {
        let mbs = MemoryBackingStore::new();

        assert_eq!(mbs.create_plain("user\nname", "password").is_ok(), true);
    }

    #[test]
    fn mbs_check_newline2() {
        let mbs = MemoryBackingStore::new();

        assert_eq!(mbs.create_plain("user\nname", "password").is_ok(), true);
        assert_eq!(mbs.check_user("user\nname").is_ok(), true);
    }

    #[test]
    fn mbs_check_newline3() {
        let mbs = MemoryBackingStore::new();

        assert_eq!(mbs.create_plain("user\nname", "password").is_ok(), true);
        assert_eq!(mbs.check_user("user\nname"), Ok(true));
    }

    #[test]
    fn fbs_fuzz_users() {
        let (fbs, _temp) = make_filebackingstore();
        let names: Vec<String> = (0 .. 20).map(|_| (0 .. 10).map(|_| rand::random::<char>()).collect()).collect();
        let passwords: Vec<String> = (0 .. 20).map(|_| (0 .. 10).map(|_| rand::random::<char>()).collect()).collect();
        let newpasswords: Vec<String> = (0 .. 20).map(|_| (0 .. 10).map(|_| rand::random::<char>()).collect()).collect();

        let mut added: HashSet<&str> = HashSet::new();
        let mut locked: HashSet<&str> = HashSet::new();
        let mut changed: HashSet<&str> = HashSet::new();

        // Things we can do:
        // - add users
        // - lock users
        // - unlock users
        // - change passwords
        // - delete users
        // - see if a user exists

        enum Things {
            Add,
            Lock,
            Unlock,
            Change,
            Delete,
            Examine,
            Verify,
        }
        impl rand::Rand for Things {
            fn rand<R: Rng>(rng: &mut R) -> Self {
                match rng.gen_range(0, 7) {
                    0 => Things::Add,
                    1 => Things::Lock,
                    2 => Things::Unlock,
                    3 => Things::Change,
                    4 => Things::Delete,
                    5 => Things::Examine,
                    _ => Things::Verify,
                }
            }
        }

        for _ in [ 1 .. 10 ].iter() {
            for (i, x) in names.iter().enumerate() {
                match rand::random::<Things>() {
                    Things::Add => if added.contains(&x.as_str()) {
                        assert_eq!(fbs.create_plain(&x, &passwords[i]), Err(BackingStoreError::UserExists));
                    } else {
                        assert_eq!(fbs.create_plain(&x, &passwords[i]), Ok(()));
                        added.insert(&x.as_str());
                    },
                    Things::Lock => if added.contains(&x.as_str()) {
                        assert_eq!(fbs.lock(&x.as_str()), Ok(()));
                        locked.insert(&x.as_str());
                    } else {
                        assert_eq!(fbs.lock(&x.as_str()), Err(BackingStoreError::NoSuchUser));
                    },
                    Things::Unlock => if added.contains(&x.as_str()) {
                        assert_eq!(fbs.unlock(&x.as_str()), Ok(()));
                        locked.remove(&x.as_str());
                    } else {
                        assert_eq!(fbs.unlock(&x.as_str()), Err(BackingStoreError::NoSuchUser));
                    },
                    Things::Change => if added.contains(&x.as_str()) {
                        if locked.contains(&x.as_str()) {
                            assert_eq!(fbs.update_credentials_plain(&x, &newpasswords[i]), Err(BackingStoreError::Locked));
                        } else {
                            assert_eq!(fbs.update_credentials_plain(&x, &newpasswords[i]), Ok(()));
                            changed.insert(&x.as_str());
                        }
                    } else {
                        assert_eq!(fbs.update_credentials_plain(&x, &newpasswords[i]), Err(BackingStoreError::NoSuchUser));
                    },
                    Things::Delete => if added.contains(&x.as_str()) {
                        assert_eq!(fbs.delete(&x.as_str()), Ok(()));
                        locked.remove(&x.as_str());
                        changed.remove(&x.as_str());
                        added.remove(&x.as_str());
                    } else {
                        assert_eq!(fbs.delete(&x.as_str()), Err(BackingStoreError::NoSuchUser));
                    },
                    Things::Examine => if added.contains(&x.as_str()) {
                        if locked.contains(&x.as_str()) {
                            assert_eq!(fbs.check_user(&x.as_str()), Err(BackingStoreError::Locked));
                        } else {
                            assert_eq!(fbs.check_user(&x.as_str()), Ok(true));
                        }
                    } else {
                        assert_eq!(fbs.check_user(&x.as_str()), Ok(false));
                    },
                    Things::Verify => if added.contains(&x.as_str()) {
                        if changed.contains(&x.as_str()) {
                            assert_eq!(fbs.verify(&x, &passwords[i]), Ok(false));
                            assert_eq!(fbs.verify(&x, &newpasswords[i]), Ok(true));
                        } else {
                            assert_eq!(fbs.verify(&x, &passwords[i]), Ok(true));
                            assert_eq!(fbs.verify(&x, &newpasswords[i]), Ok(false));
                        }
                    } else {
                        assert_eq!(fbs.verify(&x, &passwords[i]), Err(BackingStoreError::NoSuchUser));
                        assert_eq!(fbs.verify(&x, &newpasswords[i]), Err(BackingStoreError::NoSuchUser));
                    }
                }
            }
        }
    }
}
