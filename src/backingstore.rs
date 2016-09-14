use std::io;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, BufWriter};
use std::convert::From;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug)]
pub enum BackingStoreError {
    NoSuchUser,
    MissingData,
    Locked,
    UserExists,
    IO(io::Error),
    Mutex,
}

impl From<io::Error> for BackingStoreError {
    fn from(err: io::Error) -> BackingStoreError {
        BackingStoreError::IO(err)
    }
}

// The BackingStore doesn't know about userIDs vs usernames; the consumer of
// websessions is responsible for being able to change usernames w/o affecting
// userIDs.
// N.B., implementors of BackingStore provide a new that gets whatever is needed
// to connect to the store.
pub trait BackingStore {
    fn get_credentials(&self, user: &str, fail_if_locked: bool) -> Result<String, BackingStoreError>;
    fn update_credentials(&mut self, user: &str, new_creds: &str) -> Result<(), BackingStoreError>;
    fn lock(&mut self, user: &str) -> Result<(), BackingStoreError>;
    fn islocked(&self, user: &str) -> Result<bool, BackingStoreError>;
    fn unlock(&mut self, user: &str) -> Result<(), BackingStoreError>;
    fn create(&mut self, user: &str, creds: &str) -> Result<(), BackingStoreError>;
    fn delete(&mut self, user: &str) -> Result<(), BackingStoreError>;
}

#[derive(Debug)]
pub struct FileBackingStore {
    filename: Mutex<String>,
}

impl FileBackingStore {
    pub fn new(filename: &str) -> FileBackingStore {
        let fname = filename.to_string();
        FileBackingStore {
            filename: Mutex::new(fname.clone()),
        }
    }

    fn load_file(&self) -> Result<String, BackingStoreError> {
        let fname = try!(self.filename.lock().map_err(|_| BackingStoreError::Mutex));
        let name = fname.clone();
        let mut f = try!(File::open(name));
        let mut buf = String::new();
        try!(f.read_to_string(&mut buf));
        Ok(buf)
    }

    fn line_has_user(&self, line: &str, user: &str, fail_if_locked: bool) -> Result<Option<String>, BackingStoreError> {
        let v: Vec<&str> = line.split(':').collect();
        if v.len() < 1 {
            Err(BackingStoreError::MissingData)
        } else if v[0] == user {
            if v.len() != 2 {
                Err(BackingStoreError::MissingData)
            } else if fail_if_locked && try!(self.hash_is_locked(v[1])) {
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

    // We're intentionally ignoring \r\n under Windows; we're the consumer too.
    fn update_user_hash(&self, user: &str, new_creds: Option<&str>, fail_if_locked: bool) -> Result<(), BackingStoreError> {
        let mut found = false;
        let pwfile = try!(self.load_file());

        let fname = try!(self.filename.lock().map_err(|_| BackingStoreError::Mutex));
        let oldfn = fname.clone();
        let newfn = oldfn.to_string() + ".old";
        try!(fs::rename(oldfn.clone(), newfn));
        let mut f = BufWriter::new(try!(File::create(oldfn)));
        for line in pwfile.lines() {
            match try!(self.line_has_user(line, user, fail_if_locked)) {
                Some(_) => match new_creds {
                    Some(newhash) => {
                        try!(f.write_all(user.as_bytes()));
                        try!(f.write_all(b":"));
                        try!(f.write_all(newhash.as_bytes()));
                        try!(f.write_all(b"\n"));
                        found = true;
                    },
                    None => found = true, // we're deleting, don't write out
                },
                None => { // no user on this line, continue
                    try!(f.write_all(line.as_bytes()));
                    try!(f.write_all(b"\n"));
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

    fn update_credentials(&mut self, user: &str, new_creds: &str) -> Result<(), BackingStoreError> {
        self.update_user_hash(user, Some(new_creds), true)
    }

    fn lock(&mut self, user: &str) -> Result<(), BackingStoreError> {
        let mut hash = try!(self.get_credentials(user, false));
        if !try!(self.hash_is_locked(&hash)) {
            hash.insert(0, '!');
            return self.update_user_hash(user, Some(&hash), false);
        }
        // not an error to lock a locked user
        Ok(())
    }

    fn islocked(&self, user: &str) -> Result<bool, BackingStoreError> {
        let hash = try!(self.get_credentials(user, false));
        self.hash_is_locked(&hash)
    }

    fn unlock(&mut self, user: &str) -> Result<(), BackingStoreError> {
        let mut hash = try!(self.get_credentials(user, false));
        if try!(self.hash_is_locked(&hash)) {
            hash.remove(0);
            return self.update_user_hash(user, Some(&hash), false);
        }
        // not an error to unlock an unlocked user
        Ok(())
    }

    fn create(&mut self, user: &str, creds: &str) -> Result<(), BackingStoreError> {
        match self.get_credentials(user, false) {
            Ok(_) => Err(BackingStoreError::UserExists),
            Err(BackingStoreError::NoSuchUser) => {
                let fname = try!(self.filename.lock().map_err(|_| BackingStoreError::Mutex));
                let name = (*fname).clone();
                let mut f = BufWriter::new(try!(OpenOptions::new().append(true).open(name)));
                try!(f.write_all(user.as_bytes()));
                try!(f.write_all(b":"));
                try!(f.write_all(creds.as_bytes()));
                try!(f.write_all(b"\n"));
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    fn delete(&mut self, user: &str) -> Result<(), BackingStoreError> {
        self.update_user_hash(user, None, false)
    }
}

#[derive(Debug)]
struct MemoryEntry {
    credentials: String,
    locked: bool,
}

#[derive(Debug)]
pub struct MemoryBackingStore {
    users: Mutex<HashMap<String, MemoryEntry>>,
}

impl MemoryBackingStore {
    pub fn new() -> MemoryBackingStore {
        MemoryBackingStore {
            users: Mutex::new(HashMap::new()),
        }
    }
}

impl BackingStore for MemoryBackingStore {
    fn get_credentials(&self, user: &str, fail_if_locked: bool) -> Result<String, BackingStoreError> {
        let hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        match hashmap.get(user) {
            Some(entry) => if !(fail_if_locked && entry.locked) {
                Ok(entry.credentials.to_string())
            } else {
                Err(BackingStoreError::Locked)
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn update_credentials(&mut self, user: &str, new_creds: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        match hashmap.get_mut(user) {
            Some(entry) => match entry.locked {
                true => Err(BackingStoreError::Locked),
                false => {
                    entry.credentials = new_creds.to_string();
                    Ok(())
                },
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn lock(&mut self, user: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        match hashmap.get_mut(user) {
            Some(entry) => {
                entry.locked = true;
                Ok(())
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn islocked(&self, user: &str) -> Result<bool, BackingStoreError> {
        let hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        match hashmap.get(user) {
            Some(entry) => Ok(entry.locked),
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn unlock(&mut self, user: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        match hashmap.get_mut(user) {
            Some(entry) => {
                entry.locked = false;
                Ok(())
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn create(&mut self, user: &str, creds: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        if hashmap.contains_key(user) {
            Err(BackingStoreError::UserExists)
        } else {
            hashmap.insert(user.to_string(),
                MemoryEntry { credentials: creds.to_string(), locked: false, });
            Ok(())
        }
    }

    fn delete(&mut self, user: &str) -> Result<(), BackingStoreError> {
        let mut hashmap = try!(self.users.lock().map_err(|_| BackingStoreError::Mutex));
        match hashmap.remove(user) {
            Some(_) => Ok(()),
            None => Err(BackingStoreError::NoSuchUser),
        }
    }
}
