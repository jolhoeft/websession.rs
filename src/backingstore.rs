use std::io;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, BufWriter};
use std::convert::From;
use std::collections::HashMap;

#[derive(Debug)]
pub enum BackingStoreError {
    NoSuchUser,
    MissingData,
    Locked,
    UserExists,
    IO(io::Error),
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
    fn get_pwhash(&self, user: &str, fail_if_locked: bool) -> Result<String, BackingStoreError>;
    fn update_pwhash(&mut self, user: &str, new_pwhash: &str) -> Result<(), BackingStoreError>;
    fn lock(&mut self, user: &str) -> Result<(), BackingStoreError>;
    fn islocked(&self, user: &str) -> Result<bool, BackingStoreError>;
    fn unlock(&mut self, user: &str) -> Result<(), BackingStoreError>;
    fn create(&mut self, user: &str, pwhash: &str) -> Result<(), BackingStoreError>;
    fn delete(&mut self, user: &str) -> Result<(), BackingStoreError>;
}

#[derive(Debug)]
pub struct FileBackingStore {
    filename: String,
}

impl FileBackingStore {
    pub fn new(filename: &str) -> FileBackingStore {
        FileBackingStore {
            filename: filename.to_string(),
        }
    }

    fn load_file(&self) -> Result<String, BackingStoreError> {
        let mut f = try!(File::open(self.filename.clone()));
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
    fn update_user_hash(&self, user: &str, new_pwhash: Option<&str>, fail_if_locked: bool) -> Result<(), BackingStoreError> {
        let mut found = false;
        let pwfile = try!(self.load_file());

        let oldfn = self.filename.clone();
        let newfn = oldfn.clone() + ".old";
        try!(fs::rename(oldfn.clone(), newfn));
        let mut f = BufWriter::new(try!(File::create(oldfn)));
        for line in pwfile.lines() {
            match try!(self.line_has_user(line, user, fail_if_locked)) {
                Some(_) => match new_pwhash {
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
    fn get_pwhash(&self, user: &str, fail_if_locked: bool) -> Result<String, BackingStoreError> {
        let pwfile = try!(self.load_file());
        for line in pwfile.lines() {
            match try!(self.line_has_user(line, user, fail_if_locked)) {
                Some(hash) => return Ok(hash),
                None => { }, // keep looking
            }
        }
        Err(BackingStoreError::NoSuchUser)
    }

    fn update_pwhash(&mut self, user: &str, new_pwhash: &str) -> Result<(), BackingStoreError> {
        self.update_user_hash(user, Some(new_pwhash), true)
    }

    fn lock(&mut self, user: &str) -> Result<(), BackingStoreError> {
        let mut hash = try!(self.get_pwhash(user, false));
        if !try!(self.hash_is_locked(&hash)) {
            hash.insert(0, '!');
            return self.update_user_hash(user, Some(&hash), false);
        }
        // not an error to lock a locked user
        Ok(())
    }

    fn islocked(&self, user: &str) -> Result<bool, BackingStoreError> {
        let hash = try!(self.get_pwhash(user, false));
        self.hash_is_locked(&hash)
    }

    fn unlock(&mut self, user: &str) -> Result<(), BackingStoreError> {
        let mut hash = try!(self.get_pwhash(user, false));
        if try!(self.hash_is_locked(&hash)) {
            hash.remove(0);
            return self.update_user_hash(user, Some(&hash), false);
        }
        // not an error to unlock an unlocked user
        Ok(())
    }

    fn create(&mut self, user: &str, pwhash: &str) -> Result<(), BackingStoreError> {
        match self.get_pwhash(user, false) {
            Ok(_) => Err(BackingStoreError::UserExists),
            Err(BackingStoreError::NoSuchUser) => {
                let mut f = BufWriter::new(try!(OpenOptions::new().append(true).open(self.filename.clone())));
                try!(f.write_all(user.as_bytes()));
                try!(f.write_all(b":"));
                try!(f.write_all(pwhash.as_bytes()));
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
    pwhash: String,
    locked: bool,
}

#[derive(Debug)]
pub struct MemoryBackingStore {
    users: HashMap<String, MemoryEntry>,
}

impl MemoryBackingStore {
    pub fn new() -> MemoryBackingStore {
        MemoryBackingStore {
            users: HashMap::new(),
        }
    }
}

impl BackingStore for MemoryBackingStore {
    fn get_pwhash(&self, user: &str, fail_if_locked: bool) -> Result<String, BackingStoreError> {
        match self.users.get(user) {
            Some(entry) => if !(fail_if_locked && entry.locked) {
                Ok(entry.pwhash.to_string())
            } else {
                Err(BackingStoreError::Locked)
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn update_pwhash(&mut self, user: &str, new_pwhash: &str) -> Result<(), BackingStoreError> {
        match self.users.get_mut(user) {
            Some(entry) => match entry.locked {
                true => Err(BackingStoreError::Locked),
                false => {
                    entry.pwhash = new_pwhash.to_string();
                    Ok(())
                },
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn lock(&mut self, user: &str) -> Result<(), BackingStoreError> {
        match self.users.get_mut(user) {
            Some(entry) => {
                entry.locked = true;
                Ok(())
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn islocked(&self, user: &str) -> Result<bool, BackingStoreError> {
        match self.users.get(user) {
            Some(entry) => Ok(entry.locked),
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn unlock(&mut self, user: &str) -> Result<(), BackingStoreError> {
        match self.users.get_mut(user) {
            Some(entry) => {
                entry.locked = false;
                Ok(())
            },
            None => Err(BackingStoreError::NoSuchUser),
        }
    }

    fn create(&mut self, user: &str, pwhash: &str) -> Result<(), BackingStoreError> {
        if self.users.contains_key(user) {
            Err(BackingStoreError::UserExists)
        } else {
            self.users.insert(user.to_string(),
                MemoryEntry { pwhash: pwhash.to_string(), locked: false, });
            Ok(())
        }
    }

    fn delete(&mut self, user: &str) -> Result<(), BackingStoreError> {
        match self.users.remove(user) {
            Some(_) => Ok(()),
            None => Err(BackingStoreError::NoSuchUser),
        }
    }
}
