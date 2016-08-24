use std::io;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{Read, Write, BufWriter};
use std::convert::From;

#[derive(Debug)]
pub enum BackingStoreError {
    NoSuchUser,
    MissingData,
    Locked,
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
    fn get_pwhash(&self, user: &String, fail_if_locked: bool) -> Result<String, BackingStoreError>;
    fn update_pwhash(&mut self, user: &String, new_pwhash: &String) -> Result<(), BackingStoreError>;
    fn lock(&mut self, user: &String) -> Result<(), BackingStoreError>;
    fn islocked(&self, user: &String) -> Result<bool, BackingStoreError>;
    fn unlock(&mut self, user: &String) -> Result<(), BackingStoreError>;
    fn create(&mut self, user: &String, pwhash: &String) -> Result<(), BackingStoreError>;
    fn delete(&mut self, user: &String) -> Result<(), BackingStoreError>;
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
	let mut f = try!(File::open(self.filename.clone()).map_err(BackingStoreError::IO));
	let mut buf = String::new();
	try!(f.read_to_string(&mut buf).map_err(BackingStoreError::IO));
	Ok(buf)
    }

    fn line_has_user(&self, line: &str, user: &String) -> Result<Option<String>, BackingStoreError> {
	let v: Vec<&str> = line.split(':').collect();
	if v.len() < 1 {
	    Err(BackingStoreError::MissingData)
	} else if v[0] == user {
	    if v.len() != 2 {
		Err(BackingStoreError::MissingData)
	    } else {
		Ok(Some(v[1].to_string()))
	    }
	} else {
	    Ok(None)
	}
    }

    fn hash_is_locked(&self, hash: &String) -> Result<bool, BackingStoreError> {
	let mut chars = hash.chars();
	match chars.next() {
	    Some(c) => Ok(c == '!'),
	    None => Err(BackingStoreError::MissingData),
	}
    }
}

impl BackingStore for FileBackingStore {
    fn get_pwhash(&self, user: &String, fail_if_locked: bool) -> Result<String, BackingStoreError> {
	let pwfile = try!(self.load_file());
	for line in pwfile.lines() {
	    match try!(self.line_has_user(line, user)) {
		Some(hash) => return {
		    if !(fail_if_locked && try!(self.hash_is_locked(&hash))) {
			Ok(hash)
		    } else {
			Err(BackingStoreError::Locked)
		    }
		},
		None => { }, // keep looking
	    }
	}
	Err(BackingStoreError::NoSuchUser)
    }

    fn update_pwhash(&mut self, user: &String, new_pwhash: &String) -> Result<(), BackingStoreError> {
	let pwfile = try!(self.load_file());

	let mut newfn = self.filename.clone();
	newfn.push_str(".old");
	try!(fs::rename(self.filename.clone(), newfn));
	let mut f = BufWriter::new(try!(File::create(self.filename.clone())));
	for line in pwfile.lines() {
	    match try!(self.line_has_user(line, user)) {
		Some(hash) => {
		    try!(f.write_all(user.as_bytes()));
		    try!(f.write_all(b":"));
		    try!(f.write_all(new_pwhash.as_bytes()));
		},
		None => try!(f.write_all(line.as_bytes()).map_err(BackingStoreError::IO)),
	    }
	    // Intentionally ignoring \r\n under Windows; we're the consumer
	    try!(f.write_all(b"\n").map_err(BackingStoreError::IO));
	}
	Ok(())
    }

    fn lock(&mut self, user: &String) -> Result<(), BackingStoreError> {
	let mut hash = try!(self.get_pwhash(user, false));
	if !try!(self.hash_is_locked(&hash)) {
	    hash.insert(0, '!');
	    self.update_pwhash(user, &hash);
	}
	// not an error to lock a locked user
	Ok(())
    }

    fn islocked(&self, user: &String) -> Result<bool, BackingStoreError> {
	let hash = try!(self.get_pwhash(user, false));
	self.hash_is_locked(&hash)
    }

    // This is problematic because I can't find a stable mkstemp in Rust.
    fn unlock(&mut self, user: &String) -> Result<(), BackingStoreError> {
	panic!("Not implemented");
    }

    // This is problematic because I can't find a stable mkstemp in Rust.
    fn create(&mut self, user: &String, pwhash: &String) -> Result<(), BackingStoreError> {
	panic!("Not implemented");
    }

    // This is problematic because I can't find a stable mkstemp in Rust.
    fn delete(&mut self, user: &String) -> Result<(), BackingStoreError> {
	panic!("Not implemented");
    }
}
