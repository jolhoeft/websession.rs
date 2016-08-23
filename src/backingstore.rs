use std::io;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::convert::From;

#[derive(Debug)]
pub enum BackingStoreError {
    NoSuchUser,
    IO(io::Error),
}

// The BackingStore doesn't know about userIDs vs usernames; the consumer of
// websessions is responsible for being able to change usernames w/o affecting
// userIDs.
// N.B., implementors of BackingStore provide a new that gets whatever is needed
// to connect to the store.
pub trait BackingStore {
    fn get_pwhash(&self, user: &String) -> Result<String, BackingStoreError>;
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
}

impl BackingStore for FileBackingStore {
    fn get_pwhash(&self, user: &String) -> Result<String, BackingStoreError> {
	let f = try!(File::open(self.filename.clone()).map_err(BackingStoreError::IO));
	let reader = BufReader::new(f);
	for line in reader.lines() {
	    match line {
		Err(e) => return Err(BackingStoreError::IO(e)),
		Ok(s) => {
		    let v: Vec<&str> = s.split(':').collect();
		    if v[0] == user {
			println!("Found user {}!", user);
			return Ok(v[1].to_string())
		    }
		},
	    }
	}
	Err(BackingStoreError::NoSuchUser)
    }

    // This is problematic because I can't find a stable mkstemp in Rust.
    fn update_pwhash(&mut self, user: &String, new_pwhash: &String) -> Result<(), BackingStoreError> {
	panic!("Not implemented");
    }

    // This is problematic because I can't find a stable mkstemp in Rust.
    fn lock(&mut self, user: &String) -> Result<(), BackingStoreError> {
	panic!("Not implemented");
    }

    fn islocked(&self, user: &String) -> Result<bool, BackingStoreError> {
	match self.get_pwhash(user) {
	    Err(e) => Err(e),
	    Ok(hash) => Ok(hash.as_bytes()[0] == b'!'),
	}
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
