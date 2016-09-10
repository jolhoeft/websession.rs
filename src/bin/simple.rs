extern crate websession;
extern crate time;

use websession::{SessionPolicy, SessionManager, ConnectionSignature};
use websession::backingstore::FileBackingStore;
use time::Duration;

fn main() {
    let policy = SessionPolicy::new();

    let mut session_manager = SessionManager::new(Duration::seconds(3600),
	    Box::new(FileBackingStore::new("../../data/passwd")),
        "console");

    // These normally comes from something like a hyper header, but whatever
    let signature = ConnectionSignature::new(&policy);

    assert!(session_manager.start(&signature).is_ok());
    match session_manager.login(&String::from("user"),
        &String::from("password"), &signature) {
        Ok(sess) => println!("Logged in with session {:?}", sess),
        Err(err) => panic!(format!("{:?}", err)),
    };
}
