extern crate websession;
extern crate time;

use websession::{SessionPolicy, SessionManager, ConnectionSignature};
use websession::backingstore::FileBackingStore;
use time::Duration;

fn main() {
    let mut session_manager = SessionManager::new(Duration::seconds(3600),
	SessionPolicy::new(),
	Box::new(FileBackingStore::new("../../data/passwd")));

    // These normally comes from something like a hyper header, but whatever
    let signature = ConnectionSignature::new();

    let token = match session_manager.start(None, &signature) {
	Ok(t) => t,
	Err(err) => panic!(format!("{:?}", err)),
    };
    match session_manager.login(&String::from("user"), &String::from("password"), &token) {
	Ok(sess) => println!("Logged in with session {:?}", sess),
	Err(err) => panic!(format!("{:?}", err)),
    };
}
