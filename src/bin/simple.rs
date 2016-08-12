extern crate websession;
extern crate time;

use websession::{SessionPolicy, SessionManager, ConnectionSignature, Token};
use std::path::Path;
use time::Duration;

fn main() {
    let path = Path::new("../../data/passwd");
    let mut session_manager = SessionManager::new(Duration::seconds(3600),
	SessionPolicy { }, path);

    // These normally comes from something like a hyper header, but whatever
    let signature = ConnectionSignature::new();

    let token = match session_manager.start(None, &signature) {
	Ok(t) => t,
	Err(err) => panic!(err),
    };
    match session_manager.login("user".to_string(), "password", &token) {
	Ok(sess) => println!("Logged in!"),
	Err(err) => panic!(err),
    };
}
