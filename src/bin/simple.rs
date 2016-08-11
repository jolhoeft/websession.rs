extern crate websession;
extern crate time;

use websession::{SessionPolicy, SessionManager, ConnectionSignature};
use std::path::Path;
use time::Duration;

fn main() {
    let path = Path::new("../../data/passwd");
    let sessions = SessionManager::new(Duration::seconds(3600),
	SessionPolicy { }, path);
    let signature = ConnectionSignature::new();
    let mut session = match sessions.start(signature) {
	Ok(sess) => sess,
	Err(err) => panic!(err),
    };
    session = match sessions.login("user".to_string(), "password", session) {
	Ok(sess) => sess,
	Err(err) => panic!(err),
    };
}
