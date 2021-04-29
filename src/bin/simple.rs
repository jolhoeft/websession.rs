#![forbid(unsafe_code)]

extern crate websession;

use std::time::Duration;
use websession::backingstore::FileBackingStore;
use websession::connectionsignature::ConnectionSignature;
use websession::sessionpolicy::SessionPolicy;
use websession::Authenticator;

fn main() {
    let policy = SessionPolicy::new("console");

    let authmgr = Authenticator::new(
        Box::new(FileBackingStore::new("data/passwd")),
        Duration::from_secs(3600),
        policy,
    );

    // These normally comes from something like a hyper header, but whatever
    let signature = ConnectionSignature::new("sekrit");

    match authmgr.run(signature) {
        Err(e) => panic!("{:?}", e),
        Ok(sig) => match authmgr.login(&String::from("user"), &String::from("password"), &sig) {
            Ok(_) => println!("Logged in with session {:?}", sig),
            Err(err) => panic!("{:?}", err),
        },
    };
}
