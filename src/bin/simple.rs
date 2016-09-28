extern crate websession;
extern crate time;

// This is totally out of hand.
use websession::Authenticator;
use websession::backingstore::FileBackingStore;
use websession::sessionpolicy::SessionPolicy;
use websession::connectionsignature::ConnectionSignature;
use time::Duration;

fn main() {
    let policy = SessionPolicy::new("console");

    let authmgr = Authenticator::new(
	    Box::new(FileBackingStore::new("../../data/passwd")),
        Duration::seconds(3600), policy);

    // These normally comes from something like a hyper header, but whatever
    let signature = ConnectionSignature::new("sekrit");

    match authmgr.run(signature) {
        Err(e) => panic!(format!("{:?}", e)),
        Ok(sig) => match authmgr.login(&String::from("user"), &String::from("password"), &sig) {
            Ok(_) => println!("Logged in with session {:?}", sig),
            Err(err) => panic!(format!("{:?}", err)),
        },
    };
}
