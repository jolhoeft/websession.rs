#![forbid(unsafe_code)]

extern crate clap;
extern crate rpassword;
extern crate websession;

use clap::{App, AppSettings, Arg, SubCommand};
use rpassword::prompt_password_stdout;
use std::time::Duration;
use websession::backingstore::FileBackingStore;
use websession::{Authenticator, SessionPolicy};

const ADDUSER: &str = "adduser";
const DELUSER: &str = "deluser";
const LOCK: &str = "lock";
const UNLOCK: &str = "unlock";
const PASSWD: &str = "passwd";
const INFO: &str = "info";
const ID: &str = "id";

fn get_password() -> String {
    let mut pw;
    loop {
        pw = prompt_password_stdout("Password: ").expect("Password IO error");
        let pw2 = prompt_password_stdout("Repeat Password: ").expect("Password IO error");
        if pw == pw2 {
            break;
        }
        println!("The passwords didn't match.  Please try again.");
    }
    pw
}

pub fn main() {
    let matches = App::new("ws_mgr")
        .about("Manage websession users/passwords")
        .version("0.6.0")
        .author("Ben Stern <bas-github@bstern.org>, Jeff Olhoeft <jolhoeft@gmail.com>")
        .subcommand(
            SubCommand::with_name(ADDUSER).about("Add a new user").arg(
                Arg::with_name(ID)
                    .help("Identifier for new user")
                    .required(true)
                    .takes_value(true)
                    .index(1),
            ),
        )
        .subcommand(
            SubCommand::with_name(DELUSER).about("Delete a user").arg(
                Arg::with_name(ID)
                    .help("Identifier of user to delete")
                    .required(true)
                    .takes_value(true)
                    .index(1),
            ),
        )
        .subcommand(
            SubCommand::with_name(LOCK)
                .about("Lock a user account")
                .arg(
                    Arg::with_name(ID)
                        .help("Identifier of user to lock")
                        .required(true)
                        .takes_value(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name(UNLOCK)
                .about("Unlock a user account")
                .arg(
                    Arg::with_name(ID)
                        .help("Identifier of user to unlock")
                        .required(true)
                        .takes_value(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name(PASSWD)
                .about("Reset the password for an account (also unlocks it)")
                .arg(
                    Arg::with_name(ID)
                        .help("Identifier of user to reset")
                        .required(true)
                        .takes_value(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name(INFO)
                .about("Get user information")
                .arg(
                    Arg::with_name(ID)
                        .help("Identifier of user (optional)")
                        .required(false)
                        .takes_value(true)
                        .index(1),
                ),
        )
        .settings(&[
            AppSettings::SubcommandRequiredElseHelp,
            AppSettings::ArgRequiredElseHelp,
            AppSettings::StrictUtf8,
        ])
        .get_matches();

    // This is not a good salt to use in production.
    let session_salt = "sodium chloride";
    let session_policy = SessionPolicy::new(session_salt);
    let authenticator = Authenticator::new(
        Box::new(FileBackingStore::new("./data/passwd")),
        Duration::from_secs(3600),
        session_policy,
    );

    match matches.subcommand() {
        (ADDUSER, Some(idm)) => {
            let pw = get_password();
            let id = idm.value_of(ID).expect("mandatory arg");
            match authenticator.create_plain(id, &pw) {
                Ok(_) => println!("User {} created.", id),
                Err(e) => eprintln!("Couldn't create user {}: {:?}", id, e),
            }
        }
        (DELUSER, Some(idm)) => {
            let id = idm.value_of(ID).expect("mandatory arg");
            match authenticator.delete(id) {
                Ok(_) => println!("User {} deleted.", id),
                Err(e) => eprintln!("Couldn't delete user {}: {:?}", id, e),
            }
        }
        (LOCK, Some(idm)) => {
            let id = idm.value_of(ID).expect("mandatory arg");
            match authenticator.lock_user(id) {
                Ok(_) => println!("User {} locked.", id),
                Err(e) => eprintln!("Couldn't lock user {}: {:?}", id, e),
            }
        }
        (UNLOCK, Some(idm)) => {
            let id = idm.value_of(ID).expect("mandatory arg");
            match authenticator.unlock(id) {
                Ok(_) => println!("User {} unlocked.", id),
                Err(e) => eprintln!("Couldn't unlock user {}: {:?}", id, e),
            }
        }
        (PASSWD, Some(idm)) => {
            let pw = get_password();
            let id = idm.value_of(ID).expect("mandatory arg");
            match authenticator.update_credentials_plain(id, &pw) {
                Ok(_) => println!("Password for user {} updated.", id),
                Err(e) => eprintln!("Couldn't update password for user {}: {:?}", id, e),
            }
        }
        (INFO, Some(idm)) => match idm.value_of(ID) {
            Some(id) => match authenticator.is_locked(id) {
                Ok(true) => println!("User {} IS locked.", id),
                Ok(false) => println!("User {} is NOT locked.", id),
                Err(e) => eprintln!("Couldn't get information for user {}: {:?}", id, e),
            },
            None => match authenticator.users() {
                Ok(list) => {
                    for id in list {
                        match authenticator.is_locked(&id) {
                            Ok(true) => println!("{} (locked)", id),
                            Ok(false) => println!("{}", id),
                            Err(e) => eprintln!("{}: Error getting info: {:?}", id, e),
                        }
                    }
                }
                Err(e) => eprintln!("Couldn't list users: {:?}", e),
            },
        },
        (cmd, _) => println!("Command '{}' isn't implemented!", cmd),
    }
}
