These are incomplete and will be moved to an `examples directory` when they're
in better shape.

```rust
use std::fs::{File, OpenOptions};

use websession::{Authenticator, FileBackingStore};

let filename = "./etc/passwd";

// Ignore the result; if this fails, it may be because the file exists.
// If something else is wrong, the FileBackingStore will (eventually) find out.
let _ = OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(filename);

let fbs = FileBackingStore::new_with_cost(filename, 8);
let new_user = "username";
let new_pass = "correct horse battery staple";
fbs.create_plain(new_user, new_pass)?;

// ...

let user = "username";
let pass = "correct horse battery staple";
match fbs.verify(user, pass) {
    Ok(true) => println!("user {} authenticated", user),
    Ok(false) => println!("bad password!"),
    Err(BackingStoreError::Locked) => println!("user {} is locked", "username"),
    Err(e) => println!("Error: {:?}", e),
}
```
