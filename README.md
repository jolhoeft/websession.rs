# websession.rs
Web Session Support for Rust

## Usage
To use this software, you need to select a `BackingStore` implementation.

The `FileBackingStore` needs an existing file which will contain usernames and passwords.  At a minimum, you can use an empty file and then add users to it.  See the test in `backingstore.rs` for syntax.  This file will persist across runs, and is assumed to have appropriate read/write permissions.

If you use the `MemoryBackingStore`, changes will not persist across restarts.

This software is dual-licensed under the Apache and MIT licenses.
