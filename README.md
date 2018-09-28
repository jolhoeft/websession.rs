# websession.rs
Web Session Support for Rust

## Overview

`websession` provides a simple interface to web session management, with
reliably encrypted passwords (currently `bcrypt`) and automatically expiring
identifiers.

Users can be identified by any UTF-8, including a username, an email
address, a number, or anything else you can think of that does not contain
an embedded `:` (as `:` is used as the delimiter in the `FileBackingStore`
and prohibited by the `MemoryBackingStore` for compatibility reasons).

Be advised that as of 0.6.0, the FileBackingStore and the MemoryBackingStore
silently replace "\n" with "\u{FFFD}", just as `String::from_utf8_lossy`
does for invalid UTF-8.  This is unlikely to cause problems in production
because users with embedded newlines in their name already can't log in
properly.

It is expected that metadata (real names, contact information, user-based
permissions, etc.) are managed by the consuming app.

## Usage

To use this software, you need to select a `BackingStore` implementation.

The `FileBackingStore` needs an existing file which will contain identifiers
and passwords.  At a minimum, you can use an empty file and then add users
to it.  See the test in `backingstore.rs` for syntax.  This file will
persist across runs, and is assumed by the implementation to have
appropriate read/write permissions.

If you use the `MemoryBackingStore`, changes will not persist across
restarts.

## Implementation Notes

Implementations of the `BackingStore` trait are responsible for appropriate
management of passwords and especially not to store them in plaintext.  The
provided implementations do not store plaintext passwords on disk (and the
`MemoryBackingStore` attempts not to save plaintext passwords in memory).
[N.B., preventing a leak of unencrypted passwords to swap space is beyond
the scope of this project, though we would welcome pull requests that reduce
the probability of such a leak.]

Some effort is made to protect the `FileBackingStore`'s file by copying the
mode of the existing file when rewriting it, but this is only implemented
under UNIX-like operating systems.  A pull request which sets appropriate
file permissions under Windows would be gratefully accepted.

### `bcrypt` Notes

The default implementation uses eight (8) rounds of `bcrypt`.  You should
run `cargo bench` to see how long it takes to run `bcrypt` on your target
system.  If 8 rounds takes less than 0.01 seconds (10,000,000 nanoseconds)
or more than 0.25 seconds (250,000,000, you should use implement your own
`BackingStore` which uses more or fewer rounds, as needed (or, of course, a
different encryption method).  (Each additional round doubles computation
time, so increase the number by 2 to quadruple the time per hash or decrease
it by 2 to quarter the time per hash.)

## Licensing

This software is dual-licensed under the Apache and MIT licenses.
