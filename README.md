# websession.rs
<img src="https://github.com/jolhoeft/websession.rs/workflows/Rust/badge.svg" align="right" alt="build status">
<img src="https://docs.rs/websession/badge.svg" align="right" alt="docs status">

Web Session Support for Rust

## Overview

`websession` provides a simple interface to web session management, with
reliably encrypted passwords (currently `bcrypt`) and session identifiers that
automatically renew on activity or time out and expire with inactivity.

Users can be identified by any valid UTF-8, including a username, an email
address, a number, or almost anything else you can think of.  However, the
`FileBackingStore` and the `MemoryBackingStore` both silently replace "\n" with
"\u{FFFD}", just as `String::from_utf8_lossy` does for invalid UTF-8.  (This is
unlikely to cause problems in production as users with embedded newlines in
their name probably can't log in properly anyway.)

It is expected that metadata (real names, contact information, user-based
permissions, etc.) are managed by the application using `websession`.

## Usage

To use this software, you need to select a `BackingStore` implementation.

The `FileBackingStore` requires an existing file which will contain identifiers
and passwords.  At a minimum, you can start with an empty file and then add
users to it.  This file normally persists across runs, and is assumed by the
implementation to have appropriate read/write permissions.  [The supplied
implementation makes an effort to ensure the contents are written to disk as
promptly as possible.]

Backing stores are intended to be accessed via an `Authenticator`.

See the tests in `lib.rs` and the examples, as they get written.  (For now, see
`examples.md`.)

- In 0.12.1, the default number of rounds of `bcrypt` used by the
  `FileBackingStore` changed from 8 to 10.  `FileBackingStore::new_with_cost`
  which allows choosing a number of rounds for your specific system.  See below
  for guidance on how to choose an appropriate number of rounds.

If you use the `MemoryBackingStore`, credentials won't persist across restarts.

## Implementation Notes

Implementations of the `BackingStore` trait are responsible for appropriate
management of passwords and especially not to store them in plaintext.  The
provided implementations don't store plaintext passwords on disk unless they're
specifically misused.  [No effort is made to prevent a leak of unencrypted
passwords to swap space, though pull requests which reduce the probability of
such a leak are welcome.]

In particular, the `BackingStoreError::InvalidCredentials` should be used by
implementations which can detect when unencrypted credentials are supplied to a
method which expects encrypted credentials.

Some effort is made to protect the `FileBackingStore`'s file by copying the mode
of the existing file when rewriting it, but this is only implemented under
UNIX-like operating systems.  An effort is made to preserve permissions under
Windows but has not been rigorously tested.

### `bcrypt` Notes

The default implementation uses ten (10) rounds of `bcrypt`.  You should run
`cargo bench` to see how long it takes to run `bcrypt` on your target system.
If 10 rounds takes less than 0.01 seconds (10,000,000 nanoseconds) per
iteration, or more than 0.25 seconds (250,000,000 ns), you should:

- implement your own `BackingStore` which uses more or fewer rounds, as
  appropriate,
- implement your own `BackingStore` which uses a more suitable encryption
  method,
- use `FileBackingStore::new_with_cost` instead of `FileBackingStore::new` and
  specify a suitable value.

Each additional round doubles computation time, so an increase in cost of 2
will quadruple the time per hash, and a decrease of 2 will quarter the time per
hash.

After you choose a number of rounds (or accept the default), it will persist for
generated passwords, even when the underlying default changes (as it did in
`pwhash` 1.0 and `websession` 0.12.1).  Existing passwords will continue to use
the old value until they're invalidated.  However, new passwords will use the
new value.

As data points, under Linux on lightly loaded systems:

|        CPU       | Rounds | Frequency |  Mode  |   Nanoseconds per Iteration   |
|------------------|--------|-----------|--------|-------------------------------|
| Core 2 Duo T9300 |:   8  :|  2.50 GHz | 32-bit | 20,881,257 (&plusmn; 247,164) |
| Core i7-4770L    |:   8  :|  3.50 GHz | 64-bit | 13,961,105 (&plusmn; 202,267) |
| Core i7-4770L    |:  10  :|  3.50 GHz | 64-bit | 55,161,654 (&plusmn; 678,113) |

On the Core 2 Duo T9300 above, 7 rounds would be adequate, while 8 is reasonable
for the Core i7-4770L.  As noted above, 10 rounds takes approximately 4 times as
long as 8 rounds to complete, and is somewhat excessive.

(Additional data points are welcomed.)

## Licensing

This software is dual-licensed under the Apache and MIT licenses.
