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

The `FileBackingStore` needs an existing file which will contain identifiers and
passwords.  At a minimum, you can use an empty file and then add users to it.
See the test in `backingstore.rs` for syntax.  This file will persist across
runs, and is assumed by the implementation to have appropriate read/write
permissions.  [The supplied implementation makes an effort to ensure the
contents are written to disk as promptly as possible.]

If you use the `MemoryBackingStore`, changes will not persist across restarts.

## Implementation Notes

Implementations of the `BackingStore` trait are responsible for appropriate
management of passwords and especially not to store them in plaintext.  The
provided implementations do not store plaintext passwords on disk (and the
`MemoryBackingStore` attempts not to save plaintext passwords in memory).
[N.B., preventing a leak of unencrypted passwords to swap space is beyond the
scope of this project, though we would welcome pull requests that reduce the
probability of such a leak.]

Some effort is made to protect the `FileBackingStore`'s file by copying the mode
of the existing file when rewriting it, but this is only implemented under
UNIX-like operating systems.  A pull request which sets appropriate file
permissions under Windows would be gratefully accepted.

### `bcrypt` Notes

The default implementation uses eight (8) rounds of `bcrypt`.  You should run
`cargo bench` to see how long it takes to run `bcrypt` on your target system.
If 8 rounds takes less than 0.01 seconds (10,000,000 nanoseconds) per iteration,
or more than 0.25 seconds (250,000,000 ns), you should use implement your own
`BackingStore` which uses more or fewer rounds, as needed (or, of course, a
different encryption method).  (Each additional round doubles computation time,
so increase the number by 2 to quadruple the time per hash or decrease it by 2
to quarter the time per hash.)

Once you choose a number of rounds (or accept the default), you can't change it
without either invalidating all existing passwords or devising a mechanism to
transparently migrate users as they authenticate.

As data points, under Linux:

|        CPU       | Frequency |  Mode  | Nanoseconds per Iteration     |
-------------------+-----------+--------+--------------------------------
| Core 2 Duo T9300 | 2.50 GHz  | 32-bit | 20,881,257 (&plusmn; 247,164) |
| Core i7-4770L    | 3.50 GHz  | 64-bit | 13,961,105 (&plusmn; 202,267) |

(Additional data points are welcomed.)

## Licensing

This software is dual-licensed under the Apache and MIT licenses.
