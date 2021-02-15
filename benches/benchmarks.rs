#[macro_use]
extern crate bencher;
extern crate pwhash;

use bencher::Bencher;
use pwhash::bcrypt;

fn rounds_10_encrypt(bench: &mut Bencher) {
    bench.iter(|| {
        let _hash = bcrypt::hash("password").unwrap();
    })
}

benchmark_group!(benches, rounds_10_encrypt);
benchmark_main!(benches);
