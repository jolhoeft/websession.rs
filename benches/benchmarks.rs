#[macro_use]
extern crate bencher;
extern crate pwhash;

use bencher::Bencher;
use pwhash::bcrypt;

fn rounds_8_encrypt(bench: &mut Bencher) {
    bench.iter(|| {
        let hash = bcrypt::hash("password").unwrap();
    })
}

benchmark_group!(benches, rounds_8_encrypt);
benchmark_main!(benches);
