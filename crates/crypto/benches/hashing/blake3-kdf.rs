use criterion::{criterion_group, criterion_main, Criterion};
use sd_crypto::types::{Key, Salt};

fn bench(c: &mut Criterion) {
	let key = Key::generate();
	let salt = Salt::generate();
	c.bench_function("blake3-kdf", |b| b.iter(|| key.derive(salt)));
}

criterion_group!(
	name = benches;
	config = Criterion::default();
	targets = bench
);

criterion_main!(benches);
