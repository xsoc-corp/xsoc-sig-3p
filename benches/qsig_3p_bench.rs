//! Criterion benches for QSIG-3P signing, verification, and end-to-end roundtrip.
//!
//! These benches use the mock backends. Replace `MockSign` and `MockMac` with
//! the production primitives to obtain authoritative numbers.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use xsoc_sig_3p::{
    mock::{MockMac, MockSign},
    Holder, PairKey, PairSequencer, Signer, Verifier,
};

fn pair_key(byte: u8) -> PairKey {
    PairKey::from_bytes([byte; 32])
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("qsig_3p_sign");
    for &size in &[64usize, 256, 1024, 4096, 16384] {
        let msg = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &msg, |b, msg| {
            let signer = Signer::new(pair_key(0x12), pair_key(0x13), MockSign, MockMac);
            b.iter(|| signer.sign(&mut PairSequencer::fresh(), msg).unwrap());
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("qsig_3p_verify");
    for &size in &[64usize, 256, 1024, 4096, 16384] {
        let msg = vec![0xABu8; size];
        let signer = Signer::new(pair_key(0x12), pair_key(0x13), MockSign, MockMac);
        let transfer = signer.sign(&mut PairSequencer::fresh(), &msg).unwrap();
        let holder = Holder::new(pair_key(0x12), MockSign);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("holder", size), &transfer, |b, t| {
            b.iter(|| holder.accept(t).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("verifier", size), &transfer, |b, t| {
            b.iter(|| {
                let mut verifier = Verifier::new(pair_key(0x13), 0, MockMac);
                verifier.accept(t).unwrap();
            });
        });
    }
    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("qsig_3p_roundtrip");
    let msg = b"typical institutional payload, 64B".to_vec();
    group.bench_function("sign_hold_verify", |b| {
        b.iter(|| {
            let signer = Signer::new(pair_key(0x12), pair_key(0x13), MockSign, MockMac);
            let holder = Holder::new(pair_key(0x12), MockSign);
            let mut verifier = Verifier::new(pair_key(0x13), 0, MockMac);

            let t = signer.sign(&mut PairSequencer::fresh(), &msg).unwrap();
            holder.accept(&t).unwrap();
            verifier.accept(&t).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_sign, bench_verify, bench_roundtrip);
criterion_main!(benches);
