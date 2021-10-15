// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2018-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[macro_use]
extern crate criterion;
extern crate ed25519_dalek;
extern crate rand;

mod ed25519_benches {
    use super::*;
    use criterion::*;
    use ed25519_dalek::verify_batch;
    use ed25519_dalek::AggregatedSignature;
    use ed25519_dalek::Digest;
    use ed25519_dalek::ExpandedSecretKey;
    use ed25519_dalek::Keypair;
    use ed25519_dalek::PublicKey;
    use ed25519_dalek::QuasiAggregatedSignature;
    use ed25519_dalek::ScalarSize;
    use ed25519_dalek::Signature;
    use ed25519_dalek::Signer;
    use rand::prelude::ThreadRng;
    use rand::thread_rng;
    use std::time::Duration;
    use std::fmt;

    fn sign(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";

        c.bench_function("Ed25519 signing", move |b| b.iter(|| keypair.sign(msg)));
    }

    fn sign_expanded_key(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let expanded: ExpandedSecretKey = (&keypair.secret).into();
        let msg: &[u8] = b"";

        c.bench_function("Ed25519 signing with an expanded secret key", move |b| {
            b.iter(|| expanded.sign(msg, &keypair.public))
        });
    }

    fn verify(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";
        let sig: Signature = keypair.sign(msg);

        c.bench_function("Ed25519 signature verification", move |b| {
            b.iter(|| keypair.verify(msg, &sig))
        });
    }

    fn verify_strict(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";
        let sig: Signature = keypair.sign(msg);

        c.bench_function("Ed25519 strict signature verification", move |b| {
            b.iter(|| keypair.verify_strict(msg, &sig))
        });
    }

    fn verify_batch_signatures<M: measurement::Measurement>(c: &mut BenchmarkGroup<M>) {
        static BATCH_SIZES: [usize; 14] = [
            16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072,
        ];

        let mut csprng: ThreadRng = thread_rng();

        for size in BATCH_SIZES.iter() {
            let keypairs: Vec<Keypair> =
                (0..*size).map(|_| Keypair::generate(&mut csprng)).collect();
            let msg: Vec<u8> = {
                let mut h = sha2::Sha256::new();
                h.update(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                h.finalize().to_vec()
            };
            let messages: Vec<&[u8]> = (0..*size).map(|_| &msg[..]).collect();
            let signatures: Vec<Signature> = keypairs.iter().map(|key| key.sign(&msg)).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

            c.bench_with_input(
                BenchmarkId::new("Ed25519 batch verification", *size),
                &(messages, signatures, public_keys),
                |b, i| {
                    b.iter(|| verify_batch(&i.0[..], &i.1[..], &i.2[..]));
                },
            );
        }
    }

    fn key_generation(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();

        c.bench_function("Ed25519 keypair generation", move |b| {
            b.iter(|| Keypair::generate(&mut csprng))
        });
    }

    fn aggregate_signatures<M: measurement::Measurement>(c: &mut BenchmarkGroup<M>) {
        static BATCH_SIZES: [usize; 14] = [
            16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072,
        ];
        let mut csprng: ThreadRng = thread_rng();

        for size in BATCH_SIZES.iter() {
            let keypairs: Vec<Keypair> =
                (0..*size).map(|_| Keypair::generate(&mut csprng)).collect();
            let msg: Vec<u8> = {
                let mut h = sha2::Sha256::new();
                h.update(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                h.finalize().to_vec()
            };
            let messages: Vec<&[u8]> = (0..*size).map(|_| &msg[..]).collect();
            let signatures: Vec<Signature> = keypairs.iter().map(|key| key.sign(&msg)).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
            let msgs_and_pkeys: Vec<(&[u8], &PublicKey)> =
                messages.iter().cloned().zip(&public_keys).collect();

            c.bench_with_input(
                BenchmarkId::new("signature aggregation", *size),
                &(msgs_and_pkeys.clone(), signatures.clone()),
                |b, i| {
                    b.iter(|| AggregatedSignature::aggregate(&i.0[..], &i.1, ScalarSize::Full));
                },
            );
            c.bench_with_input(
                BenchmarkId::new("signature aggregation with half scalars", *size),
                &(msgs_and_pkeys.clone(), signatures.clone()),
                |b, i| {
                    b.iter(|| AggregatedSignature::aggregate(&i.0[..], &i.1, ScalarSize::Half));
                },
            );
            c.bench_with_input(
                BenchmarkId::new("signature aggregation with double scalars", *size),
                &(msgs_and_pkeys, signatures),
                |b, i| {
                    b.iter(|| AggregatedSignature::aggregate(&i.0[..], &i.1, ScalarSize::Double));
                },
            );
        }
    }

    fn verify_aggregated_signatures<M: measurement::Measurement>(c: &mut BenchmarkGroup<M>) {
        static BATCH_SIZES: [usize; 14] = [
            16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072,
        ];
        let mut csprng: ThreadRng = thread_rng();

        for size in BATCH_SIZES.iter() {
            let keypairs: Vec<Keypair> =
                (0..*size).map(|_| Keypair::generate(&mut csprng)).collect();
            let msg: Vec<u8> = {
                let mut h = sha2::Sha256::new();
                h.update(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                h.finalize().to_vec()
            };
            let messages: Vec<&[u8]> = (0..*size).map(|_| &msg[..]).collect();
            let signatures: Vec<Signature> = keypairs.iter().map(|key| key.sign(&msg)).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
            let msgs_and_pkeys: Vec<(&[u8], &PublicKey)> =
                messages.iter().cloned().zip(&public_keys).collect();

            let agg =
                AggregatedSignature::aggregate(&msgs_and_pkeys[..], &signatures, ScalarSize::Full)
                    .unwrap();

            let mezz_agg =
                AggregatedSignature::aggregate(&msgs_and_pkeys[..], &signatures, ScalarSize::Half)
                    .unwrap();

            let double_agg = AggregatedSignature::aggregate(
                &msgs_and_pkeys[..],
                &signatures,
                ScalarSize::Double,
            )
            .unwrap();

            c.bench_with_input(
                BenchmarkId::new("aggregated signature verification", *size),
                &(msgs_and_pkeys.clone(), agg),
                |b, i| {
                    b.iter(|| AggregatedSignature::verify(&i.0[..], &i.1, ScalarSize::Full));
                },
            );
            c.bench_with_input(
                BenchmarkId::new("aggregated signature verification with half scalars", *size),
                &(msgs_and_pkeys.clone(), mezz_agg),
                |b, i| {
                    b.iter(|| AggregatedSignature::verify(&i.0[..], &i.1, ScalarSize::Half));
                },
            );
            c.bench_with_input(
                BenchmarkId::new(
                    "aggregated signature verification with double scalars",
                    *size,
                ),
                &(msgs_and_pkeys, double_agg),
                |b, i| {
                    b.iter(|| AggregatedSignature::verify(&i.0[..], &i.1, ScalarSize::Double));
                },
            );
        }
    }

    #[derive(Debug)]
    struct Param(usize, usize);

    impl fmt::Display for Param {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "[n={} r={}]", self.0, self.1)
        }
    }

    // These are benchmark params published in the CTRSA paper.
    // Format is (n,r) pairs, and the order is meant to speed up
    // arrival of results.
    static PARAMS: [Param; 12] = [
        Param(128,16), Param(256,32),              // c=0.57
        Param(32, 8), Param(64,16), Param(128,32), // c=0.63
        Param(16,8), Param(32,16), Param(64,32),   // c=0.77
        Param(256,16), Param(512,32),              // c=0.53
        Param(512,16), Param(1024,32),             // c=0.52
    ];
        
    /// This benchmark method reproduces the results from Table 2 in the CTRSA paper.
    fn quasi_aggregate_signatures<M: measurement::Measurement>(c: &mut BenchmarkGroup<M>) {
        let mut csprng: ThreadRng = thread_rng();

        for param in PARAMS.iter() {
            let (n,r) = (param.0,param.1);
            let keypairs: Vec<Keypair> =
                (0..n).map(|_| Keypair::generate(&mut csprng)).collect();
            let msg: Vec<u8> = {
                let mut h = sha2::Sha256::new();
                h.update(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                h.finalize().to_vec()
            };
            let messages: Vec<&[u8]> = (0..n).map(|_| &msg[..]).collect();
            let signatures: Vec<Signature> = keypairs.iter().map(|key| key.sign(&msg)).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
            let msgs_and_pkeys: Vec<(&[u8], &PublicKey)> =
                messages.iter().cloned().zip(&public_keys).collect();

            c.bench_with_input(
                BenchmarkId::new("signature quasi-aggregation", param),
                &(msgs_and_pkeys, signatures, r),
                |b, i| {
                    b.iter(|| QuasiAggregatedSignature::aggregate(i.2, &i.0[..], &i.1));
                },
            );
        }
    }

    /// This benchmark method reproduces the AggVerify results from Table 2 in the CTRSA paper.
    fn verify_quasi_aggregated_signatures<M: measurement::Measurement>(c: &mut BenchmarkGroup<M>) {
        let mut csprng: ThreadRng = thread_rng();
        for param in PARAMS.iter() {
            let (n,r) = (param.0,param.1);
            let keypairs: Vec<Keypair> =
                (0..n).map(|_| Keypair::generate(&mut csprng)).collect();
            let msg: Vec<u8> = {
                let mut h = sha2::Sha256::new();
                h.update(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                h.finalize().to_vec()
            };
            let messages: Vec<&[u8]> = (0..n).map(|_| &msg[..]).collect();
            let signatures: Vec<Signature> = keypairs.iter().map(|key| key.sign(&msg)).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
            let msgs_and_pkeys: Vec<(&[u8], &PublicKey)> =
                messages.iter().cloned().zip(&public_keys).collect();

            let agg =
                QuasiAggregatedSignature::aggregate(r, &msgs_and_pkeys[..], &signatures).unwrap();

            c.bench_with_input(
                BenchmarkId::new("quasi-aggregated signature verification", param),
                &(msgs_and_pkeys, agg, r),
                |b, i| {
                    b.iter(|| QuasiAggregatedSignature::verify(i.2, &i.0[..], &i.1));
                },
            );
        }
    }

    fn compare_r_values_aggregate<M: measurement::Measurement>(c: &mut BenchmarkGroup<M>) {
        static BATCH_SIZE: usize = 256;
        static R_VALUES: [usize; 4] = [16, 32, 64, 128];
        let mut csprng: ThreadRng = thread_rng();

        for r in R_VALUES.iter() {
            let keypairs: Vec<Keypair> = (0..BATCH_SIZE)
                .map(|_| Keypair::generate(&mut csprng))
                .collect();
            let msg: Vec<u8> = {
                let mut h = sha2::Sha256::new();
                h.update(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                h.finalize().to_vec()
            };
            let messages: Vec<&[u8]> = (0..BATCH_SIZE).map(|_| &msg[..]).collect();
            let signatures: Vec<Signature> = keypairs.iter().map(|key| key.sign(&msg)).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
            let msgs_and_pkeys: Vec<(&[u8], &PublicKey)> =
                messages.iter().cloned().zip(&public_keys).collect();

            c.bench_with_input(
                BenchmarkId::new("signature quasi-aggregation r comparison", r),
                r,
                |b, r| {
                    b.iter(|| {
                        QuasiAggregatedSignature::aggregate(*r, &msgs_and_pkeys[..], &signatures)
                            .unwrap()
                    });
                },
            );
        }
    }

    fn compare_r_values_verify<M: measurement::Measurement>(c: &mut BenchmarkGroup<M>) {
        static BATCH_SIZE: usize = 256;
        static R_VALUES: [usize; 4] = [16, 32, 64, 128];
        let mut csprng: ThreadRng = thread_rng();

        for r in R_VALUES.iter() {
            let keypairs: Vec<Keypair> = (0..BATCH_SIZE)
                .map(|_| Keypair::generate(&mut csprng))
                .collect();
            let msg: Vec<u8> = {
                let mut h = sha2::Sha256::new();
                h.update(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                h.finalize().to_vec()
            };
            let messages: Vec<&[u8]> = (0..BATCH_SIZE).map(|_| &msg[..]).collect();
            let signatures: Vec<Signature> = keypairs.iter().map(|key| key.sign(&msg)).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
            let msgs_and_pkeys: Vec<(&[u8], &PublicKey)> =
                messages.iter().cloned().zip(&public_keys).collect();

            c.bench_with_input(
                BenchmarkId::new("quasi-aggregated signature verification r comparison", r),
                r,
                |b, r| {
                    let agg =
                        QuasiAggregatedSignature::aggregate(*r, &msgs_and_pkeys[..], &signatures)
                            .unwrap();
                    b.iter(|| {
                        QuasiAggregatedSignature::verify(*r, &msgs_and_pkeys[..], &agg).unwrap()
                    });
                },
            );
        }
    }


    fn compare_n_values_aggregate<M: measurement::Measurement>(c: &mut BenchmarkGroup<M>) {
        static BATCH_SIZE_VALUES: [usize; 5] = [59, 74, 98, 148, 296];
        static R_VALUE: usize = 30;
        let mut csprng: ThreadRng = thread_rng();

        for batch_size in BATCH_SIZE_VALUES.iter() {
            let keypairs: Vec<Keypair> = vec![0; *batch_size]
                .iter()
                .map(|_| Keypair::generate(&mut csprng))
                .collect();
            let msg: Vec<u8> = {
                let mut h = sha2::Sha256::new();
                h.update(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                h.finalize().to_vec()
            };
            let messages: Vec<&[u8]> = vec![0; *batch_size].iter().map(|_| &msg[..]).collect();
            let signatures: Vec<Signature> = keypairs.iter().map(|key| key.sign(&msg)).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
            let msgs_and_pkeys: Vec<(&[u8], &PublicKey)> =
                messages.iter().cloned().zip(&public_keys).collect();

            c.bench_with_input(
                BenchmarkId::new("signature quasi-aggregation n comparison", batch_size),
                &R_VALUE,
                |b, r| {
                    b.iter(|| {
                        QuasiAggregatedSignature::aggregate(*r, &msgs_and_pkeys[..], &signatures)
                            .unwrap()
                    });
                },
            );
        }
    }

    fn compare_n_values_verify<M: measurement::Measurement>(c: &mut BenchmarkGroup<M>) {
        static BATCH_SIZE_VALUES: [usize; 5] = [59, 74, 98, 148, 296];
        static R_VALUE: usize = 30;
        let mut csprng: ThreadRng = thread_rng();

        for batch_size in BATCH_SIZE_VALUES.iter() {
            let keypairs: Vec<Keypair> = vec![0; *batch_size]
                .iter()
                .map(|_| Keypair::generate(&mut csprng))
                .collect();
            let msg: Vec<u8> = {
                let mut h = sha2::Sha256::new();
                h.update(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                h.finalize().to_vec()
            };
            let messages: Vec<&[u8]> = vec![0; *batch_size].iter().map(|_| &msg[..]).collect();
            let signatures: Vec<Signature> = keypairs.iter().map(|key| key.sign(&msg)).collect();
            let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
            let msgs_and_pkeys: Vec<(&[u8], &PublicKey)> =
                messages.iter().cloned().zip(&public_keys).collect();

            c.bench_with_input(
                BenchmarkId::new("quasi-aggregated signature verification n comparison", batch_size),
                &R_VALUE,
                |b, r| {
                    let agg =
                        QuasiAggregatedSignature::aggregate(*r, &msgs_and_pkeys[..], &signatures)
                            .unwrap();
                    b.iter(|| {
                        QuasiAggregatedSignature::verify(*r, &msgs_and_pkeys[..], &agg).unwrap()
                    });
                },
            );
        }
    }

    criterion_group! {
        name = ed25519_benches;
        config = Criterion::default().sample_size(100);
        targets =
           sign,
           sign_expanded_key,
           verify,
           verify_strict,
           key_generation,
           aggregation_comparison,
           verification_comparison,
           quasi_aggregation_comparison,
           quasi_aggregated_verification_comparison,
           quasi_r_comparison,
           quasi_n_comparison,
    }

    fn aggregation_comparison(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("aggregation_comparison");
        group.sampling_mode(SamplingMode::Flat);

        aggregate_signatures(&mut group);
        group.finish();
    }

    fn quasi_aggregation_comparison(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("quasi_aggregation_comparison");
        group.sampling_mode(SamplingMode::Flat);

        quasi_aggregate_signatures(&mut group);
        group.finish();
    }

    fn verification_comparison(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("verification_comparison");
        group.sampling_mode(SamplingMode::Flat);

        verify_batch_signatures(&mut group);
        verify_aggregated_signatures(&mut group);
        group.finish();
    }

    fn quasi_aggregated_verification_comparison(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> =
            c.benchmark_group("quasi_aggregated_verification_comparison");
        group.sampling_mode(SamplingMode::Flat);

        verify_quasi_aggregated_signatures(&mut group);
        group.finish();
    }

    fn quasi_r_comparison(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("R_value_comparison");
        group.sampling_mode(SamplingMode::Flat);

        compare_r_values_aggregate(&mut group);
        compare_r_values_verify(&mut group);

        group.finish();
    }

    fn quasi_n_comparison(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("nx_value_comparison");
        group.sampling_mode(SamplingMode::Flat);

        compare_n_values_aggregate(&mut group);
        compare_n_values_verify(&mut group);

        group.finish();
    }
}

criterion_main!(ed25519_benches::ed25519_benches,);
