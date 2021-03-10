extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::*;
use rand::rngs::OsRng;

#[test]
fn single_aggregate() {
    let keypair: Keypair;
    let good_sig: Signature;

    let good: &[u8] = "test message".as_bytes();

    let mut csprng = OsRng;

    keypair = Keypair::generate(&mut csprng);
    good_sig = keypair.sign(&good);

    assert!(
        keypair.verify(&good, &good_sig).is_ok(),
        "Verification of a valid signature failed!"
    );

    let msg_and_keys = vec![(good, &keypair.public)];
    let sigs = vec![good_sig];

    let agg = AggregatedSignature::aggregate(&msg_and_keys[..], &sigs, ScalarSize::Full);
    assert!(agg.is_ok());

    assert!(
        AggregatedSignature::verify(&msg_and_keys[..], &agg.unwrap(), ScalarSize::Full).is_ok(),
        false
    )
}

#[test]
fn many_aggregate() {
    const MANY: usize = 10;

    let mut keypairs: Vec<Keypair> = vec![];
    let msg: Vec<Vec<u8>> = (0..MANY)
        .map(|i| format!("test messsage#{}", i).as_bytes().to_vec())
        .collect();

    let mut csprng = OsRng;

    for _ in 0..MANY {
        keypairs.push(Keypair::generate(&mut csprng));
    }
    let sigs: Vec<Signature> = keypairs
        .iter()
        .zip(&msg)
        .map(|(kp, msg)| kp.sign(&msg[..]))
        .collect();

    assert!(keypairs
        .iter()
        .zip(&msg)
        .zip(&sigs)
        .map(|((kp, msg), sig)| kp.verify(msg, sig))
        .collect::<Result<Vec<_>, _>>()
        .is_ok());

    let pkeys: Vec<&PublicKey> = keypairs.iter().map(|kp| &kp.public).collect();
    let msg_and_keys: Vec<(&[u8], &PublicKey)> = msg
        .iter()
        .zip(pkeys)
        .map(|(msg, pkey)| (&msg[..], pkey))
        .collect();

    let agg = AggregatedSignature::aggregate(&msg_and_keys[..], &sigs, ScalarSize::Full);
    assert!(agg.is_ok());

    assert!(AggregatedSignature::verify(&msg_and_keys[..], &agg.unwrap(), ScalarSize::Full).is_ok())
}

#[test]
fn single_quasi_aggregate() {
    let keypair: Keypair;
    let good_sig: Signature;

    let good: &[u8] = "test message".as_bytes();

    let mut csprng = OsRng;

    keypair = Keypair::generate(&mut csprng);
    good_sig = keypair.sign(&good);

    assert!(
        keypair.verify(&good, &good_sig).is_ok(),
        "Verification of a valid signature failed!"
    );

    let msg_and_keys = vec![(good, &keypair.public)];
    let sigs = vec![good_sig];

    let agg = QuasiAggregatedSignature::aggregate(128, &msg_and_keys[..], &sigs);
    assert!(agg.is_ok());

    assert!(QuasiAggregatedSignature::verify(128, &msg_and_keys[..], &agg.unwrap()).is_ok())
}

#[test]
fn many_quasi_aggregate() {
    const MANY: usize = 4;

    let mut keypairs: Vec<Keypair> = vec![];
    let msg: Vec<Vec<u8>> = (0..MANY)
        .map(|i| format!("test messsage#{}", i).as_bytes().to_vec())
        .collect();

    let mut csprng = OsRng;

    for _ in 0..MANY {
        keypairs.push(Keypair::generate(&mut csprng));
    }
    let sigs: Vec<Signature> = keypairs
        .iter()
        .zip(&msg)
        .map(|(kp, msg)| kp.sign(&msg[..]))
        .collect();

    assert!(keypairs
        .iter()
        .zip(&msg)
        .zip(&sigs)
        .map(|((kp, msg), sig)| kp.verify(msg, sig))
        .collect::<Result<Vec<_>, _>>()
        .is_ok());

    let pkeys: Vec<&PublicKey> = keypairs.iter().map(|kp| &kp.public).collect();
    let msg_and_keys: Vec<(&[u8], &PublicKey)> = msg
        .iter()
        .zip(pkeys)
        .map(|(msg, pkey)| (&msg[..], pkey))
        .collect();

    let agg = QuasiAggregatedSignature::aggregate(128, &msg_and_keys[..], &sigs);
    assert!(agg.is_ok());

    assert!(QuasiAggregatedSignature::verify(128, &msg_and_keys[..], &agg.unwrap()).is_ok())
}
