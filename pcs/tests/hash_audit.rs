#![cfg(feature = "hash-audit")]
use pcs::utils::hash::{Digest512, Hash, audit};
use sha2::{Digest, Sha512};
use std::sync::{Arc, Mutex};

#[test]
fn standard_hash_outputs_follow_workers_and_exclusive_scope() {
    let outputs = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&outputs);
    let guard = audit::observe(move |output| observed.lock().unwrap().push(output)).unwrap();
    assert!(audit::observe(|_| {}).is_err());
    let mut parent = Sha512::default();
    parent.update_hash_value(b"standard hash audit scope");
    let child = parent.clone();
    let result = std::thread::spawn(move || {
        let mut child = child;
        child.update_hash_value(b" child");
        let mut fresh = Sha512::default();
        fresh.update_hash_value(b"fresh worker hash");
        (child.output_reset(), fresh.output_reset())
    })
    .join()
    .unwrap();
    assert_eq!(
        result,
        (
            Digest512(Sha512::digest(b"standard hash audit scope child").into()),
            Digest512(Sha512::digest(b"fresh worker hash").into())
        )
    );
    assert_eq!(*outputs.lock().unwrap(), vec![result.0, result.1]);
    drop(guard);
    parent.output_reset();
    let mut later = Sha512::default();
    later.update_hash_value(b"fresh worker hash");
    later.output_reset();
    assert_eq!(outputs.lock().unwrap().len(), 2);
}
