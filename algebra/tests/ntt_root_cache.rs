//! Root-only parameter setup must preserve native plan domains and exact bytes.
use algebra::{BabyBear, Field, Goldilocks, NTTField, transformation::AbstractNTT};

fn native_roots<F: NTTField + serde::Serialize>() {
    for bits in 5..=12 {
        let native = F::generate_ntt_table(bits).unwrap().root();
        for _ in 0..3 {
            let cached = F::get_ntt_root(bits).unwrap();
            assert_eq!(cached.value(), native.value());
            assert_eq!(
                bincode::serde::encode_to_vec(cached, bincode::config::standard()).unwrap(),
                bincode::serde::encode_to_vec(native, bincode::config::standard()).unwrap()
            );
        }
    }
    let retained = F::get_ntt_table(14).unwrap();
    assert_eq!(
        F::get_ntt_root(14).unwrap().value(),
        retained.root().value()
    );
    // Unsupported small native plans must still report their original error.
    assert!(F::generate_ntt_table(3).is_err());
    assert!(F::get_ntt_root(3).is_err());
    assert!(F::get_ntt_root(8).is_ok());
}

#[test]
fn root_cache_preserves_both_native_encodings_and_errors() {
    native_roots::<BabyBear>();
    native_roots::<Goldilocks>();
}

#[test]
fn concurrent_root_requests_keep_fields_and_domains_separate() {
    let baby = BabyBear::generate_ntt_table(13).unwrap().root().value();
    let gold = Goldilocks::generate_ntt_table(13).unwrap().root().value();
    let threads: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                (
                    BabyBear::get_ntt_root(13).unwrap().value(),
                    Goldilocks::get_ntt_root(13).unwrap().value(),
                )
            })
        })
        .collect();
    for thread in threads {
        assert_eq!(thread.join().unwrap(), (baby, gold));
    }
}
