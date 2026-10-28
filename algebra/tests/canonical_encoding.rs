use algebra::{
    AbstractExtensionField, BabyBear, Field, Goldilocks, GoldilocksExtension3, GoldilocksExtension5,
};
use serde::Serialize;
fn wire<T: Serialize>(v: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(v, bincode::config::standard()).unwrap()
}
#[test]
fn goldilocks_lazy_representatives_have_one_canonical_encoding() {
    let p = Goldilocks::MODULUS_VALUE;
    for raw in [0, 1, p - 1, p, p + 1, u64::MAX] {
        let value = Goldilocks::new(raw);
        let normalized = value.canonicalized();
        assert_eq!(value, normalized);
        assert!(normalized.is_canonical());
        assert_eq!(value.is_canonical(), raw < p);
        assert_eq!(wire(&normalized), wire(&Goldilocks::new(raw % p)));
        assert_eq!(wire(&normalized), wire(&normalized.canonicalized()));
    }
    assert_ne!(wire(&Goldilocks::new(p)), wire(&Goldilocks::new(0)));
}
fn extension<EF: AbstractExtensionField<Goldilocks> + Serialize>() {
    let raw = EF::from_base_fn(|i| Goldilocks::new(Goldilocks::MODULUS_VALUE + i as u64));
    assert!(!raw.is_canonical());
    let expected = EF::from_base_fn(|i| Goldilocks::new(i as u64));
    let normalized = raw.canonicalized();
    assert!(normalized.is_canonical());
    assert_eq!(normalized, expected);
    assert_eq!(raw, normalized);
    assert_eq!(wire(&normalized), wire(&expected));
    assert_ne!(wire(&raw), wire(&normalized));
    // value() sees only coordinate zero; normalization must retain the others.
    let zero = EF::from_base_fn(|_| Goldilocks::new(0));
    assert_eq!(raw.value(), zero.value());
    assert_ne!(normalized, zero);
}
#[test]
fn extension_normalization_preserves_all_coordinates() {
    extension::<GoldilocksExtension3>();
    extension::<GoldilocksExtension5>();
}
#[test]
fn babybear_existing_montgomery_encoding_is_unchanged() {
    for n in [0, 1, BabyBear::MODULUS_VALUE - 1] {
        let value = BabyBear::new(n);
        assert!(value.is_canonical());
        assert_eq!(wire(&value), wire(&value.canonicalized()));
    }
}
