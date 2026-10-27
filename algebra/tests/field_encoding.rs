#![cfg(feature = "concrete-ntt")]
use algebra::{AbstractExtensionField, BabyBear, BabyBearExtension8, Field};

#[test]
fn babybear_decoder_rejects_out_of_range_internal_representatives() {
    for raw in [
        BabyBear::MODULUS_VALUE,
        BabyBear::MODULUS_VALUE + 1,
        u32::MAX,
    ] {
        let bytes = bincode::serde::encode_to_vec(raw, bincode::config::standard()).unwrap();
        let result: Result<(BabyBear, usize), _> =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard());
        assert!(
            result.is_err(),
            "accepted out-of-range internal BabyBear representative {raw}"
        );
    }
}
#[test]
fn extension_decoder_rejects_an_out_of_range_base_coefficient() {
    let mut raw = vec![0u32; 8];
    raw[7] = BabyBear::MODULUS_VALUE;
    let bytes = bincode::serde::encode_to_vec(&raw, bincode::config::standard()).unwrap();
    let result: Result<(BabyBearExtension8, usize), _> =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard());
    assert!(result.is_err());
}
#[test]
fn valid_babybear_wire_format_retains_internal_montgomery_values() {
    for value in [0, 1, 2, 997, BabyBear::MODULUS_VALUE - 1] {
        let a = BabyBear::new(value);
        let bytes = bincode::serde::encode_to_vec(a, bincode::config::standard()).unwrap();
        let (raw, used): (u32, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(raw, algebra::modulus::to_monty(value));
        let (decoded, used): (BabyBear, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, a);
        let ef = BabyBearExtension8::from_base(a);
        let bytes = bincode::serde::encode_to_vec(ef, bincode::config::standard()).unwrap();
        let (decoded, used): (BabyBearExtension8, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, ef);
    }
}
