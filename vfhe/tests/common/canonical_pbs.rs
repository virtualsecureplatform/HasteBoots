use algebra::{
    AsInto, NTTField,
    utils::{Block, Prg},
};
use fhe_core::{
    ConstParameters, LWESecretKeyType, Parameters as FheParameters, RingSecretKeyType,
    SecretKeyPack,
};
use rand::SeedableRng;
pub fn params<F: NTTField>() -> FheParameters<F> {
    FheParameters::new(ConstParameters {
        lwe_dimension: 21,
        lwe_plain_modulus: 4usize.as_into(),
        lwe_noise_standard_deviation: 1.0,
        lwe_secret_key_type: LWESecretKeyType::Binary,
        ring_dimension: 32,
        ring_modulus: F::MODULUS_VALUE,
        ring_noise_standard_deviation: 1.0,
        ring_secret_key_type: RingSecretKeyType::Ternary,
        blind_rotation_basis_bits: 8,
        key_switching_basis_bits: 5,
        key_switching_standard_deviation: 1.0,
    })
    .unwrap()
}
pub fn secret<F: NTTField>(seed: u64) -> SecretKeyPack<F> {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    SecretKeyPack::with_rng(params::<F>(), Prg::from_seed(Block::from(bytes)))
}
