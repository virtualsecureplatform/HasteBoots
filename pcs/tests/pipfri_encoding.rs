//! The arithmetic optimization must preserve the complete protocol byte stream.
use algebra::{AbstractExtensionField, NTTField, TwoAdicField, transformation::AbstractNTT};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    pipfri::{self, Basis, Parameters},
    rolling_fri,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
fn bytes<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap()
}
fn exercise<Base, EF>()
where
    Base: NTTField,
    EF: AbstractExtensionField<Base> + Serialize + DeserializeOwned,
{
    let root = EF::from_base(Base::generate_ntt_table(5).unwrap().root());
    let mut fixture = Transcript::<EF>::new_direct_extension::<Base>();
    for basis in [Basis::Coefficients, Basis::BooleanEvaluations] {
        for mode in 0..4 {
            let regular = Parameters::new(8, 4, 4, 32, root, basis).unwrap();
            let fast = regular.clone().with_base_field_encoder::<Base>().unwrap();
            assert_eq!(bytes(&regular), bytes(&fast));
            let data: Vec<_> = (0..regular.table_len())
                .map(|i| match mode {
                    0 => EF::zero(),
                    1 => EF::from_base(Base::from(i * 13 + 1)),
                    2 => EF::from_base_fn(|j| {
                        if j + 1 == EF::D {
                            Base::from(i + 9)
                        } else {
                            Base::zero()
                        }
                    }),
                    _ => EF::from_base_fn(|j| Base::from(i * i + 17 * j + 3)),
                })
                .collect();
            let point = fixture.get_vec_challenge(b"coordinate encoder point", regular.num_vars());
            let state = pipfri::commit::<EF, Sha256>(&regular, &data).unwrap();
            let optimized = pipfri::commit::<EF, Sha256>(&fast, &data).unwrap();
            let root = state.commitment();
            assert_eq!(root.root, optimized.commitment().root);
            let mut a = Transcript::new_direct_extension::<Base>();
            let (value, proof) = pipfri::open_at(&mut a, &regular, &root, &state, &point).unwrap();
            let mut b = Transcript::new_direct_extension::<Base>();
            let (fast_value, fast_proof) =
                pipfri::open_at(&mut b, &fast, &root, &optimized, &point).unwrap();
            assert_eq!(value, fast_value);
            assert_eq!(bytes(&proof), bytes(&fast_proof));
            let after = a.get_challenge(b"after encoder");
            assert_eq!(after, b.get_challenge(b"after encoder"));
            // Either verifier parameter object accepts the other's exact proof.
            for pp in [&regular, &fast] {
                let mut t = Transcript::new_direct_extension::<Base>();
                pipfri::verify::<EF, Sha256>(&mut t, pp, &root, &point, value, &fast_proof)
                    .unwrap();
                assert_eq!(after, t.get_challenge(b"after encoder"));
            }
        }
    }
    // Check parameter serialization against the pre-optimization field tuple.
    let pp = rolling_fri::Parameters::new(8, 4, 32, root).unwrap();
    assert_eq!(bytes(&pp), bytes(&(8usize, 4usize, 32usize, root)));
    let fast = pp.clone().with_base_field_encoder::<Base>().unwrap();
    assert_eq!(bytes(&pp), bytes(&fast));
    let data: Vec<_> = (0..8)
        .map(|i| EF::from_base_fn(|j| Base::from(i + 3 * j + 1)))
        .collect();
    for layer in 0..pp.rounds() {
        let state =
            rolling_fri::commit_original::<EF, Sha256>(&pp, layer, &data[..8 >> layer]).unwrap();
        let other =
            rolling_fri::commit_original::<EF, Sha256>(&fast, layer, &data[..8 >> layer]).unwrap();
        assert_eq!(state.commitment().root, other.commitment().root);
    }
}
#[test]
fn babybear_coordinate_encoding_preserves_protocol() {
    exercise::<algebra::BabyBear, algebra::BabyBearExetension>();
}
#[test]
fn goldilocks_coordinate_encoding_preserves_protocol() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension>();
}
#[test]
fn extension_domain_roots_are_not_silently_projected_to_the_base_field() {
    // Parameter checks do not allocate the large domain. These genuine roots
    // use the extension's extra two-adicity and cannot use base-field FFTs.
    type BB = algebra::BabyBearExetension;
    type Gold = algebra::GoldilocksExtension;
    let pp = rolling_fri::Parameters::new(2, 1 << 26, 1, BB::two_adic_generator(28)).unwrap();
    assert!(pp.with_base_field_encoder::<algebra::BabyBear>().is_err());
    let pp = rolling_fri::Parameters::new(2, 1 << 31, 1, Gold::two_adic_generator(33)).unwrap();
    assert!(pp.with_base_field_encoder::<algebra::Goldilocks>().is_err());
}

#[test]
fn babybearextension8_coordinate_encoding_preserves_protocol() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension8>();
}

#[test]
fn goldilocksextension4_coordinate_encoding_preserves_protocol() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension4>();
}

#[test]
fn babybearextension5_coordinate_encoding_preserves_protocol() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension5>();
}

#[test]
fn goldilocksextension5_coordinate_encoding_preserves_protocol() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
}
