//! A radius-transfer control, not a complete PCS attack or security certificate.
use super::*;
use algebra::{NTTField, transformation::AbstractNTT};
use sha2::Sha256;

fn transcript<Base: algebra::PrimeField, E: AbstractExtensionField<Base>>(
    nonce: u64,
) -> Transcript<E> {
    let mut t = Transcript::<E>::new_direct_extension::<Base>();
    t.append_message(b"rolling radius control", &nonce);
    t
}

fn radius_control<Base, E>()
where
    Base: NTTField + algebra::PrimeField,
    E: AbstractExtensionField<Base> + Serialize,
{
    let root = E::from_base(power(Base::generate_ntt_table(6).unwrap().root(), 2));
    let pp = Parameters::new(16, 2, 1, root).unwrap();
    let mut originals: Vec<_> = (0..pp.rounds())
        .map(|layer| state::<E, Sha256>(&pp, Role::Original, layer, vec![E::zero(); pp.len(layer)]))
        .collect();
    let mut corrupted = vec![E::zero(); pp.len(0)];
    corrupted[..5].fill(E::one());
    originals[0] = state::<E, Sha256>(&pp, Role::Original, 0, corrupted);
    let roots: Vec<_> = originals.iter().map(State::commitment).collect();
    let identifiers: Vec<_> = roots.iter().map(|c| c.root).collect();
    let derived: Vec<_> = (1..pp.rounds())
        .map(|layer| state::<E, Sha256>(&pp, Role::Derived, layer, vec![E::zero(); pp.len(layer)]))
        .collect();

    // RS[32,16] has distance 17. This word is distance 5 from zero and
    // distance >=12 from every nonzero codeword, so it is outside radius 4.
    // Its five errors occupy only three of the sixteen antipodal pairs.
    assert_eq!((pp.len(0), pp.message), (32, 16));
    assert!(4 * (16 - 3) > 3 * 16); // 13/16 exceeds 3/4, exactly.

    for virtual_all in [false, true] {
        let mode = if virtual_all {
            Virtual::All
        } else {
            Virtual::None
        };
        let mut seen = [false; 32];
        let mut accepts = 0;
        let mut rejects = 0;
        for nonce in 0..2048 {
            let mut prover = transcript::<Base, E>(nonce);
            bind_mode::<E, Sha256>(&mut prover, &pp, &roots, mode).unwrap();
            let mut alphas = Vec::new();
            for layer in 0..pp.rounds() {
                alphas.push(prover.get_challenge(b"rolling FRI fold challenge"));
                if layer + 1 == pp.rounds() {
                    prover.append_message(b"rolling FRI terminal", &E::zero());
                } else {
                    prover.append_message(
                        b"rolling FRI derived root",
                        &(layer + 1, derived[layer].commitment()),
                    );
                }
            }
            let locations = indices(&mut prover, &pp);
            let index = locations[0];
            seen[index] = true;
            let proof = Proof {
                derived: derived.iter().map(State::commitment).collect(),
                terminal: E::zero(),
                queries: vec![Query {
                    originals: originals
                        .iter()
                        .enumerate()
                        .map(|(layer, word)| {
                            let mut pair = opening(word, (index >> layer) / 2);
                            if virtual_all {
                                pair.path.clear();
                            }
                            pair
                        })
                        .collect(),
                    derived: derived
                        .iter()
                        .enumerate()
                        .map(|(layer, word)| opening(word, (index >> (layer + 1)) / 2))
                        .collect(),
                }],
            };
            let mut verifier = transcript::<Base, E>(nonce);
            let accepted = if virtual_all {
                verify_virtual_all::<E, Sha256, _>(
                    &mut verifier,
                    &pp,
                    &identifiers,
                    &proof,
                    |layer, initial, supplied| {
                        let position = (initial >> layer) / 2;
                        let actual = opening(&originals[layer], position);
                        check_pair::<E, Sha256>(
                            &pp,
                            Role::Original,
                            layer,
                            &roots[layer],
                            position,
                            &actual,
                        )?;
                        if supplied.values != actual.values {
                            return Err(Error("audit virtual values"));
                        }
                        Ok(())
                    },
                )
                .is_ok()
            } else {
                verify::<E, Sha256>(&mut verifier, &pp, &roots, &proof).is_ok()
            };
            // All later equations are zero. The first fold is the only possible
            // rejection; all paths are real, including on rejected samples.
            let [a, b] = proof.queries[0].originals[0].values;
            let x = point(pp.shift(0), pp.len(0), index & !1);
            let first_fold =
                (a + b) / (E::one() + E::one()) + alphas[0] * (a - b) / ((E::one() + E::one()) * x);
            assert_eq!(accepted, first_fold == E::zero());
            if index / 2 >= 3 {
                assert!(accepted);
            }
            if index / 2 < 2 {
                assert!(!accepted);
            }
            accepts += usize::from(accepted);
            rejects += usize::from(!accepted);
            let mut a = [0; 32];
            let mut b = [0; 32];
            prover.get_challenge_bytes(b"radius audit final state", &mut a);
            verifier.get_challenge_bytes(b"radius audit final state", &mut b);
            assert_eq!(a, b);
            if seen.iter().all(|&x| x) {
                break;
            }
        }
        assert!(seen.iter().all(|&x| x));
        assert!(accepts > 0 && rejects > 0);
    }
}

#[test]
fn babybear_radius_transfer_control() {
    radius_control::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_radius_transfer_control() {
    radius_control::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
