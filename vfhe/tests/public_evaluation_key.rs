use algebra::{AsInto, NTTField};
use vfhe::{Encryptor, bfhe::{Evaluator, PublicEvaluationKey}};
#[path = "common/canonical_pbs.rs"]
mod fixture;

fn exercise<F: NTTField>() {
    // Only setup/encryption has access to a secret key. The worker receives
    // encrypted evaluation material and ciphertexts, never a SecretKeyPack.
    let (key, cases, expected) = {
        let secret = fixture::secret::<F>(6301);
        let encryptor = Encryptor::new(secret.clone());
        let evaluator = Evaluator::new(&secret);
        let cases: Vec<_> = [(0,0), (0,1), (1,0), (1,1)].into_iter()
            .map(|(x,y)| (encryptor.encrypt(x.as_into()), encryptor.encrypt(y.as_into())))
            .collect();
        let expected: Vec<_> = cases.iter().map(|(x,y)| {
            let (output, trace) = evaluator.nand(x,y);
            (format!("{output:?}"), format!("{:?}", trace.modulus_switching_trace.input))
        }).collect();
        (evaluator.public_evaluation_key(), cases, expected)
    };
    fn worker<F: NTTField>(key: PublicEvaluationKey<F>, cases: Vec<(fhe_core::LWECiphertext<F>, fhe_core::LWECiphertext<F>)>) -> Vec<(String,String)> {
        let evaluator = Evaluator::from_public_evaluation_key(key);
        cases.iter().map(|(x,y)| {
            let (output, trace) = evaluator.nand(x,y);
            (format!("{output:?}"), format!("{:?}", trace.modulus_switching_trace.input))
        }).collect()
    }
    assert_eq!(worker(key, cases), expected);
}
#[test]
fn babybear_public_key_reproduces_nand() { exercise::<algebra::BabyBear>(); }
#[test]
fn goldilocks_public_key_reproduces_nand() { exercise::<algebra::Goldilocks>(); }
