type F = algebra::BabyBear;
type EF = algebra::BabyBearExtension6;
use vfhe::bfhe::BABYBEAR_BINARY_128_BITS_PARAMETERS as PARAMETERS;
const FIELD: &str = "babybear";
const WIDTH: usize = 8;
const HELPER_EXTRA: usize = 1;
include!("packed_batch_pbs.rs.inc");
