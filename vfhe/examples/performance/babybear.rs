type FF = algebra::BabyBear;
type EF = algebra::BabyBearExetension;
use vfhe::bfhe::BABYBEAR_BINARY_128_BITS_PARAMETERS as PARAMETERS;
const FIELD: &str = "babybear";
const BASE_FIELD_BITS: usize = 32;
include!("pbs.rs.inc");
