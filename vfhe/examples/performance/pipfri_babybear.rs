type FF = algebra::BabyBear;
type EF = algebra::BabyBearExetension;
use vfhe::bfhe::BABYBEAR_BINARY_128_BITS_PARAMETERS as PARAMETERS;
const FIELD: &str = "babybear";
include!("pipfri_pbs.rs.inc");
