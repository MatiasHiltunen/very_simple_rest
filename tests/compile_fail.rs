#[test]
fn derive_row_policy_compile_failures() {
    let test_cases = trybuild::TestCases::new();
    test_cases.compile_fail("tests/ui/*.rs");
}
