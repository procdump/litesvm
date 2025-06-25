rm -rf /Users/boris/projects/litesvm/crates/litesvm/tests/profraw/
export LLVM_PROFILE_FILE="/Users/boris/projects/litesvm/crates/litesvm/tests/profraw/%p-%m.profraw"
mkdir -p /Users/boris/projects/litesvm/crates/litesvm/tests/profraw
RUSTFLAGS="--emit=llvm-ir -Z coverage-options=mcdc -C instrument-coverage" cargo +nightly test -- --nocapture  --exact integration_test
llvm-profdata merge -sparse profraw/*.profraw -o merged.profdata
llvm-cov show \
	/Users/boris/projects/litesvm/crates/litesvm/test_programs/target/debug/libcounter.dylib \
	-instr-profile=merged.profdata \
	--format=html -output-dir=htmlcov
#open htmlcov/index.html
