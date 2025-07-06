check:
	cargo build;
	env CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo" \
	cargo test -- --test-threads=1 --show-output;
