.PHONY: rebuild

rebuild:
	@echo "Removing target"
	@rm -rf target
	@echo "Running cargo xtask build-ebpf..."
	@cargo xtask build-ebpf
	@echo "Running cargo build..."
	@cargo build
	@echo "Running RUST_LOG=info cargo xtask run..."
	@RUST_LOG=aya=trace cargo xtask run
