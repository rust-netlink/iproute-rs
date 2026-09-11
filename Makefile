IPROUTE2_DIR ?= $(HOME)/Source/iproute2
IPROUTE2_IP_DIR := $(IPROUTE2_DIR)/ip

check:
	@if [ -d "$(IPROUTE2_DIR)" ]; then \
		set -e; \
		echo "Building iproute2 in $(IPROUTE2_DIR)"; \
		git -C "$(IPROUTE2_DIR)" pull; \
		$(MAKE) -C "$(IPROUTE2_DIR)" SUBDIRS="lib ip"; \
		export PATH="$(IPROUTE2_IP_DIR):$$PATH"; \
	fi; \
	env CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo env PATH=$$PATH" \
		cargo test -- --show-output
