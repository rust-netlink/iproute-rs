tests_setup:
	sudo ip netns list | grep -qw iproute-rs-test && sudo ip netns del iproute-rs-test || true
	sudo ip netns add iproute-rs-test

	# Create veth pair and move one end into the test netns
	sudo ip link add veth0 type veth peer name veth1
	sudo ip link set veth1 netns iproute-rs-test
	sudo ip addr add 192.0.2.1/24 dev veth0
	sudo ip link set veth0 up
	sudo ip -n iproute-rs-test addr add 192.0.2.2/24 dev veth1
	sudo ip -n iproute-rs-test link set veth1 up
	sudo ip -n iproute-rs-test link set lo up

	# create dummy, altname, bridge and vlan inside the test netns
	sudo ip -n iproute-rs-test link add dummy0 type dummy
	sudo ip -n iproute-rs-test link property add dev dummy0 altname dmmy-zero
	sudo ip -n iproute-rs-test link add br0 type bridge
	sudo ip -n iproute-rs-test link add link dummy0 name dummy0.1 type vlan id 1
	sudo ip -n iproute-rs-test link set dev dummy0.1 master br0

	sudo ip -n iproute-rs-test link set dummy0 up
	sudo ip -n iproute-rs-test link set dummy0.1 up
	sudo ip -n iproute-rs-test link set br0 up

	echo "setup network namespace for tests finished"
	sudo ip -n iproute-rs-test -c -d link show

check: tests_setup
	cargo build;
	env CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo" \
	cargo test -- --test-threads=1 --show-output $(WHAT) ;
	sudo ip netns del iproute-rs-test
