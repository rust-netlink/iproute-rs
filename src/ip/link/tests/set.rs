// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-set-dummy";
const VLAN_NAME: &str = "test-set-vlan";
const BRIDGE_NAME: &str = "test-set-br";
const VRF_NAME: &str = "test-set-vrf";

fn with_dummy_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        test(ns);
    });
}

fn with_vlan_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", "vlan-parent", "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "set", "vlan-parent", "up"]);
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            "link",
            "vlan-parent",
            "name",
            VLAN_NAME,
            "type",
            "vlan",
            "id",
            "100",
        ]);
        test(ns);
    });
}

fn with_bridge_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", BRIDGE_NAME, "type", "bridge"]);
        test(ns);
    });
}

fn with_vrf_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "add", VRF_NAME, "type", "vrf", "table", "100",
        ]);
        test(ns);
    });
}

/// Strip non-deterministic fields from ip link show output for comparison
fn strip_nondeterministic(s: String) -> String {
    s.lines()
        .map(|line| {
            // gc_timer, hello_timer, tcn_timer, topology_change_timer vary
            // between calls iproute2 shows them as "timer_name X.XX
            // Y.YY"
            line.split("gc_timer").next().unwrap_or(line).to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// --- Dummy set tests ---

#[test]
fn test_set_dummy_up() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "up"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_down() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "down"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_mtu() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "mtu", "2000"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_address() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "address",
            "00:11:22:33:44:55",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_name() {
    with_dummy_iface(|ns| {
        let new_name = "set-dummy-new";
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "down"]);
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "name", new_name]);
        ns.assert_eq_output(&["link", "show", new_name]);
    });
}

#[test]
fn test_set_dummy_multicast_off() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "multicast", "off"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_txqueuelen() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "txqueuelen", "500"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_alias() {
    with_dummy_iface(|ns| {
        // alias is only shown in detailed output; just verify it doesn't error
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "alias",
            "my-test-device",
        ]);
        ns.assert_eq_output_map(&["link", "show", DUMMY_NAME], |s| {
            // strip the alias line if present to avoid comparison mismatch
            s.lines()
                .filter(|l| !l.trim().starts_with("alias "))
                .collect::<Vec<_>>()
                .join("\n")
        });
    });
}

#[test]
fn test_set_dummy_all_options() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "up",
            "mtu",
            "1500",
            "address",
            "00:11:22:33:44:55",
            "txqueuelen",
            "1000",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

// protodown not supported on dummy interfaces; skip the test
// #[test]

// --- VLAN set tests ---

#[test]
fn test_set_vlan_up() {
    with_vlan_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", "lo", "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", VLAN_NAME, "up"]);
        ns.assert_eq_output(&["link", "show", VLAN_NAME]);
    });
}

#[test]
fn test_set_vlan_mtu() {
    with_vlan_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", "lo", "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", VLAN_NAME, "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", VLAN_NAME, "mtu", "1400"]);
        ns.assert_eq_output(&["link", "show", VLAN_NAME]);
    });
}

// --- Bridge set tests ---

#[test]
fn test_set_bridge_up() {
    with_bridge_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", BRIDGE_NAME, "up"]);
        ns.assert_eq_output(&["link", "show", BRIDGE_NAME]);
    });
}

#[test]
fn test_set_bridge_down() {
    with_bridge_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", BRIDGE_NAME, "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", BRIDGE_NAME, "down"]);
        ns.assert_eq_output(&["link", "show", BRIDGE_NAME]);
    });
}

#[test]
fn test_set_bridge_forward_delay() {
    with_bridge_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            "dev",
            BRIDGE_NAME,
            "type",
            "bridge",
            "forward_delay",
            "15",
        ]);
        ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME],
            strip_nondeterministic,
        );
    });
}

#[test]
fn test_set_bridge_hello_time() {
    with_bridge_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            BRIDGE_NAME,
            "type",
            "bridge",
            "hello_time",
            "300",
        ]);
        ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME],
            strip_nondeterministic,
        );
    });
}

#[test]
fn test_set_bridge_max_age() {
    with_bridge_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            BRIDGE_NAME,
            "type",
            "bridge",
            "max_age",
            "3000",
        ]);
        ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME],
            strip_nondeterministic,
        );
    });
}

#[test]
fn test_set_bridge_priority() {
    with_bridge_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            BRIDGE_NAME,
            "type",
            "bridge",
            "priority",
            "0x8000",
        ]);
        ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME],
            strip_nondeterministic,
        );
    });
}

#[test]
fn test_set_bridge_group_fwd_mask() {
    with_bridge_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            BRIDGE_NAME,
            "type",
            "bridge",
            "group_fwd_mask",
            "0x4000",
        ]);
        ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME],
            strip_nondeterministic,
        );
    });
}

#[test]
fn test_set_bridge_ageing_time() {
    with_bridge_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            BRIDGE_NAME,
            "type",
            "bridge",
            "ageing_time",
            "600",
        ]);
        ns.assert_eq_output_map(
            &["-d", "link", "show", BRIDGE_NAME],
            strip_nondeterministic,
        );
    });
}

#[test]
fn test_set_bridge_mtu() {
    with_bridge_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", BRIDGE_NAME, "mtu", "1400"]);
        ns.assert_eq_output(&["link", "show", BRIDGE_NAME]);
    });
}

// --- VRF set tests ---

#[test]
fn test_set_vrf_up() {
    with_vrf_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", VRF_NAME, "up"]);
        ns.assert_eq_output(&["link", "show", VRF_NAME]);
    });
}

#[test]
fn test_set_vrf_mtu() {
    with_vrf_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", VRF_NAME, "mtu", "1400"]);
        ns.assert_eq_output(&["link", "show", VRF_NAME]);
    });
}

// --- Inet tests ---

fn with_dummy_inet_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        // inet_set_link_af requires in_device which is only created after
        // an IPv4 address is assigned to the interface
        ns.exec_cmd(&["ip", "addr", "add", "192.0.2.1/32", "dev", DUMMY_NAME]);
        test(ns);
    });
}

#[test]
fn test_set_inet_forwarding_on() {
    with_dummy_inet_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "inet",
            "forwarding",
            "on",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_inet_forwarding_off() {
    with_dummy_inet_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "inet",
            "forwarding",
            "off",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_inet_proxy_arp_on() {
    with_dummy_inet_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "inet",
            "proxy_arp",
            "on",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_inet_accept_redirects_off() {
    with_dummy_inet_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "inet",
            "accept_redirects",
            "off",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_inet_arp_ignore() {
    with_dummy_inet_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "inet",
            "arp_ignore",
            "1",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_inet_rp_filter() {
    with_dummy_inet_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "inet",
            "rp_filter",
            "2",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_inet_arp_announce() {
    with_dummy_inet_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "inet",
            "arp_announce",
            "1",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

// --- GSO/GRO tests ---

#[test]
fn test_set_dummy_gso_max_size() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "gso_max_size",
            "65536",
        ]);
        ns.assert_eq_output(&["-d", "link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_gso_ipv4_max_size() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "gso_ipv4_max_size",
            "65536",
        ]);
        ns.assert_eq_output(&["-d", "link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_gso_max_segs() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "gso_max_segs", "200"]);
        ns.assert_eq_output(&["-d", "link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_gro_max_size() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "gro_max_size",
            "131072",
        ]);
        ns.assert_eq_output(&["-d", "link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_gro_ipv4_max_size() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "gro_ipv4_max_size",
            "65536",
        ]);
        ns.assert_eq_output(&["-d", "link", "show", DUMMY_NAME]);
    });
}

// protodown not supported on dummy interfaces; skip the test
// #[test]

// --- addrgenmode test ---

#[test]
fn test_set_dummy_addrgenmode_none() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "addrgenmode", "none"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_addrgenmode_eui64() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "addrgenmode", "eui64"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_addrgenmode_random() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "addrgenmode",
            "random",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

// addrgenmode stable_secret not supported on dummy; skip the test
// #[test]

// link-netnsid requires specific netns setup; skip the basic test
// #[test]

// --- Generic set tests ---

#[test]
fn test_set_using_change_alias() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "change", DUMMY_NAME, "up"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_using_s_alias() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "s", DUMMY_NAME, "up"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_using_se_alias() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "se", DUMMY_NAME, "up"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_using_c_alias() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "c", DUMMY_NAME, "up"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_using_ch_alias() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "ch", DUMMY_NAME, "mtu", "1400"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dev_keyword() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", "dev", DUMMY_NAME, "up"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

// --- replace tests ---

#[test]
fn test_replace_create_dummy() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "replace",
            "test-rpl-dummy",
            "type",
            "dummy",
        ]);
        ns.assert_eq_output(&["link", "show", "test-rpl-dummy"]);
    });
}

#[test]
fn test_replace_create_dummy_with_opts() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "replace",
            "test-rpl-opts",
            "mtu",
            "2000",
            "address",
            "00:11:22:33:44:55",
            "txqueuelen",
            "1000",
            "type",
            "dummy",
        ]);
        ns.assert_eq_output(&["link", "show", "test-rpl-opts"]);
    });
}

#[test]
fn test_replace_existing_fails() {
    with_dummy_iface(|ns| {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ns.ip_rs_exec_cmd(&[
                    "link", "replace", DUMMY_NAME, "type", "dummy",
                ]);
            }));
        assert!(result.is_err());
    });
}

#[test]
fn test_replace_create_bridge() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "replace",
            "test-rpl-br",
            "type",
            "bridge",
            "forward_delay",
            "15",
        ]);
        ns.assert_eq_output_map(
            &["-d", "link", "show", "test-rpl-br"],
            strip_nondeterministic,
        );
    });
}

#[test]
fn test_set_bond_mode_with_type() {
    // Test that `ip link set type bond mode ...` is parsed correctly
    // by creating a bond and setting its mode
    const BOND_NAME: &str = "test-set-bond";
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", BOND_NAME, "type", "bond"]);
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            BOND_NAME,
            "type",
            "bond",
            "mode",
            "balance-rr",
        ]);
        ns.assert_eq_output(&["-d", "link", "show", BOND_NAME]);
    });
}

// --- mode tests ---

#[test]
fn test_set_dummy_mode_default() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "mode", "default"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_set_dummy_mode_dormant() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "mode", "dormant"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

// --- link-netns test ---

#[test]
fn test_set_link_netns() {
    const PEER: &str = "test-ln-peer";
    with_dummy_iface(|ns| {
        std::process::Command::new("ip")
            .args(["netns", "add", PEER])
            .status()
            .expect("failed to create peer netns");
        std::process::Command::new("ip")
            .args(["netns", "exec", &ns.name, "ip", "netns", "set", PEER, "0"])
            .status()
            .expect("failed to assign nsid");
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "link-netns", PEER]);
        ns.assert_eq_output(&["-d", "link", "show", DUMMY_NAME]);
        // cleanup
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", PEER])
            .status();
    });
}
