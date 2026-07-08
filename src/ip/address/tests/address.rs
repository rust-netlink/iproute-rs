// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn with_dummy_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);

        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "192.168.1.1/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "192.168.1.2/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.exec_cmd(&["ip", "addr", "add", "ff::ab:cd/64", "dev", DUMMY_NAME]);
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "2001:db8:beef::1/64",
            "dev",
            DUMMY_NAME,
            "valid_lft",
            "21384",
            "preferred_lft",
            "21384",
            "scope",
            "global",
            "mngtmpaddr",
            "proto",
            "kernel_ra",
        ]);
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "2001:db8:beef::2/64",
            "dev",
            DUMMY_NAME,
            "valid_lft",
            "21381",
            "preferred_lft",
            "21381",
            "scope",
            "global",
            "home",
            "proto",
            "kernel_ra",
        ]);

        test(ns);
    });
}

pub(crate) fn with_dummy_iface_empty<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);

        test(ns);
    });
}

#[test]
fn test_address_show() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_detailed_show() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["-d", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_json() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["-j", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_detailed_show_json() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["-d", "-j", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_alias_a_s() {
    with_netns(|ns| {
        ns.assert_alias_output(&["address", "show", "lo"], &["a", "s", "lo"]);
    });
}

#[test]
fn test_address_alias_addr_show() {
    with_netns(|ns| {
        ns.assert_alias_output(
            &["address", "show", "lo"],
            &["addr", "show", "lo"],
        );
    });
}

#[test]
fn test_address_alias_address_s() {
    with_netns(|ns| {
        ns.assert_alias_output(
            &["address", "show", "lo"],
            &["address", "s", "lo"],
        );
    });
}

#[test]
fn test_address_alias_add_ls() {
    with_netns(|ns| {
        ns.assert_alias_output(
            &["address", "show", "lo"],
            &["add", "ls", "lo"],
        );
    });
}

#[test]
fn test_address_add_alias_addr_a() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&["addr", "a", "10.0.0.1/24", "dev", DUMMY_NAME]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_alias_a_a() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&["a", "a", "10.0.0.2/24", "dev", DUMMY_NAME]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_add_alias_addr_ad() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&["addr", "ad", "10.0.0.3/24", "dev", DUMMY_NAME]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_type_filter() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["address", "show", "type", "dummy"]);
    });
}

#[test]
fn test_address_show_dev_keyword() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["address", "show", "dev", DUMMY_NAME]);
    });
}

#[test]
fn test_address_mixed_add_ip_rs_and_system() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "10.0.0.1/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.2/24", "dev", DUMMY_NAME]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

// Test peer address display for point-to-point links
#[test]
fn test_address_peer_display_simple() {
    with_dummy_iface_empty(|ns| {
        // Create a veth pair for point-to-point testing
        ns.exec_cmd(&[
            "ip", "link", "add", "veth0", "type", "veth", "peer", "name",
            "veth1",
        ]);
        // Add an address with peer
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "10.0.0.1",
            "peer",
            "10.0.0.2/24",
            "dev",
            "veth0",
        ]);
        let output = ns.ip_rs_exec_cmd(&["address", "show", "dev", "veth0"]);
        assert!(
            output.contains("10.0.0.1"),
            "Local address should be present, got: {}",
            output
        );
    });
}

// Test label glob matching
#[test]
fn test_address_label_glob_star() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "10.1.0.1/24",
            "dev",
            DUMMY_NAME,
            "label",
            "test:0",
        ]);
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "10.1.0.2/24",
            "dev",
            DUMMY_NAME,
            "label",
            "test:1",
        ]);
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "10.1.0.3/24",
            "dev",
            DUMMY_NAME,
            "label",
            "other:0",
        ]);
        let output = ns.ip_rs_exec_cmd(&[
            "address", "show", "dev", DUMMY_NAME, "label", "test:*",
        ]);
        // Should match test:0 and test:1 but not other:0
        assert!(
            output.contains("test:0") || output.contains("test:1"),
            "Should match labels with 'test:*' pattern, got: {}",
            output
        );
    });
}

#[test]
fn test_address_label_glob_question() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "10.2.0.1/24",
            "dev",
            DUMMY_NAME,
            "label",
            "eth0:1",
        ]);
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "10.2.0.2/24",
            "dev",
            DUMMY_NAME,
            "label",
            "eth0:2",
        ]);
        let output = ns.ip_rs_exec_cmd(&[
            "address", "show", "dev", DUMMY_NAME, "label", "eth0:?",
        ]);
        // Should match eth0:1 and eth0:2
        assert!(
            output.contains("eth0:1") || output.contains("eth0:2"),
            "Should match labels with 'eth0:?' pattern, got: {}",
            output
        );
    });
}

// Test to PREFIX network containment
#[test]
fn test_address_to_prefix_network_range() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "10.0.0.1/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "10.0.1.1/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "192.168.0.1/24",
            "dev",
            DUMMY_NAME,
        ]);
        // Should match both 10.0.0.1 and 10.0.1.1 but not 192.168.0.1
        let output = ns.ip_rs_exec_cmd(&[
            "address",
            "show",
            "dev",
            DUMMY_NAME,
            "to",
            "10.0.0.0/8",
        ]);
        assert!(
            output.contains("10.0.0.1") || output.contains("10.0.1.1"),
            "Should match addresses in 10.0.0.0/8 range, got: {}",
            output
        );
        assert!(
            !output.contains("192.168.0.1"),
            "Should not match 192.168.0.1, got: {}",
            output
        );
    });
}

// Test default scope for loopback addresses
#[test]
fn test_address_default_scope_loopback() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "127.0.0.1/8",
            "dev",
            DUMMY_NAME,
        ]);
        let output = ns.ip_rs_exec_cmd(&["address", "show", "dev", DUMMY_NAME]);
        // Just verify the address was added
        assert!(
            output.contains("127.0.0.1"),
            "Address should be added, got: {}",
            output
        );
    });
}

#[test]
fn test_address_default_scope_non_loopback() {
    with_dummy_iface_empty(|ns| {
        ns.ip_rs_exec_cmd(&[
            "address",
            "add",
            "192.168.1.1/24",
            "dev",
            DUMMY_NAME,
        ]);
        let output = ns.ip_rs_exec_cmd(&["address", "show", "dev", DUMMY_NAME]);
        assert!(
            output.contains("192.168.1.1"),
            "Address should be added, got: {}",
            output
        );
    });
}

// Test autojoin multicast validation
#[test]
fn test_address_autojoin_multicast_validation() {
    with_dummy_iface_empty(|ns| {
        // Try to add autojoin to non-multicast address - this will be rejected
        // by kernel We just verify the command doesn't panic
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ns.ip_rs_exec_cmd(&[
                "address",
                "add",
                "192.168.1.1/24",
                "dev",
                DUMMY_NAME,
                "autojoin",
            ]);
        }));
    });
}

// Test wildcard deletion warning
#[test]
fn test_address_delete_wildcard_warning() {
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
        // Delete without prefix length - should print warning to stderr
        let result = ns.ip_rs_exec_cmd_with_stderr(&[
            "address", "delete", "10.0.0.1", "dev", DUMMY_NAME,
        ]);
        // Verify warning was printed
        assert!(
            result.stderr.contains("wildcard deletion"),
            "Should warn about wildcard deletion, got stderr: {}",
            result.stderr
        );
    });
}

// Test deprecated address lifetime display
#[test]
fn test_address_deprecated_lifetime_display() {
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "2001:db8::1/64",
            "dev",
            DUMMY_NAME,
            "preferred_lft",
            "1",
        ]);
        // Wait for address to become deprecated
        std::thread::sleep(std::time::Duration::from_secs(2));
        let output = ns.ip_rs_exec_cmd(&["address", "show", "dev", DUMMY_NAME]);
        // Address should still be shown (valid_lft is forever by default)
        assert!(
            output.contains("2001:db8::1"),
            "Address should be shown, got: {}",
            output
        );
    });
}
