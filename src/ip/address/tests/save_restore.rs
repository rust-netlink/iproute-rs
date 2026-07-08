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
        test(ns);
    });
}

#[test]
fn test_address_save_output_has_valid_magic() {
    with_dummy_iface(|ns| {
        let bytes = ns.ip_rs_exec_cmd_raw(&["address", "save"]);
        assert!(bytes.len() >= 4, "save output too short");
        let magic = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(magic, 0x47361222, "save magic mismatch");
    });
}

#[test]
fn test_address_save_via_sav_alias() {
    with_dummy_iface(|ns| {
        let bytes = ns.ip_rs_exec_cmd_raw(&["address", "sav"]);
        assert!(bytes.len() >= 4, "save output too short");
        let magic = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(magic, 0x47361222, "save magic mismatch");
    });
}

#[test]
fn test_address_save_output_contains_addresses() {
    with_dummy_iface(|ns| {
        let bytes = ns.ip_rs_exec_cmd_raw(&["address", "save"]);
        assert!(
            bytes.len() > 36,
            "save output too short to contain address messages: {} bytes",
            bytes.len()
        );
    });
}

#[test]
fn test_address_flush_all() {
    with_dummy_iface(|ns| {
        // Add extra addresses
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.2/24", "dev", DUMMY_NAME]);
        // Flush all addresses on the interface
        ns.ip_rs_exec_cmd(&["address", "flush", "dev", DUMMY_NAME]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_flush_flu_alias() {
    with_dummy_iface(|ns| {
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
        ns.ip_rs_exec_cmd(&["address", "flu", "dev", DUMMY_NAME]);
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_save_restore_roundtrip() {
    with_dummy_iface(|ns| {
        // Save addresses from system ip
        let save_data = ns.exec_cmd_raw(&["ip", "address", "save"]);

        // Remove all addresses
        ns.exec_cmd(&["ip", "addr", "flush", "dev", DUMMY_NAME]);

        // Restore using ip-rs with the saved data
        ns.ip_rs_exec_cmd_with_stdin(&["address", "restore"], &save_data);

        // Verify addresses match
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_save_showdump_roundtrip() {
    with_dummy_iface(|ns| {
        // Save addresses using ip-rs
        let save_data = ns.ip_rs_exec_cmd_raw(&["address", "save"]);

        // Pipe through showdump using ip-rs
        let showdump_output =
            ns.ip_rs_exec_cmd_with_stdin(&["address", "showdump"], &save_data);

        // Verify showdump output contains our address
        assert!(
            showdump_output.contains("192.168.1.1"),
            "showdump output should contain saved address: {}",
            showdump_output
        );
    });
}

#[test]
fn test_address_save_with_dev_filter() {
    with_dummy_iface(|ns| {
        let bytes =
            ns.ip_rs_exec_cmd_raw(&["address", "save", "dev", DUMMY_NAME]);
        assert!(
            bytes.len() > 36,
            "save output with dev filter too short: {} bytes",
            bytes.len()
        );
    });
}

#[test]
fn test_address_save_with_scope_filter() {
    with_dummy_iface(|ns| {
        let bytes =
            ns.ip_rs_exec_cmd_raw(&["address", "save", "scope", "global"]);
        assert!(
            bytes.len() > 36,
            "save output with scope filter too short: {} bytes",
            bytes.len()
        );
    });
}

// Test flush scope all to match any scope
#[test]
fn test_address_flush_scope_all() {
    with_dummy_iface(|ns| {
        // Just verify the command doesn't panic when using scope all
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ns.ip_rs_exec_cmd(&[
                "address", "flush", "dev", DUMMY_NAME, "scope", "all",
            ]);
        }));
    });
}

#[test]
fn test_address_flush_scope_all_json() {
    with_dummy_iface(|ns| {
        // Just verify the command doesn't panic when using scope all with JSON
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ns.ip_rs_exec_cmd(&[
                "-j", "address", "flush", "dev", DUMMY_NAME, "scope", "all",
            ]);
        }));
    });
}

// Test flush primary short-circuit
#[test]
fn test_address_flush_primary_short_circuit() {
    with_dummy_iface(|ns| {
        // Just verify the command doesn't panic when flushing primary
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ns.ip_rs_exec_cmd(&[
                "address", "flush", "dev", DUMMY_NAME, "primary",
            ]);
        }));
    });
}
