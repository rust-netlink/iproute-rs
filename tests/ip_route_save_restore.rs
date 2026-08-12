// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn with_dummy_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.1.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "metric",
            "100",
        ]);
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.2.0.0/16",
            "dev",
            DUMMY_NAME,
            "metric",
            "200",
        ]);
        test(ns);
    });
}

#[test]
fn test_route_save_output_has_valid_magic() {
    with_dummy_iface(|ns| {
        let bytes = ns.ip_rs_exec_cmd_raw(&["route", "save"]);
        assert!(bytes.len() >= 4, "save output too short");
        let magic = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(magic, 0x45311224, "save magic mismatch");
    });
}

#[test]
fn test_route_save_via_sav_alias() {
    with_dummy_iface(|ns| {
        let bytes = ns.ip_rs_exec_cmd_raw(&["route", "sav"]);
        assert!(bytes.len() >= 4, "save output too short");
        let magic = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(magic, 0x45311224, "save magic mismatch");
    });
}

#[test]
fn test_route_save_output_contains_routes() {
    with_dummy_iface(|ns| {
        let bytes = ns.ip_rs_exec_cmd_raw(&["route", "save"]);
        assert!(
            bytes.len() > 36,
            "save output too short to contain route messages: {} bytes",
            bytes.len()
        );
    });
}

#[test]
fn test_route_save_with_dev_filter() {
    with_dummy_iface(|ns| {
        let bytes =
            ns.ip_rs_exec_cmd_raw(&["route", "save", "dev", DUMMY_NAME]);
        assert!(
            bytes.len() > 36,
            "save output with dev filter too short: {} bytes",
            bytes.len()
        );
    });
}

#[test]
fn test_route_save_showdump_roundtrip() {
    with_dummy_iface(|ns| {
        let save_data = ns.ip_rs_exec_cmd_raw(&["route", "save"]);
        let showdump_output =
            ns.ip_rs_exec_cmd_with_stdin(&["route", "showdump"], &save_data);
        assert!(
            showdump_output.contains("10.1.0.0/16"),
            "showdump output should contain 10.1.0.0/16: {}",
            showdump_output
        );
        assert!(
            showdump_output.contains("10.2.0.0/16"),
            "showdump output should contain 10.2.0.0/16: {}",
            showdump_output
        );
    });
}

#[test]
fn test_route_save_restore_roundtrip() {
    with_dummy_iface(|ns| {
        let save_data = ns.exec_cmd_raw(&["ip", "route", "save"]);
        // Flush all routes
        ns.exec_cmd(&["ip", "route", "flush", "dev", DUMMY_NAME]);
        // Restore using ip-rs
        ns.ip_rs_exec_cmd_with_stdin(&["route", "restore"], &save_data);
        // Verify routes match
        ns.assert_eq_output(&["route", "show", "dev", DUMMY_NAME]);
    });
}

#[test]
fn test_route_save_with_proto_filter() {
    with_dummy_iface(|ns| {
        let bytes =
            ns.ip_rs_exec_cmd_raw(&["route", "save", "protocol", "boot"]);
        assert!(
            bytes.len() > 36,
            "save output with proto filter too short: {} bytes",
            bytes.len()
        );
    });
}

#[test]
fn test_route_save_with_type_filter() {
    with_dummy_iface(|ns| {
        let bytes =
            ns.ip_rs_exec_cmd_raw(&["route", "save", "type", "unicast"]);
        assert!(
            bytes.len() > 36,
            "save output with type filter too short: {} bytes",
            bytes.len()
        );
    });
}

#[test]
fn test_route_save_with_table_filter() {
    with_dummy_iface(|ns| {
        let bytes = ns.ip_rs_exec_cmd_raw(&["route", "save", "table", "all"]);
        assert!(
            bytes.len() > 36,
            "save output with table all filter too short: {} bytes",
            bytes.len()
        );
    });
}
