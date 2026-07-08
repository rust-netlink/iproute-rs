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
        ns.exec_cmd(&["ip", "addr", "add", "192.168.1.1/24", "dev", DUMMY_NAME]);
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
