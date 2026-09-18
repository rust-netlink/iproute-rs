// SPDX-License-Identifier: MIT

mod common;
use self::common::{
    DUMMY_NAME, NetnsGuard, with_dummy_iface_empty, with_dummy_iface_static_ip,
};

/// Add addresses with and without an `IFA_PROTO` attribute to a dummy
/// interface: only the first address carries the unknown protocol 99.
fn with_protocol_addresses<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_dummy_iface_empty(|ns| {
        ns.exec_cmd(&[
            "ip",
            "address",
            "add",
            "192.0.2.1/24",
            "dev",
            DUMMY_NAME,
            "proto",
            "99",
        ]);
        ns.exec_cmd(&[
            "ip",
            "address",
            "add",
            "192.0.2.2/24",
            "dev",
            DUMMY_NAME,
        ]);
        ns.exec_cmd(&["ip", "address", "add", "fd00::1/64", "dev", DUMMY_NAME]);
        test(ns);
    });
}

#[test]
fn test_address_show_protocol_filter() {
    with_protocol_addresses(|ns| {
        ns.assert_eq_output(&[
            "address", "show", "dev", DUMMY_NAME, "proto", "99",
        ]);
    });
}

#[test]
fn test_address_show_protocol_filter_hex() {
    with_protocol_addresses(|ns| {
        ns.assert_eq_output(&[
            "address", "show", "dev", DUMMY_NAME, "proto", "0x63",
        ]);
    });
}

#[test]
fn test_address_show_oneline() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-o", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_oneline_all_links() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-o", "address", "show"]);
    });
}

#[test]
fn test_address_show_oneline_interface_without_address() {
    with_dummy_iface_empty(|ns| {
        ns.assert_eq_output(&["-o", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_oneline_json() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-j", "-o", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_oneline_json_interface_without_address() {
    with_dummy_iface_empty(|ns| {
        ns.assert_eq_output(&["-j", "-o", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-s", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats_all_links() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-s", "address", "show"]);
    });
}

#[test]
fn test_address_show_stats_detailed() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-s", "-s", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats_json() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-j", "-s", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats_detailed_json() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-j", "-s", "-s", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats_oneline() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-o", "-s", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_stats_brief() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["--brief", "-s", "address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_filter_scope() {
    with_dummy_iface_static_ip(|ns| {
        // No interface has a host scope address, so iproute2 drops every
        // interface from the output.
        ns.assert_eq_output(&["address", "show", "scope", "host"]);
    });
}

#[test]
fn test_address_show_filter_json_oneline() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-j", "-o", "-4", "address", "show"]);
    });
}

#[test]
fn test_address_show_filter_json_oneline_ipv6() {
    with_dummy_iface_static_ip(|ns| {
        ns.assert_eq_output(&["-j", "-o", "-6", "address", "show"]);
    });
}

#[test]
fn test_address_show_unknown_protocol() {
    with_protocol_addresses(|ns| {
        ns.assert_eq_output(&["address", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_address_show_unknown_protocol_json() {
    with_protocol_addresses(|ns| {
        ns.assert_eq_output(&["-j", "address", "show", DUMMY_NAME]);
    });
}
