// SPDX-License-Identifier: MIT

mod common;
use self::common::{
    DUMMY_NAME, with_dummy_iface_empty, with_dummy_iface_static_ip,
};

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
