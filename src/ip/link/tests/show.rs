// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "tshow-dummy";
const DUMMY2_NAME: &str = "tshow-dummy2";
const BRIDGE_NAME: &str = "tshow-br";
const VRF_NAME: &str = "tshow-vrf";

fn with_dummy_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        test(ns);
    });
}

fn with_two_dummies<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY2_NAME, "type", "dummy"]);
        test(ns);
    });
}

fn with_bridge_and_enslaved_dummy<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "add", BRIDGE_NAME, "type", "bridge"]);
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            "dev",
            DUMMY_NAME,
            "master",
            BRIDGE_NAME,
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", BRIDGE_NAME, "up"]);
        test(ns);
    });
}

fn with_vrf_and_enslaved_dummy<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&[
            "link", "add", VRF_NAME, "type", "vrf", "table", "100",
        ]);
        ns.ip_rs_exec_cmd(&[
            "link", "set", "dev", DUMMY_NAME, "master", VRF_NAME,
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", VRF_NAME, "up"]);
        test(ns);
    });
}

#[test]
fn test_show_type_dummy() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["link", "show", "type", "dummy"]);
    });
}

#[test]
fn test_show_type_dummy_dev_keyword() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&[
            "link", "show", "dev", DUMMY_NAME, "type", "dummy",
        ]);
    });
}

#[test]
fn test_show_type_dummy_down() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["link", "show", "down", "type", "dummy"]);
    });
}

#[test]
fn test_show_dummy_up() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "up"]);
        ns.assert_eq_output(&["link", "show", "type", "dummy", "up"]);
    });
}

#[test]
fn test_show_master() {
    with_bridge_and_enslaved_dummy(|ns| {
        ns.assert_eq_output(&["link", "show", "master", BRIDGE_NAME]);
    });
}

#[test]
fn test_show_master_json() {
    with_bridge_and_enslaved_dummy(|ns| {
        ns.assert_eq_output(&["-j", "link", "show", "master", BRIDGE_NAME]);
    });
}

#[test]
fn test_show_nomaster() {
    with_bridge_and_enslaved_dummy(|ns| {
        // The enslaved dummy should NOT appear in nomaster output
        let output = ns.ip_rs_exec_cmd(&["link", "show", "nomaster"]);
        assert!(!output.contains(DUMMY_NAME));
    });
}

#[test]
fn test_show_vrf() {
    with_vrf_and_enslaved_dummy(|ns| {
        ns.assert_eq_output(&["link", "show", "vrf", VRF_NAME]);
    });
}

#[test]
fn test_show_group_default() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&[
            "link", "show", "group", "default", "type", "dummy",
        ]);
    });
}

#[test]
fn test_show_group_0() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["link", "show", "group", "0", "type", "dummy"]);
    });
}

#[test]
fn test_show_group_custom() {
    with_dummy_iface(|ns| {
        // Set dummy to group 42
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "group", "42"]);
        ns.assert_eq_output(&["link", "show", "group", "42"]);
    });
}

#[test]
fn test_show_novf() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["link", "show", DUMMY_NAME, "novf"]);
    });
}

#[test]
fn test_show_two_dummies_type_filter() {
    with_two_dummies(|ns| {
        ns.assert_eq_output(&["link", "show", "type", "dummy"]);
    });
}
