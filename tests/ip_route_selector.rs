// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME0: &str = "test-dummy0";
const DUMMY_NAME1: &str = "test-dummy1";
const VRF_NAME: &str = "test-vrf";

fn setup_interfaces(ns: &NetnsGuard) {
    for (name, addr) in
        [(DUMMY_NAME0, "10.0.0.1/24"), (DUMMY_NAME1, "10.1.0.1/24")]
    {
        ns.exec_cmd(&["ip", "link", "add", name, "type", "dummy"]);
        ns.exec_cmd(&["ip", "link", "set", name, "up"]);
        ns.exec_cmd(&["ip", "addr", "add", addr, "dev", name]);
    }
    ns.exec_cmd(&["ip", "route", "add", "10.101.0.0/16", "dev", DUMMY_NAME0]);
    ns.exec_cmd(&["ip", "route", "add", "10.102.0.0/16", "dev", DUMMY_NAME0]);
    ns.exec_cmd(&[
        "ip", "link", "add", VRF_NAME, "type", "vrf", "table", "100",
    ]);
    ns.exec_cmd(&["ip", "link", "set", VRF_NAME, "up"]);
    ns.exec_cmd(&[
        "ip",
        "route",
        "add",
        "table",
        "100",
        "10.103.0.0/16",
        "dev",
        DUMMY_NAME0,
    ]);
}

fn assert_route_show_eq(ns: &NetnsGuard, args: &[&str]) {
    ns.assert_eq_output(args);
    let mut json_args = vec!["-j"];
    json_args.extend_from_slice(args);
    ns.assert_eq_output(&json_args);
}

// A plain prefix only selects the exact prefix.
#[test]
fn test_route_show_prefix() {
    with_netns(|ns| {
        setup_interfaces(ns);
        assert_route_show_eq(ns, &["route", "show", "10.101.0.0/16"]);
        assert_route_show_eq(ns, &["route", "show", "exact", "10.101.0.0/16"]);
    });
}

// `root PREFIX` selects the routes inside the subtree of the prefix.
#[test]
fn test_route_show_root_prefix() {
    with_netns(|ns| {
        setup_interfaces(ns);
        assert_route_show_eq(ns, &["route", "show", "root", "10.0.0.0/8"]);
    });
}

// `match PREFIX` selects the routes covering the prefix.
#[test]
fn test_route_show_match_prefix() {
    with_netns(|ns| {
        setup_interfaces(ns);
        assert_route_show_eq(ns, &["route", "show", "match", "10.101.5.0/24"]);
    });
}

// `table TABLE` and `vrf NAME` select one routing table.
#[test]
fn test_route_show_table_and_vrf() {
    with_netns(|ns| {
        setup_interfaces(ns);
        assert_route_show_eq(ns, &["route", "show", "table", "100"]);
        assert_route_show_eq(ns, &["route", "show", "vrf", VRF_NAME]);
    });
}
