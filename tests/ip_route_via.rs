// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn setup_interface(ns: &NetnsGuard) {
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
    ns.exec_cmd(&["ip", "-6", "addr", "add", "fe80::1/64", "dev", DUMMY_NAME]);
}

// A route using a gateway of another address family shows the family of
// the gateway in both the plain and the JSON output.
#[test]
fn test_route_show_via_ipv6_gateway() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.201.0.0/16",
            "via",
            "inet6",
            "fe80::2",
            "dev",
            DUMMY_NAME,
        ]);

        ns.assert_eq_output(&["route", "show", "10.201.0.0/16"]);
        ns.assert_eq_output(&["-j", "route", "show", "10.201.0.0/16"]);
    });
}
