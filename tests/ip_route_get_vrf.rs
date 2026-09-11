// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";
const VRF_NAME: &str = "test-vrf";

fn setup_interfaces(ns: &NetnsGuard) {
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
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
        "10.0.0.0/24",
        "dev",
        DUMMY_NAME,
    ]);
}

// `vrf NAME` looks the address up in the routing table of the VRF device.
#[test]
fn test_route_get_vrf() {
    with_netns(|ns| {
        setup_interfaces(ns);
        ns.assert_eq_output(&["route", "get", "10.0.0.2", "vrf", VRF_NAME]);
        ns.assert_eq_output(&[
            "-j", "route", "get", "10.0.0.2", "vrf", VRF_NAME,
        ]);
    });
}
