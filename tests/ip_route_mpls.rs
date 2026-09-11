// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn setup_interface(ns: &NetnsGuard) {
    ns.exec_cmd(&["modprobe", "mpls_router"]);
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
    ns.exec_cmd(&["sysctl", "-qw", "net.mpls.platform_labels=1048575"]);
}

// MPLS routes carry the TTL propagation setting.
#[test]
fn test_route_show_mpls_ttl_propagate() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "-f",
            "mpls",
            "route",
            "add",
            "100",
            "dev",
            DUMMY_NAME,
            "ttl-propagate",
            "enabled",
        ]);
        ns.exec_cmd(&[
            "ip",
            "-f",
            "mpls",
            "route",
            "add",
            "200",
            "dev",
            DUMMY_NAME,
            "ttl-propagate",
            "disabled",
        ]);

        ns.assert_eq_output(&["-f", "mpls", "route", "show"]);
        ns.assert_eq_output(&["-j", "-f", "mpls", "route", "show"]);
    });
}

// MPLS routes can push a new label and use a gateway of another address
// family.
#[test]
fn test_route_show_mpls_new_destination() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "-f",
            "mpls",
            "route",
            "add",
            "300",
            "via",
            "inet",
            "10.0.0.2",
            "dev",
            DUMMY_NAME,
            "as",
            "to",
            "400",
            "ttl-propagate",
            "enabled",
        ]);

        ns.assert_eq_output(&["-f", "mpls", "route", "show"]);
        ns.assert_eq_output(&["-j", "-f", "mpls", "route", "show"]);
    });
}
