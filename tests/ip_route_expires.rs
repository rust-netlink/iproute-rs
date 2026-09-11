// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn setup_interface(ns: &NetnsGuard) {
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
    ns.exec_cmd(&["ip", "addr", "add", "2001:db8::1/64", "dev", DUMMY_NAME]);
}

// Routes with a lifetime show the remaining time in seconds.
#[test]
fn test_route_show_expires() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "-6",
            "route",
            "add",
            "2001:db8:1::/64",
            "dev",
            DUMMY_NAME,
            "expires",
            "300",
        ]);

        ns.assert_eq_output(&["-6", "route", "show", "2001:db8:1::/64"]);
        ns.assert_eq_output(&["-j", "-6", "route", "show", "2001:db8:1::/64"]);
    });
}

// Cached IPv4 routes show the cache information on a dedicated line.
#[test]
fn test_route_get_cache_line() {
    with_netns(|ns| {
        setup_interface(ns);

        ns.assert_eq_output(&["route", "get", "10.0.0.5"]);
    });
}
