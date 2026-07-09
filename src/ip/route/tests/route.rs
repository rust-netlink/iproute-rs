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
        ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
        ns.exec_cmd(&[
            "ip",
            "addr",
            "add",
            "2001:db8::1/64",
            "dev",
            DUMMY_NAME,
        ]);

        test(ns);
    });
}

fn with_routes<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_dummy_iface(|ns| {
        // Add some routes using real ip command
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
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.3.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "table",
            "100",
        ]);

        test(ns);
    });
}

#[test]
fn test_route_show() {
    with_routes(|ns| {
        ns.assert_eq_output(&["route", "show"]);
    });
}

#[test]
fn test_route_show_dev() {
    with_routes(|ns| {
        ns.assert_eq_output(&["route", "show", "dev", DUMMY_NAME]);
    });
}

#[test]
fn test_route_show_table() {
    with_routes(|ns| {
        ns.assert_eq_output(&["route", "show", "table", "all"]);
    });
}

#[test]
fn test_route_show_json() {
    with_routes(|ns| {
        ns.assert_eq_output(&["-j", "route", "show"]);
    });
}

#[test]
fn test_route_show_json_table_all() {
    with_routes(|ns| {
        ns.assert_eq_output(&["-j", "route", "show", "table", "all"]);
    });
}

#[test]
fn test_route_show_via() {
    with_routes(|ns| {
        ns.assert_eq_output(&["route", "show", "via", "10.0.0.254"]);
    });
}

#[test]
fn test_route_show_protocol() {
    with_routes(|ns| {
        ns.assert_eq_output(&["route", "show", "protocol", "boot"]);
    });
}

#[test]
fn test_route_show_type() {
    with_routes(|ns| {
        ns.assert_eq_output(&["route", "show", "type", "unicast"]);
    });
}

#[test]
fn test_route_show_ipv4() {
    with_routes(|ns| {
        ns.assert_eq_output(&["-4", "route", "show"]);
    });
}

#[test]
fn test_route_show_ipv6() {
    with_routes(|ns| {
        ns.assert_eq_output(&["-6", "route", "show"]);
    });
}

#[test]
fn test_route_add_via_dev() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "route",
            "add",
            "172.16.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["route", "show", "172.16.0.0/16"]);
    });
}

#[test]
fn test_route_add_metric() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "route",
            "add",
            "172.17.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "metric",
            "50",
        ]);
        ns.assert_eq_output(&["route", "show", "172.17.0.0/16"]);
    });
}

#[test]
fn test_route_add_table() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "route",
            "add",
            "172.18.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "table",
            "200",
        ]);
        ns.assert_eq_output(&[
            "route",
            "show",
            "table",
            "all",
            "172.18.0.0/16",
        ]);
    });
}

#[test]
fn test_route_add_proto() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "route",
            "add",
            "172.19.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "proto",
            "static",
        ]);
        ns.assert_eq_output(&["route", "show", "172.19.0.0/16"]);
    });
}

#[test]
fn test_route_add_scope() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "route",
            "add",
            "172.20.0.0/16",
            "dev",
            DUMMY_NAME,
            "scope",
            "link",
        ]);
        ns.assert_eq_output(&["route", "show", "172.20.0.0/16"]);
    });
}

#[test]
fn test_route_add_onlink() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "route",
            "add",
            "172.21.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "onlink",
        ]);
        ns.assert_eq_output(&["route", "show", "172.21.0.0/16"]);
    });
}

#[test]
fn test_route_delete() {
    with_routes(|ns| {
        ns.ip_rs_exec_cmd(&[
            "route",
            "delete",
            "10.1.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["route", "show"]);
    });
}

#[test]
fn test_route_replace() {
    with_dummy_iface(|ns| {
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "172.22.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
        ]);
        ns.ip_rs_exec_cmd(&[
            "route",
            "replace",
            "172.22.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "metric",
            "42",
        ]);
        ns.assert_eq_output(&["route", "show", "172.22.0.0/16"]);
    });
}

#[test]
fn test_route_show_type_local() {
    with_dummy_iface(|ns| {
        // Add a local address which creates local routes
        ns.exec_cmd(&["ip", "addr", "add", "10.10.10.1/32", "dev", DUMMY_NAME]);
        ns.assert_eq_output(&[
            "route", "show", "table", "all", "type", "local",
        ]);
    });
}

#[test]
fn test_route_detailed_show() {
    with_routes(|ns| {
        ns.assert_eq_output(&["-d", "route", "show"]);
    });
}

#[test]
fn test_route_detailed_show_json() {
    with_routes(|ns| {
        ns.assert_eq_output(&["-d", "-j", "route", "show"]);
    });
}
