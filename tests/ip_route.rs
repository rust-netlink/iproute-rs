// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

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

// ---------------------------------------------------------------------------
// ip route get tests
// ---------------------------------------------------------------------------

#[test]
fn test_route_get_destination() {
    with_dummy_iface(|ns| {
        let out = ns.ip_rs_exec_cmd(&["route", "get", "10.0.0.5"]);
        assert!(out.contains("10.0.0.5"), "should contain destination");
        assert!(
            out.contains("dev ") || out.contains("via "),
            "should contain dev or via"
        );
        assert!(out.contains("uid"), "should contain uid");
    });
}

#[test]
fn test_route_get_destination_json() {
    with_dummy_iface(|ns| {
        let out = ns.ip_rs_exec_cmd(&["-j", "route", "get", "10.0.0.5"]);
        assert!(out.contains(r#""dst":"10.0.0.5""#), "should have dst");
    });
}

#[test]
fn test_route_get_from() {
    with_dummy_iface(|ns| {
        let out = ns
            .ip_rs_exec_cmd(&["route", "get", "10.0.0.5", "from", "10.0.0.1"]);
        assert!(out.contains("10.0.0.5"), "should contain destination");
        assert!(out.contains("from 10.0.0.1"), "should contain from");
    });
}

#[test]
fn test_route_get_from_json() {
    with_dummy_iface(|ns| {
        let out = ns.ip_rs_exec_cmd(&[
            "-j", "route", "get", "10.0.0.5", "from", "10.0.0.1",
        ]);
        assert!(out.contains(r#""dst":"10.0.0.5""#));
        assert!(
            out.contains(r#""from":"10.0.0.1""#)
                || out.contains(r#""src":"10.0.0.1""#),
            "should have from/src in json"
        );
    });
}

#[test]
fn test_route_get_oif() {
    with_dummy_iface(|ns| {
        let out =
            ns.ip_rs_exec_cmd(&["route", "get", "10.0.0.5", "oif", DUMMY_NAME]);
        assert!(out.contains("dev"), "should specify dev");
        assert!(out.contains(DUMMY_NAME), "should contain dev name");
    });
}

#[test]
fn test_route_get_dev() {
    with_dummy_iface(|ns| {
        let out =
            ns.ip_rs_exec_cmd(&["route", "get", "10.0.0.5", "dev", DUMMY_NAME]);
        assert!(out.contains(DUMMY_NAME), "should contain dev name");
    });
}

#[test]
fn test_route_get_tos() {
    with_dummy_iface(|ns| {
        let out = ns.ip_rs_exec_cmd(&["route", "get", "10.0.0.5", "tos", "16"]);
        assert!(out.contains("10.0.0.5"), "should contain destination");
    });
}

#[test]
fn test_route_get_mark() {
    with_dummy_iface(|ns| {
        let out =
            ns.ip_rs_exec_cmd(&["route", "get", "10.0.0.5", "mark", "42"]);
        assert!(out.contains("mark 0x2a"), "should show mark in hex");
    });
}

#[test]
fn test_route_get_uid() {
    with_dummy_iface(|ns| {
        let out =
            ns.ip_rs_exec_cmd(&["route", "get", "10.0.0.5", "uid", "12345"]);
        assert!(out.contains("uid 12345"), "should show uid");
    });
}

#[test]
fn test_route_get_connected() {
    with_dummy_iface(|ns| {
        let out = ns.ip_rs_exec_cmd(&["route", "get", "10.0.0.5", "connected"]);
        assert!(out.contains("10.0.0.5"), "should contain destination");
        assert!(
            out.contains("from") || out.contains("src"),
            "connected should have from/src"
        );
    });
}

#[test]
fn test_route_get_fibmatch() {
    with_dummy_iface(|ns| {
        let out = ns.ip_rs_exec_cmd(&["route", "get", "10.0.0.5", "fibmatch"]);
        // fibmatch returns the FIB entry, not the destination itself
        assert!(
            out.contains("10.0.0.0/24") || out.contains("dev"),
            "fibmatch should show fib entry"
        );
    });
}

#[test]
fn test_route_get_ipv6() {
    with_dummy_iface(|ns| {
        // Query a local IPv6 address that is reachable
        let out = ns.ip_rs_exec_cmd(&["route", "get", "2001:db8::1"]);
        assert!(out.contains("2001:db8::1"), "should contain destination");
        assert!(out.contains("dev"), "should specify dev");
    });
}

#[test]
fn test_route_get_ipv6_json() {
    with_dummy_iface(|ns| {
        let out = ns.ip_rs_exec_cmd(&["-j", "route", "get", "2001:db8::1"]);
        assert!(out.contains(r#""dst":"2001:db8::1""#));
    });
}

#[test]
fn test_route_get_all_opts() {
    with_dummy_iface(|ns| {
        let out = ns.ip_rs_exec_cmd(&[
            "route", "get", "10.0.0.5", "from", "10.0.0.1", "tos", "16", "dev",
            DUMMY_NAME, "mark", "42",
        ]);
        assert!(out.contains("10.0.0.5"), "should contain destination");
        assert!(out.contains("from 10.0.0.1"), "should contain from");
        assert!(out.contains("dev"), "should specify dev");
    });
}

#[test]
fn test_route_get_from_oif_json() {
    with_dummy_iface(|ns| {
        let out = ns.ip_rs_exec_cmd(&[
            "-j", "route", "get", "10.0.0.5", "from", "10.0.0.1", "oif",
            DUMMY_NAME,
        ]);
        assert!(out.contains(r#""dst":"10.0.0.5""#));
    });
}
