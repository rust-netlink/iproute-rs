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
            "metric",
            "300",
        ]);
        test(ns);
    });
}

#[test]
fn test_route_flush_all() {
    with_routes(|ns| {
        ns.ip_rs_exec_cmd(&["route", "flush", "10.1.0.0/16"]);
        // Verify the route was removed
        let out = ns.ip_rs_exec_cmd(&["route", "show", "10.1.0.0/16"]);
        assert!(out.is_empty(), "Expected no routes after flush, got: {out}");
    });
}

#[test]
fn test_route_flush_via() {
    with_routes(|ns| {
        ns.ip_rs_exec_cmd(&["route", "flush", "via", "10.0.0.254"]);
        // Only routes via 10.0.0.254 should be removed
        let out = ns.ip_rs_exec_cmd(&["route", "show", "10.1.0.0/16"]);
        assert!(out.is_empty(), "Route via 10.0.0.254 should be flushed");
        let out = ns.ip_rs_exec_cmd(&["route", "show", "10.2.0.0/16"]);
        assert!(!out.is_empty(), "Route without via should remain");
    });
}

#[test]
fn test_route_flush_dev() {
    with_routes(|ns| {
        ns.ip_rs_exec_cmd(&["route", "flush", "dev", DUMMY_NAME]);
        // All routes on the dummy device should be removed
        let out = ns.ip_rs_exec_cmd(&["route", "show", "dev", DUMMY_NAME]);
        assert!(
            out.is_empty(),
            "All routes on {DUMMY_NAME} should be flushed"
        );
    });
}

#[test]
fn test_route_flush_protocol() {
    with_routes(|ns| {
        // Add a static route
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.4.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "proto",
            "static",
        ]);
        // Flush routes with proto static
        ns.ip_rs_exec_cmd(&["route", "flush", "proto", "static"]);
        let out = ns.ip_rs_exec_cmd(&["route", "show", "10.4.0.0/16"]);
        assert!(out.is_empty(), "Static route should be flushed");
    });
}

#[test]
fn test_route_flush_type() {
    with_dummy_iface(|ns| {
        // Add a blackhole route
        ns.exec_cmd(&["ip", "route", "add", "blackhole", "10.5.0.0/16"]);
        ns.ip_rs_exec_cmd(&["route", "flush", "type", "blackhole"]);
        let out = ns.ip_rs_exec_cmd(&["route", "show", "10.5.0.0/16"]);
        assert!(out.is_empty(), "Blackhole route should be flushed");
    });
}

#[test]
fn test_route_flush_table() {
    with_dummy_iface(|ns| {
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.6.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "table",
            "100",
        ]);
        ns.ip_rs_exec_cmd(&["route", "flush", "table", "100"]);
        // Verify by showing table 100
        let out = ns.ip_rs_exec_cmd(&["route", "show", "table", "100"]);
        assert!(out.is_empty(), "Table 100 routes should be flushed");
    });
}
