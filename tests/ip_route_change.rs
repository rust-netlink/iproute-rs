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
fn test_route_append() {
    with_dummy_iface(|ns| {
        // Add a route first
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "172.26.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "metric",
            "100",
        ]);
        // Append a duplicate with different metric
        ns.ip_rs_exec_cmd(&[
            "route",
            "append",
            "172.26.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "metric",
            "200",
        ]);
        ns.assert_eq_output(&["route", "show", "172.26.0.0/16"]);
    });
}

#[test]
fn test_route_append_fresh() {
    with_dummy_iface(|ns| {
        // Append a brand new route (no existing route)
        ns.ip_rs_exec_cmd(&[
            "route",
            "append",
            "172.27.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["route", "show", "172.27.0.0/16"]);
    });
}

#[test]
fn test_route_append_multiple() {
    with_dummy_iface(|ns| {
        // Add a route first
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "172.28.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "metric",
            "100",
        ]);
        // Append first duplicate
        ns.ip_rs_exec_cmd(&[
            "route",
            "append",
            "172.28.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "metric",
            "200",
        ]);
        // Append second duplicate
        ns.ip_rs_exec_cmd(&[
            "route",
            "append",
            "172.28.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "metric",
            "300",
        ]);
        ns.assert_eq_output(&["route", "show", "172.28.0.0/16"]);
    });
}

#[test]
fn test_route_append_onlink() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "route",
            "append",
            "172.29.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "onlink",
        ]);
        ns.assert_eq_output(&["route", "show", "172.29.0.0/16"]);
    });
}

#[test]
fn test_route_prepend() {
    with_dummy_iface(|ns| {
        // Prepend a new route (no existing route)
        ns.ip_rs_exec_cmd(&[
            "route",
            "prepend",
            "172.30.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["route", "show", "172.30.0.0/16"]);
    });
}

#[test]
fn test_route_prepend_existing() {
    with_dummy_iface(|ns| {
        // Add a route first
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "172.31.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "metric",
            "100",
        ]);
        // Prepend a route with same key but different metric
        ns.ip_rs_exec_cmd(&[
            "route",
            "prepend",
            "172.31.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "metric",
            "200",
        ]);
        ns.assert_eq_output(&["route", "show", "172.31.0.0/16"]);
    });
}

#[test]
fn test_route_change() {
    with_dummy_iface(|ns| {
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "172.23.0.0/16",
            "dev",
            DUMMY_NAME,
            "metric",
            "100",
        ]);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ns.ip_rs_exec_cmd(&[
                "route",
                "change",
                "172.23.0.0/16",
                "dev",
                DUMMY_NAME,
                "metric",
                "200",
            ]);
        }))
        .ok();
        ns.assert_eq_output(&["route", "show", "172.23.0.0/16"]);
    });
}
