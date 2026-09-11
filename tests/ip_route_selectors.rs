// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";
const VRF_NAME: &str = "test-vrf";
const VRF_TABLE: &str = "1001";

fn setup_interfaces(ns: &NetnsGuard) {
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "link", "set", "lo", "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
    for prefix in [
        "10.0.0.0/8",
        "10.10.0.0/16",
        "10.10.0.0/24",
        "10.10.1.0/24",
        "10.10.1.0/25",
    ] {
        ns.exec_cmd(&["ip", "route", "add", prefix, "dev", DUMMY_NAME]);
    }
    ns.exec_cmd(&[
        "ip", "link", "add", VRF_NAME, "type", "vrf", "table", VRF_TABLE,
    ]);
    ns.exec_cmd(&["ip", "link", "set", VRF_NAME, "up"]);
    ns.exec_cmd(&[
        "ip",
        "route",
        "add",
        "10.20.0.0/16",
        "dev",
        DUMMY_NAME,
        "vrf",
        VRF_NAME,
    ]);
}

fn with_two_netns<T>(test: impl FnOnce(&NetnsGuard, &NetnsGuard) -> T) -> T {
    with_netns(|ip_rs_ns| {
        with_netns(|ip_ns| {
            setup_interfaces(ip_rs_ns);
            setup_interfaces(ip_ns);
            test(ip_rs_ns, ip_ns)
        })
    })
}

fn ip_cmd(ns: &NetnsGuard, args: &[&str]) -> String {
    let args: Vec<&str> =
        std::iter::once("ip").chain(args.iter().copied()).collect();
    ns.exec_cmd(&args)
}

fn assert_show_eq(
    ip_rs_ns: &NetnsGuard,
    ip_ns: &NetnsGuard,
    show_args: &[&str],
) {
    pretty_assertions::assert_eq!(
        ip_cmd(ip_ns, show_args),
        ip_rs_ns.ip_rs_exec_cmd(show_args)
    );

    let mut json_show_args = vec!["-j"];
    json_show_args.extend_from_slice(show_args);
    pretty_assertions::assert_eq!(
        ip_cmd(ip_ns, &json_show_args),
        ip_rs_ns.ip_rs_exec_cmd(&json_show_args)
    );
}

// `root PREFIX` selects the routes inside the subtree of the prefix.
#[test]
fn test_route_show_root() {
    with_two_netns(|ip_rs_ns, ip_ns| {
        assert_show_eq(
            ip_rs_ns,
            ip_ns,
            &["route", "show", "root", "10.10.0.0/16"],
        );
        assert_show_eq(
            ip_rs_ns,
            ip_ns,
            &["route", "show", "to", "root", "10.10.0.0/16"],
        );
        assert_show_eq(
            ip_rs_ns,
            ip_ns,
            &["route", "show", "root", "10.0.0.0/8"],
        );
    });
}

// `match PREFIX` selects the routes covering the prefix.
#[test]
fn test_route_show_match() {
    with_two_netns(|ip_rs_ns, ip_ns| {
        assert_show_eq(
            ip_rs_ns,
            ip_ns,
            &["route", "show", "match", "10.10.1.0/25"],
        );
        assert_show_eq(
            ip_rs_ns,
            ip_ns,
            &["route", "show", "match", "10.10.0.0/8"],
        );
        assert_show_eq(
            ip_rs_ns,
            ip_ns,
            &["route", "show", "to", "match", "10.10.1.128/25"],
        );
    });
}

// `exact PREFIX` and a plain prefix match the prefix itself only.
#[test]
fn test_route_show_exact() {
    with_two_netns(|ip_rs_ns, ip_ns| {
        assert_show_eq(
            ip_rs_ns,
            ip_ns,
            &["route", "show", "exact", "10.10.0.0/16"],
        );
        assert_show_eq(ip_rs_ns, ip_ns, &["route", "show", "10.10.0.0/16"]);
        assert_show_eq(ip_rs_ns, ip_ns, &["route", "show", "10.10.1.0/25"]);
        assert_show_eq(ip_rs_ns, ip_ns, &["route", "show", "10.10.2.0/24"]);
    });
}

// `vrf NAME` selects the routing table of the VRF device.
#[test]
fn test_route_show_vrf() {
    with_two_netns(|ip_rs_ns, ip_ns| {
        assert_show_eq(ip_rs_ns, ip_ns, &["route", "show", "vrf", VRF_NAME]);
        assert_show_eq(ip_rs_ns, ip_ns, &["route", "show", "table", VRF_TABLE]);
    });
}

// `flush root PREFIX` removes the same routes as iproute2.
#[test]
fn test_route_flush_root() {
    with_two_netns(|ip_rs_ns, ip_ns| {
        let flush_args = ["route", "flush", "root", "10.10.0.0/16"];
        ip_rs_ns.ip_rs_exec_cmd(&flush_args);
        ip_cmd(ip_ns, &flush_args);
        // The flushed subtree is empty, the other routes are untouched.
        assert!(
            ip_rs_ns
                .ip_rs_exec_cmd(&["route", "show", "root", "10.10.0.0/16"])
                .trim()
                .is_empty()
        );
        assert_show_eq(ip_rs_ns, ip_ns, &["route", "show"]);
    });
}

// `flush vrf NAME` removes the routes of the VRF table.
#[test]
fn test_route_flush_vrf() {
    with_two_netns(|ip_rs_ns, ip_ns| {
        let flush_args = ["route", "flush", "vrf", VRF_NAME];
        ip_rs_ns.ip_rs_exec_cmd(&flush_args);
        ip_cmd(ip_ns, &flush_args);
        // The VRF table is empty, the main table is untouched.
        assert!(
            ip_rs_ns
                .ip_rs_exec_cmd(&["route", "show", "vrf", VRF_NAME])
                .trim()
                .is_empty()
        );
        assert_show_eq(ip_rs_ns, ip_ns, &["route", "show"]);
    });
}
