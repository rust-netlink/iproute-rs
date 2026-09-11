// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn setup_interfaces(ns: &NetnsGuard) {
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "link", "set", "lo", "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
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

fn assert_route_dump_eq(
    ip_rs_ns: &NetnsGuard,
    ip_ns: &NetnsGuard,
    show_args: &[&str],
) {
    let ip_rs_dump = ip_rs_ns.exec_cmd(show_args);
    let ip_dump = ip_ns.exec_cmd(show_args);
    pretty_assertions::assert_eq!(ip_rs_dump, ip_dump);
}

// IPv4 routes without a gateway use link scope even when `dev` is given.
#[test]
fn test_route_add_dev_only_scope() {
    let args = ["route", "add", "10.1.0.0/16", "dev", DUMMY_NAME];

    with_two_netns(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&args);
        ip_cmd(ip_ns, &args);
        assert_route_dump_eq(
            ip_rs_ns,
            ip_ns,
            &["ip", "-j", "route", "show", "10.1.0.0/16"],
        );
    });
}

// `pref` does not change the IPv4 default scope.
#[test]
fn test_route_add_dev_with_pref_scope() {
    let args = [
        "route",
        "add",
        "10.2.0.0/16",
        "dev",
        DUMMY_NAME,
        "pref",
        "low",
    ];

    with_two_netns(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&args);
        ip_cmd(ip_ns, &args);
        assert_route_dump_eq(
            ip_rs_ns,
            ip_ns,
            &["ip", "-j", "route", "show", "10.2.0.0/16"],
        );
    });
}

// IPv6 routes always default to universe scope, even `local` routes.
#[test]
fn test_route_add_ipv6_local_scope() {
    let args = [
        "-6",
        "route",
        "add",
        "local",
        "2001:db8::2/128",
        "dev",
        "lo",
    ];

    with_two_netns(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&args);
        ip_cmd(ip_ns, &args);
        assert_route_dump_eq(
            ip_rs_ns,
            ip_ns,
            &[
                "ip",
                "-6",
                "-j",
                "route",
                "show",
                "table",
                "local",
                "2001:db8::2/128",
            ],
        );
    });
}

// Deleting an IPv4 route must use `nowhere` as the scope wildcard, matching
// iproute2.
#[test]
fn test_route_del_dev_only_scope() {
    let add_args = ["route", "add", "10.3.0.0/16", "dev", DUMMY_NAME];
    let del_args = ["route", "del", "10.3.0.0/16", "dev", DUMMY_NAME];

    with_two_netns(|ip_rs_ns, ip_ns| {
        ip_cmd(ip_rs_ns, &add_args);
        ip_cmd(ip_ns, &add_args);
        ip_rs_ns.ip_rs_exec_cmd(&del_args);
        ip_cmd(ip_ns, &del_args);
        assert_route_dump_eq(
            ip_rs_ns,
            ip_ns,
            &["ip", "-j", "route", "show", "10.3.0.0/16"],
        );
    });
}
