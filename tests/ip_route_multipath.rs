// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn setup_dummy_iface(ns: &NetnsGuard) {
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
    ns.exec_cmd(&["ip", "addr", "add", "2001:db8::1/64", "dev", DUMMY_NAME]);
}

fn with_two_dummy_ifaces<T>(
    test: impl FnOnce(&NetnsGuard, &NetnsGuard) -> T,
) -> T {
    with_netns(|ip_rs_ns| {
        with_netns(|ip_ns| {
            setup_dummy_iface(ip_rs_ns);
            setup_dummy_iface(ip_ns);
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
    prefix: &str,
) {
    let ip_rs_dump = ip_rs_ns.exec_cmd(&["ip", "-j", "route", "show", prefix]);
    let ip_dump = ip_ns.exec_cmd(&["ip", "-j", "route", "show", prefix]);
    pretty_assertions::assert_eq!(ip_rs_dump, ip_dump);
}

#[test]
fn test_route_add_multipath_weights() {
    let args = [
        "route",
        "add",
        "10.109.0.0/16",
        "nexthop",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
        "weight",
        "1",
        "nexthop",
        "via",
        "10.0.0.253",
        "dev",
        DUMMY_NAME,
        "weight",
        "2",
        "onlink",
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&args);
        ip_cmd(ip_ns, &args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.109.0.0/16");
    });
}

#[test]
fn test_route_add_multipath_cross_family_via() {
    let args = [
        "route",
        "add",
        "10.112.0.0/16",
        "nexthop",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
        "nexthop",
        "via",
        "inet6",
        "2001:db8::2",
        "dev",
        DUMMY_NAME,
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&args);
        ip_cmd(ip_ns, &args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.112.0.0/16");
    });
}

#[test]
fn test_route_add_multipath_ipv6() {
    let args = [
        "-6",
        "route",
        "add",
        "2001:db8:1::/64",
        "nexthop",
        "via",
        "2001:db8::2",
        "dev",
        DUMMY_NAME,
        "weight",
        "2",
        "nexthop",
        "via",
        "2001:db8::3",
        "dev",
        DUMMY_NAME,
        "weight",
        "3",
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&args);
        ip_cmd(ip_ns, &args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "2001:db8:1::/64");
    });
}

#[test]
fn test_route_add_nhid() {
    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        let nexthop_args = [
            "nexthop",
            "add",
            "id",
            "10",
            "via",
            "10.0.0.253",
            "dev",
            DUMMY_NAME,
        ];
        ip_cmd(ip_rs_ns, &nexthop_args);
        ip_cmd(ip_ns, &nexthop_args);

        let args = ["route", "add", "10.111.0.0/16", "nhid", "10"];
        ip_rs_ns.ip_rs_exec_cmd(&args);
        ip_cmd(ip_ns, &args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.111.0.0/16");
    });
}

// iproute2 v7.2.0 advertises `pervasive` as a nexthop flag but its parser
// rejects it. The kernel accepts the flag but does not report it in route
// dumps (`fib_nexthop_info()` only reports onlink, offload and trap), so the
// emitted attribute is checked by the `test_build_route_multipath_message`
// unit test and this test only verifies the kernel accepts the route.
#[test]
fn test_route_add_nexthop_pervasive() {
    with_netns(|ns| {
        setup_dummy_iface(ns);
        ns.ip_rs_exec_cmd(&[
            "route",
            "add",
            "10.110.0.0/16",
            "nexthop",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "pervasive",
        ]);
        let dump = ns.exec_cmd(&["ip", "-j", "route", "show", "10.110.0.0/16"]);
        assert!(
            dump.contains("\"gateway\":\"10.0.0.254\""),
            "unexpected kernel dump: {dump}"
        );
        assert!(
            dump.contains("\"dev\":\"test-dummy\""),
            "unexpected kernel dump: {dump}"
        );
    });
}

#[test]
fn test_route_change_multipath() {
    let add_args = [
        "route",
        "add",
        "10.115.0.0/16",
        "nexthop",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
        "weight",
        "1",
        "nexthop",
        "via",
        "10.0.0.253",
        "dev",
        DUMMY_NAME,
        "weight",
        "2",
    ];
    let change_args = [
        "route",
        "change",
        "10.115.0.0/16",
        "nexthop",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
        "weight",
        "3",
        "nexthop",
        "via",
        "10.0.0.253",
        "dev",
        DUMMY_NAME,
        "weight",
        "4",
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_cmd(ip_rs_ns, &add_args);
        ip_cmd(ip_ns, &add_args);
        ip_rs_ns.ip_rs_exec_cmd(&change_args);
        ip_cmd(ip_ns, &change_args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.115.0.0/16");
    });
}

#[test]
fn test_route_replace_multipath() {
    let add_args = [
        "route",
        "add",
        "10.116.0.0/16",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
    ];
    let replace_args = [
        "route",
        "replace",
        "10.116.0.0/16",
        "nexthop",
        "via",
        "10.0.0.253",
        "dev",
        DUMMY_NAME,
        "nexthop",
        "via",
        "10.0.0.252",
        "dev",
        DUMMY_NAME,
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_cmd(ip_rs_ns, &add_args);
        ip_cmd(ip_ns, &add_args);
        ip_rs_ns.ip_rs_exec_cmd(&replace_args);
        ip_cmd(ip_ns, &replace_args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.116.0.0/16");
    });
}

#[test]
fn test_route_del_multipath() {
    let add_args = [
        "route",
        "add",
        "10.117.0.0/16",
        "nexthop",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
        "nexthop",
        "via",
        "10.0.0.253",
        "dev",
        DUMMY_NAME,
    ];
    let del_args = [
        "route",
        "del",
        "10.117.0.0/16",
        "nexthop",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
        "nexthop",
        "via",
        "10.0.0.253",
        "dev",
        DUMMY_NAME,
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&add_args);
        ip_cmd(ip_ns, &add_args);
        ip_rs_ns.ip_rs_exec_cmd(&del_args);
        ip_cmd(ip_ns, &del_args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.117.0.0/16");
    });
}

#[test]
fn test_route_append_multipath() {
    let add_args = [
        "route",
        "add",
        "10.118.0.0/16",
        "metric",
        "100",
        "nexthop",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
        "nexthop",
        "via",
        "10.0.0.253",
        "dev",
        DUMMY_NAME,
    ];
    let append_args = [
        "route",
        "append",
        "10.118.0.0/16",
        "metric",
        "200",
        "nexthop",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
        "nexthop",
        "via",
        "10.0.0.253",
        "dev",
        DUMMY_NAME,
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_cmd(ip_rs_ns, &add_args);
        ip_cmd(ip_ns, &add_args);
        ip_rs_ns.ip_rs_exec_cmd(&append_args);
        ip_cmd(ip_ns, &append_args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.118.0.0/16");
    });
}
