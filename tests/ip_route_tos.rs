// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn setup_dummy_iface(ns: &NetnsGuard) {
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
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
fn test_route_add_tos_symbolic() {
    let args = [
        "route",
        "add",
        "10.201.0.0/16",
        "tos",
        "AF11",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&args);
        ip_cmd(ip_ns, &args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.201.0.0/16");
    });
}

#[test]
fn test_route_add_tos_hexadecimal() {
    let args = [
        "route",
        "add",
        "10.202.0.0/16",
        "tos",
        "28",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&args);
        ip_cmd(ip_ns, &args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.202.0.0/16");
    });
}

#[test]
fn test_route_del_tos() {
    let add_args = [
        "route",
        "add",
        "10.203.0.0/16",
        "tos",
        "CS1",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
    ];
    let del_args = [
        "route",
        "del",
        "10.203.0.0/16",
        "tos",
        "CS1",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&add_args);
        ip_cmd(ip_ns, &add_args);
        ip_rs_ns.ip_rs_exec_cmd(&del_args);
        ip_cmd(ip_ns, &del_args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.203.0.0/16");
    });
}

// The kernel accepts `RTA_TTL_PROPAGATE` on IPv4 routes but does not report
// it in dumps, so the emitted value is covered by unit tests and the kernel
// acceptance is compared against iproute2 here.
#[test]
fn test_route_add_ttl_propagate() {
    let enabled_args = [
        "route",
        "add",
        "10.204.0.0/16",
        "ttl-propagate",
        "enabled",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
    ];
    let disabled_args = [
        "route",
        "add",
        "10.205.0.0/16",
        "ttl-propagate",
        "disabled",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&enabled_args);
        ip_cmd(ip_ns, &enabled_args);
        ip_rs_ns.ip_rs_exec_cmd(&disabled_args);
        ip_cmd(ip_ns, &disabled_args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.204.0.0/16");
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.205.0.0/16");
    });
}

#[test]
fn test_route_add_tos_and_ttl_propagate() {
    let args = [
        "route",
        "add",
        "10.206.0.0/16",
        "tos",
        "EF",
        "ttl-propagate",
        "disabled",
        "via",
        "10.0.0.254",
        "dev",
        DUMMY_NAME,
    ];

    with_two_dummy_ifaces(|ip_rs_ns, ip_ns| {
        ip_rs_ns.ip_rs_exec_cmd(&args);
        ip_cmd(ip_ns, &args);
        assert_route_dump_eq(ip_rs_ns, ip_ns, "10.206.0.0/16");
    });
}

// The DS field of a route is shown with its name or as a hexadecimal
// number.
#[test]
fn test_route_show_tos() {
    with_netns(|ns| {
        setup_dummy_iface(ns);
        for prefix in ["10.207.0.0/16", "10.208.0.0/16"] {
            let tos = if prefix == "10.207.0.0/16" {
                "AF11"
            } else {
                "4"
            };
            ns.exec_cmd(&[
                "ip",
                "route",
                "add",
                prefix,
                "tos",
                tos,
                "via",
                "10.0.0.254",
                "dev",
                DUMMY_NAME,
            ]);

            ns.assert_eq_output(&["route", "show", prefix]);
            ns.assert_eq_output(&["-j", "route", "show", prefix]);
        }
    });
}
