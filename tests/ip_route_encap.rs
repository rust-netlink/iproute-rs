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

fn assert_route_show_eq(ns: &NetnsGuard, args: &[&str]) {
    ns.assert_eq_output(args);
    let mut json_args = vec!["-j"];
    json_args.extend_from_slice(args);
    ns.assert_eq_output(&json_args);
}

// MPLS encapsulation pushes a label stack.
#[test]
fn test_route_show_encap_mpls() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.106.0.0/16",
            "encap",
            "mpls",
            "100/200",
            "dev",
            DUMMY_NAME,
        ]);

        assert_route_show_eq(ns, &["route", "show", "10.106.0.0/16"]);
    });
}

// IPv6 encapsulation of an IPv6 route.
#[test]
fn test_route_show_encap_ip6() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "-6",
            "route",
            "add",
            "2001:db8:5::/64",
            "encap",
            "ip6",
            "id",
            "101",
            "dst",
            "2001:db8::2",
            "dev",
            DUMMY_NAME,
        ]);

        assert_route_show_eq(ns, &["-6", "route", "show", "2001:db8:5::/64"]);
    });
}

// SRv6 encapsulation with a segment list.
#[test]
fn test_route_show_encap_seg6() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "-6",
            "route",
            "add",
            "2001:db8:2::/64",
            "encap",
            "seg6",
            "mode",
            "encap",
            "segs",
            "2001:db8::2,2001:db8::3",
            "dev",
            DUMMY_NAME,
        ]);

        assert_route_show_eq(ns, &["-6", "route", "show", "2001:db8:2::/64"]);
    });
}
