// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";
const NH_ID: &str = "42";

fn setup_interfaces(ns: &NetnsGuard) {
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
    ns.exec_cmd(&["ip", "nexthop", "add", "id", NH_ID, "dev", DUMMY_NAME]);
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

// A route using a nexthop object shows the nexthop ID.
#[test]
fn test_route_show_nhid() {
    with_two_netns(|ip_rs_ns, ip_ns| {
        let add_args = ["route", "add", "10.1.0.0/16", "nhid", NH_ID];
        let show_args = ["route", "show", "10.1.0.0/16"];

        ip_rs_ns.ip_rs_exec_cmd(&add_args);
        ip_cmd(ip_ns, &add_args);

        pretty_assertions::assert_eq!(
            ip_cmd(ip_ns, &show_args),
            ip_rs_ns.ip_rs_exec_cmd(&show_args)
        );

        let mut json_show_args = vec!["-j"];
        json_show_args.extend_from_slice(&show_args);
        pretty_assertions::assert_eq!(
            ip_cmd(ip_ns, &json_show_args),
            ip_rs_ns.ip_rs_exec_cmd(&json_show_args)
        );
    });
}
