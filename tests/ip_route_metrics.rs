// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn setup_interface(ns: &NetnsGuard) {
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
}

#[test]
fn test_route_show_metrics() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.102.0.0/16",
            "via",
            "10.0.0.254",
            "dev",
            DUMMY_NAME,
            "mtu",
            "1400",
            "rtt",
            "100ms",
            "rttvar",
            "50ms",
            "ssthresh",
            "10",
            "cwnd",
            "20",
            "advmss",
            "1300",
            "reordering",
            "3",
            "hoplimit",
            "64",
            "initcwnd",
            "5",
            "rto_min",
            "1s",
            "initrwnd",
            "6",
            "quickack",
            "1",
        ]);

        ns.assert_eq_output(&["route", "show", "10.102.0.0/16"]);
        ns.assert_eq_output(&["-j", "route", "show", "10.102.0.0/16"]);
    });
}

// A locked metric is shown with the `lock` keyword.
#[test]
fn test_route_show_metrics_lock() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.103.0.0/16",
            "dev",
            DUMMY_NAME,
            "mtu",
            "lock",
            "1400",
        ]);

        ns.assert_eq_output(&["route", "show", "10.103.0.0/16"]);
        ns.assert_eq_output(&["-j", "route", "show", "10.103.0.0/16"]);
    });
}
