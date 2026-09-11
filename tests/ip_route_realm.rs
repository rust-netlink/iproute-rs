// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy";

fn setup_interface(ns: &NetnsGuard) {
    ns.exec_cmd(&["ip", "link", "add", DUMMY_NAME, "type", "dummy"]);
    ns.exec_cmd(&["ip", "link", "set", DUMMY_NAME, "up"]);
    ns.exec_cmd(&["ip", "addr", "add", "10.0.0.1/24", "dev", DUMMY_NAME]);
}

// `realms FROM/TO` is shown as `realms FROM/TO` and serialized as
// `flow.from`/`flow.to`.
#[test]
fn test_route_show_realms() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.104.0.0/16",
            "dev",
            DUMMY_NAME,
            "realms",
            "250/254",
        ]);

        ns.assert_eq_output(&["route", "show", "10.104.0.0/16"]);
        ns.assert_eq_output(&["-j", "route", "show", "10.104.0.0/16"]);
    });
}

// A realm without source is shown as `realm TO` and serialized without
// `flow.from`.
#[test]
fn test_route_show_realm_destination_only() {
    with_netns(|ns| {
        setup_interface(ns);
        ns.exec_cmd(&[
            "ip",
            "route",
            "add",
            "10.107.0.0/16",
            "dev",
            DUMMY_NAME,
            "realms",
            "254",
        ]);

        ns.assert_eq_output(&["route", "show", "10.107.0.0/16"]);
        ns.assert_eq_output(&["-j", "route", "show", "10.107.0.0/16"]);
    });
}
