// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const BATADV_NAME: &str = "bat0";

#[test]
fn test_link_add_batadv() {
    with_batadv_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", BATADV_NAME]);
    });
}

#[test]
fn test_link_detailed_show_batadv() {
    with_batadv_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", BATADV_NAME]);
    });
}

#[test]
fn test_link_show_batadv_json() {
    with_batadv_iface(&[], |ns| {
        ns.assert_eq_output(&["-j", "link", "show", BATADV_NAME]);
    });
}

#[test]
fn test_link_detailed_show_batadv_json() {
    with_batadv_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", BATADV_NAME]);
    });
}

#[test]
fn test_link_add_batadv_with_ra() {
    with_batadv_iface(&["ra", "BATMAN_IV"], |ns| {
        ns.assert_eq_output(&["link", "show", BATADV_NAME]);
    });
}

#[test]
fn test_link_detailed_show_batadv_with_ra() {
    with_batadv_iface(&["ra", "BATMAN_IV"], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", BATADV_NAME]);
    });
}

#[test]
fn test_set_batadv_up() {
    with_batadv_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", BATADV_NAME]);
    });
}

#[test]
fn test_set_batadv_down() {
    with_batadv_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&["link", "set", BATADV_NAME, "down"]);
        ns.assert_eq_output(&["link", "show", BATADV_NAME]);
    });
}

fn with_batadv_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let mut args = vec!["link", "add", BATADV_NAME, "type", "batadv"];
        args.extend_from_slice(opts);
        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", BATADV_NAME, "up"]);

        test(ns);
    });
}
