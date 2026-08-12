// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-prop-dummy";

#[test]
fn test_link_property_add_altname() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "property", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_link_property_del_altname() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "property", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.ip_rs_exec_cmd(&[
            "link", "property", "del", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_link_property_add_multiple_altnames() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "property", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
            "altname", "alt-bar",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_link_property_del_one_of_multiple_altnames() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "property", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
            "altname", "alt-bar",
        ]);
        ns.ip_rs_exec_cmd(&[
            "link", "property", "del", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_link_property_detailed_show_with_altname() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "property", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["-d", "link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_link_property_show_json_with_altname() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "property", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["-j", "link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_link_property_dev_as_bare_arg() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "property", "add", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

fn with_dummy_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            DUMMY_NAME,
            "address",
            "12:26:8a:bb:b4:2c",
            "type",
            "dummy",
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", DUMMY_NAME, "up"]);

        test(ns);
    });
}
