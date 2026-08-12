// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "ali-dummy";
const BRIDGE_NAME: &str = "ali-bridge";

fn with_dummy_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        test(ns);
    });
}

fn with_bridge_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", BRIDGE_NAME, "type", "bridge"]);
        ns.ip_rs_exec_cmd(&["link", "set", BRIDGE_NAME, "up"]);
        test(ns);
    });
}

// ===== show aliases =====

#[test]
fn test_show_alias_sh() {
    with_netns(|ns| {
        ns.assert_alias_output(&["link", "show", "lo"], &["link", "sh", "lo"]);
    });
}

#[test]
fn test_show_alias_sho() {
    with_netns(|ns| {
        ns.assert_alias_output(&["link", "show", "lo"], &["link", "sho", "lo"]);
    });
}

// ===== help aliases =====

#[test]
fn test_help_alias_h() {
    with_netns(|ns| {
        ns.assert_alias_output(&["link", "help"], &["link", "h"]);
    });
}

#[test]
fn test_help_alias_he() {
    with_netns(|ns| {
        ns.assert_alias_output(&["link", "help"], &["link", "he"]);
    });
}

#[test]
fn test_help_alias_hel() {
    with_netns(|ns| {
        ns.assert_alias_output(&["link", "help"], &["link", "hel"]);
    });
}

// ===== add aliases =====
// For add, we run the alias command once, then verify the device was created

#[test]
fn test_add_alias_a() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "a", DUMMY_NAME, "type", "dummy"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_add_alias_ad() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "ad", DUMMY_NAME, "type", "dummy"]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

// ===== delete aliases =====
// For delete, we create the device, then run the alias delete, then verify

#[test]
fn test_delete_alias_d() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "d", DUMMY_NAME]);
        let output = ns.ip_rs_exec_cmd(&["link", "show", DUMMY_NAME]);
        assert!(
            !output.contains(DUMMY_NAME),
            "Device should have been deleted"
        );
    });
}

#[test]
fn test_delete_alias_de() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "de", DUMMY_NAME]);
        let output = ns.ip_rs_exec_cmd(&["link", "show", DUMMY_NAME]);
        assert!(
            !output.contains(DUMMY_NAME),
            "Device should have been deleted"
        );
    });
}

#[test]
fn test_delete_alias_del() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "del", DUMMY_NAME]);
        let output = ns.ip_rs_exec_cmd(&["link", "show", DUMMY_NAME]);
        assert!(
            !output.contains(DUMMY_NAME),
            "Device should have been deleted"
        );
    });
}

#[test]
fn test_delete_alias_dele() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "dele", DUMMY_NAME]);
        let output = ns.ip_rs_exec_cmd(&["link", "show", DUMMY_NAME]);
        assert!(
            !output.contains(DUMMY_NAME),
            "Device should have been deleted"
        );
    });
}

#[test]
fn test_delete_alias_delet() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DUMMY_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "delet", DUMMY_NAME]);
        let output = ns.ip_rs_exec_cmd(&["link", "show", DUMMY_NAME]);
        assert!(
            !output.contains(DUMMY_NAME),
            "Device should have been deleted"
        );
    });
}

// ===== set aliases =====
// set is idempotent, so assert_alias_output works

#[test]
fn test_set_alias_s() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(
            &["link", "set", DUMMY_NAME, "up"],
            &["link", "s", DUMMY_NAME, "up"],
        );
    });
}

#[test]
fn test_set_alias_se() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(
            &["link", "set", DUMMY_NAME, "up"],
            &["link", "se", DUMMY_NAME, "up"],
        );
    });
}

// ===== change aliases =====

#[test]
fn test_change_alias_c() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(
            &["link", "set", DUMMY_NAME, "up"],
            &["link", "c", DUMMY_NAME, "up"],
        );
    });
}

#[test]
fn test_change_alias_ch() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(
            &["link", "set", DUMMY_NAME, "up"],
            &["link", "ch", DUMMY_NAME, "up"],
        );
    });
}

#[test]
fn test_change_alias_cha() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(
            &["link", "set", DUMMY_NAME, "up"],
            &["link", "cha", DUMMY_NAME, "up"],
        );
    });
}

#[test]
fn test_change_alias_chan() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(
            &["link", "set", DUMMY_NAME, "up"],
            &["link", "chan", DUMMY_NAME, "up"],
        );
    });
}

#[test]
fn test_change_alias_chang() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(
            &["link", "set", DUMMY_NAME, "up"],
            &["link", "chang", DUMMY_NAME, "up"],
        );
    });
}

#[test]
fn test_change_alias_change() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(
            &["link", "set", DUMMY_NAME, "up"],
            &["link", "change", DUMMY_NAME, "up"],
        );
    });
}

// ===== xstats aliases =====
// xstats is read-only, assert_alias_output works

#[test]
fn test_xstats_alias_x() {
    with_bridge_iface(|ns| {
        ns.assert_alias_output(
            &["link", "xstats", "type", "bridge"],
            &["link", "x", "type", "bridge"],
        );
    });
}

#[test]
fn test_xstats_alias_xs() {
    with_bridge_iface(|ns| {
        ns.assert_alias_output(
            &["link", "xstats", "type", "bridge"],
            &["link", "xs", "type", "bridge"],
        );
    });
}

#[test]
fn test_xstats_alias_xst() {
    with_bridge_iface(|ns| {
        ns.assert_alias_output(
            &["link", "xstats", "type", "bridge"],
            &["link", "xst", "type", "bridge"],
        );
    });
}

#[test]
fn test_xstats_alias_xsta() {
    with_bridge_iface(|ns| {
        ns.assert_alias_output(
            &["link", "xstats", "type", "bridge"],
            &["link", "xsta", "type", "bridge"],
        );
    });
}

#[test]
fn test_xstats_alias_xstat() {
    with_bridge_iface(|ns| {
        ns.assert_alias_output(
            &["link", "xstats", "type", "bridge"],
            &["link", "xstat", "type", "bridge"],
        );
    });
}

// ===== afstats aliases =====
// afstats is read-only, assert_alias_output works

#[test]
fn test_afstats_alias_af() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(&["link", "afstats"], &["link", "af"]);
    });
}

#[test]
fn test_afstats_alias_afs() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(&["link", "afstats"], &["link", "afs"]);
    });
}

#[test]
fn test_afstats_alias_afst() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(&["link", "afstats"], &["link", "afst"]);
    });
}

#[test]
fn test_afstats_alias_afsta() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(&["link", "afstats"], &["link", "afsta"]);
    });
}

#[test]
fn test_afstats_alias_afstat() {
    with_dummy_iface(|ns| {
        ns.assert_alias_output(&["link", "afstats"], &["link", "afstat"]);
    });
}

// ===== property aliases =====
// property add is not idempotent, so run alias once then verify

#[test]
fn test_property_alias_p() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "p", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_property_alias_pr() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "pr", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_property_alias_pro() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "pro", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_property_alias_prop() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "prop", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_property_alias_prope() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "prope", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_property_alias_proper() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "proper", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}

#[test]
fn test_property_alias_propert() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link", "propert", "add", "dev", DUMMY_NAME, "altname", "alt-foo",
        ]);
        ns.assert_eq_output(&["link", "show", DUMMY_NAME]);
    });
}
