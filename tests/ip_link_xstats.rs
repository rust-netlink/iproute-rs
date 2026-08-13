// SPDX-License-Identifier: MIT

use std::process::Command;

mod common;
use self::common::{NetnsGuard, with_netns};

const BRIDGE_NAME: &str = "br-xst";
const BOND_NAME: &str = "bond-xst";
const SLAVE_NAME: &str = "slv-xst";

fn with_bridge_xstats<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", BRIDGE_NAME, "type", "bridge"]);
        ns.ip_rs_exec_cmd(&["link", "set", BRIDGE_NAME, "up"]);
        test(ns);
    });
}

fn with_bridge_slave_xstats<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", BRIDGE_NAME, "type", "bridge"]);
        ns.ip_rs_exec_cmd(&["link", "add", SLAVE_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "set", SLAVE_NAME, "master", BRIDGE_NAME]);
        ns.ip_rs_exec_cmd(&["link", "set", SLAVE_NAME, "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", BRIDGE_NAME, "up"]);
        test(ns);
    });
}

fn with_bond_xstats<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", BOND_NAME, "type", "bond"]);
        ns.ip_rs_exec_cmd(&["link", "set", BOND_NAME, "up"]);
        test(ns);
    });
}

fn with_bond_slave_xstats<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", BOND_NAME, "type", "bond"]);
        ns.ip_rs_exec_cmd(&["link", "add", SLAVE_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "set", SLAVE_NAME, "master", BOND_NAME]);
        ns.ip_rs_exec_cmd(&["link", "set", SLAVE_NAME, "up"]);
        ns.ip_rs_exec_cmd(&["link", "set", BOND_NAME, "up"]);
        test(ns);
    });
}

fn ip_rs_path() -> String {
    env!("CARGO_BIN_EXE_ip-rs").to_string()
}

// ===== Bridge xstats tests =====

#[test]
fn test_xstats_bridge() {
    with_bridge_xstats(|ns| {
        ns.assert_eq_output(&["link", "xstats", "type", "bridge"]);
    });
}

#[test]
fn test_xstats_bridge_json() {
    with_bridge_xstats(|ns| {
        ns.assert_eq_output(&["-j", "link", "xstats", "type", "bridge"]);
    });
}

#[test]
fn test_xstats_bridge_filter_igmp() {
    with_bridge_xstats(|ns| {
        ns.assert_eq_output(&["link", "xstats", "type", "bridge", "igmp"]);
    });
}

#[test]
fn test_xstats_bridge_filter_stp() {
    with_bridge_xstats(|ns| {
        ns.assert_eq_output(&["link", "xstats", "type", "bridge", "stp"]);
    });
}

#[test]
fn test_xstats_bridge_dev_filter() {
    with_bridge_xstats(|ns| {
        ns.assert_eq_output(&[
            "link",
            "xstats",
            "type",
            "bridge",
            "dev",
            BRIDGE_NAME,
        ]);
    });
}

// ===== Bridge slave xstats tests =====

#[test]
fn test_xstats_bridge_slave() {
    with_bridge_slave_xstats(|ns| {
        ns.assert_eq_output(&["link", "xstats", "type", "bridge_slave"]);
    });
}

#[test]
fn test_xstats_bridge_slave_json() {
    with_bridge_slave_xstats(|ns| {
        ns.assert_eq_output(&["-j", "link", "xstats", "type", "bridge_slave"]);
    });
}

// ===== Bond xstats tests =====

#[test]
fn test_xstats_bond() {
    with_bond_xstats(|ns| {
        ns.assert_eq_output(&["link", "xstats", "type", "bond"]);
    });
}

#[test]
fn test_xstats_bond_json() {
    with_bond_xstats(|ns| {
        ns.assert_eq_output(&["-j", "link", "xstats", "type", "bond"]);
    });
}

#[test]
fn test_xstats_bond_filter_lacp() {
    with_bond_xstats(|ns| {
        ns.assert_eq_output(&["link", "xstats", "type", "bond", "lacp"]);
    });
}

// ===== Bond slave xstats tests =====

#[test]
fn test_xstats_bond_slave() {
    with_bond_slave_xstats(|ns| {
        ns.assert_eq_output(&["link", "xstats", "type", "bond_slave"]);
    });
}

// ===== Help tests =====

#[test]
fn test_xstats_generic_help() {
    with_netns(|ns| {
        ns.assert_eq_output(&["link", "xstats", "help"]);
    });
}

#[test]
fn test_xstats_bridge_help() {
    with_bridge_xstats(|ns| {
        ns.assert_eq_output(&["link", "xstats", "type", "bridge", "help"]);
    });
}

#[test]
fn test_xstats_bond_help() {
    with_bond_xstats(|ns| {
        ns.assert_eq_output(&["link", "xstats", "type", "bond", "help"]);
    });
}

// ===== Error tests =====

#[test]
fn test_xstats_missing_argument() {
    with_netns(|ns| {
        let output = Command::new("ip")
            .args(["netns", "exec", &ns.name, &ip_rs_path(), "link", "xstats"])
            .output()
            .expect("failed to execute command");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("xstats: missing argument"));
    });
}

#[test]
fn test_xstats_unsupported_link_type() {
    with_netns(|ns| {
        let output = Command::new("ip")
            .args([
                "netns",
                "exec",
                &ns.name,
                &ip_rs_path(),
                "link",
                "xstats",
                "type",
                "vlan",
            ])
            .output()
            .expect("failed to execute command");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("doesn't support xstats"));
    });
}
