// SPDX-License-Identifier: MIT

mod common;

use std::process::Command;

use self::common::{
    DUMMY_NAME, NetnsGuard, with_dummy_iface_empty, with_netns,
};

/// The `fou` generic netlink family does not auto-load when the family is
/// resolved, so the module is loaded before the reference implementation
/// would fail with `ENOENT`.
fn load_fou_module(ns: &NetnsGuard) {
    let output = Command::new("ip")
        .args(["netns", "exec", &ns.name, "modprobe", "fou"])
        .output()
        .expect("failed to run modprobe");
    assert!(
        output.status.success(),
        "modprobe fou failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn with_fou_netns<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        load_fou_module(ns);
        test(ns);
    });
}

fn with_fou_dummy_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_dummy_iface_empty(|ns| {
        load_fou_module(ns);
        test(ns);
    });
}

#[test]
fn test_fou_show_empty() {
    with_fou_netns(|ns| {
        ns.assert_eq_output(&["fou", "show"]);
        ns.assert_eq_output(&["-j", "fou", "show"]);
    });
}

#[test]
fn test_fou_add_delete_ipproto_name() {
    with_fou_netns(|ns| {
        ns.ip_rs_exec_cmd(&["fou", "add", "port", "5555", "ipproto", "udp"]);
        ns.assert_eq_output(&["fou", "show"]);
        ns.assert_eq_output(&["-j", "fou", "show"]);

        ns.ip_rs_exec_cmd(&["fou", "del", "port", "5555"]);
        ns.assert_eq_output(&["fou", "show"]);
    });
}

#[test]
fn test_fou_add_gue_with_all_options() {
    with_fou_dummy_iface(|ns| {
        ns.exec_cmd(&["ip", "addr", "add", "10.9.9.1/24", "dev", DUMMY_NAME]);

        ns.ip_rs_exec_cmd(&[
            "fou",
            "add",
            "port",
            "5556",
            "gue",
            "local",
            "10.9.9.1",
            "peer",
            "10.9.9.2",
            "peer_port",
            "2001",
            "dev",
            DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["fou", "show"]);
        ns.assert_eq_output(&["-j", "fou", "show"]);

        ns.ip_rs_exec_cmd(&[
            "fou",
            "del",
            "port",
            "5556",
            "gue",
            "local",
            "10.9.9.1",
            "peer",
            "10.9.9.2",
            "peer_port",
            "2001",
            "dev",
            DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["fou", "show"]);
    });
}

#[test]
fn test_fou_add_ipv6() {
    with_fou_dummy_iface(|ns| {
        ns.exec_cmd(&[
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8::1/64",
            "dev",
            DUMMY_NAME,
            "nodad",
        ]);

        ns.ip_rs_exec_cmd(&[
            "-6",
            "fou",
            "add",
            "port",
            "5557",
            "ipproto",
            "17",
            "local",
            "2001:db8::1",
            "-6",
        ]);
        ns.assert_eq_output(&["fou", "show"]);
        ns.assert_eq_output(&["-j", "fou", "show"]);
        ns.assert_eq_output(&["-j", "-6", "fou", "show"]);

        ns.ip_rs_exec_cmd(&[
            "-6",
            "fou",
            "del",
            "port",
            "5557",
            "-6",
            "local",
            "2001:db8::1",
        ]);
        ns.assert_eq_output(&["fou", "show"]);
    });
}

#[test]
fn test_fou_delete_iproute2_entry() {
    with_fou_dummy_iface(|ns| {
        ns.exec_cmd(&["ip", "addr", "add", "10.9.9.1/24", "dev", DUMMY_NAME]);
        ns.exec_cmd(&[
            "ip",
            "fou",
            "add",
            "port",
            "5558",
            "gue",
            "local",
            "10.9.9.1",
            "peer",
            "10.9.9.2",
            "peer_port",
            "2002",
            "dev",
            DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["fou", "show"]);

        ns.ip_rs_exec_cmd(&[
            "fou",
            "del",
            "port",
            "5558",
            "gue",
            "local",
            "10.9.9.1",
            "peer",
            "10.9.9.2",
            "peer_port",
            "2002",
            "dev",
            DUMMY_NAME,
        ]);
        ns.assert_eq_output(&["fou", "show"]);
    });
}

#[test]
fn test_fou_legacy_ipv4_address() {
    with_fou_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "fou", "add", "port", "5561", "ipproto", "17", "local", "127.1",
        ]);
        ns.assert_eq_output(&["fou", "show"]);
        ns.assert_eq_output(&["-j", "fou", "show"]);

        ns.ip_rs_exec_cmd(&[
            "fou",
            "add",
            "port",
            "5562",
            "ipproto",
            "17",
            "local",
            "0x7f.0.0.1",
        ]);
        ns.assert_eq_output(&["fou", "show"]);

        ns.ip_rs_exec_cmd(&[
            "fou", "add", "port", "5563", "ipproto", "17", "local", "default",
        ]);
        ns.assert_eq_output(&["fou", "show"]);
    });
}

#[test]
fn test_fou_address_family_order() {
    with_fou_dummy_iface(|ns| {
        // iproute2 parses the addresses after all options, so the inline
        // `-6` behind the address still selects the address family.
        ns.exec_cmd(&[
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8::1/64",
            "dev",
            DUMMY_NAME,
            "nodad",
        ]);
        ns.ip_rs_exec_cmd(&[
            "fou",
            "add",
            "port",
            "5566",
            "ipproto",
            "17",
            "local",
            "2001:db8::1",
            "-6",
        ]);
        ns.assert_eq_output(&["fou", "show"]);
        ns.assert_eq_output(&["-j", "fou", "show"]);
    });
}

#[test]
fn test_fou_address_family_mismatch_order() {
    with_fou_netns(|ns| {
        let ip_args = [
            "ip", "fou", "add", "port", "5567", "ipproto", "17", "local",
            "10.9.9.1", "-6",
        ];
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&ip_args);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&ip_args[1..]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_fou_address_hostname_error() {
    with_fou_netns(|ns| {
        let ip_args = [
            "ip",
            "fou",
            "add",
            "port",
            "5564",
            "ipproto",
            "17",
            "local",
            "localhost",
        ];
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&ip_args);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&ip_args[1..]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_fou_address_keyword_error() {
    with_fou_netns(|ns| {
        let ip_args = [
            "ip", "fou", "add", "port", "5565", "ipproto", "17", "local", "any",
        ];
        let (_, expected_code) = ns.exec_cmd_expect_failure(&ip_args);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&ip_args[1..]);
        assert!(!stderr.trim().is_empty());
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_fou_unknown_subcommand() {
    with_fou_netns(|ns| {
        let ip_args = ["ip", "fou", "bogus"];
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&ip_args);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&ip_args[1..]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_fou_prefix_aliases() {
    with_fou_netns(|ns| {
        ns.ip_rs_exec_cmd(&["fou", "a", "port", "5559", "ipproto", "udp"]);
        ns.assert_eq_output(&["fou", "sho"]);
        ns.ip_rs_exec_cmd(&["fou", "dele", "port", "5559"]);
        ns.assert_eq_output(&["fou", "s"]);
        ns.assert_eq_output(&["-j", "fou", "s"]);
    });
}

#[test]
fn test_fou_help() {
    with_netns(|ns| {
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&["ip", "fou", "help"]);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&["fou", "help"]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_fou_no_subcommand() {
    with_netns(|ns| {
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&["ip", "fou"]);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&["fou"]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}
