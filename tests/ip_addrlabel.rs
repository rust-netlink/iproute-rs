// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const LABEL_PREFIX: &str = "2001:db8:1::/64";
const LABEL_DEV_PREFIX: &str = "2001:db8:2::/64";

fn with_addrlabels<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&[
            "ip",
            "addrlabel",
            "add",
            "prefix",
            LABEL_PREFIX,
            "label",
            "5",
        ]);
        ns.exec_cmd(&[
            "ip",
            "addrlabel",
            "add",
            "prefix",
            LABEL_DEV_PREFIX,
            "dev",
            "lo",
            "label",
            "7",
        ]);
        test(ns);
    });
}

/// Assert both iproute2 and ip-rs reject the command, iproute2 is checked
/// first so the test cannot assert a behavior the kernel does not have.
fn assert_ip_and_ip_rs_fail(ns: &NetnsGuard, args: &[&str]) {
    let mut ip_args = vec!["netns", "exec", ns.name.as_str(), "ip"];
    ip_args.extend_from_slice(args);
    let output = std::process::Command::new("ip")
        .args(&ip_args)
        .output()
        .expect("failed to execute ip");
    assert!(
        !output.status.success(),
        "ip unexpectedly succeeded: {args:?}"
    );

    let stderr = ns.ip_rs_exec_cmd_expect_failure(args);
    assert!(!stderr.trim().is_empty(), "no error message for {args:?}");
}

#[test]
fn test_addrlabel_list() {
    with_netns(|ns| {
        ns.assert_eq_output(&["addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_show() {
    with_netns(|ns| {
        ns.assert_eq_output(&["addrlabel", "show"]);
    });
}

#[test]
fn test_addrlabel_no_subcommand() {
    with_netns(|ns| {
        ns.assert_eq_output(&["addrlabel"]);
    });
}

#[test]
fn test_addrlabel_json() {
    with_netns(|ns| {
        ns.assert_eq_output(&["-j", "addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_oneline() {
    with_addrlabels(|ns| {
        ns.assert_eq_output(&["-o", "addrlabel", "list"]);
        ns.assert_eq_output(&["-o", "-6", "addrlabel", "list"]);
        ns.assert_eq_output(&["-br", "addrlabel", "list"]);
        ns.assert_eq_output(&["-s", "addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_help() {
    with_netns(|ns| {
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&["ip", "addrlabel", "help"]);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&["addrlabel", "help"]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_addrlabel_delete_with_dev() {
    with_netns(|ns| {
        ns.exec_cmd(&[
            "ip",
            "addrlabel",
            "add",
            "prefix",
            LABEL_DEV_PREFIX,
            "dev",
            "lo",
            "label",
            "7",
        ]);
        ns.ip_rs_exec_cmd(&[
            "addrlabel",
            "delete",
            "prefix",
            LABEL_DEV_PREFIX,
            "dev",
            "lo",
            "label",
            "7",
        ]);
        ns.assert_eq_output(&["addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_family_filter() {
    with_addrlabels(|ns| {
        ns.assert_eq_output(&["-6", "addrlabel", "list"]);
        ns.assert_eq_output(&["-6", "-j", "addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_add_display() {
    with_addrlabels(|ns| {
        ns.assert_eq_output(&["addrlabel", "list"]);
        ns.assert_eq_output(&["-j", "addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_add() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "addrlabel",
            "add",
            "prefix",
            LABEL_PREFIX,
            "label",
            "5",
        ]);
        ns.assert_eq_output(&["addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_add_with_dev() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "addrlabel",
            "add",
            "prefix",
            LABEL_DEV_PREFIX,
            "dev",
            "lo",
            "label",
            "7",
        ]);
        ns.assert_eq_output(&["-j", "addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_add_reversed_args() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "addrlabel",
            "add",
            "label",
            "7",
            "dev",
            "lo",
            "prefix",
            LABEL_DEV_PREFIX,
        ]);
        ns.assert_eq_output(&["addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_add_hex_label() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "addrlabel",
            "add",
            "prefix",
            "2001:db8:3::/64",
            "label",
            "0x10",
        ]);
        ns.assert_eq_output(&["addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_add_octal_label() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "addrlabel",
            "add",
            "prefix",
            "2001:db8:3::/64",
            "label",
            "010",
        ]);
        ns.assert_eq_output(&["-j", "addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_add_without_prefix_len() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "addrlabel",
            "add",
            "prefix",
            "2001:db8:4::",
            "label",
            "6",
        ]);
        ns.assert_eq_output(&["addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_delete() {
    with_addrlabels(|ns| {
        ns.ip_rs_exec_cmd(&[
            "addrlabel",
            "delete",
            "prefix",
            LABEL_PREFIX,
            "label",
            "5",
        ]);
        ns.assert_eq_output(&["addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_flush() {
    with_addrlabels(|ns| {
        ns.ip_rs_exec_cmd(&["addrlabel", "flush"]);
        ns.assert_eq_output(&["addrlabel", "list"]);
        ns.assert_eq_output(&["-j", "addrlabel", "list"]);
        let output = ns.ip_rs_exec_cmd(&["addrlabel", "list"]);
        assert!(output.is_empty(), "Expected no label, got: {output}");
    });
}

#[test]
fn test_addrlabel_flush_ipv6() {
    with_addrlabels(|ns| {
        ns.ip_rs_exec_cmd(&["-6", "addrlabel", "flush"]);
        ns.assert_eq_output(&["-6", "addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_deleted_device() {
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "link", "add", "dummy0", "type", "dummy"]);
        ns.exec_cmd(&[
            "ip",
            "addrlabel",
            "add",
            "prefix",
            "2001:db8:5::/64",
            "dev",
            "dummy0",
            "label",
            "42",
        ]);
        ns.assert_eq_output(&["addrlabel", "list"]);
        // iproute2 falls back to `if<index>` when the device is gone.
        ns.exec_cmd(&["ip", "link", "del", "dummy0"]);
        ns.assert_eq_output(&["addrlabel", "list"]);
        ns.assert_eq_output(&["-j", "addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_aliases() {
    with_addrlabels(|ns| {
        ns.assert_alias_output(&["addrlabel", "list"], &["addrl", "show"]);
        ns.assert_alias_output(&["addrlabel", "list"], &["addrlabel", "s"]);
        ns.assert_alias_output(&["addrlabel", "list"], &["addrla", "l"]);
    });
}

#[test]
fn test_addrlabel_add_without_label() {
    with_netns(|ns| {
        assert_ip_and_ip_rs_fail(
            ns,
            &["addrlabel", "add", "prefix", LABEL_PREFIX, "dev", "lo"],
        );
    });
}

#[test]
fn test_addrlabel_add_invalid_label() {
    with_netns(|ns| {
        assert_ip_and_ip_rs_fail(
            ns,
            &[
                "addrlabel",
                "add",
                "prefix",
                LABEL_PREFIX,
                "label",
                "0xffffffff",
            ],
        );
        assert_ip_and_ip_rs_fail(
            ns,
            &[
                "addrlabel",
                "add",
                "prefix",
                LABEL_PREFIX,
                "label",
                "notanumber",
            ],
        );
    });
}

#[test]
fn test_addrlabel_add_invalid_prefix() {
    with_netns(|ns| {
        assert_ip_and_ip_rs_fail(
            ns,
            &["addrlabel", "add", "prefix", "notanaddr", "label", "5"],
        );
        // The kernel only supports IPv6 address labels.
        assert_ip_and_ip_rs_fail(
            ns,
            &["addrlabel", "add", "prefix", "192.0.2.0/24", "label", "5"],
        );
    });
}

#[test]
fn test_addrlabel_add_invalid_dev() {
    with_netns(|ns| {
        assert_ip_and_ip_rs_fail(
            ns,
            &[
                "addrlabel",
                "add",
                "prefix",
                LABEL_PREFIX,
                "dev",
                "notexist",
                "label",
                "5",
            ],
        );
    });
}

#[test]
fn test_addrlabel_family_rejected() {
    with_netns(|ns| {
        assert_ip_and_ip_rs_fail(ns, &["-4", "addrlabel", "list"]);
        assert_ip_and_ip_rs_fail(ns, &["-0", "addrlabel", "list"]);
    });
}

#[test]
fn test_addrlabel_extra_args() {
    with_netns(|ns| {
        assert_ip_and_ip_rs_fail(ns, &["addrlabel", "show", "extra"]);
        assert_ip_and_ip_rs_fail(ns, &["addrlabel", "flush", "extra"]);
    });
}
