// SPDX-License-Identifier: MIT

use std::process::Command;

mod common;
use self::common::{NetnsGuard, with_netns};

const GTP_NAME: &str = "gtp0";

fn run_ip_cmd_in_ns(
    ns: &NetnsGuard,
    args: &[&str],
) -> (String, String, Option<i32>) {
    let mut full_args = vec!["netns", "exec", &ns.name, "ip"];
    full_args.extend_from_slice(args);
    let output = Command::new("ip")
        .args(&full_args)
        .output()
        .expect("failed to run ip command");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code(),
    )
}

fn run_ip_rs_cmd_in_ns(
    ns: &NetnsGuard,
    args: &[&str],
) -> (String, String, Option<i32>) {
    let ip_rs = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("ip-rs");
    let mut full_args = vec!["netns", "exec", &ns.name];
    full_args.push(ip_rs.to_str().unwrap());
    full_args.extend_from_slice(args);
    let output = Command::new("ip")
        .args(&full_args)
        .output()
        .expect("failed to run ip-rs command");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code(),
    )
}

#[test]
fn test_link_add_gtp_basic() {
    with_gtp_iface(&["role", "sgsn"], |ns| {
        ns.assert_eq_output(&["link", "show", GTP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_gtp_basic() {
    with_gtp_iface(&["role", "sgsn"], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", GTP_NAME]);
    });
}

#[test]
fn test_link_show_gtp_basic_json() {
    with_gtp_iface(&["role", "sgsn"], |ns| {
        ns.assert_eq_output(&["-j", "link", "show", GTP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_gtp_basic_json() {
    with_gtp_iface(&["role", "sgsn"], |ns| {
        ns.assert_eq_output(&["-d", "-j", "link", "show", GTP_NAME]);
    });
}

#[test]
fn test_link_add_gtp_full() {
    with_gtp_iface(
        &["role", "ggsn", "hsize", "2048", "restart_count", "5"],
        |ns| {
            ns.assert_eq_output(&["link", "show", GTP_NAME]);
        },
    );
}

#[test]
fn test_link_detailed_show_gtp_full() {
    with_gtp_iface(
        &["role", "ggsn", "hsize", "2048", "restart_count", "5"],
        |ns| {
            ns.assert_eq_output(&["-d", "link", "show", GTP_NAME]);
        },
    );
}

#[test]
fn test_link_show_gtp_full_json() {
    with_gtp_iface(
        &["role", "ggsn", "hsize", "2048", "restart_count", "5"],
        |ns| {
            ns.assert_eq_output(&["-j", "link", "show", GTP_NAME]);
        },
    );
}

#[test]
fn test_link_detailed_show_gtp_full_json() {
    with_gtp_iface(
        &["role", "ggsn", "hsize", "2048", "restart_count", "5"],
        |ns| {
            ns.assert_eq_output(&["-d", "-j", "link", "show", GTP_NAME]);
        },
    );
}

#[test]
fn test_link_set_gtp_eopnotsupp() {
    let gtp_set_name = "gtp-eopnotsupp";
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            gtp_set_name,
            "type",
            "gtp",
            "role",
            "sgsn",
        ]);

        let (_ip_stdout, ip_stderr, ip_code) = run_ip_cmd_in_ns(
            ns,
            &["link", "set", gtp_set_name, "type", "gtp", "role", "ggsn"],
        );
        let (_rs_stdout, rs_stderr, rs_code) = run_ip_rs_cmd_in_ns(
            ns,
            &["link", "set", gtp_set_name, "type", "gtp", "role", "ggsn"],
        );

        assert_eq!(ip_code, Some(2), "ip should exit 2: {ip_stderr}");
        assert_eq!(rs_code, Some(2), "ip-rs should exit 2: {rs_stderr}");
        assert!(
            ip_stderr.contains("Operation not supported"),
            "ip stderr: {ip_stderr}"
        );
        assert!(
            rs_stderr.contains("Operation not supported"),
            "ip-rs stderr: {rs_stderr}"
        );
    });
}

fn with_gtp_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let mut args = vec!["link", "add", GTP_NAME, "type", "gtp"];
        args.extend_from_slice(opts);
        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", GTP_NAME, "up"]);

        test(ns);
    });
}
