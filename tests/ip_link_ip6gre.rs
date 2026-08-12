// SPDX-License-Identifier: MIT

use std::process::Command;

mod common;
use self::common::{NetnsGuard, with_netns};

const IP6GRE_NAME: &str = "test-ip6gre";
const IP6GRETAP_NAME: &str = "test-ip6gretap";

#[test]
fn test_link_show_ip6gre() {
    with_ip6gre_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", IP6GRE_NAME]);
    });
}

#[test]
fn test_link_detailed_show_ip6gre() {
    with_ip6gre_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", IP6GRE_NAME]);
    });
}

#[test]
fn test_ip6gre_hoplimit_inherit() {
    with_ip6gre_iface(&["hoplimit", "inherit"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IP6GRE_NAME]);
        assert!(outputs.expected.contains("hoplimit inherit"));
    });
}

#[test]
fn test_ip6gre_hoplimit_64() {
    with_ip6gre_iface(&["hoplimit", "64"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IP6GRE_NAME]);
        assert!(outputs.expected.contains("hoplimit 64"));
    });
}

#[test]
fn test_ip6gre_encaplimit() {
    with_ip6gre_iface(&["encaplimit", "4"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IP6GRE_NAME]);
        assert!(outputs.expected.contains("encaplimit 4"));
    });
}

#[test]
fn test_ip6gre_tclass() {
    with_ip6gre_iface(&["tclass", "0x10"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IP6GRE_NAME]);
        assert!(outputs.expected.contains("tclass 0x10"));
    });
}

#[test]
fn test_ip6gre_flowlabel() {
    with_ip6gre_iface(&["flowlabel", "0x12345"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IP6GRE_NAME]);
        assert!(outputs.expected.contains("flowlabel 0x12345"));
    });
}

#[test]
fn test_ip6gre_key() {
    with_ip6gre_iface(&["key", "42"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IP6GRE_NAME]);
        assert!(outputs.expected.contains("ikey 0.0.0.42"));
        assert!(outputs.expected.contains("okey 0.0.0.42"));
    });
}

#[test]
fn test_ip6gre_fwmark() {
    with_ip6gre_iface(&["fwmark", "0x1234"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IP6GRE_NAME]);
        assert!(outputs.expected.contains("fwmark 0x1234"));
    });
}

#[test]
fn test_ip6gre_seq() {
    with_ip6gre_iface(&["seq"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IP6GRE_NAME]);
        assert!(outputs.expected.contains("iseq"));
        assert!(outputs.expected.contains("oseq"));
    });
}

#[test]
fn test_ip6gre_csum() {
    with_ip6gre_iface(&["csum"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", IP6GRE_NAME]);
        assert!(outputs.expected.contains("icsum"));
        assert!(outputs.expected.contains("ocsum"));
    });
}

#[test]
fn test_link_show_ip6gretap() {
    with_ip6gretap_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", IP6GRETAP_NAME]);
    });
}

#[test]
fn test_link_detailed_show_ip6gretap() {
    with_ip6gretap_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", IP6GRETAP_NAME]);
    });
}

#[test]
fn test_ip6gretap_hoplimit_inherit() {
    with_ip6gretap_iface(&["hoplimit", "inherit"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", IP6GRETAP_NAME]);
        assert!(outputs.expected.contains("hoplimit inherit"));
    });
}

#[test]
fn test_ip6gretap_hoplimit_64() {
    with_ip6gretap_iface(&["hoplimit", "64"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", IP6GRETAP_NAME]);
        assert!(outputs.expected.contains("hoplimit 64"));
    });
}

#[test]
fn test_ip6gretap_encaplimit() {
    with_ip6gretap_iface(&["encaplimit", "4"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", IP6GRETAP_NAME]);
        assert!(outputs.expected.contains("encaplimit 4"));
    });
}

#[test]
fn test_ip6gretap_tclass() {
    with_ip6gretap_iface(&["tclass", "0x10"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", IP6GRETAP_NAME]);
        assert!(outputs.expected.contains("tclass 0x10"));
    });
}

#[test]
fn test_ip6gretap_flowlabel() {
    with_ip6gretap_iface(&["flowlabel", "0x12345"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", IP6GRETAP_NAME]);
        assert!(outputs.expected.contains("flowlabel 0x12345"));
    });
}

#[test]
fn test_ip6gretap_key() {
    with_ip6gretap_iface(&["key", "42"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", IP6GRETAP_NAME]);
        assert!(outputs.expected.contains("ikey 0.0.0.42"));
        assert!(outputs.expected.contains("okey 0.0.0.42"));
    });
}

#[test]
fn test_ip6gretap_fwmark() {
    with_ip6gretap_iface(&["fwmark", "0x1234"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", IP6GRETAP_NAME]);
        assert!(outputs.expected.contains("fwmark 0x1234"));
    });
}

#[test]
fn test_ip6gretap_seq() {
    with_ip6gretap_iface(&["seq"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", IP6GRETAP_NAME]);
        assert!(outputs.expected.contains("iseq"));
        assert!(outputs.expected.contains("oseq"));
    });
}

#[test]
fn test_ip6gretap_csum() {
    with_ip6gretap_iface(&["csum"], |ns| {
        let outputs =
            ns.assert_eq_output(&["-d", "link", "show", IP6GRETAP_NAME]);
        assert!(outputs.expected.contains("icsum"));
        assert!(outputs.expected.contains("ocsum"));
    });
}

// --- Set tests ---

#[test]
fn test_set_ip6gre_mtu() {
    with_ip6gre_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&["link", "set", IP6GRE_NAME, "mtu", "1400"]);
        ns.assert_eq_output(&["link", "show", IP6GRE_NAME]);
    });
}

#[test]
fn test_set_ip6gre_address_eopnotsupp() {
    with_ip6gre_iface(&[], |ns| {
        let mut full_args = vec!["netns", "exec", &ns.name, "ip"];
        full_args.extend_from_slice(&[
            "link",
            "set",
            IP6GRE_NAME,
            "address",
            "00:11:22:33:44:55",
        ]);
        let ip_output = std::process::Command::new("ip")
            .args(&full_args)
            .output()
            .expect("failed to run ip command");
        let ip_stderr = String::from_utf8_lossy(&ip_output.stderr).to_string();
        let ip_code = ip_output.status.code();

        let (_rs_stdout, rs_stderr, rs_code) = run_ip_rs_cmd_in_ns(
            ns,
            &["link", "set", IP6GRE_NAME, "address", "00:11:22:33:44:55"],
        );

        assert!(
            ip_code.is_some() && ip_code.unwrap() > 0,
            "ip should exit non-zero: {ip_code:?} stderr: {ip_stderr}"
        );
        assert!(
            rs_code.is_some() && rs_code.unwrap() > 0,
            "ip-rs should exit non-zero: {rs_code:?} stderr: {rs_stderr}"
        );
        assert!(!ip_stderr.is_empty(), "ip stderr should not be empty");
        assert!(!rs_stderr.is_empty(), "ip-rs stderr should not be empty");
    });
}

#[test]
fn test_set_ip6gretap_mtu() {
    with_ip6gretap_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&["link", "set", IP6GRETAP_NAME, "mtu", "1400"]);
        ns.assert_eq_output(&["link", "show", IP6GRETAP_NAME]);
    });
}

#[test]
fn test_set_ip6gretap_address() {
    with_ip6gretap_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            IP6GRETAP_NAME,
            "address",
            "00:11:22:33:44:55",
        ]);
        ns.assert_eq_output(&["link", "show", IP6GRETAP_NAME]);
    });
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

fn with_ip6gre_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{IP6GRE_NAME}");

        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            &parent_name,
            "address",
            "0e:d1:49:08:27:84",
            "type",
            "dummy",
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", &parent_name, "up"]);

        let mut args = vec![
            "link",
            "add",
            "link",
            &parent_name,
            "name",
            IP6GRE_NAME,
            "type",
            "ip6gre",
            "remote",
            "2001:db8::1",
        ];

        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", IP6GRE_NAME, "up"]);

        test(ns);
    });
}

fn with_ip6gretap_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{IP6GRETAP_NAME}");

        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            &parent_name,
            "address",
            "0e:d1:49:08:27:84",
            "type",
            "dummy",
        ]);
        ns.ip_rs_exec_cmd(&["link", "set", &parent_name, "up"]);

        let mut args = vec![
            "link",
            "add",
            "link",
            &parent_name,
            "name",
            IP6GRETAP_NAME,
            "type",
            "ip6gretap",
            "remote",
            "2001:db8::1",
        ];

        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", IP6GRETAP_NAME, "up"]);

        test(ns);
    });
}
