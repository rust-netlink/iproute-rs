use std::process::Command;

use crate::tests::{NetnsGuard, with_netns};

const DEV_NAME: &str = "afst0";

fn load_mpls_module() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let status = Command::new("modprobe")
            .args(["mpls_router"])
            .status()
            .expect("failed to run modprobe");
        if !status.success() {
            panic!("mpls_router kernel module not available");
        }
    });
}

fn with_dummy_iface<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    load_mpls_module();
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DEV_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "set", DEV_NAME, "up"]);
        test(ns);
    });
}

fn ip_rs_path() -> String {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("ip-rs")
        .to_str()
        .unwrap()
        .to_string()
}

#[test]
fn test_afstats() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["link", "afstats"]);
    });
}

#[test]
fn test_afstats_dev() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["link", "afstats", "dev", DEV_NAME]);
    });
}

#[test]
fn test_afstats_json() {
    with_dummy_iface(|ns| {
        ns.assert_eq_output(&["-j", "link", "afstats"]);
    });
}

#[test]
fn test_afstats_dev_nonexistent() {
    load_mpls_module();
    with_netns(|ns| {
        let output = Command::new("ip")
            .args([
                "netns",
                "exec",
                &ns.name,
                &ip_rs_path(),
                "link",
                "afstats",
                "dev",
                "nonexistent0",
            ])
            .output()
            .expect("failed to execute command");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("does not exist"));
    });
}
