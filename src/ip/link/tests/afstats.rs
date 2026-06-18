use std::process::Command;

use crate::tests::with_netns;

const DEV_NAME: &str = "afst0";

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
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DEV_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "set", DEV_NAME, "up"]);
        ns.assert_eq_output(&["link", "afstats"]);
    });
}

#[test]
fn test_afstats_dev() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DEV_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "set", DEV_NAME, "up"]);
        ns.assert_eq_output(&["link", "afstats", "dev", DEV_NAME]);
    });
}

#[test]
fn test_afstats_json() {
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "add", DEV_NAME, "type", "dummy"]);
        ns.ip_rs_exec_cmd(&["link", "set", DEV_NAME, "up"]);
        ns.assert_eq_output(&["-j", "link", "afstats"]);
    });
}

#[test]
fn test_afstats_dev_nonexistent() {
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
