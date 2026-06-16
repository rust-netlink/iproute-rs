// SPDX-License-Identifier: MIT

use std::process::Command;

use crate::tests::{NetnsGuard, with_netns};

const DUMMY_NAME: &str = "test-dummy-del";
const DUMMY_GROUP: u32 = 42;

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

fn with_dummy_iface_group<T>(test: T)
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
        ns.ip_rs_exec_cmd(&[
            "link",
            "set",
            DUMMY_NAME,
            "group",
            &DUMMY_GROUP.to_string(),
        ]);
        test(ns);
    });
}

fn link_exists(ns: &NetnsGuard) -> bool {
    let output = Command::new("ip")
        .args(["netns", "exec", &ns.name, "ip", "link", "show", DUMMY_NAME])
        .output()
        .expect("failed to execute command");
    output.status.success()
}

#[test]
fn test_link_del_dummy_bare() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "del", DUMMY_NAME]);
        assert!(!link_exists(ns), "Device should have been deleted");
    });
}

#[test]
fn test_link_del_dummy_dev() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "del", "dev", DUMMY_NAME]);
        assert!(!link_exists(ns), "Device should have been deleted");
    });
}

#[test]
fn test_link_del_dummy_with_type() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "del", DUMMY_NAME, "type", "dummy"]);
        assert!(!link_exists(ns), "Device should have been deleted");
    });
}

#[test]
fn test_link_del_dummy_dev_with_type() {
    with_dummy_iface(|ns| {
        ns.ip_rs_exec_cmd(&["link", "del", "dev", DUMMY_NAME, "type", "dummy"]);
        assert!(!link_exists(ns), "Device should have been deleted");
    });
}

#[test]
fn test_link_del_by_group() {
    with_dummy_iface_group(|ns| {
        ns.ip_rs_exec_cmd(&["link", "del", "group", &DUMMY_GROUP.to_string()]);
        assert!(!link_exists(ns), "Device should have been deleted");
    });
}

#[test]
fn test_link_del_nonexistent() {
    with_netns(|ns| {
        let output = Command::new("ip")
            .args([
                "netns",
                "exec",
                &ns.name,
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("ip-rs")
                    .to_str()
                    .unwrap(),
                "link",
                "del",
                "nonexistent-device",
            ])
            .output()
            .expect("failed to execute command");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("does not exist"));
    });
}
