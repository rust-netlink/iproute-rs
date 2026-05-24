// SPDX-License-Identifier: MIT

use crate::tests::{exec_cmd, ip_rs_exec_cmd};

#[test]
fn test_link_show_nlmon() {
    let ifname = "tnlm0";

    with_nlmon_iface(ifname, || {
        let expected_output = exec_cmd(&["ip", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

#[test]
fn test_link_detailed_show_nlmon() {
    let ifname = "tnlm1";

    with_nlmon_iface(ifname, || {
        let expected_output = exec_cmd(&["ip", "-d", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["-d", "link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

#[test]
fn test_link_show_nlmon_json() {
    let ifname = "tnlm2";

    with_nlmon_iface(ifname, || {
        let expected_output = exec_cmd(&["ip", "-j", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["-j", "link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

#[test]
fn test_link_detailed_show_nlmon_json() {
    let ifname = "tnlm3";

    with_nlmon_iface(ifname, || {
        let expected_output =
            exec_cmd(&["ip", "-d", "-j", "link", "show", ifname]);

        let our_output = ip_rs_exec_cmd(&["-d", "-j", "link", "show", ifname]);

        pretty_assertions::assert_eq!(expected_output, our_output);
    })
}

fn with_nlmon_iface<T>(name: &str, test: T)
where
    T: FnOnce() + std::panic::UnwindSafe,
{
    ip_rs_exec_cmd(&["link", "add", name, "type", "nlmon"]);
    exec_cmd(&["ip", "link", "set", name, "up"]);

    let result = std::panic::catch_unwind(|| {
        test();
    });

    // clean up
    let _ = exec_cmd(&["ip", "link", "del", name]);

    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
