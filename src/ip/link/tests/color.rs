// SPDX-License-Identifier: MIT

use crate::tests::with_netns;

const COLOR_CLEAR: &str = "\x1b[0m";

#[test]
fn test_ip_link_show_color_always() {
    with_netns(|ns| {
        let expected_output =
            ns.exec_cmd(&["ip", "-c=always", "link", "show", "lo"]);
        let our_output =
            ns.ip_rs_exec_cmd(&["-c=always", "link", "show", "lo"]);

        assert!(our_output.contains(COLOR_CLEAR));
        assert_eq!(expected_output, our_output);
    });
}

#[test]
fn test_ip_link_show_color_auto_without_terminal() {
    with_netns(|ns| {
        let expected_output =
            ns.exec_cmd(&["ip", "-c=auto", "link", "show", "lo"]);
        let our_output = ns.ip_rs_exec_cmd(&["-c=auto", "link", "show", "lo"]);

        assert!(!our_output.contains(COLOR_CLEAR));
        assert_eq!(expected_output, our_output);
    });
}

#[test]
fn test_ip_link_show_color_never() {
    with_netns(|ns| {
        let expected_output =
            ns.exec_cmd(&["ip", "-c=never", "link", "show", "lo"]);
        let our_output = ns.ip_rs_exec_cmd(&["-c=never", "link", "show", "lo"]);

        assert!(!our_output.contains(COLOR_CLEAR));
        assert_eq!(expected_output, our_output);
    });
}
