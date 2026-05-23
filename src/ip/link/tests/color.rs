// SPDX-License-Identifier: MIT

use crate::tests::with_netns;

const COLOR_CLEAR: &str = "\x1b[0m";

#[test]
fn test_ip_link_show_color_always() {
    with_netns(|ns| {
        let outputs = ns.assert_eq_output(&["-c=always", "link", "show", "lo"]);
        assert!(outputs.actual.contains(COLOR_CLEAR));
    });
}

#[test]
fn test_ip_link_show_color_auto_without_terminal() {
    with_netns(|ns| {
        let outputs = ns.assert_eq_output(&["-c=auto", "link", "show", "lo"]);
        assert!(!outputs.actual.contains(COLOR_CLEAR));
    });
}

#[test]
fn test_ip_link_show_color_never() {
    with_netns(|ns| {
        let outputs = ns.assert_eq_output(&["-c=never", "link", "show", "lo"]);
        assert!(!outputs.actual.contains(COLOR_CLEAR));
    });
}
