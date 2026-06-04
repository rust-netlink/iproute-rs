// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const HSR_NAME: &str = "thsr";
const PORT1_NAME: &str = "thsr-p1";
const PORT2_NAME: &str = "thsr-p2";

/// Kernel maintains `hsr->sequence_nr` starting at `USHRT_MAX - 1024` (64511)
/// and increments it on every sent data or supervision frame (supervision
/// frames fire every 2 seconds). Between two `ip link show` calls the value
/// advances, making direct comparison flaky — we zero it out for testing.
fn normalize_seq(mut s: String) -> String {
    for target in [" sequence ", "\"seq_nr\":"] {
        let mut result = String::new();
        let mut remaining = s.as_str();
        while let Some(pos) = remaining.find(target) {
            result.push_str(&remaining[..=pos + target.len() - 1]);
            remaining = &remaining[pos + target.len()..];
            let num_len =
                remaining.chars().take_while(|c| c.is_ascii_digit()).count();
            result.push('0');
            remaining = &remaining[num_len..];
        }
        result.push_str(remaining);
        s = result;
    }
    s
}

#[test]
fn test_hsr_create_and_show_default() {
    with_hsr_iface(&[], |ns| {
        ns.assert_eq_output_map(
            &["-d", "link", "show", HSR_NAME],
            normalize_seq,
        );
    });
}

#[test]
fn test_hsr_create_and_show_with_options() {
    with_hsr_iface(&["supervision", "42", "version", "1"], |ns| {
        ns.assert_eq_output_map(
            &["-d", "link", "show", HSR_NAME],
            normalize_seq,
        );
    });
}

#[test]
fn test_hsr_create_and_show_json() {
    with_hsr_iface(&[], |ns| {
        ns.assert_eq_output_map(
            &["-d", "-j", "link", "show", HSR_NAME],
            normalize_seq,
        );
    });
}

fn with_hsr_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        // Create two dummy interfaces as slaves
        ns.exec_cmd(&["ip", "link", "add", PORT1_NAME, "type", "dummy"]);
        ns.exec_cmd(&["ip", "link", "add", PORT2_NAME, "type", "dummy"]);
        ns.exec_cmd(&["ip", "link", "set", PORT1_NAME, "up"]);
        ns.exec_cmd(&["ip", "link", "set", PORT2_NAME, "up"]);

        // Create HSR interface via ip-rs
        let mut args = vec![
            "link", "add", HSR_NAME, "type", "hsr", "slave1", PORT1_NAME,
            "slave2", PORT2_NAME,
        ];
        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.exec_cmd(&["ip", "link", "set", HSR_NAME, "up"]);

        test(ns);
    });
}
