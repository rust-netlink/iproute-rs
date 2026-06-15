// SPDX-License-Identifier: MIT

use crate::tests::{NetnsGuard, with_netns};

const MACSEC_NAME: &str = "test-macsec";

#[test]
fn test_link_show_macsec() {
    with_macsec_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", MACSEC_NAME]);
    });
}

#[test]
fn test_link_detailed_show_macsec() {
    with_macsec_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", MACSEC_NAME]);
    });
}

#[test]
fn test_macsec_cipher() {
    with_macsec_iface(&["cipher", "gcm-aes-256"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", MACSEC_NAME]);
        assert!(outputs.expected.contains("cipher GCM-AES-256"));
    });
}

#[test]
fn test_macsec_protect_off() {
    with_macsec_iface(&["protect", "off"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", MACSEC_NAME]);
        assert!(outputs.expected.contains("protect off"));
    });
}

#[test]
fn test_macsec_encrypt_off() {
    with_macsec_iface(&["encrypt", "off"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", MACSEC_NAME]);
        assert!(outputs.expected.contains("encrypt off"));
    });
}

#[test]
fn test_macsec_send_sci_off() {
    with_macsec_iface(&["send_sci", "off"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", MACSEC_NAME]);
        assert!(outputs.expected.contains("send_sci off"));
    });
}

#[test]
fn test_macsec_end_station_on() {
    with_macsec_iface(&["end_station", "on"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", MACSEC_NAME]);
        assert!(outputs.expected.contains("end_station on"));
    });
}

#[test]
fn test_macsec_scb_on() {
    with_macsec_iface(&["scb", "on"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", MACSEC_NAME]);
        assert!(outputs.expected.contains("scb on"));
    });
}

#[test]
fn test_macsec_validate_check() {
    with_macsec_iface(&["validate", "check"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", MACSEC_NAME]);
        assert!(outputs.expected.contains("validate check"));
    });
}

#[test]
fn test_macsec_validate_strict() {
    with_macsec_iface(&["validate", "strict"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", MACSEC_NAME]);
        assert!(outputs.expected.contains("validate strict"));
    });
}

#[test]
fn test_macsec_encoding_sa() {
    with_macsec_iface(&["encodingsa", "2"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", MACSEC_NAME]);
        assert!(outputs.expected.contains("encodingsa 2"));
    });
}

#[test]
fn test_macsec_replay_on() {
    with_macsec_iface(&["replay", "on", "window", "100"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", MACSEC_NAME]);
        assert!(outputs.expected.contains("replay on"));
        assert!(outputs.expected.contains("window 100"));
    });
}

fn with_macsec_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{MACSEC_NAME}");

        // create parent dummy interface using ip-rs
        ns.ip_rs_exec_cmd(&[
            "link",
            "add",
            &parent_name,
            "address",
            "0e:d1:49:08:27:84",
            "type",
            "dummy",
        ]);
        ns.exec_cmd(&["ip", "link", "set", &parent_name, "up"]);

        let mut args = vec![
            "link",
            "add",
            "link",
            &parent_name,
            "name",
            MACSEC_NAME,
            "type",
            "macsec",
        ];

        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.exec_cmd(&["ip", "link", "set", MACSEC_NAME, "up"]);

        test(ns);
    });
}
