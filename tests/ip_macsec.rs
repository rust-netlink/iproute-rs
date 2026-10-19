// SPDX-License-Identifier: MIT

mod common;

use self::common::{NetnsGuard, with_netns};

const MACSEC_NAME: &str = "test-macsec";
const PEER_SCI: &str = "0ed1490827840009";
const KEY_ID: &str = "01";
const KEY: &str = "0102030405060708090a0b0c0d0e0f10";

fn with_macsec_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{MACSEC_NAME}");
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
            MACSEC_NAME,
            "type",
            "macsec",
        ];
        args.extend_from_slice(opts);
        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", MACSEC_NAME, "up"]);

        test(ns);
    });
}

fn assert_show(ns: &NetnsGuard) {
    // Stop the interface so IPv6 link-local traffic cannot advance the PN or
    // statistics between the two compared commands.
    ns.exec_cmd(&["ip", "link", "set", MACSEC_NAME, "down"]);
    ns.assert_eq_output(&["macsec", "show"]);
    ns.assert_eq_output(&["-j", "macsec", "show"]);
    ns.assert_eq_output(&["-s", "macsec", "show"]);
    ns.assert_eq_output(&["-j", "-s", "macsec", "show"]);
    ns.assert_eq_output(&["macsec", "show", MACSEC_NAME]);
}

#[test]
fn test_macsec_show_empty() {
    with_macsec_iface(&[], assert_show);
}

#[test]
fn test_macsec_add_tx_sa() {
    with_macsec_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "add",
            MACSEC_NAME,
            "tx",
            "sa",
            "0",
            "pn",
            "1",
            "on",
            "key",
            KEY_ID,
            KEY,
        ]);
        assert_show(ns);
    });
}

#[test]
fn test_macsec_add_rx_sc_and_sa() {
    with_macsec_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "add",
            MACSEC_NAME,
            "rx",
            "sci",
            PEER_SCI,
            "on",
        ]);
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "add",
            MACSEC_NAME,
            "rx",
            "sci",
            PEER_SCI,
            "sa",
            "0",
            "pn",
            "2",
            "on",
            "key",
            KEY_ID,
            KEY,
        ]);
        assert_show(ns);
    });
}

#[test]
fn test_macsec_add_xpn_sa() {
    with_macsec_iface(&["cipher", "gcm-aes-xpn-128"], |ns| {
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "add",
            MACSEC_NAME,
            "tx",
            "sa",
            "0",
            "xpn",
            "5",
            "salt",
            "0102030405060708090a0b0c",
            "ssci",
            "7",
            "on",
            "key",
            KEY_ID,
            KEY,
        ]);
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "add",
            MACSEC_NAME,
            "rx",
            "sci",
            PEER_SCI,
            "on",
        ]);
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "add",
            MACSEC_NAME,
            "rx",
            "sci",
            PEER_SCI,
            "sa",
            "0",
            "xpn",
            "8",
            "salt",
            "0102030405060708090a0b0c",
            "ssci",
            "9",
            "on",
            "key",
            KEY_ID,
            KEY,
        ]);
        assert_show(ns);
    });
}

#[test]
fn test_macsec_set_rx_sc_active() {
    with_macsec_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "add",
            MACSEC_NAME,
            "rx",
            "sci",
            PEER_SCI,
            "on",
        ]);
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "set",
            MACSEC_NAME,
            "rx",
            "sci",
            PEER_SCI,
            "off",
        ]);
        assert_show(ns);
    });
}

#[test]
fn test_macsec_delete_tx_sa() {
    with_macsec_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "add",
            MACSEC_NAME,
            "tx",
            "sa",
            "0",
            "pn",
            "1",
            "off",
            "key",
            KEY_ID,
            KEY,
        ]);
        ns.ip_rs_exec_cmd(&["macsec", "del", MACSEC_NAME, "tx", "sa", "0"]);
        assert_show(ns);
    });
}

#[test]
fn test_macsec_delete_rx_sc() {
    with_macsec_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "add",
            MACSEC_NAME,
            "rx",
            "sci",
            PEER_SCI,
            "off",
        ]);
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "del",
            MACSEC_NAME,
            "rx",
            "sci",
            PEER_SCI,
        ]);
        assert_show(ns);
    });
}

#[test]
fn test_macsec_offload_off() {
    with_macsec_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&["macsec", "offload", MACSEC_NAME, "off"]);
        assert_show(ns);
    });
}

#[test]
fn test_macsec_prefix_aliases() {
    with_macsec_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "a",
            MACSEC_NAME,
            "tx",
            "sa",
            "0",
            "pn",
            "1",
            "off",
            "key",
            KEY_ID,
            KEY,
        ]);
        ns.assert_eq_output(&["macsec", "s"]);
        ns.ip_rs_exec_cmd(&["macsec", "del", MACSEC_NAME, "tx", "sa", "0"]);
        ns.assert_eq_output(&["macsec", "sho"]);
    });
}

#[test]
fn test_macsec_help_and_unknown() {
    with_netns(|ns| {
        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&["ip", "macsec", "help"]);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&["macsec", "help"]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);

        let (expected_stderr, expected_code) =
            ns.exec_cmd_expect_failure(&["ip", "macsec", "bogus"]);
        let (stderr, code) =
            ns.ip_rs_exec_cmd_expect_failure_with_code(&["macsec", "bogus"]);
        pretty_assertions::assert_eq!(expected_stderr, stderr);
        assert_eq!(expected_code, code);
    });
}

#[test]
fn test_macsec_delete_one_of_multiple_tx_sa() {
    with_macsec_iface(&[], |ns| {
        for an in ["0", "1"] {
            ns.ip_rs_exec_cmd(&[
                "macsec",
                "add",
                MACSEC_NAME,
                "tx",
                "sa",
                an,
                "pn",
                "1",
                "off",
                "key",
                KEY_ID,
                KEY,
            ]);
        }
        ns.ip_rs_exec_cmd(&["macsec", "del", MACSEC_NAME, "tx", "sa", "0"]);
        assert_show(ns);
    });
}

#[test]
fn test_macsec_delete_one_rx_sa_keeps_other() {
    with_macsec_iface(&[], |ns| {
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "add",
            MACSEC_NAME,
            "rx",
            "sci",
            PEER_SCI,
            "off",
        ]);
        for an in ["0", "1"] {
            ns.ip_rs_exec_cmd(&[
                "macsec",
                "add",
                MACSEC_NAME,
                "rx",
                "sci",
                PEER_SCI,
                "sa",
                an,
                "pn",
                "1",
                "off",
                "key",
                KEY_ID,
                KEY,
            ]);
        }
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "del",
            MACSEC_NAME,
            "rx",
            "sci",
            PEER_SCI,
            "sa",
            "0",
        ]);
        assert_show(ns);
    });
}

#[test]
fn test_macsec_delete_one_of_multiple_rx_sc() {
    with_macsec_iface(&[], |ns| {
        for sci in [PEER_SCI, "0ed149082784000a"] {
            ns.ip_rs_exec_cmd(&[
                "macsec",
                "add",
                MACSEC_NAME,
                "rx",
                "sci",
                sci,
                "off",
            ]);
        }
        ns.ip_rs_exec_cmd(&[
            "macsec",
            "del",
            MACSEC_NAME,
            "rx",
            "sci",
            PEER_SCI,
        ]);
        assert_show(ns);
    });
}
