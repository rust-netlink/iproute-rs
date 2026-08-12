// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const GENEVE_NAME: &str = "test-geneve";

#[test]
fn test_link_show_geneve() {
    with_geneve_iface(&[], |ns| {
        ns.assert_eq_output(&["link", "show", GENEVE_NAME]);
    });
}

#[test]
fn test_link_detailed_show_geneve() {
    with_geneve_iface(&[], |ns| {
        ns.assert_eq_output(&["-d", "link", "show", GENEVE_NAME]);
    });
}

#[test]
fn test_geneve_ttl_inherit() {
    with_geneve_iface(&["ttl", "inherit"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", GENEVE_NAME]);
        assert!(outputs.expected.contains("ttl inherit"));
    });
}

#[test]
fn test_geneve_tos_inherit() {
    with_geneve_iface(&["tos", "inherit"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", GENEVE_NAME]);
        assert!(outputs.expected.contains("tos inherit"));
    });
}

#[test]
fn test_geneve_df_set() {
    with_geneve_iface(&["df", "set"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", GENEVE_NAME]);
        assert!(outputs.expected.contains("df set"));
    });
}

#[test]
fn test_geneve_df_inherit() {
    with_geneve_iface(&["df", "inherit"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", GENEVE_NAME]);
        assert!(outputs.expected.contains("df inherit"));
    });
}

#[test]
fn test_geneve_udpcsum_off() {
    with_geneve_iface(&["noudpcsum"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", GENEVE_NAME]);
        assert!(outputs.expected.contains("noudpcsum"));
    });
}

#[test]
fn test_geneve_udp6zerocsumtx() {
    with_geneve_iface(&["udp6zerocsumtx"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", GENEVE_NAME]);
        assert!(outputs.expected.contains("udp6zerocsumtx"));
    });
}

#[test]
fn test_geneve_dstport() {
    with_geneve_iface(&["dstport", "6081"], |ns| {
        let outputs = ns.assert_eq_output(&["-d", "link", "show", GENEVE_NAME]);
        assert!(outputs.expected.contains("dstport 6081"));
    });
}

fn with_geneve_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        let parent_name = format!("p{GENEVE_NAME}");

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
        ns.ip_rs_exec_cmd(&["link", "set", &parent_name, "up"]);

        // Use IPv6 remote when testing udp6zerocsumtx (kernel only sends
        // IFLA_GENEVE_UDP_ZERO_CSUM6_TX for IPv6 tunnels)
        let remote = if opts.contains(&"udp6zerocsumtx")
            || opts.contains(&"noudp6zerocsumtx")
        {
            "::1"
        } else {
            "10.0.0.1"
        };

        let mut args = vec![
            "link",
            "add",
            "link",
            &parent_name,
            "name",
            GENEVE_NAME,
            "type",
            "geneve",
            "id",
            "100",
            "remote",
            remote,
        ];

        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", GENEVE_NAME, "up"]);

        test(ns);
    });
}
