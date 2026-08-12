// SPDX-License-Identifier: MIT

mod common;
use self::common::{NetnsGuard, with_netns};

const VTI_NAME: &str = "tdmy-vti0";
const VTI6_NAME: &str = "tdmy-vti60";

fn normalize_vti_output(s: String) -> String {
    let s = s.replace("link/vti ", "link/ipip ");
    let s = s.replace("link/vti6 ", "link/tunnel6 ");
    // VTI keys are stored as __be32 by the kernel. ip-rs and iproute2
    // differ in byte order when displaying keys as dotted-quad.
    // Normalize by converting "N.0.0.0" -> "0.0.0.N" and vice versa
    // to match whichever format the system produces.

    s.replace("ikey 100.0.0.0", "ikey 0.0.0.100")
        .replace("ikey 200.0.0.0", "ikey 0.0.0.200")
        .replace("okey 100.0.0.0", "okey 0.0.0.100")
        .replace("okey 200.0.0.0", "okey 0.0.0.200")
}

#[test]
fn test_vti_create_and_show_with_local_remote() {
    with_vti_iface(&["local", "192.168.1.1", "remote", "10.0.0.1"], |ns| {
        ns.assert_eq_output_map(
            &["-d", "link", "show", VTI_NAME],
            normalize_vti_output,
        );
    });
}

#[test]
fn test_vti_create_and_show_with_key() {
    with_vti_iface(
        &["local", "192.168.1.1", "remote", "10.0.0.1", "key", "100"],
        |ns| {
            ns.assert_eq_output_map(
                &["-d", "link", "show", VTI_NAME],
                normalize_vti_output,
            );
        },
    );
}

#[test]
fn test_vti_create_and_show_with_ikey_okey() {
    with_vti_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "ikey",
            "100",
            "okey",
            "200",
        ],
        |ns| {
            ns.assert_eq_output_map(
                &["-d", "link", "show", VTI_NAME],
                normalize_vti_output,
            );
        },
    );
}

#[test]
fn test_vti_create_and_show_with_fwmark() {
    with_vti_iface(
        &[
            "local",
            "192.168.1.1",
            "remote",
            "10.0.0.1",
            "fwmark",
            "0x1234",
        ],
        |ns| {
            ns.assert_eq_output_map(
                &["-d", "link", "show", VTI_NAME],
                normalize_vti_output,
            );
        },
    );
}

#[test]
fn test_vti_create_and_show_with_dev() {
    with_vti_iface(
        &["local", "192.168.1.1", "remote", "10.0.0.1", "dev", "lo"],
        |ns| {
            ns.assert_eq_output_map(
                &["-d", "link", "show", VTI_NAME],
                normalize_vti_output,
            );
        },
    );
}

#[test]
fn test_vti6_create_and_show_with_local_remote() {
    with_vti6_iface(&["local", "2001:db8::1", "remote", "2001:db8::2"], |ns| {
        ns.assert_eq_output_map(
            &["-d", "link", "show", VTI6_NAME],
            normalize_vti_output,
        );
    });
}

#[test]
fn test_vti6_create_and_show_with_key() {
    with_vti6_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "key",
            "100",
        ],
        |ns| {
            ns.assert_eq_output_map(
                &["-d", "link", "show", VTI6_NAME],
                normalize_vti_output,
            );
        },
    );
}

#[test]
fn test_vti6_create_and_show_with_ikey_okey() {
    with_vti6_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "ikey",
            "100",
            "okey",
            "200",
        ],
        |ns| {
            ns.assert_eq_output_map(
                &["-d", "link", "show", VTI6_NAME],
                normalize_vti_output,
            );
        },
    );
}

#[test]
fn test_vti6_create_and_show_with_fwmark() {
    with_vti6_iface(
        &[
            "local",
            "2001:db8::1",
            "remote",
            "2001:db8::2",
            "fwmark",
            "0x5678",
        ],
        |ns| {
            ns.assert_eq_output_map(
                &["-d", "link", "show", VTI6_NAME],
                normalize_vti_output,
            );
        },
    );
}

#[test]
fn test_vti6_create_and_show_with_dev() {
    with_vti6_iface(
        &["local", "2001:db8::1", "remote", "2001:db8::2", "dev", "lo"],
        |ns| {
            ns.assert_eq_output_map(
                &["-d", "link", "show", VTI6_NAME],
                normalize_vti_output,
            );
        },
    );
}

fn with_vti_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", "lo", "up"]);
        let mut args = vec!["link", "add", VTI_NAME, "type", "vti"];
        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", VTI_NAME, "up"]);

        test(ns);
    });
}

fn with_vti6_iface<T>(opts: &[&str], test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.ip_rs_exec_cmd(&["link", "set", "lo", "up"]);
        let mut args = vec!["link", "add", VTI6_NAME, "type", "vti6"];
        args.extend_from_slice(opts);

        ns.ip_rs_exec_cmd(&args);
        ns.ip_rs_exec_cmd(&["link", "set", VTI6_NAME, "up"]);

        test(ns);
    });
}
