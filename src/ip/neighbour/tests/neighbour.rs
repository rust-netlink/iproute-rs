// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rtnetlink::packet_route::neighbour::NeighbourState;

use crate::tests::{NetnsGuard, with_netns};

#[test]
fn test_neighbour_show() {
    let neigh_address1 = Ipv4Addr::new(10, 0, 0, 1).into();
    let neigh_address2 = Ipv4Addr::new(10, 0, 0, 2).into();
    let neigh_address3 = Ipv6Addr::from_bits(0x3000u128).into();
    let lladdr = "AA:AA:AA:AA:AA:AA";

    with_tap_netns(|ns| {
        add_neighbour(
            ns,
            neigh_address1,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        add_neighbour(
            ns,
            neigh_address2,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        add_neighbour(
            ns,
            neigh_address3,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        let expected_output = ns.exec_cmd(&["ip", "neigh", "show"]);
        let our_output = ns.ip_rs_exec_cmd(&["neigh", "show"]);

        trimmed_assert_eq(&expected_output, &our_output);
    });
}

#[test]
fn test_neighbour_show_json() {
    let neigh_address1 = Ipv4Addr::new(10, 0, 0, 1).into();
    let neigh_address2 = Ipv4Addr::new(10, 0, 0, 2).into();
    let neigh_address3 = Ipv6Addr::from_bits(0x3000u128).into();
    let lladdr = "AA:AA:AA:AA:AA:AA";

    with_tap_netns(|ns| {
        add_neighbour(
            ns,
            neigh_address1,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        add_neighbour(
            ns,
            neigh_address2,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        add_neighbour(
            ns,
            neigh_address3,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        let expected_output = ns.exec_cmd(&["ip", "-j", "neigh", "show"]);
        let our_output = ns.ip_rs_exec_cmd(&["-j", "neigh", "show"]);

        trimmed_assert_eq(&expected_output, &our_output);
    });
}

#[test]
fn test_neighbour_show_to() {
    let neigh_address1 = Ipv4Addr::new(10, 0, 0, 1).into();
    let neigh_address2 = Ipv4Addr::new(10, 0, 0, 2).into();
    let lladdr = "AA:AA:AA:AA:AA:AA";

    with_tap_netns(|ns| {
        add_neighbour(
            ns,
            neigh_address1,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        add_neighbour(
            ns,
            neigh_address2,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        // Implicit "to" parameter
        let expected_output =
            ns.exec_cmd(&["ip", "neigh", "show", &neigh_address1.to_string()]);
        let our_output =
            ns.ip_rs_exec_cmd(&["neigh", "show", &neigh_address1.to_string()]);

        trimmed_assert_eq(&expected_output, &our_output);

        // Explicit "to" parameter
        let expected_output = ns.exec_cmd(&[
            "ip",
            "neigh",
            "show",
            "to",
            &neigh_address1.to_string(),
        ]);
        let our_output = ns.ip_rs_exec_cmd(&[
            "neigh",
            "show",
            "to",
            &neigh_address1.to_string(),
        ]);

        trimmed_assert_eq(&expected_output, &our_output);
    });
}

#[test]
fn test_neighbour_show_nud() {
    let neigh_address1 = Ipv4Addr::new(10, 0, 0, 1).into();
    let neigh_address2 = Ipv4Addr::new(10, 0, 0, 2).into();
    let neigh_address3 = Ipv4Addr::new(10, 0, 0, 3).into();
    let neigh_address4 = Ipv4Addr::new(10, 0, 0, 4).into();
    let lladdr = "AA:AA:AA:AA:AA:AA";

    with_tap_netns(|ns| {
        add_neighbour(
            ns,
            neigh_address1,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        add_neighbour(ns, neigh_address2, NeighbourState::Stale, Some(lladdr));
        add_neighbour(ns, neigh_address3, NeighbourState::Noarp, Some(lladdr));
        add_neighbour(ns, neigh_address4, NeighbourState::None, Some(lladdr));

        // First, make sure that by default we don't show none/noarp neighs
        let expected_output = ns.exec_cmd(&["ip", "neigh", "show"]);
        let our_output = ns.ip_rs_exec_cmd(&["neigh", "show"]);

        trimmed_assert_eq(&expected_output, &our_output);

        // Then, ask for them explictly
        let expected_output =
            ns.exec_cmd(&["ip", "neigh", "show", "nud", "none"]);
        let our_output = ns.ip_rs_exec_cmd(&["neigh", "show", "nud", "none"]);
        trimmed_assert_eq(&expected_output, &our_output);

        let expected_output =
            ns.exec_cmd(&["ip", "neigh", "show", "nud", "noarp"]);
        let our_output = ns.ip_rs_exec_cmd(&["neigh", "show", "nud", "noarp"]);
        trimmed_assert_eq(&expected_output, &our_output);
    });
}

#[test]
fn test_neighbour_show_dev() {
    let tap0_neigh = Ipv4Addr::new(10, 0, 0, 1).into();
    let tap1_neigh = Ipv4Addr::new(10, 0, 1, 1).into();
    let lladdr = "AA:AA:AA:AA:AA:AA";

    with_multi_dev_netns(|ns| {
        add_neighbour_on(
            ns,
            "tap0",
            tap0_neigh,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        add_neighbour_on(
            ns,
            "tap1",
            tap1_neigh,
            NeighbourState::Reachable,
            Some(lladdr),
        );

        // `dev` selects neighbours on a single interface.
        let expected_output =
            ns.exec_cmd(&["ip", "neigh", "show", "dev", "tap0"]);
        let our_output = ns.ip_rs_exec_cmd(&["neigh", "show", "dev", "tap0"]);
        trimmed_assert_eq(&expected_output, &our_output);

        // `vrf` selects neighbours whose interface is enslaved to the VRF
        // (only `tap0` is a member of `tvrf`).
        let expected_output =
            ns.exec_cmd(&["ip", "neigh", "show", "vrf", "tvrf"]);
        let our_output = ns.ip_rs_exec_cmd(&["neigh", "show", "vrf", "tvrf"]);
        trimmed_assert_eq(&expected_output, &our_output);

        // `nomaster` selects neighbours whose interface has no controller
        // (only `tap1` is unenslaved).
        let expected_output = ns.exec_cmd(&["ip", "neigh", "show", "nomaster"]);
        let our_output = ns.ip_rs_exec_cmd(&["neigh", "show", "nomaster"]);
        trimmed_assert_eq(&expected_output, &our_output);
    });
}

#[test]
fn test_neighbour_show_unused() {
    let neigh_address1 = Ipv4Addr::new(10, 0, 0, 1).into();
    let neigh_address2 = Ipv4Addr::new(10, 0, 0, 2).into();
    let lladdr = "AA:AA:AA:AA:AA:AA";

    with_tap_netns(|ns| {
        add_neighbour(
            ns,
            neigh_address1,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        add_neighbour(
            ns,
            neigh_address2,
            NeighbourState::Reachable,
            Some(lladdr),
        );

        // Freshly-added static neighbours are unreferenced (refcnt == 0),
        // so `unused` must list all of them.
        let expected_output = ns.exec_cmd(&["ip", "neigh", "show", "unused"]);
        let our_output = ns.ip_rs_exec_cmd(&["neigh", "show", "unused"]);
        trimmed_assert_eq(&expected_output, &our_output);
    });
}

#[test]
fn test_neighbour_show_proxy() {
    let normal_address = Ipv4Addr::new(10, 0, 0, 1).into();
    let proxy_address = Ipv4Addr::new(10, 0, 0, 5).to_string();
    let lladdr = "AA:AA:AA:AA:AA:AA";

    with_tap_netns(|ns| {
        add_neighbour(
            ns,
            normal_address,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        ns.exec_cmd(&[
            "ip",
            "neigh",
            "add",
            "proxy",
            &proxy_address,
            "dev",
            "tap0",
        ]);

        let expected_output = ns.exec_cmd(&["ip", "neigh", "show", "proxy"]);
        let our_output = ns.ip_rs_exec_cmd(&["neigh", "show", "proxy"]);
        trimmed_assert_eq(&expected_output, &our_output);
    });
}

#[test]
fn test_neighbour_show_statistics() {
    let neigh_address1 = Ipv4Addr::new(10, 0, 0, 1).into();
    let neigh_address2 = Ipv4Addr::new(10, 0, 0, 2).into();
    let lladdr = "AA:AA:AA:AA:AA:AA";

    with_tap_netns(|ns| {
        add_neighbour(
            ns,
            neigh_address1,
            NeighbourState::Reachable,
            Some(lladdr),
        );
        add_neighbour(
            ns,
            neigh_address2,
            NeighbourState::Reachable,
            Some(lladdr),
        );

        // The `used a/b/c` counters are time-derived and drift between the two
        // `show` invocations, so normalize them to zero before comparing.
        let expected_output =
            normalize_stats(ns.exec_cmd(&["ip", "-s", "neigh", "show"]));
        let our_output =
            normalize_stats(ns.ip_rs_exec_cmd(&["-s", "neigh", "show"]));

        trimmed_assert_eq(&expected_output, &our_output);
    });
}

/// Runs the test body in a dedicated disposable network-namespace
/// containing a single tap-device `tap0` we can attach neighbours to.
fn with_tap_netns<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "tuntap", "add", "mode", "tap", "name", "tap0"]);

        test(ns);
    });
}

/// Runs the test body in a disposable network-namespace containing two
/// tap-devices, `tap0` and `tap1`, where `tap0` is enslaved to a VRF `tvrf`
/// and `tap1` has no master.
fn with_multi_dev_netns<T>(test: T)
where
    T: FnOnce(&NetnsGuard),
{
    with_netns(|ns| {
        ns.exec_cmd(&["ip", "tuntap", "add", "mode", "tap", "name", "tap0"]);
        ns.exec_cmd(&["ip", "tuntap", "add", "mode", "tap", "name", "tap1"]);
        ns.exec_cmd(&[
            "ip", "link", "add", "tvrf", "type", "vrf", "table", "10",
        ]);
        ns.exec_cmd(&["ip", "link", "set", "tap0", "master", "tvrf"]);

        test(ns);
    });
}

fn add_neighbour(
    ns: &NetnsGuard,
    neigh_address: IpAddr,
    nud: NeighbourState,
    lladdr: Option<&str>,
) {
    add_neighbour_on(ns, "tap0", neigh_address, nud, lladdr);
}

fn add_neighbour_on(
    ns: &NetnsGuard,
    dev: &str,
    neigh_address: IpAddr,
    nud: NeighbourState,
    lladdr: Option<&str>,
) {
    let neigh_address = neigh_address.to_string();
    let nud = nud.to_string();
    let mut cmd = vec![
        "ip",
        "neigh",
        "add",
        "dev",
        dev,
        &neigh_address,
        "nud",
        &nud,
    ];
    if let Some(lladdr) = lladdr {
        cmd.extend(["lladdr", lladdr]);
    }
    ns.exec_cmd(&cmd);
}

fn normalize_stats(output: String) -> String {
    const MARKER: &str = "used ";

    let mut result = String::new();
    let mut remaining = output.as_str();

    if let Some(pos) = remaining.find(MARKER) {
        result.push_str(&remaining[..pos]);
        result.push_str(MARKER);
        remaining = &remaining[pos + MARKER.len()..];

        // Skip the `a/b/c` value (digits and slashes), replacing it with zeros.
        let value_len = remaining
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '/')
            .count();
        result.push_str("0/0/0");
        remaining = &remaining[value_len..];
    }
    result.push_str(remaining);

    result
}

/// Asserts textual outputs of us and iproute2 are equal,
/// normalizing iproute2 output to remove trailing whitespace.
#[track_caller]
fn trimmed_assert_eq(expected: &str, actual: &str) {
    let expected: Vec<_> = expected.lines().map(|l| l.trim_end()).collect();
    let mut expected = expected.join("\n");
    expected.push('\n');

    pretty_assertions::assert_eq!(expected, actual);
}
