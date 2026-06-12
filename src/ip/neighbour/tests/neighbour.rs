// SPDX-License-Identifier: MIT

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsFd,
};

use nix::sched::CloneFlags;
use rtnetlink::packet_route::neighbour::NeighbourState;

use crate::tests::{exec_cmd, ip_rs_exec_cmd};

#[test]
fn test_neighbour_show() {
    let neigh_address1 = Ipv4Addr::new(10, 0, 0, 1).into();
    let neigh_address2 = Ipv4Addr::new(10, 0, 0, 2).into();
    let neigh_address3 = Ipv6Addr::from_bits(0x3000u128).into();
    let lladdr = "AA:AA:AA:AA:AA:AA";

    in_test_netns(|| {
        add_neighbour(neigh_address1, NeighbourState::Reachable, Some(lladdr));
        add_neighbour(neigh_address2, NeighbourState::Reachable, Some(lladdr));
        add_neighbour(neigh_address3, NeighbourState::Reachable, Some(lladdr));
        let expected_output = exec_cmd(&["ip", "neigh", "show"]);
        let our_output = ip_rs_exec_cmd(&["neigh", "show"]);

        trimmed_assert_eq(&expected_output, &our_output);
    });
}

#[test]
fn test_neighbour_show_json() {
    let neigh_address1 = Ipv4Addr::new(10, 0, 0, 1).into();
    let neigh_address2 = Ipv4Addr::new(10, 0, 0, 2).into();
    let neigh_address3 = Ipv6Addr::from_bits(0x3000u128).into();
    let lladdr = "AA:AA:AA:AA:AA:AA";

    in_test_netns(|| {
        add_neighbour(neigh_address1, NeighbourState::Reachable, Some(lladdr));
        add_neighbour(neigh_address2, NeighbourState::Reachable, Some(lladdr));
        add_neighbour(neigh_address3, NeighbourState::Reachable, Some(lladdr));
        let expected_output = exec_cmd(&["ip", "-j", "neigh", "show"]);
        let our_output = ip_rs_exec_cmd(&["-j", "neigh", "show"]);

        trimmed_assert_eq(&expected_output, &our_output);
    });
}

#[test]
fn test_neighbour_show_to() {
    let neigh_address1 = Ipv4Addr::new(10, 0, 0, 1).into();
    let neigh_address2 = Ipv4Addr::new(10, 0, 0, 2).into();
    let lladdr = "AA:AA:AA:AA:AA:AA";

    in_test_netns(|| {
        add_neighbour(neigh_address1, NeighbourState::Reachable, Some(lladdr));
        add_neighbour(neigh_address2, NeighbourState::Reachable, Some(lladdr));
        // Implicit "to" parameter
        let expected_output =
            exec_cmd(&["ip", "neigh", "show", &neigh_address1.to_string()]);
        let our_output =
            ip_rs_exec_cmd(&["neigh", "show", &neigh_address1.to_string()]);

        trimmed_assert_eq(&expected_output, &our_output);

        // Explicit "to" parameter
        let expected_output = exec_cmd(&[
            "ip",
            "neigh",
            "show",
            "to",
            &neigh_address1.to_string(),
        ]);
        let our_output = ip_rs_exec_cmd(&[
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

    in_test_netns(|| {
        add_neighbour(neigh_address1, NeighbourState::Reachable, Some(lladdr));
        add_neighbour(neigh_address2, NeighbourState::Stale, Some(lladdr));
        add_neighbour(neigh_address3, NeighbourState::Noarp, Some(lladdr));
        add_neighbour(neigh_address4, NeighbourState::None, Some(lladdr));

        // First, make sure that by default we don't show none/noarp neighs
        let expected_output = exec_cmd(&["ip", "neigh", "show"]);
        let our_output = ip_rs_exec_cmd(&["neigh", "show"]);

        trimmed_assert_eq(&expected_output, &our_output);

        // Then, ask for them explictly
        let expected_output = exec_cmd(&["ip", "neigh", "show", "nud", "none"]);
        let our_output = ip_rs_exec_cmd(&["neigh", "show", "nud", "none"]);
        trimmed_assert_eq(&expected_output, &our_output);

        let expected_output =
            exec_cmd(&["ip", "neigh", "show", "nud", "noarp"]);
        let our_output = ip_rs_exec_cmd(&["neigh", "show", "nud", "noarp"]);
        trimmed_assert_eq(&expected_output, &our_output);
    });
}

// TODO: Tests
//  - Filter by dev, vrf, and nomaster
//  - Filter by pneigh (proxy)
//  - Show statistics (need to figure out how to handle time differences)

fn add_neighbour(
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
        "tap0",
        &neigh_address,
        "nud",
        &nud,
    ];
    if let Some(lladdr) = lladdr {
        cmd.extend(["lladdr", lladdr]);
    }
    exec_cmd(&cmd);
}

/// Asserts textual outputs of us and iproute2 are equal,
/// normalizing iproute2 output to remove trailing whitespace.
fn trimmed_assert_eq(expected: &str, actual: &str) {
    let expected: Vec<_> = expected.lines().map(|l| l.trim_end()).collect();
    let mut expected = expected.join("\n");
    expected.push('\n');

    pretty_assertions::assert_eq!(expected, actual);
}

/// Runs the test body in a dedicated disposable network-namespace.
/// The namespace is created with a single tap-device `tap0`.
/// No need to cleanup anything inside the test; the namespace is deleted afterwards.
fn in_test_netns<T>(test: T)
where
    T: FnOnce() + std::panic::UnwindSafe,
{
    // Get reference to old netns, create and enter a new one.
    let current_fd = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
    nix::sched::unshare(CloneFlags::CLONE_NEWNET).unwrap();

    // Create a tap device we can put our neighbours on.
    exec_cmd(&["ip", "tuntap", "add", "mode", "tap", "name", "tap0"]);

    let result = std::panic::catch_unwind(|| {
        test();
    });

    // Switch back to old netns
    nix::sched::setns(current_fd.as_fd(), CloneFlags::CLONE_NEWNET).unwrap();

    assert!(result.is_ok())

    // No need for explicit cleanup, we did not mount our netns anywhere in the filesystem,
    // so it will die now that we exited it.
}
