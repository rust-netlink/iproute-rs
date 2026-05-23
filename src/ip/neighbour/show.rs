// SPDX-License-Identifier: MIT

use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use futures_util::TryStreamExt;
use iproute_rs::{
    CanDisplay, CanOutput, CliColor, mac_to_string, write_with_color,
};
use rtnetlink::{
    Handle,
    packet_route::{
        link::LinkAttribute,
        neighbour::{
            NeighbourAddress, NeighbourAttribute, NeighbourFlags,
            NeighbourMessage, NeighbourState,
        },
    },
};
use serde::Serialize;

use crate::CliError;

#[derive(Serialize, Debug)]
pub(crate) struct CliNeighbourInfo {
    #[serde(skip)]
    family: String,
    dst: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    dev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lladdr: Option<String>,

    #[serde(skip)]
    refcnt: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    used: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmed: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    probes: Option<u32>,

    #[serde(skip_serializing_if = "std::ops::Not::not")]
    #[serde(serialize_with = "serialize_flag_as_null")]
    router: bool,

    /// iproute2 emits a bare `"proxy": null` in JSON, mirroring `router`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    #[serde(serialize_with = "serialize_flag_as_null")]
    proxy: bool,

    /// TODO: iproute2 emits a JSON array for these; need to figure out in what
    /// situation we have more than 1.
    state: Vec<String>,
}

/// Serialize a set boolean flag as a JSON `null`, matching iproute2's
/// `print_null` behaviour for marker flags such as `router`/`proxy`.
fn serialize_flag_as_null<S>(_: &bool, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_none()
}

impl std::fmt::Display for CliNeighbourInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_with_color!(
            f,
            CliColor::address_color(&self.family),
            "{}",
            self.dst
        )?;
        if let Some(dev) = &self.dev {
            write!(f, " dev ")?;
            write_with_color!(f, CliColor::IfaceName, "{}", dev)?;
        }
        if let Some(lladdr) = &self.lladdr {
            write!(f, " lladdr ")?;
            write_with_color!(f, CliColor::Mac, "{lladdr}")?;
        }

        if self.router {
            write!(f, " router")?;
        }

        if self.proxy {
            write!(f, " proxy")?;
        }

        // Statistics block, only populated with `-s`. iproute2 prefixes the
        // whole cache-info block with an extra separating space and prints
        // `probes` immediately after the `used` counters (without a space).
        if let Some(used) = self.used {
            write!(f, " ")?;

            if let Some(refcnt) = self.refcnt
                && refcnt != 0
            {
                write!(f, " ref {refcnt}")?;
            }

            let confirmed = self.confirmed.unwrap_or(0);
            let updated = self.updated.unwrap_or(0);
            write!(f, " used {used}/{confirmed}/{updated}")?;

            if let Some(probes) = self.probes {
                write!(f, "probes {probes}")?;
            }
        }

        for state in &self.state {
            write!(f, " {state}")?;
        }

        Ok(())
    }
}

impl CanDisplay for CliNeighbourInfo {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliNeighbourInfo {}

#[derive(Default, Debug)]
enum NudFilter {
    #[default]
    Default,
    All,
    Specified(NeighbourState),
}

impl FromStr for NudFilter {
    type Err = CliError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "all" {
            return Ok(NudFilter::All);
        }
        let Ok(state) = s.parse::<NeighbourState>() else {
            return Err("Invalid nud `{s}`".into());
        };

        Ok(NudFilter::Specified(state))
    }
}

#[derive(Default, Debug)]
enum ControllerFilter<'a> {
    #[default]
    Unfiltered,
    DeviceName(&'a str),
    NoController,
}

#[derive(Default, Debug)]
struct ShowArguments<'a> {
    nud_filter: NudFilter,
    dev_filter: Option<&'a str>,
    controller_filter: ControllerFilter<'a>,
    proxy: bool,
    unused: bool,
    address_filter: Option<IpAddr>,
}

impl<'a> ShowArguments<'a> {
    fn from_arguments(
        mut arguments: impl Iterator<Item = &'a str>,
    ) -> Result<Self, CliError> {
        let mut args = Self::default();
        while let Some(opt) = arguments.next() {
            match opt {
                "proxy" => {
                    args.proxy = true;
                }

                "unused" => {
                    args.unused = true;
                }

                "dev" => {
                    let Some(dev_name) = arguments.next() else {
                        return Err("Missing argument for `dev`".into());
                    };
                    args.dev_filter = Some(dev_name);
                }

                "vrf" => {
                    let Some(vrf_name) = arguments.next() else {
                        return Err("Missing argument for `vrf`".into());
                    };
                    args.controller_filter =
                        ControllerFilter::DeviceName(vrf_name);
                }

                "nomaster" => {
                    args.controller_filter = ControllerFilter::NoController;
                }

                "nud" => {
                    let Some(nud) = arguments.next() else {
                        return Err("Missing argument for `nud`".into());
                    };
                    args.nud_filter = nud.parse()?;
                }

                "to" => {
                    let Some(address) = arguments.next() else {
                        return Err("Missing argument for `to`".into());
                    };
                    args.address_filter = Some(parse_address(address)?);
                }

                raw => {
                    args.address_filter = Some(parse_address(raw)?);
                }
            }
        }

        Ok(args)
    }
}

/// Parse an address similarly to `ip neigh show <ADDR>`.
/// It accepts either an IP-address, or a numeric IPv4 (probably network-order).
///
/// TODO: Check if `0XXXX` is represented as octal.
fn parse_address(address: &str) -> Result<IpAddr, CliError> {
    if let Ok(address) = address.parse() {
        return Ok(address);
    }

    // Try to parse as an integer and convert to ipv4
    let (address, radix) = if let Some(address) = address.strip_prefix("0x") {
        (address, 16)
    } else if let Some(address) = address.strip_prefix("0b") {
        (address, 2)
    } else {
        (address, 10)
    };
    let address_num = u32::from_str_radix(address, radix)
        .map_err(|_| format!("Invalid address `{address}`"))?;

    Ok(Ipv4Addr::from_bits(address_num).into())
}

fn parse_nl_msg_to_neighbour(
    nl_msg: NeighbourMessage,
    interface_names: &BTreeMap<u32, String>,
    clocks_per_second: u32,
) -> Result<Option<CliNeighbourInfo>, CliError> {
    let family = nl_msg.header.family.to_string();
    let flags = NeighbourFlags::from_bits_retain(nl_msg.header.flags.bits());
    let mut dst = None;
    let mut lladdr = None;
    let mut confirmed = None;
    let mut used = None;
    let mut updated = None;
    let mut refcnt = None;
    let mut probes = None;

    let state = if nl_msg.header.state == NeighbourState::None {
        vec![]
    } else {
        vec![nl_msg.header.state.to_string().to_ascii_uppercase()]
    };

    let dev = interface_names
        .get(&nl_msg.header.ifindex)
        .cloned()
        .unwrap_or_else(|| nl_msg.header.ifindex.to_string());
    let dev = Some(dev);

    for nla in nl_msg.attributes {
        match nla {
            NeighbourAttribute::Destination(a) => {
                dst = match a {
                    NeighbourAddress::Inet(addr) => Some(addr.into()),
                    NeighbourAddress::Inet6(addr) => Some(addr.into()),
                    _ => None,
                };
            }
            NeighbourAttribute::LinkLayerAddress(raw_lladdr) => {
                lladdr = Some(mac_to_string(&raw_lladdr));
            }
            NeighbourAttribute::CacheInfo(info) => {
                confirmed = Some(info.confirmed / clocks_per_second);
                used = Some(info.used / clocks_per_second);
                updated = Some(info.updated / clocks_per_second);
                refcnt = Some(info.refcnt);
            }
            NeighbourAttribute::Probes(probes_) => {
                probes = Some(probes_);
            }
            _ => {}
        }
    }

    let router = flags.contains(NeighbourFlags::Router);
    let proxy = flags.contains(NeighbourFlags::Proxy);

    let Some(dst) = dst else {
        return Ok(None);
    };

    let cli_addr_info = CliNeighbourInfo {
        family,
        dst,
        dev,
        lladdr,
        refcnt,
        used,
        confirmed,
        updated,
        probes,
        router,
        proxy,
        state,
    };

    Ok(Some(cli_addr_info))
}

/// Build a bidrectional-mapping between interface names and their indicies.
/// Optionally retrieves a single link if limited by the user.
async fn get_links(
    handle: &Handle,
    dev_filter: Option<&str>,
) -> Result<(BTreeMap<u32, String>, HashMap<String, u32>), CliError> {
    let mut links_get_handler = handle.link().get();

    if let Some(dev_filter) = dev_filter {
        links_get_handler = links_get_handler.match_name(dev_filter);
    }

    let mut links = links_get_handler.execute();
    let mut link_names = BTreeMap::new();
    let mut link_indicies = HashMap::new();
    while let Some(nl_msg) = links.try_next().await? {
        let index = nl_msg.header.index;
        for attr in nl_msg.attributes {
            if let LinkAttribute::IfName(name) = attr {
                link_names.insert(index, name.clone());
                link_indicies.insert(name, index);
            }
        }
    }

    Ok((link_names, link_indicies))
}

pub(crate) async fn handle_show(
    opts: impl Iterator<Item = &str>,
    show_statistics: bool,
) -> Result<Vec<CliNeighbourInfo>, CliError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;

    tokio::spawn(connection);

    let mut args = ShowArguments::from_arguments(opts)?;
    let (link_names, link_indicies) =
        get_links(&handle, args.dev_filter).await?;

    let mut neighbours_get_handle = handle.neighbours().get();
    if args.proxy {
        neighbours_get_handle = neighbours_get_handle.proxies();

        // When listing proxy entries, iproute2 ignores this filter.
        // We must override it because all parps are nud=none, but we hide it by
        // default.
        args.nud_filter = NudFilter::Specified(NeighbourState::None);
    }
    if let Some(dev_name) = args.dev_filter {
        let dev_index = link_indicies
            .get(dev_name)
            .ok_or_else(|| format!("Cannot find device \"{dev_name}\""))?;

        neighbours_get_handle
            .message_mut()
            .attributes
            .push(NeighbourAttribute::IfIndex(*dev_index));
    }
    let controller_filter = match args.controller_filter {
        ControllerFilter::DeviceName(vrf_name) => {
            let index = link_indicies.get(vrf_name).ok_or_else(|| {
                format!(
                    "argument \"{vrf_name}\" is wrong: Not a valid VRF name"
                )
            })?;
            Some(*index)
        }
        ControllerFilter::NoController => Some(u32::MAX),
        _ => None,
    };
    neighbours_get_handle
        .message_mut()
        .attributes
        .extend(controller_filter.map(NeighbourAttribute::Controller));

    let mut neighbours = neighbours_get_handle.execute();
    let mut neighbour_info: Vec<CliNeighbourInfo> = Vec::new();

    // Retrieve clock resolution (USER_HZ in kernel) for time calculations.
    // Typically it is set to a hundreth of a second, but this is overridable
    // when compiling the kernel.
    let clock = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
        .unwrap_or(None)
        .unwrap_or(100) as u32;

    while let Some(nl_msg) = neighbours.try_next().await? {
        match args.nud_filter {
            NudFilter::Default => {
                if nl_msg.header.state == NeighbourState::None
                    || nl_msg.header.state == NeighbourState::Noarp
                {
                    continue;
                }
            }
            NudFilter::Specified(neighbour_state) => {
                if nl_msg.header.state != neighbour_state {
                    continue;
                }
            }
            NudFilter::All => {}
        }

        let Some(mut neigh) =
            parse_nl_msg_to_neighbour(nl_msg, &link_names, clock)?
        else {
            continue;
        };

        if let Some(address_filter) = args.address_filter
            && neigh.dst != address_filter
        {
            continue;
        }
        if args.unused && neigh.refcnt.unwrap_or(0) != 0 {
            continue;
        }
        if args.dev_filter.is_some() {
            neigh.dev = None;
        }
        if !show_statistics {
            neigh.refcnt = None;
            neigh.used = None;
            neigh.confirmed = None;
            neigh.updated = None;
            neigh.probes = None;
        }

        neighbour_info.push(neigh);
    }

    Ok(neighbour_info)
}
