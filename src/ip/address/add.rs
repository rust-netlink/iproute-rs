// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::stream::StreamExt;
use futures_util::TryStreamExt;
use rtnetlink::packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL,
    NLM_F_REPLACE, NLM_F_REQUEST,
};
use rtnetlink::packet_route::address::{
    AddressAttribute, AddressFlags, AddressMessage, AddressProtocol,
    AddressScope, CacheInfo,
};
use rtnetlink::packet_route::RouteNetlinkMessage;

use crate::CliError;

pub(crate) enum AddressModifyOp {
    Add,
    Change,
    Replace,
}

pub(crate) async fn handle_add(opts: &[String]) -> Result<(), CliError> {
    handle_modify(opts, AddressModifyOp::Add).await
}

pub(crate) async fn handle_modify(
    opts: &[String],
    op: AddressModifyOp,
) -> Result<(), CliError> {
    let (connection, mut handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut dev: Option<String> = None;
    let mut local: Option<IpAddr> = None;
    let mut local_prefix_len: Option<u8> = None;
    let mut peer: Option<IpAddr> = None;
    let mut peer_prefix_len: Option<u8> = None;
    let mut broadcast: Option<BroadcastSpec> = None;
    let mut anycast: Option<Ipv6Addr> = None;
    let mut label: Option<String> = None;
    let mut scope: Option<AddressScope> = None;
    let mut metric: Option<u32> = None;
    let mut valid_lft: Option<String> = None;
    let mut preferred_lft: Option<String> = None;
    let mut proto: Option<AddressProtocol> = None;
    let mut flags = AddressFlags::empty();
    let mut local_parsed = false;
    let mut peer_parsed = false;

    let mut iter = opts.iter().peekable();
    while let Some(key) = iter.next() {
        match key.as_str() {
            "peer" | "remote" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"peer\" argument requires a value")
                })?;
                if peer_parsed {
                    return Err(CliError::from("duplicate \"peer\" argument"));
                }
                peer_parsed = true;
                let (addr, plen) = parse_prefix(val)?;
                peer = Some(addr);
                peer_prefix_len = plen;
            }
            "broadcast" | "brd" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"broadcast\" argument requires a value")
                })?;
                if val == "+" {
                    broadcast = Some(BroadcastSpec::AutoOnes);
                } else if val == "-" {
                    broadcast = Some(BroadcastSpec::AutoZeros);
                } else {
                    let addr = val.parse::<Ipv4Addr>().map_err(|_| {
                        CliError::from(format!(
                            "invalid broadcast address: {val}"
                        ))
                    })?;
                    broadcast = Some(BroadcastSpec::Explicit(addr));
                }
            }
            "anycast" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"anycast\" argument requires a value")
                })?;
                anycast = Some(val.parse::<Ipv6Addr>().map_err(|_| {
                    CliError::from(format!("invalid anycast address: {val}"))
                })?);
            }
            "scope" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"scope\" argument requires a value")
                })?;
                scope = Some(parse_scope(val)?);
            }
            "dev" => {
                dev = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::from("\"dev\" argument requires a value")
                        })?
                        .clone(),
                );
            }
            "label" => {
                label = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::from(
                                "\"label\" argument requires a value",
                            )
                        })?
                        .clone(),
                );
            }
            "metric" | "priority" | "preference" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"metric\" argument requires a value")
                })?;
                metric = Some(val.parse::<u32>().map_err(|_| {
                    CliError::from(format!("invalid metric value: {val}"))
                })?);
            }
            "valid_lft" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"valid_lft\" argument requires a value")
                })?;
                valid_lft = Some(val.clone());
            }
            "preferred_lft" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from(
                        "\"preferred_lft\" argument requires a value",
                    )
                })?;
                preferred_lft = Some(val.clone());
            }
            "proto" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"proto\" argument requires a value")
                })?;
                proto = Some(parse_protocol(val)?);
            }
            "home" | "mngtmpaddr" | "nodad" | "optimistic"
            | "noprefixroute" | "autojoin" | "secondary" | "temporary"
            | "dadfailed" | "deprecated" | "tentative" | "permanent"
            | "stable-privacy" => {
                flags |= parse_flag(key.as_str())?;
            }
            "local" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"local\" argument requires a value")
                })?;
                if local_parsed {
                    return Err(CliError::from("duplicate \"local\" argument"));
                }
                local_parsed = true;
                let (addr, plen) = parse_prefix(val)?;
                local = Some(addr);
                local_prefix_len = plen;
            }
            _ => {
                // iproute2 falls through to the else clause:
                // if not any known keyword, treat as the local address
                if local_parsed {
                    return Err(CliError::from(format!(
                        "unknown argument: {key}"
                    )));
                }
                local_parsed = true;
                let (addr, plen) = parse_prefix(key)?;
                local = Some(addr);
                local_prefix_len = plen;
            }
        }
    }

    let dev = dev.ok_or_else(|| {
        CliError::from("required \"dev\" argument is missing")
    })?;

    let local =
        local.ok_or_else(|| CliError::from("missing address argument"))?;

    let family = if local.is_ipv4() {
        rtnetlink::packet_route::AddressFamily::Inet
    } else {
        rtnetlink::packet_route::AddressFamily::Inet6
    };

    // Determine prefix length
    let prefix_len = local_prefix_len
        .or(peer_prefix_len)
        .unwrap_or_else(|| default_prefix_len(&local));

    // Filter v6only flags for non-IPv6 addresses (matching iproute2 behavior)
    if family != rtnetlink::packet_route::AddressFamily::Inet6 {
        for (name, mask) in V6ONLY_FLAGS {
            if flags.contains(*mask) {
                eprintln!(
                    "Warning: {name} option can be set only for IPv6 addresses"
                );
                flags.remove(*mask);
            }
        }
    }

    // Build the address message
    let config = AddressAddConfig {
        local,
        prefix_len,
        family,
        peer,
        broadcast,
        anycast,
        label,
        scope,
        metric,
        valid_lft,
        preferred_lft,
        proto,
        flags,
    };
    let mut msg = build_address_message(&config)?;

    // Look up the interface index
    let mut links = handle.link().get().match_name(dev.clone()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device \"{dev}\" does not exist"))
    })?;

    let index = link.header.index;
    msg.header.index = index;

    let mut nl_msg =
        NetlinkMessage::from(RouteNetlinkMessage::NewAddress(msg));
    nl_msg.header.flags = match op {
        AddressModifyOp::Add => {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE
        }
        AddressModifyOp::Change => NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE,
        AddressModifyOp::Replace => {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE
        }
    };

    let mut response = handle.request(nl_msg).map_err(|e| {
        CliError::from(format!("{e}"))
    })?;
    while let Some(msg) = response.next().await {
        if let NetlinkPayload::Error(err) = msg.payload {
            return Err(CliError::from(format!(
                "Received a netlink error message {err}"
            )));
        }
    }

    Ok(())
}

fn parse_prefix(s: &str) -> Result<(IpAddr, Option<u8>), CliError> {
    if let Some((addr_str, plen_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str.parse().map_err(|_| {
            CliError::from(format!("invalid address: {addr_str}"))
        })?;
        let plen: u8 = plen_str.parse().map_err(|_| {
            CliError::from(format!("invalid prefix length: {plen_str}"))
        })?;
        Ok((addr, Some(plen)))
    } else {
        let addr: IpAddr = s
            .parse()
            .map_err(|_| CliError::from(format!("invalid address: {s}")))?;
        Ok((addr, None))
    }
}

fn default_prefix_len(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

#[derive(Debug)]
enum BroadcastSpec {
    Explicit(Ipv4Addr),
    AutoOnes,
    AutoZeros,
}

struct AddressAddConfig {
    local: IpAddr,
    prefix_len: u8,
    family: rtnetlink::packet_route::AddressFamily,
    peer: Option<IpAddr>,
    broadcast: Option<BroadcastSpec>,
    anycast: Option<Ipv6Addr>,
    label: Option<String>,
    scope: Option<AddressScope>,
    metric: Option<u32>,
    valid_lft: Option<String>,
    preferred_lft: Option<String>,
    proto: Option<AddressProtocol>,
    flags: AddressFlags,
}

const V6ONLY_FLAGS: &[(&str, AddressFlags)] = &[
    ("nodad", AddressFlags::Nodad),
    ("optimistic", AddressFlags::Optimistic),
    ("home", AddressFlags::Homeaddress),
    ("mngtmpaddr", AddressFlags::Managetempaddr),
];

fn compute_auto_broadcast(
    addr: &IpAddr,
    prefix_len: u8,
    set_ones: bool,
) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(v4) => {
            if prefix_len > 30 {
                return None;
            }
            let ip = u32::from(*v4);
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            let brd = if set_ones {
                (ip & mask) | !mask
            } else {
                ip & mask
            };
            Some(Ipv4Addr::from(brd))
        }
        IpAddr::V6(_) => None,
    }
}

fn build_address_message(
    cfg: &AddressAddConfig,
) -> Result<AddressMessage, CliError> {
    let mut msg = AddressMessage::default();
    msg.header.family = cfg.family;
    msg.header.prefix_len = cfg.prefix_len;
    msg.header.scope = cfg.scope.unwrap_or(AddressScope::Universe);

    msg.attributes.push(AddressAttribute::Local(cfg.local));

    let address_attr = cfg.peer.unwrap_or(cfg.local);
    msg.attributes.push(AddressAttribute::Address(address_attr));

    let brd_addr = cfg.peer.unwrap_or(cfg.local);
    match &cfg.broadcast {
        Some(BroadcastSpec::Explicit(brd)) => {
            if cfg.family != rtnetlink::packet_route::AddressFamily::Inet {
                return Err(CliError::from(
                    "Broadcast can be set only for IPv4 addresses",
                ));
            }
            msg.attributes.push(AddressAttribute::Broadcast(*brd));
        }
        Some(BroadcastSpec::AutoOnes) => {
            if let Some(brd) =
                compute_auto_broadcast(&brd_addr, cfg.prefix_len, true)
            {
                msg.attributes.push(AddressAttribute::Broadcast(brd));
            }
        }
        Some(BroadcastSpec::AutoZeros) => {
            if let Some(brd) =
                compute_auto_broadcast(&brd_addr, cfg.prefix_len, false)
            {
                msg.attributes.push(AddressAttribute::Broadcast(brd));
            }
        }
        None => {}
    }

    if let Some(any) = &cfg.anycast {
        msg.attributes.push(AddressAttribute::Anycast(*any));
    }

    if let Some(l) = &cfg.label {
        msg.attributes.push(AddressAttribute::Label(l.clone()));
    }

    if let Some(m) = cfg.metric {
        msg.attributes.push(AddressAttribute::RoutePriority(m));
    }

    if cfg.valid_lft.is_some() || cfg.preferred_lft.is_some() {
        let valid = if let Some(v) = &cfg.valid_lft {
            let v = parse_lifetime(v)?;
            if v == 0 {
                return Err(CliError::from("valid_lft is zero"));
            }
            v
        } else {
            u32::MAX
        };
        let preferred = if let Some(p) = &cfg.preferred_lft {
            parse_lifetime(p)?
        } else {
            u32::MAX
        };
        if preferred > valid {
            return Err(CliError::from(
                "preferred_lft is greater than valid_lft",
            ));
        }
        let mut ci = CacheInfo::default();
        ci.ifa_preferred = preferred;
        ci.ifa_valid = valid;
        msg.attributes.push(AddressAttribute::CacheInfo(ci));
    }

    if let Some(p) = &cfg.proto {
        msg.attributes.push(AddressAttribute::Protocol(*p));
    }

    if cfg.flags.bits() <= 0xff {
        msg.header.flags =
            rtnetlink::packet_route::address::AddressHeaderFlags::from_bits_retain(
                cfg.flags.bits() as u8,
            );
    }
    if !cfg.flags.is_empty() {
        msg.attributes.push(AddressAttribute::Flags(cfg.flags));
    }

    Ok(msg)
}

fn parse_scope(s: &str) -> Result<AddressScope, CliError> {
    match s {
        "global" | "universe" => Ok(AddressScope::Universe),
        "site" => Ok(AddressScope::Site),
        "link" => Ok(AddressScope::Link),
        "host" => Ok(AddressScope::Host),
        "nowhere" => Ok(AddressScope::Nowhere),
        _ => {
            let v = s
                .parse::<u8>()
                .map_err(|_| CliError::from(format!("invalid scope: {s}")))?;
            Ok(AddressScope::from(v))
        }
    }
}

fn parse_lifetime(s: &str) -> Result<u32, CliError> {
    match s {
        "forever" => Ok(u32::MAX),
        _ => s.parse::<u32>().map_err(|_| {
            CliError::from(format!("invalid lifetime value: {s}"))
        }),
    }
}

fn parse_protocol(s: &str) -> Result<AddressProtocol, CliError> {
    match s {
        "kernel_lo" => Ok(AddressProtocol::Loopback),
        "kernel_ra" => Ok(AddressProtocol::RouterAnnouncement),
        "kernel_ll" => Ok(AddressProtocol::LinkLocal),
        _ => {
            let v = s.parse::<u8>().map_err(|_| {
                CliError::from(format!("invalid protocol: {s}"))
            })?;
            Ok(AddressProtocol::Other(v))
        }
    }
}

fn parse_flag(name: &str) -> Result<AddressFlags, CliError> {
    match name {
        "secondary" | "temporary" => {
            eprintln!("Warning: {name} option is not mutable from userspace");
            Ok(AddressFlags::empty())
        }
        "dadfailed" => {
            eprintln!(
                "Warning: dadfailed option is not mutable from userspace"
            );
            Ok(AddressFlags::empty())
        }
        "deprecated" => {
            eprintln!(
                "Warning: deprecated option is not mutable from userspace"
            );
            Ok(AddressFlags::empty())
        }
        "tentative" => {
            eprintln!(
                "Warning: tentative option is not mutable from userspace"
            );
            Ok(AddressFlags::empty())
        }
        "permanent" => {
            eprintln!(
                "Warning: permanent option is not mutable from userspace"
            );
            Ok(AddressFlags::empty())
        }
        "stable-privacy" => {
            eprintln!(
                "Warning: stable-privacy option is not mutable from userspace"
            );
            Ok(AddressFlags::empty())
        }
        "nodad" => Ok(AddressFlags::Nodad),
        "optimistic" => Ok(AddressFlags::Optimistic),
        "home" => Ok(AddressFlags::Homeaddress),
        "mngtmpaddr" => Ok(AddressFlags::Managetempaddr),
        "noprefixroute" => Ok(AddressFlags::Noprefixroute),
        "autojoin" => Ok(AddressFlags::Mcautojoin),
        _ => Err(CliError::from(format!("unknown flag: {name}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope_values() {
        assert_eq!(parse_scope("global").unwrap(), AddressScope::Universe);
        assert_eq!(parse_scope("universe").unwrap(), AddressScope::Universe);
        assert_eq!(parse_scope("site").unwrap(), AddressScope::Site);
        assert_eq!(parse_scope("link").unwrap(), AddressScope::Link);
        assert_eq!(parse_scope("host").unwrap(), AddressScope::Host);
        assert_eq!(parse_scope("nowhere").unwrap(), AddressScope::Nowhere);
        assert_eq!(parse_scope("0").unwrap(), AddressScope::Universe);
        assert_eq!(parse_scope("200").unwrap(), AddressScope::Site);
        assert_eq!(parse_scope("253").unwrap(), AddressScope::Link);
        assert_eq!(parse_scope("254").unwrap(), AddressScope::Host);
        assert_eq!(parse_scope("255").unwrap(), AddressScope::Nowhere);
        assert_eq!(parse_scope("42").unwrap(), AddressScope::Other(42));
        assert!(parse_scope("bad").is_err());
    }

    #[test]
    fn parse_lifetime_values() {
        assert_eq!(parse_lifetime("forever").unwrap(), u32::MAX);
        assert_eq!(parse_lifetime("0").unwrap(), 0);
        assert_eq!(parse_lifetime("12345").unwrap(), 12345);
        assert!(parse_lifetime("bad").is_err());
    }

    #[test]
    fn parse_protocol_values() {
        assert_eq!(
            parse_protocol("kernel_lo").unwrap(),
            AddressProtocol::Loopback
        );
        assert_eq!(
            parse_protocol("kernel_ra").unwrap(),
            AddressProtocol::RouterAnnouncement
        );
        assert_eq!(
            parse_protocol("kernel_ll").unwrap(),
            AddressProtocol::LinkLocal
        );
        assert_eq!(parse_protocol("0").unwrap(), AddressProtocol::Other(0));
        assert_eq!(parse_protocol("42").unwrap(), AddressProtocol::Other(42));
        assert!(parse_protocol("bad").is_err());
    }

    #[test]
    fn parse_prefix_with_len() {
        let (addr, plen) = parse_prefix("192.168.1.1/24").unwrap();
        assert_eq!(addr, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(plen, Some(24));
    }

    #[test]
    fn parse_prefix_without_len() {
        let (addr, plen) = parse_prefix("192.168.1.1").unwrap();
        assert_eq!(addr, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(plen, None);
    }

    #[test]
    fn parse_prefix_ipv6_with_len() {
        let (addr, plen) = parse_prefix("2001:db8::1/64").unwrap();
        assert_eq!(addr, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(plen, Some(64));
    }

    #[test]
    fn parse_prefix_invalid() {
        assert!(parse_prefix("bad").is_err());
        assert!(parse_prefix("1.2.3.4/bad").is_err());
        assert!(parse_prefix("bad/24").is_err());
    }

    #[test]
    fn default_prefix_len_v4() {
        assert_eq!(
            default_prefix_len(&"10.0.0.1".parse::<IpAddr>().unwrap()),
            32
        );
    }

    #[test]
    fn default_prefix_len_v6() {
        assert_eq!(default_prefix_len(&"::1".parse::<IpAddr>().unwrap()), 128);
    }

    #[test]
    fn compute_auto_broadcast_ones() {
        let addr: IpAddr = "192.168.1.0".parse().unwrap();
        let brd = compute_auto_broadcast(&addr, 24, true);
        assert_eq!(brd, Some(Ipv4Addr::new(192, 168, 1, 255)));

        let brd = compute_auto_broadcast(&addr, 24, false);
        assert_eq!(brd, Some(Ipv4Addr::new(192, 168, 1, 0)));
    }

    #[test]
    fn compute_auto_broadcast_31_prefix() {
        let addr: IpAddr = "192.168.1.0".parse().unwrap();
        let brd = compute_auto_broadcast(&addr, 31, true);
        assert_eq!(brd, None);
    }

    #[test]
    fn compute_auto_broadcast_ipv6() {
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        let brd = compute_auto_broadcast(&addr, 64, true);
        assert_eq!(brd, None);
    }

    #[test]
    fn parse_flag_readonly_warnings() {
        assert_eq!(parse_flag("secondary").unwrap(), AddressFlags::empty());
        assert_eq!(parse_flag("temporary").unwrap(), AddressFlags::empty());
        assert_eq!(parse_flag("dadfailed").unwrap(), AddressFlags::empty());
        assert_eq!(parse_flag("deprecated").unwrap(), AddressFlags::empty());
        assert_eq!(parse_flag("tentative").unwrap(), AddressFlags::empty());
        assert_eq!(parse_flag("permanent").unwrap(), AddressFlags::empty());
        assert_eq!(
            parse_flag("stable-privacy").unwrap(),
            AddressFlags::empty()
        );
    }

    #[test]
    fn parse_flag_mutable() {
        assert_eq!(parse_flag("nodad").unwrap(), AddressFlags::Nodad);
        assert_eq!(parse_flag("optimistic").unwrap(), AddressFlags::Optimistic);
        assert_eq!(parse_flag("home").unwrap(), AddressFlags::Homeaddress);
        assert_eq!(
            parse_flag("mngtmpaddr").unwrap(),
            AddressFlags::Managetempaddr
        );
        assert_eq!(
            parse_flag("noprefixroute").unwrap(),
            AddressFlags::Noprefixroute
        );
        assert_eq!(parse_flag("autojoin").unwrap(), AddressFlags::Mcautojoin);
    }

    #[test]
    fn parse_flag_unknown() {
        assert!(parse_flag("nonexistent").is_err());
    }
}
