// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use futures_util::TryStreamExt;
use rtnetlink::packet_route::{
    AddressFamily,
    route::{RouteAddress, RouteAttribute, RouteFlags, RouteMessage},
};

use super::show::{CliRouteInfo, parse_nl_msg_to_route};
use crate::CliError;

struct RouteGetConfig {
    dst: IpAddr,
    dst_len: u8,
    from: Option<IpAddr>,
    from_len: u8,
    tos: Option<u8>,
    iif: Option<String>,
    oif: Option<String>,
    mark: Option<u32>,
    uid: Option<u32>,
    ipproto: Option<u8>,
    sport: Option<u16>,
    dport: Option<u16>,
    flowlabel: Option<u32>,
    notify: bool,
    connected: bool,
    fib_match: bool,
    family: AddressFamily,
}

pub(crate) async fn handle_get(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<Vec<CliRouteInfo>, CliError> {
    let config = parse_get_config(opts, preferred_family)?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // Build link index -> name map
    let link_map = build_link_map(&handle).await?;

    // Build and send first request
    let mut msg = build_get_message(&config)?;

    // Resolve interface names to ifindex
    if let Some(ref name) = config.iif {
        let idx = resolve_ifindex(&handle, name).await?;
        msg.attributes.push(RouteAttribute::Iif(idx));
    }
    if let Some(ref name) = config.oif {
        let idx = resolve_ifindex(&handle, name).await?;
        msg.attributes.push(RouteAttribute::Oif(idx));
    }

    let mut stream = handle.route().get(msg).execute();
    let first_resp = stream
        .try_next()
        .await?
        .ok_or_else(|| CliError::from("no response to route get"))?;

    // Connected two-pass logic: if connected and no from specified,
    // use the prefsrc from the first response as the from address
    let final_msg = if config.connected && config.from.is_none() {
        let prefsrc = first_resp.attributes.iter().find_map(|attr| {
            if let RouteAttribute::PrefSource(addr) = attr {
                match addr {
                    RouteAddress::Inet(a) => Some(IpAddr::V4(*a)),
                    RouteAddress::Inet6(a) => Some(IpAddr::V6(*a)),
                    _ => None,
                }
            } else {
                None
            }
        });

        let src = first_resp.attributes.iter().find_map(|attr| {
            if let RouteAttribute::Source(addr) = attr {
                match addr {
                    RouteAddress::Inet(a) => Some(IpAddr::V4(*a)),
                    RouteAddress::Inet6(a) => Some(IpAddr::V6(*a)),
                    _ => None,
                }
            } else {
                None
            }
        });

        let from_addr = prefsrc.or(src).ok_or_else(|| {
            CliError::from("connected route lookup failed: no source address")
        })?;

        let mut msg2 = build_get_message(&config)?;

        let family = config.family;
        let rta = match from_addr {
            IpAddr::V4(a) => RouteAttribute::Source(RouteAddress::Inet(a)),
            IpAddr::V6(a) => RouteAttribute::Source(RouteAddress::Inet6(a)),
        };
        msg2.attributes.push(rta);
        msg2.header.source_prefix_length = if family == AddressFamily::Inet {
            32
        } else {
            128
        };

        // Only add OIF if user explicitly specified oif
        if let Some(ref name) = config.oif {
            let idx = resolve_ifindex(&handle, name).await?;
            msg2.attributes.push(RouteAttribute::Oif(idx));
        }
        // Only add IIF if user explicitly specified iif
        if let Some(ref name) = config.iif {
            let idx = resolve_ifindex(&handle, name).await?;
            msg2.attributes.push(RouteAttribute::Iif(idx));
        }

        let mut stream2 = handle.route().get(msg2).execute();
        stream2.try_next().await?.ok_or_else(|| {
            CliError::from("no response to connected route get")
        })?
    } else {
        first_resp
    };

    let route = parse_nl_msg_to_route(final_msg, false, &link_map);
    Ok(vec![route])
}

fn parse_get_config(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<RouteGetConfig, CliError> {
    let mut dst: Option<IpAddr> = None;
    let mut dst_len: u8 = 0;
    let mut from: Option<IpAddr> = None;
    let mut from_len: u8 = 0;
    let mut tos: Option<u8> = None;
    let mut iif: Option<String> = None;
    let mut oif: Option<String> = None;
    let mut mark: Option<u32> = None;
    let mut uid: Option<u32> = None;
    let mut ipproto: Option<u8> = None;
    let mut sport: Option<u16> = None;
    let mut dport: Option<u16> = None;
    let mut flowlabel: Option<u32> = None;
    let mut notify = false;
    let mut connected = false;
    let mut fib_match = false;
    let mut address_found = false;
    let mut family = preferred_family.unwrap_or(AddressFamily::Unspec);

    let mut iter = opts.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "from" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"from\" requires a value")
                })?;
                let (addr, plen) = parse_get_prefix(val)?;
                from = Some(addr);
                from_len = plen;
                if family == AddressFamily::Unspec {
                    family = addr_to_family(&addr);
                }
            }
            "tos" | "dsfield" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"tos\" requires a value")
                })?;
                tos = Some(val.parse::<u8>().map_err(|_| {
                    CliError::from(format!("invalid tos: {val}"))
                })?);
            }
            "iif" => {
                iif = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::from("\"iif\" requires a value")
                        })?
                        .clone(),
                );
            }
            "oif" | "dev" => {
                oif = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::from("\"dev\" requires a value")
                        })?
                        .clone(),
                );
            }
            "mark" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"mark\" requires a value")
                })?;
                mark = Some(parse_mark_val(val)?);
            }
            "uid" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"uid\" requires a value")
                })?;
                uid = Some(val.parse::<u32>().map_err(|_| {
                    CliError::from(format!("invalid uid: {val}"))
                })?);
            }
            "ipproto" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"ipproto\" requires a value")
                })?;
                ipproto = Some(match val.as_str() {
                    "tcp" => 6u8,
                    "udp" => 17u8,
                    "sctp" => 132u8,
                    _ => val.parse::<u8>().map_err(|_| {
                        CliError::from(format!("invalid ipproto: {val}"))
                    })?,
                });
            }
            "sport" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"sport\" requires a value")
                })?;
                let p: u16 = val.parse::<u16>().map_err(|_| {
                    CliError::from(format!("invalid sport: {val}"))
                })?;
                sport = Some(p);
            }
            "dport" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"dport\" requires a value")
                })?;
                let p: u16 = val.parse::<u16>().map_err(|_| {
                    CliError::from(format!("invalid dport: {val}"))
                })?;
                dport = Some(p);
            }
            "flowlabel" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"flowlabel\" requires a value")
                })?;
                let fl: u32 = val.parse::<u32>().map_err(|_| {
                    CliError::from(format!("invalid flowlabel: {val}"))
                })?;
                flowlabel = Some(fl);
            }
            "notify" => notify = true,
            "connected" => connected = true,
            "fibmatch" => fib_match = true,
            "to" => {
                let val = iter
                    .next()
                    .ok_or_else(|| CliError::from("\"to\" requires a value"))?;
                let (addr, plen) = parse_get_prefix(val)?;
                dst = Some(addr);
                dst_len = plen;
                address_found = true;
                if family == AddressFamily::Unspec {
                    family = addr_to_family(&addr);
                }
            }
            _ => {
                if !address_found {
                    let (addr, plen) = parse_get_prefix(arg)?;
                    dst = Some(addr);
                    dst_len = plen;
                    address_found = true;
                    if family == AddressFamily::Unspec {
                        family = addr_to_family(&addr);
                    }
                } else {
                    return Err(CliError::from(format!(
                        "unexpected argument: {arg}"
                    )));
                }
            }
        }
    }

    if !address_found {
        return Err(CliError::from("need at least a destination address"));
    }

    if family == AddressFamily::Unspec {
        family = AddressFamily::Inet;
    }

    Ok(RouteGetConfig {
        dst: dst.unwrap(),
        dst_len,
        from,
        from_len,
        tos,
        iif,
        oif,
        mark,
        uid,
        ipproto,
        sport,
        dport,
        flowlabel,
        notify,
        connected,
        fib_match,
        family,
    })
}

fn parse_get_prefix(s: &str) -> Result<(IpAddr, u8), CliError> {
    if let Some((addr_str, plen_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str.parse().map_err(|_| {
            CliError::from(format!("invalid address: {addr_str}"))
        })?;
        let plen = plen_str.parse::<u8>().map_err(|_| {
            CliError::from(format!("invalid prefix length: {plen_str}"))
        })?;
        Ok((addr, plen))
    } else {
        let addr: IpAddr = s
            .parse()
            .map_err(|_| CliError::from(format!("invalid address: {s}")))?;
        let plen = if addr.is_ipv4() { 32 } else { 128 };
        Ok((addr, plen))
    }
}

fn addr_to_family(addr: &IpAddr) -> AddressFamily {
    match addr {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    }
}

fn parse_mark_val(s: &str) -> Result<u32, CliError> {
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
    {
        u32::from_str_radix(hex_str, 16)
            .map_err(|_| CliError::from(format!("invalid mark: {s}")))
    } else {
        s.parse::<u32>()
            .map_err(|_| CliError::from(format!("invalid mark: {s}")))
    }
}

fn build_get_message(
    config: &RouteGetConfig,
) -> Result<RouteMessage, CliError> {
    let mut msg = RouteMessage::default();
    msg.header.address_family = config.family;
    msg.header.destination_prefix_length = config.dst_len;

    // Destination (required)
    let rta = match config.dst {
        IpAddr::V4(a) => RouteAttribute::Destination(RouteAddress::Inet(a)),
        IpAddr::V6(a) => RouteAttribute::Destination(RouteAddress::Inet6(a)),
    };
    msg.attributes.push(rta);

    // Source (from)
    if let Some(ref addr) = config.from {
        msg.header.source_prefix_length = config.from_len;
        let rta = match *addr {
            IpAddr::V4(a) => RouteAttribute::Source(RouteAddress::Inet(a)),
            IpAddr::V6(a) => RouteAttribute::Source(RouteAddress::Inet6(a)),
        };
        msg.attributes.push(rta);
    }

    // TOS
    if let Some(tos) = config.tos {
        msg.header.tos = tos;
    }

    // Mark
    if let Some(m) = config.mark {
        msg.attributes.push(RouteAttribute::Mark(m));
    }

    // UID
    if let Some(u) = config.uid {
        msg.attributes.push(RouteAttribute::Uid(u));
    }

    // IP proto
    if let Some(p) = config.ipproto {
        msg.attributes.push(RouteAttribute::IpProto(p));
    }

    // Source port
    if let Some(p) = config.sport {
        msg.attributes.push(RouteAttribute::Sport(p));
    }

    // Destination port
    if let Some(p) = config.dport {
        msg.attributes.push(RouteAttribute::Dport(p));
    }

    // Flow label
    if let Some(fl) = config.flowlabel {
        msg.attributes.push(RouteAttribute::Flowlabel(fl));
    }

    // Flags
    if config.family == AddressFamily::Inet {
        msg.header.flags |= RouteFlags::LookupTable;
    }
    if config.fib_match {
        msg.header.flags |= RouteFlags::FibMatch;
    }
    if config.notify {
        msg.header.flags |= RouteFlags::Notify;
    }

    Ok(msg)
}

async fn build_link_map(
    handle: &rtnetlink::Handle,
) -> Result<std::collections::HashMap<u32, String>, CliError> {
    let mut link_map = std::collections::HashMap::new();
    let mut links = handle.link().get().execute();
    while let Ok(Some(link)) = links.try_next().await {
        let ifname = link
            .attributes
            .iter()
            .find_map(|attr| {
                if let rtnetlink::packet_route::link::LinkAttribute::IfName(
                    name,
                ) = attr
                {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| format!("if{}", link.header.index));
        link_map.insert(link.header.index, ifname);
    }
    Ok(link_map)
}

async fn resolve_ifindex(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, CliError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device \"{name}\" does not exist"))
    })?;
    Ok(link.header.index)
}
