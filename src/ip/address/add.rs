// SPDX-License-Identifier: MIT

use std::net::{IpAddr, Ipv4Addr};

use futures_util::TryStreamExt;
use rtnetlink::packet_route::address::{
    AddressAttribute, AddressFlags, AddressProtocol, AddressScope, CacheInfo,
};

use crate::CliError;

pub(crate) async fn handle_add(opts: &[String]) -> Result<(), CliError> {
    let Some((addr, opts)) = opts.split_first() else {
        return Err(CliError::from("missing address argument"));
    };

    let (addr_str, prefix_len_str) = addr.split_once('/').ok_or_else(|| {
        CliError::from(format!("invalid address format: {addr}"))
    })?;

    let address: IpAddr = addr_str
        .parse()
        .map_err(|_| CliError::from(format!("invalid address: {addr_str}")))?;
    let prefix_len: u8 = prefix_len_str.parse().map_err(|_| {
        CliError::from(format!("invalid prefix length: {prefix_len_str}"))
    })?;

    let mut dev: Option<String> = None;
    let mut label: Option<String> = None;
    let mut scope: Option<AddressScope> = None;
    let mut broadcast: Option<Ipv4Addr> = None;
    let mut valid_lft: Option<u32> = None;
    let mut preferred_lft: Option<u32> = None;
    let mut proto: Option<AddressProtocol> = None;
    let mut flags = AddressFlags::empty();

    let mut iter = opts.iter();
    while let Some(key) = iter.next() {
        match key.as_str() {
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
            "scope" => {
                scope = Some(parse_scope(iter.next().ok_or_else(|| {
                    CliError::from("\"scope\" argument requires a value")
                })?)?);
            }
            "broadcast" | "brd" => {
                let val = iter.next().ok_or_else(|| {
                    CliError::from("\"broadcast\" argument requires a value")
                })?;
                broadcast = Some(val.parse::<Ipv4Addr>().map_err(|_| {
                    CliError::from(format!("invalid broadcast address: {val}"))
                })?);
            }
            "valid_lft" => {
                valid_lft =
                    Some(parse_lifetime(iter.next().ok_or_else(|| {
                        CliError::from(
                            "\"valid_lft\" argument requires a value",
                        )
                    })?)?);
            }
            "preferred_lft" => {
                preferred_lft =
                    Some(parse_lifetime(iter.next().ok_or_else(|| {
                        CliError::from(
                            "\"preferred_lft\" argument requires a value",
                        )
                    })?)?);
            }
            "proto" => {
                proto =
                    Some(parse_protocol(iter.next().ok_or_else(|| {
                        CliError::from("\"proto\" argument requires a value")
                    })?)?);
            }
            "home" => flags |= AddressFlags::Homeaddress,
            "mngtmpaddr" => flags |= AddressFlags::Managetempaddr,
            "nodad" => flags |= AddressFlags::Nodad,
            "optimistic" => flags |= AddressFlags::Optimistic,
            "noprefixroute" => flags |= AddressFlags::Noprefixroute,
            "autojoin" => flags |= AddressFlags::Mcautojoin,
            _ => {
                return Err(CliError::from(format!("unknown argument: {key}")));
            }
        }
    }

    let dev = dev.ok_or_else(|| {
        CliError::from("required \"dev\" argument is missing")
    })?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(dev.clone()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device \"{dev}\" does not exist"))
    })?;

    let index = link.header.index;

    let mut req = handle.address().add(index, address, prefix_len);
    let msg = req.message_mut();

    if let Some(label) = label {
        msg.attributes.push(AddressAttribute::Label(label));
    }

    if let Some(scope) = scope {
        msg.header.scope = scope;
    }

    if let Some(broadcast) = broadcast {
        msg.attributes.push(AddressAttribute::Broadcast(broadcast));
    }

    if !flags.is_empty() {
        msg.attributes.push(AddressAttribute::Flags(flags));
    }

    if valid_lft.is_some() || preferred_lft.is_some() {
        let mut ci = CacheInfo::default();
        ci.ifa_preferred = preferred_lft.unwrap_or(u32::MAX);
        ci.ifa_valid = valid_lft.unwrap_or(u32::MAX);
        msg.attributes.push(AddressAttribute::CacheInfo(ci));
    }

    if let Some(proto) = proto {
        msg.attributes.push(AddressAttribute::Protocol(proto));
    }

    req.execute()
        .await
        .map_err(|e| CliError::from(format!("{e}")))
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
}
