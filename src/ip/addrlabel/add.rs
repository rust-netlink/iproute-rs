// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use futures_util::TryStreamExt;
use iproute_rs::CliError;
use rtnetlink::{
    IpVersion,
    packet_route::{
        AddressFamily,
        addrlabel::{AddrLabelAttribute, AddrLabelMessage},
    },
};

use super::show::resolve_family;

struct AddrLabelConfig {
    address: IpAddr,
    prefix_len: u8,
    dev: Option<String>,
    label: u32,
}

impl AddrLabelConfig {
    fn parse(opts: &[String]) -> Result<Self, CliError> {
        let mut prefix: Option<(IpAddr, u8)> = None;
        let mut dev: Option<String> = None;
        let mut label: Option<u32> = None;

        // Like iproute2, arguments which are not recognized are ignored.
        let mut iter = opts.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "prefix" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"prefix\" argument requires a value")
                    })?;
                    let (address, prefix_len) = parse_prefix(val)?;
                    prefix = Some((
                        address,
                        prefix_len.unwrap_or_else(|| {
                            if address.is_ipv6() { 128 } else { 32 }
                        }),
                    ));
                }
                "dev" => {
                    dev = Some(
                        iter.next()
                            .ok_or_else(|| {
                                CliError::from(
                                    "\"dev\" argument requires a value",
                                )
                            })?
                            .to_string(),
                    );
                }
                "label" => {
                    let val = iter.next().ok_or_else(|| {
                        CliError::from("\"label\" argument requires a value")
                    })?;
                    label = Some(parse_label(val)?);
                }
                _ => {}
            }
        }

        let (address, prefix_len) = prefix.ok_or_else(|| {
            CliError::from(
                "Not enough information: \"prefix\" argument is required.",
            )
        })?;
        let label = label.ok_or_else(|| {
            CliError::from(
                "Not enough information: \"label\" argument is required.",
            )
        })?;

        Ok(Self {
            address,
            prefix_len,
            dev,
            label,
        })
    }
}

fn parse_prefix(s: &str) -> Result<(IpAddr, Option<u8>), CliError> {
    if let Some((addr_str, plen_str)) = s.split_once('/') {
        let addr = addr_str.parse::<IpAddr>().map_err(|_| {
            CliError::from(format!("invalid address: {addr_str}"))
        })?;
        let plen = plen_str.parse::<u8>().map_err(|_| {
            CliError::from(format!("invalid prefix length: {plen_str}"))
        })?;
        Ok((addr, Some(plen)))
    } else {
        let addr = s
            .parse::<IpAddr>()
            .map_err(|_| CliError::from(format!("invalid address: {s}")))?;
        Ok((addr, None))
    }
}

/// iproute2 `get_u32()` uses base 0 and rejects `0xffffffff` as label.
fn parse_label(s: &str) -> Result<u32, CliError> {
    let (radix, digits) = if let Some(hex) =
        s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
    {
        (16, hex)
    } else if s.len() > 1 && s.starts_with('0') {
        (8, &s[1..])
    } else {
        (10, s)
    };
    let label = u32::from_str_radix(digits, radix)
        .map_err(|_| CliError::from(format!("invalid label: {s}")))?;
    if label == u32::MAX {
        return Err(CliError::from(format!("invalid label: {s}")));
    }
    Ok(label)
}

async fn resolve_ifindex(
    handle: &rtnetlink::Handle,
    dev: Option<&str>,
) -> Result<u32, CliError> {
    let Some(dev) = dev else {
        return Ok(0);
    };
    let mut links = handle.link().get().match_name(dev.to_string()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device \"{dev}\" does not exist.").as_str())
    })?;
    Ok(link.header.index)
}

pub(crate) async fn handle_add(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    let config = AddrLabelConfig::parse(opts)?;
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    let index = resolve_ifindex(&handle, config.dev.as_deref()).await?;

    handle
        .addrlabel()
        .add()
        .family(resolve_family(preferred_family))
        .address(config.address)
        .prefix_len(config.prefix_len)
        .index(index)
        .label(config.label)
        .execute()
        .await?;

    Ok(())
}

pub(crate) async fn handle_delete(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    let config = AddrLabelConfig::parse(opts)?;
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    let index = resolve_ifindex(&handle, config.dev.as_deref()).await?;

    handle
        .addrlabel()
        .del()
        .family(resolve_family(preferred_family))
        .address(config.address)
        .prefix_len(config.prefix_len)
        .index(index)
        .label(config.label)
        .execute()
        .await?;

    Ok(())
}

pub(crate) async fn handle_flush(
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut request = handle.addrlabel().get(IpVersion::V6);
    request.message_mut().header.family = resolve_family(preferred_family);

    let mut labels = request.execute();
    let mut dumped: Vec<AddrLabelMessage> = Vec::new();
    while let Some(nl_msg) = labels.try_next().await? {
        dumped.push(nl_msg);
    }

    for entry in dumped {
        let header = entry.header;
        let mut address = None;
        let mut label = None;
        for nla in entry.attributes {
            match nla {
                AddrLabelAttribute::Address(a) => address = Some(a),
                AddrLabelAttribute::Label(l) => label = Some(l),
                _ => {}
            }
        }
        // iproute2 skips entries without the address attribute.
        let Some(address) = address else {
            continue;
        };
        let mut del_request = handle
            .addrlabel()
            .del()
            .address(address)
            .prefix_len(header.prefix_len)
            .index(header.index);
        if let Some(label) = label {
            del_request = del_request.label(label);
        }
        del_request.execute().await?;
    }

    Ok(())
}
