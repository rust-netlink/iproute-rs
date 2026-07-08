// SPDX-License-Identifier: MIT

use std::net::{Ipv4Addr, Ipv6Addr};

use iproute_rs::CliError;
use rtnetlink::{
    LinkGeneve, LinkMessageBuilder,
    packet_route::link::{GeneveDf, InfoGeneve, InfoKind, LinkInfo},
};
use serde::Serialize;

use super::parse::{extract_link_info, parse_u8, parse_u16};
use crate::link::LinkBaseConf;

#[derive(Serialize, Default)]
pub(crate) struct CliLinkInfoDataGeneve {
    #[serde(skip_serializing_if = "is_false")]
    external: bool,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote6: Option<Ipv6Addr>,
    ttl: u8,
    #[serde(skip_serializing_if = "is_false")]
    ttl_inherit: bool,
    tos: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    df: Option<String>,
    label: u32,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_csum: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp6zerocsumtx: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp6zerocsumrx: Option<bool>,
    #[serde(skip_serializing_if = "is_false", rename = "inner_proto_inherit")]
    innerprotoinherit: bool,
}

fn is_false(v: &bool) -> bool {
    !*v
}

impl From<&[InfoGeneve]> for CliLinkInfoDataGeneve {
    fn from(info: &[InfoGeneve]) -> Self {
        let mut external = false;
        let mut id = 0;
        let mut remote = None;
        let mut remote6 = None;
        let mut ttl = 0;
        let mut ttl_inherit = false;
        let mut tos = 0;
        let mut df = None;
        let mut label = 0;
        let mut port = 0;
        let mut udp_csum = None;
        let mut udp6zerocsumtx = None;
        let mut udp6zerocsumrx = None;
        let mut innerprotoinherit = false;

        for nla in info {
            match nla {
                InfoGeneve::Id(v) => id = *v,
                InfoGeneve::Remote(v) => remote = Some(*v),
                InfoGeneve::Remote6(v) => remote6 = Some(*v),
                InfoGeneve::Ttl(v) => ttl = *v,
                InfoGeneve::Tos(v) => tos = *v,
                InfoGeneve::Port(v) => port = *v,
                InfoGeneve::CollectMetadata => external = true,
                InfoGeneve::UdpCsum(v) => udp_csum = Some(*v),
                InfoGeneve::UdpZeroCsum6Tx(v) => udp6zerocsumtx = Some(*v),
                InfoGeneve::UdpZeroCsum6Rx(v) => udp6zerocsumrx = Some(*v),
                InfoGeneve::Label(v) => label = *v,
                InfoGeneve::TtlInherit(v) => ttl_inherit = *v,
                InfoGeneve::Df(v) => df = Some(v.to_string()),
                InfoGeneve::InnerProtoInherit => innerprotoinherit = true,
                _ => (),
            }
        }

        Self {
            external,
            id,
            remote,
            remote6,
            ttl,
            ttl_inherit,
            tos,
            df,
            label,
            port,
            udp_csum,
            udp6zerocsumtx,
            udp6zerocsumrx,
            innerprotoinherit,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataGeneve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.external {
            write!(f, "external ")?;
        }
        write!(f, "id {}", self.id)?;
        if let Some(v) = self.remote {
            write!(f, " remote {v}")?;
        }
        if let Some(v) = &self.remote6 {
            write!(f, " remote {v}")?;
        }
        if self.ttl_inherit {
            write!(f, " ttl inherit")?;
        } else if self.ttl == 0 {
            write!(f, " ttl auto")?;
        } else {
            write!(f, " ttl {}", self.ttl)?;
        }
        if self.tos > 0 {
            if self.tos == 1 {
                write!(f, " tos inherit")?;
            } else {
                write!(f, " tos {:#x}", self.tos)?;
            }
        }
        if let Some(v) = &self.df
            && v != "unset"
        {
            write!(f, " df {v}")?;
        }
        if self.label > 0 {
            write!(f, " flowlabel {:#x}", self.label)?;
        }
        if self.port > 0 {
            write!(f, " dstport {}", self.port)?;
        }
        if let Some(v) = self.udp_csum {
            if !v {
                write!(f, " noudpcsum")?;
            } else {
                write!(f, " udpcsum")?;
            }
        }
        if let Some(v) = self.udp6zerocsumtx {
            if v {
                write!(f, " udp6zerocsumtx")?;
            } else {
                write!(f, " noudp6zerocsumtx")?;
            }
        }
        if let Some(v) = self.udp6zerocsumrx {
            if v {
                write!(f, " udp6zerocsumrx")?;
            } else {
                write!(f, " noudp6zerocsumrx")?;
            }
        }
        if self.innerprotoinherit {
            write!(f, " innerprotoinherit")?;
        }
        Ok(())
    }
}

fn parse_geneve_args<'a>(
    mut builder: LinkMessageBuilder<LinkGeneve>,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<LinkMessageBuilder<LinkGeneve>, CliError> {
    while let Some(key) = iter.next() {
        match key {
            "id" | "vni" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("GENEVE id requires a value"));
                };
                let val: u32 = v.parse().map_err(|_| {
                    CliError::from(format!("Invalid GENEVE id: {v}"))
                })?;
                if val >= 1u32 << 24 {
                    return Err(CliError::from(format!(
                        "Invalid GENEVE id: {v}, must be <= 16777215"
                    )));
                }
                builder = builder.id(val);
            }
            "remote" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "GENEVE remote requires a value",
                    ));
                };
                if let Ok(addr) = v.parse::<Ipv4Addr>() {
                    builder = builder.remote(addr);
                } else if let Ok(addr) = v.parse::<Ipv6Addr>() {
                    builder = builder.remote6(addr);
                } else {
                    return Err(CliError::from(format!(
                        "Invalid GENEVE remote address: {v}"
                    )));
                }
            }
            "ttl" | "hoplimit" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("GENEVE ttl requires a value"));
                };
                if v == "inherit" {
                    builder = builder.ttl_inherit(true);
                } else if v != "auto" {
                    let val: u8 = v.parse().map_err(|_| {
                        CliError::from(format!("Invalid GENEVE ttl: {v}"))
                    })?;
                    builder = builder.ttl(val);
                }
            }
            "tos" | "dsfield" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("GENEVE tos requires a value"));
                };
                if v == "inherit" {
                    builder = builder.tos(1);
                } else {
                    let val: u8 = parse_u8(v, "GENEVE tos")?;
                    builder = builder.tos(val);
                }
            }
            "df" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("GENEVE df requires a value"));
                };
                let val = v.parse::<GeneveDf>().map_err(|e| {
                    CliError::from(format!(
                        "Invalid GENEVE df: {v}, supported: unset, set, \
                         inherit: {e}"
                    ))
                })?;
                builder = builder.df(val);
            }
            "label" | "flowlabel" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "GENEVE label requires a value",
                    ));
                };
                let val: u32 = v.parse().map_err(|_| {
                    CliError::from(format!("Invalid GENEVE label: {v}"))
                })?;
                if val & 0xfff00000 != 0 {
                    return Err(CliError::from(format!(
                        "Invalid GENEVE label: {v}, must be <= 1048575"
                    )));
                }
                builder = builder.label(val);
            }
            "dstport" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "GENEVE dstport requires a value",
                    ));
                };
                let val = parse_u16(v, "GENEVE dstport")?;
                builder = builder.port(val);
            }
            "external" => {
                builder = builder.collect_metadata();
            }
            "noexternal" => {}
            "udpcsum" => {
                builder = builder.udp_csum(true);
            }
            "noudpcsum" => {
                builder = builder.udp_csum(false);
            }
            "udp6zerocsumtx" => {
                builder = builder.udp_zero_csum6_tx(true);
            }
            "noudp6zerocsumtx" => {
                builder = builder.udp_zero_csum6_tx(false);
            }
            "udp6zerocsumrx" => {
                builder = builder.udp_zero_csum6_rx(true);
            }
            "noudp6zerocsumrx" => {
                builder = builder.udp_zero_csum6_rx(false);
            }
            "innerprotoinherit" => {
                builder = builder.inner_proto_inherit();
            }
            _ => {
                return Err(CliError::from(format!(
                    "Unknown GENEVE argument: {key}"
                )));
            }
        }
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) async fn apply_geneve(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkGeneve>, CliError> {
        let link_name = self
            .link
            .as_deref()
            .ok_or_else(|| CliError::from("GENEVE requires link device"))?;

        let link_ifindex = self.get_ifindex_by_name(handle, link_name).await?;

        let builder = LinkMessageBuilder::<LinkGeneve>::new(&self.name)
            .link(link_ifindex);

        let mut iter = self.iface_specific.iter().map(|s| s.as_str());
        let builder = parse_geneve_args(builder, &mut iter)?;

        Ok(builder)
    }
}

pub(crate) struct IfaceGeneve;

impl IfaceGeneve {
    pub(crate) fn build_entries(
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder = LinkMessageBuilder::<LinkGeneve>::new_with_info_kind(
            InfoKind::Geneve,
        );
        let mut iter = args.iter().map(|s| s.as_str());
        let builder = parse_geneve_args(builder, &mut iter)?;
        Ok(extract_link_info(builder.build()))
    }

    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... geneve id VNI
                remote ADDR
                [ ttl TTL ]
                [ tos TOS ]
                [ df DF ]
                [ flowlabel LABEL ]
                [ dstport PORT ]
                [ [no]external ]
                [ [no]udpcsum ]
                [ [no]udp6zerocsumtx ]
                [ [no]udp6zerocsumrx ]
                [ innerprotoinherit ]

Where:        VNI   := 0-16777215
        ADDR  := IP_ADDRESS
        TOS   := { NUMBER | inherit }
        TTL   := { 1..255 | auto | inherit }
        DF    := { unset | set | inherit }
        LABEL := 0-1048575
"
    }
}
