// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use iproute_rs::{CliError, mac_to_string};
use rtnetlink::{
    LinkHsr, LinkMessageBuilder,
    packet_route::link::{HsrProtocol, InfoHsr, InfoKind, LinkInfo},
};
use serde::Serialize;

use super::parse::{extract_link_info, parse_u8};
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataHsr {
    #[serde(skip)]
    port1_index: Option<u32>,
    #[serde(skip)]
    port2_index: Option<u32>,
    #[serde(skip)]
    interlink_index: Option<u32>,
    #[serde(rename = "slave1", skip_serializing_if = "Option::is_none")]
    port1: Option<String>,
    #[serde(rename = "slave2", skip_serializing_if = "Option::is_none")]
    port2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interlink: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "seq_nr")]
    sequence: Option<u16>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "supervision_addr"
    )]
    supervision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proto: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u8>,
}

impl CliLinkInfoDataHsr {
    pub(crate) fn resolve_link(&mut self, index_2_name: &HashMap<u32, String>) {
        let resolve = |idx: u32| {
            index_2_name
                .get(&idx)
                .cloned()
                .unwrap_or_else(|| format!("if{idx}"))
        };
        self.port1 = self.port1_index.map(resolve);
        self.port2 = self.port2_index.map(resolve);
        self.interlink = self.interlink_index.map(resolve);
    }
}

impl From<&[InfoHsr]> for CliLinkInfoDataHsr {
    fn from(info: &[InfoHsr]) -> Self {
        let mut port1_index = None;
        let mut port2_index = None;
        let mut interlink_index = None;
        let mut sequence = None;
        let mut supervision = None;
        let mut proto = None;
        let mut version = None;

        for nla in info {
            match nla {
                InfoHsr::Port1(v) => port1_index = Some(*v),
                InfoHsr::Port2(v) => port2_index = Some(*v),
                InfoHsr::Interlink(v) => interlink_index = Some(*v),
                InfoHsr::SeqNr(v) => sequence = Some(*v),
                InfoHsr::SupervisionAddr(v) => {
                    supervision = Some(mac_to_string(v))
                }
                InfoHsr::Protocol(HsrProtocol::Hsr) => proto = Some(0),
                InfoHsr::Protocol(HsrProtocol::Prp) => proto = Some(1),
                InfoHsr::Protocol(HsrProtocol::Other(v)) => proto = Some(*v),
                InfoHsr::Version(v) => version = Some(*v),
                _ => (),
            }
        }

        Self {
            port1_index,
            port2_index,
            interlink_index,
            port1: None,
            port2: None,
            interlink: None,
            sequence,
            supervision,
            proto,
            version,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataHsr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(v) = &self.port1 {
            write!(f, "slave1 {v}")?;
        }
        if let Some(v) = &self.port2 {
            write!(f, " slave2 {v}")?;
        }
        if let Some(v) = &self.interlink {
            write!(f, " interlink {v}")?;
        }
        if let Some(v) = self.sequence {
            write!(f, " sequence {v}")?;
        }
        if let Some(v) = &self.supervision {
            write!(f, " supervision {v}")?;
        }
        if let Some(v) = self.proto {
            write!(f, " proto {v}")?;
        }
        if let Some(v) = self.version {
            write!(f, " version {v}")?;
        }
        Ok(())
    }
}

fn apply_hsr_args<'a>(
    mut builder: LinkMessageBuilder<LinkHsr>,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<LinkMessageBuilder<LinkHsr>, CliError> {
    while let Some(key) = iter.next() {
        let Some(v) = iter.next() else {
            return Err(CliError::from(format!("hsr {key} requires a value")));
        };
        match key {
            "supervision" => {
                builder = builder.supervision(parse_u8(v, "supervision")?);
            }
            "version" => {
                builder = builder.version(parse_u8(v, "version")?);
            }
            "proto" => {
                let proto: u8 = parse_u8(v, "proto")?;
                builder = builder.protocol(proto.into());
            }
            _ => {
                return Err(CliError::from(format!(
                    "Unknown hsr argument: {key}"
                )));
            }
        }
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) async fn apply_hsr(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkHsr>, CliError> {
        let mut builder = LinkHsr::new(&self.name);
        let mut has_port1 = false;
        let mut has_port2 = false;

        let mut remaining: Vec<&str> = Vec::new();
        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            match key.as_str() {
                "slave1" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "hsr slave1 requires a value",
                        ));
                    };
                    let ifindex = self.get_ifindex_by_name(handle, v).await?;
                    builder = builder.port1(ifindex);
                    has_port1 = true;
                }
                "slave2" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "hsr slave2 requires a value",
                        ));
                    };
                    let ifindex = self.get_ifindex_by_name(handle, v).await?;
                    builder = builder.port2(ifindex);
                    has_port2 = true;
                }
                "interlink" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "hsr interlink requires a value",
                        ));
                    };
                    let ifindex = self.get_ifindex_by_name(handle, v).await?;
                    builder = builder.interlink(ifindex);
                }
                _ => {
                    remaining.push(key);
                    if let Some(v) = iter.next() {
                        remaining.push(v);
                    }
                }
            }
        }

        if !has_port1 || !has_port2 {
            return Err(CliError::from(
                "hsr requires slave1 and slave2 arguments",
            ));
        }

        let mut remaining_iter = remaining.into_iter();
        builder = apply_hsr_args(builder, &mut remaining_iter)?;
        Ok(builder)
    }
}

pub(crate) fn build_hsr_entries(
    args: &[String],
) -> Result<Vec<LinkInfo>, CliError> {
    let builder =
        LinkMessageBuilder::<LinkHsr>::new_with_info_kind(InfoKind::Hsr);
    let mut iter = args.iter().map(|s| s.as_str());
    let builder = apply_hsr_args(builder, &mut iter)?;
    Ok(extract_link_info(builder.build()))
}

pub(crate) struct IfaceHsr;

impl IfaceHsr {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage:        ip link add name NAME type hsr slave1 SLAVE1-IF slave2 SLAVE2-IF
        [ interlink INTERLINK-IF ] [ supervision ADDR-BYTE ] [ version VERSION ]
        [ proto PROTOCOL ]

NAME
        name of new hsr device (e.g. hsr0)
SLAVE1-IF, SLAVE2-IF
        the two slave devices bound to the HSR device
INTERLINK-IF
        the interlink device bound to the HSR network to connect SAN device(s)
ADDR-BYTE
        0-255; the last byte of the multicast address used for HSR supervision
        frames (default = 0)
VERSION
        0,1; the protocol version to be used. (default = 0)
PROTOCOL
        0 - HSR, 1 - PRP. (default = 0 - HSR)
"
    }
}
