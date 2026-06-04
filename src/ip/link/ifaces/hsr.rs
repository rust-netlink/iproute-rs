// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use iproute_rs::{CliError, mac_to_string};
use rtnetlink::{
    LinkHsr, LinkMessageBuilder,
    packet_route::link::{HsrProtocol, InfoHsr},
};
use serde::Serialize;

use super::parse::parse_u8;
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

impl LinkBaseConf {
    pub(crate) async fn apply_hsr(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkHsr>, CliError> {
        let mut builder = LinkHsr::new(&self.name);
        let mut has_port1 = false;
        let mut has_port2 = false;

        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            let mut next_val = || {
                iter.next().ok_or_else(|| {
                    CliError::from(format!("hsr {key} requires a value"))
                })
            };
            match key.as_str() {
                "slave1" => {
                    let v = next_val()?;
                    let ifindex = self.get_ifindex_by_name(handle, v).await?;
                    builder = builder.port1(ifindex);
                    has_port1 = true;
                }
                "slave2" => {
                    let v = next_val()?;
                    let ifindex = self.get_ifindex_by_name(handle, v).await?;
                    builder = builder.port2(ifindex);
                    has_port2 = true;
                }
                "interlink" => {
                    let v = next_val()?;
                    let ifindex = self.get_ifindex_by_name(handle, v).await?;
                    builder = builder.interlink(ifindex);
                }
                "supervision" => {
                    let v = next_val()?;
                    builder = builder.supervision(parse_u8(v, "supervision")?);
                }
                "version" => {
                    let v = next_val()?;
                    builder = builder.version(parse_u8(v, "version")?);
                }
                "proto" => {
                    let v = next_val()?;
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

        if !has_port1 || !has_port2 {
            return Err(CliError::from(
                "hsr requires slave1 and slave2 arguments",
            ));
        }

        Ok(builder)
    }
}
