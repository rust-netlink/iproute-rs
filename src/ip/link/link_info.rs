// SPDX-License-Identifier: MIT

use std::convert::TryFrom;

use rtnetlink::packet_route::link::{InfoData, InfoPortData, LinkInfo};
use serde::Serialize;

use super::ifaces::{
    bridge::{CliLinkInfoDataBridge, CliLinkInfoDataBridgePort},
    vlan::CliLinkInfoDataVlan,
};

#[derive(Serialize)]
pub(super) struct CliLinkInfo {
    info_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    info_data: Option<CliLinkInfoData>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "info_slave_kind"
    )]
    info_port_kind: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "info_slave_data"
    )]
    info_port_data: Option<CliLinkInfoPortData>,
}

impl TryFrom<&[LinkInfo]> for CliLinkInfo {
    type Error = ();

    fn try_from(infos: &[LinkInfo]) -> Result<Self, ()> {
        let mut info_kind = String::new();
        let mut info_data = None;
        let mut info_port_kind = None;
        let mut info_port_data = None;
        for info in infos {
            match info {
                LinkInfo::Kind(v) => {
                    info_kind = v.to_string();
                }
                LinkInfo::Data(v) => {
                    info_data = v.try_into().ok();
                }
                LinkInfo::PortKind(v) => info_port_kind = Some(v.to_string()),
                LinkInfo::PortData(v) => info_port_data = v.try_into().ok(),
                _ => (),
            }
        }
        if info_kind.is_empty() {
            Err(())
        } else {
            Ok(Self {
                info_kind,
                info_data,
                info_port_kind,
                info_port_data,
            })
        }
    }
}

impl std::fmt::Display for CliLinkInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\n    ")?;
        write!(f, "{} ", self.info_kind)?;
        if let Some(data) = &self.info_data {
            write!(f, "{data} ")?;
        }

        if let Some(port_kind) = &self.info_port_kind {
            write!(f, "\n    {}_slave ", port_kind)?;
            if let Some(port_data) = &self.info_port_data {
                write!(f, "{port_data} ")?;
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum CliLinkInfoData {
    Vlan(Box<CliLinkInfoDataVlan>),
    Bridge(Box<CliLinkInfoDataBridge>),
}

impl TryFrom<&InfoData> for CliLinkInfoData {
    type Error = ();

    fn try_from(info_data: &InfoData) -> Result<CliLinkInfoData, ()> {
        match info_data {
            InfoData::Bridge(v) => {
                Ok(Self::Bridge(Box::new(v.as_slice().into())))
            }
            InfoData::Vlan(v) => Ok(Self::Vlan(Box::new(v.as_slice().into()))),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for CliLinkInfoData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliLinkInfoData::Vlan(v) => write!(f, "{v}"),
            CliLinkInfoData::Bridge(v) => write!(f, "{v}"),
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum CliLinkInfoPortData {
    BridgePort(CliLinkInfoDataBridgePort),
}

impl std::fmt::Display for CliLinkInfoPortData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliLinkInfoPortData::BridgePort(v) => write!(f, "{v}"),
        }
    }
}

impl TryFrom<&InfoPortData> for CliLinkInfoPortData {
    type Error = ();

    fn try_from(info_data: &InfoPortData) -> Result<CliLinkInfoPortData, ()> {
        match info_data {
            InfoPortData::BridgePort(v) => {
                Ok(Self::BridgePort(v.as_slice().into()))
            }
            _ => Err(()),
        }
    }
}
