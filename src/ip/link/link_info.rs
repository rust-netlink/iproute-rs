// SPDX-License-Identifier: MIT

use std::{collections::HashMap, convert::TryFrom};

use rtnetlink::packet_route::link::{InfoData, InfoPortData, LinkInfo};
use serde::Serialize;

use super::ifaces::{
    bareudp::CliLinkInfoDataBareudp,
    bridge::{CliLinkInfoDataBridge, CliLinkInfoDataBridgePort},
    can::CliLinkInfoDataCan,
    dsa::CliLinkInfoDataDsa,
    geneve::CliLinkInfoDataGeneve,
    gre::CliLinkInfoDataGre,
    gtp::CliLinkInfoDataGtp,
    hsr::CliLinkInfoDataHsr,
    iptun::CliLinkInfoDataIpIp,
    ipvlan::{CliLinkInfoDataIpVlan, CliLinkInfoDataIpVtap},
    mac_vlan::{CliLinkInfoDataMacVlan, CliLinkInfoDataMacVtap},
    macsec::CliLinkInfoDataMacSec,
    netkit::CliLinkInfoDataNetkit,
    rmnet::CliLinkInfoDataRmNet,
    veth::CliLinkInfoDataVeth,
    vlan::CliLinkInfoDataVlan,
    vrf::{CliLinkInfoDataVrf, CliLinkInfoDataVrfPort},
    vxlan::CliLinkInfoDataVxlan,
    wwan::CliLinkInfoDataWwan,
    xfrm::CliLinkInfoDataXfrm,
};
use crate::link::ifaces::bond::{CliLinkInfoDataBond, CliLinkInfoDataBondPort};

#[derive(Serialize)]
pub(super) struct CliLinkInfo {
    pub(super) info_kind: String,
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

impl CliLinkInfo {
    pub(crate) fn resolve_link(&mut self, index_2_name: &HashMap<u32, String>) {
        if let Some(ref mut data) = self.info_data {
            data.resolve_link(index_2_name);
        }
    }
}

impl std::fmt::Display for CliLinkInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\n    ")?;
        write!(f, "{}", self.info_kind)?;
        if let Some(data) = &self.info_data {
            write!(f, " ")?;
            write!(f, "{data}")?;
        }

        if let Some(port_kind) = &self.info_port_kind {
            if self.info_kind == "dummy" {
                // iproute2 add a trailing space for dummy interface when it is
                // port, do the same to pass the tests
                write!(f, " ")?;
            }
            write!(f, "\n    {}_slave", port_kind)?;
            if let Some(port_data) = &self.info_port_data {
                write!(f, " {port_data}")?;
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum CliLinkInfoData {
    BareUdp(Box<CliLinkInfoDataBareudp>),
    Can(Box<CliLinkInfoDataCan>),
    Dsa(Box<CliLinkInfoDataDsa>),
    Netkit(Box<CliLinkInfoDataNetkit>),
    Vlan(Box<CliLinkInfoDataVlan>),
    Veth(Box<CliLinkInfoDataVeth>),
    Bridge(Box<CliLinkInfoDataBridge>),
    Bond(Box<CliLinkInfoDataBond>),
    Vxlan(Box<CliLinkInfoDataVxlan>),
    Hsr(Box<CliLinkInfoDataHsr>),
    IpIp(Box<CliLinkInfoDataIpIp>),
    IpVlan(Box<CliLinkInfoDataIpVlan>),
    IpVtap(Box<CliLinkInfoDataIpVtap>),
    MacVlan(Box<CliLinkInfoDataMacVlan>),
    MacVtap(Box<CliLinkInfoDataMacVtap>),
    MacSec(Box<CliLinkInfoDataMacSec>),
    Geneve(Box<CliLinkInfoDataGeneve>),
    Gtp(Box<CliLinkInfoDataGtp>),
    GreTun(Box<CliLinkInfoDataGre>),
    GreTap(Box<CliLinkInfoDataGre>),
    GreTun6(Box<CliLinkInfoDataGre>),
    GreTap6(Box<CliLinkInfoDataGre>),
    ErSpan(Box<CliLinkInfoDataGre>),
    Ip6ErSpan(Box<CliLinkInfoDataGre>),
    Vrf(Box<CliLinkInfoDataVrf>),
    Wwan(Box<CliLinkInfoDataWwan>),
    Xfrm(Box<CliLinkInfoDataXfrm>),
    RmNet(Box<CliLinkInfoDataRmNet>),
}

impl TryFrom<&InfoData> for CliLinkInfoData {
    type Error = ();

    fn try_from(info_data: &InfoData) -> Result<CliLinkInfoData, ()> {
        match info_data {
            InfoData::Bridge(v) => {
                Ok(Self::Bridge(Box::new(v.as_slice().into())))
            }
            InfoData::Vlan(v) => Ok(Self::Vlan(Box::new(v.as_slice().into()))),
            InfoData::Veth(v) => Ok(Self::Veth(Box::new(v.into()))),
            InfoData::Bond(v) => Ok(Self::Bond(Box::new(v.as_slice().into()))),
            InfoData::Vxlan(v) => {
                Ok(Self::Vxlan(Box::new(v.as_slice().into())))
            }
            InfoData::Hsr(v) => Ok(Self::Hsr(Box::new(v.as_slice().into()))),
            InfoData::IpTunnel(v) => {
                Ok(Self::IpIp(Box::new(v.as_slice().into())))
            }
            InfoData::IpVlan(v) => {
                Ok(Self::IpVlan(Box::new(v.as_slice().into())))
            }
            InfoData::IpVtap(v) => {
                Ok(Self::IpVtap(Box::new(v.as_slice().into())))
            }
            InfoData::MacVlan(v) => {
                Ok(Self::MacVlan(Box::new(v.as_slice().into())))
            }
            InfoData::MacVtap(v) => {
                Ok(Self::MacVtap(Box::new(v.as_slice().into())))
            }
            InfoData::Netkit(v) => {
                Ok(Self::Netkit(Box::new(v.as_slice().into())))
            }
            InfoData::Vrf(v) => Ok(Self::Vrf(Box::new(v.as_slice().into()))),
            InfoData::MacSec(v) => {
                Ok(Self::MacSec(Box::new(v.as_slice().into())))
            }
            InfoData::Geneve(v) => {
                Ok(Self::Geneve(Box::new(v.as_slice().into())))
            }
            InfoData::Gtp(v) => Ok(Self::Gtp(Box::new(v.as_slice().into()))),
            InfoData::GreTun(v) => {
                Ok(Self::GreTun(Box::new(v.as_slice().into())))
            }
            InfoData::GreTap(v) => {
                Ok(Self::GreTap(Box::new(v.as_slice().into())))
            }
            InfoData::GreTun6(v) => {
                Ok(Self::GreTun6(Box::new(v.as_slice().into())))
            }
            InfoData::GreTap6(v) => {
                Ok(Self::GreTap6(Box::new(v.as_slice().into())))
            }
            InfoData::ErSpan(v) => {
                Ok(Self::ErSpan(Box::new(v.as_slice().into())))
            }
            InfoData::Ip6ErSpan(v) => {
                Ok(Self::Ip6ErSpan(Box::new(v.as_slice().into())))
            }
            InfoData::Xfrm(v) => Ok(Self::Xfrm(Box::new(v.as_slice().into()))),
            InfoData::RmNet(v) => {
                Ok(Self::RmNet(Box::new(v.as_slice().into())))
            }
            InfoData::BareUdp(v) => {
                Ok(Self::BareUdp(Box::new(v.as_slice().into())))
            }
            InfoData::Wwan(v) => Ok(Self::Wwan(Box::new(v.as_slice().into()))),
            InfoData::Can(v) => Ok(Self::Can(Box::new(v.as_slice().into()))),
            InfoData::Dsa(v) => Ok(Self::Dsa(Box::new(v.as_slice().into()))),
            _ => Err(()),
        }
    }
}

impl CliLinkInfoData {
    pub(crate) fn resolve_link(&mut self, index_2_name: &HashMap<u32, String>) {
        match self {
            Self::Dsa(dsa) => dsa.resolve_link(index_2_name),
            Self::Vxlan(vxlan) => vxlan.resolve_link(index_2_name),
            Self::Hsr(hsr) => hsr.resolve_link(index_2_name),
            Self::IpIp(ipip) => ipip.resolve_link(index_2_name),
            Self::GreTun(gre) => gre.resolve_link(index_2_name),
            Self::GreTap(gre) => gre.resolve_link(index_2_name),
            Self::GreTun6(gre) => gre.resolve_link(index_2_name),
            Self::GreTap6(gre) => gre.resolve_link(index_2_name),
            Self::ErSpan(gre) => gre.resolve_link(index_2_name),
            Self::Ip6ErSpan(gre) => gre.resolve_link(index_2_name),
            _ => (),
        }
    }
}

impl std::fmt::Display for CliLinkInfoData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliLinkInfoData::BareUdp(v) => write!(f, "{v}"),
            CliLinkInfoData::Can(v) => write!(f, "{v}"),
            CliLinkInfoData::Dsa(v) => write!(f, "{v}"),
            CliLinkInfoData::Netkit(v) => write!(f, "{v}"),
            CliLinkInfoData::Vlan(v) => write!(f, "{v}"),
            CliLinkInfoData::Veth(v) => write!(f, "{v}"),
            CliLinkInfoData::Bridge(v) => write!(f, "{v}"),
            CliLinkInfoData::Bond(v) => write!(f, "{v}"),
            CliLinkInfoData::Vxlan(v) => write!(f, "{v}"),
            CliLinkInfoData::Hsr(v) => write!(f, "{v}"),
            CliLinkInfoData::IpIp(v) => write!(f, "{v}"),
            CliLinkInfoData::IpVlan(v) => write!(f, "{v}"),
            CliLinkInfoData::IpVtap(v) => write!(f, "{v}"),
            CliLinkInfoData::MacVlan(v) => write!(f, "{v}"),
            CliLinkInfoData::MacVtap(v) => write!(f, "{v}"),
            CliLinkInfoData::MacSec(v) => write!(f, "{v}"),
            CliLinkInfoData::Geneve(v) => write!(f, "{v}"),
            CliLinkInfoData::Gtp(v) => write!(f, "{v}"),
            CliLinkInfoData::GreTun(v) => write!(f, "{v}"),
            CliLinkInfoData::GreTap(v) => write!(f, "{v}"),
            CliLinkInfoData::GreTun6(v) => write!(f, "{v}"),
            CliLinkInfoData::GreTap6(v) => write!(f, "{v}"),
            CliLinkInfoData::ErSpan(v) => write!(f, "{v}"),
            CliLinkInfoData::Ip6ErSpan(v) => write!(f, "{v}"),
            CliLinkInfoData::Vrf(v) => write!(f, "{v}"),
            CliLinkInfoData::Wwan(v) => write!(f, "{v}"),
            CliLinkInfoData::Xfrm(v) => write!(f, "{v}"),
            CliLinkInfoData::RmNet(v) => write!(f, "{v}"),
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum CliLinkInfoPortData {
    BridgePort(CliLinkInfoDataBridgePort),
    BondPort(CliLinkInfoDataBondPort),
    VrfPort(CliLinkInfoDataVrfPort),
}

impl std::fmt::Display for CliLinkInfoPortData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliLinkInfoPortData::BridgePort(v) => write!(f, "{v}"),
            CliLinkInfoPortData::BondPort(v) => write!(f, "{v}"),
            CliLinkInfoPortData::VrfPort(v) => write!(f, "{v}"),
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
            InfoPortData::BondPort(v) => {
                Ok(Self::BondPort(v.as_slice().into()))
            }
            InfoPortData::VrfPort(v) => Ok(Self::VrfPort(v.as_slice().into())),
            _ => Err(()),
        }
    }
}
