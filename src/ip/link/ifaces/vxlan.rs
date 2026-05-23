// SPDX-License-Identifier: MIT

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use rtnetlink::packet_route::link::InfoVxlan;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataVxlan {
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group6: Option<Ipv6Addr>,
    #[serde(skip_serializing)]
    link: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "link")]
    link_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local6: Option<Ipv6Addr>,
    tos: u8,
    ttl: u8,
    label: u32,
    learning: bool,
    ageing: u32,
    limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    port_range: Option<(u16, u16)>,
    proxy: bool,
    rsc: bool,
    l2miss: bool,
    l3miss: bool,
    collect_metadata: bool,
    port: u16,
    udp_csum: bool,
    udp_zero_csum6_tx: bool,
    udp_zero_csum6_rx: bool,
    remcsum_tx: bool,
    remcsum_rx: bool,
    gbp: bool,
    gpe: bool,
    remcsum_no_partial: bool,
    ttl_inherit: bool,
    df: u8,
    vnifilter: bool,
    localbypass: bool,
    label_policy: u32,
    reserved_bits: u64,
}

impl CliLinkInfoDataVxlan {
    pub(crate) fn resolve_link(&mut self, index_2_name: &HashMap<u32, String>) {
        if let Some(idx) = self.link
            && let Some(name) = index_2_name.get(&idx)
        {
            self.link_name = Some(name.clone());
        }
    }
}

impl From<&[InfoVxlan]> for CliLinkInfoDataVxlan {
    fn from(info: &[InfoVxlan]) -> Self {
        let mut id = 0;
        let mut group = None;
        let mut group6 = None;
        let mut link = None;
        let mut local = None;
        let mut local6 = None;
        let mut tos = 0;
        let mut ttl = 0;
        let mut label = 0;
        let mut learning = true;
        let mut ageing = 300;
        let mut limit = 0;
        let mut port_range = None;
        let mut proxy = false;
        let mut rsc = false;
        let mut l2miss = false;
        let mut l3miss = false;
        let mut collect_metadata = false;
        let mut port = 0;
        let mut udp_csum = true;
        let mut udp_zero_csum6_tx = false;
        let mut udp_zero_csum6_rx = false;
        let mut remcsum_tx = false;
        let mut remcsum_rx = false;
        let mut gbp = false;
        let mut gpe = false;
        let mut remcsum_no_partial = false;
        let mut ttl_inherit = false;
        let mut df = 0;
        let mut vnifilter = false;
        let mut localbypass = true;
        let mut label_policy = 0;
        let mut reserved_bits = 0;

        for nla in info {
            match nla {
                InfoVxlan::Id(v) => id = *v,
                InfoVxlan::Group(v) => group = Some(*v),
                InfoVxlan::Group6(v) => group6 = Some(*v),
                InfoVxlan::Link(v) => link = Some(*v),
                InfoVxlan::Local(v) => local = Some(*v),
                InfoVxlan::Local6(v) => local6 = Some(*v),
                InfoVxlan::Tos(v) => tos = *v,
                InfoVxlan::Ttl(v) => ttl = *v,
                InfoVxlan::Label(v) => label = *v,
                InfoVxlan::Learning(v) => learning = *v,
                InfoVxlan::Ageing(v) => ageing = *v,
                InfoVxlan::Limit(v) => limit = *v,
                InfoVxlan::PortRange(v) => port_range = Some(*v),
                InfoVxlan::Proxy(v) => proxy = *v,
                InfoVxlan::Rsc(v) => rsc = *v,
                InfoVxlan::L2Miss(v) => l2miss = *v,
                InfoVxlan::L3Miss(v) => l3miss = *v,
                InfoVxlan::CollectMetadata(v) => collect_metadata = *v,
                InfoVxlan::Port(v) => port = *v,
                InfoVxlan::UDPCsum(v) => udp_csum = *v,
                InfoVxlan::UDPZeroCsumTX(v) => udp_zero_csum6_tx = *v,
                InfoVxlan::UDPZeroCsumRX(v) => udp_zero_csum6_rx = *v,
                InfoVxlan::RemCsumTX(v) => remcsum_tx = *v,
                InfoVxlan::RemCsumRX(v) => remcsum_rx = *v,
                InfoVxlan::Gbp(v) => gbp = *v,
                InfoVxlan::Gpe(v) => gpe = *v,
                InfoVxlan::RemCsumNoPartial(v) => remcsum_no_partial = *v,
                InfoVxlan::TtlInherit(v) => ttl_inherit = *v,
                InfoVxlan::Df(v) => df = *v,
                InfoVxlan::Vnifilter(v) => vnifilter = *v,
                InfoVxlan::Localbypass(v) => localbypass = *v,
                InfoVxlan::LabelPolicy(v) => label_policy = *v,
                InfoVxlan::ReservedBits(v) => reserved_bits = *v,
                _ => (),
            }
        }

        Self {
            id,
            group,
            group6,
            link,
            link_name: None,
            local,
            local6,
            tos,
            ttl,
            label,
            learning,
            ageing,
            limit,
            port_range,
            proxy,
            rsc,
            l2miss,
            l3miss,
            collect_metadata,
            port,
            udp_csum,
            udp_zero_csum6_tx,
            udp_zero_csum6_rx,
            remcsum_tx,
            remcsum_rx,
            gbp,
            gpe,
            remcsum_no_partial,
            ttl_inherit,
            df,
            vnifilter,
            localbypass,
            label_policy,
            reserved_bits,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataVxlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "id {} ", self.id)?;
        if let Some(v) = self.group {
            write!(f, "group {v} ")?;
        }
        if let Some(v) = self.group6 {
            write!(f, "group6 {v} ")?;
        }
        if let Some(v) = self.local {
            write!(f, "local {v} ")?;
        }
        if let Some(v) = self.local6 {
            write!(f, "local6 {v} ")?;
        }
        if let Some(v) = &self.link_name {
            write!(f, "dev {v} ")?;
        } else if let Some(v) = self.link {
            write!(f, "dev if{v} ")?;
        }
        if let Some((low, high)) = self.port_range {
            write!(f, "srcport {low} {high} ")?;
        }
        if self.port > 0 {
            write!(f, "dstport {} ", self.port)?;
        }
        if self.ttl == 0 {
            write!(f, "ttl auto ")?;
        } else {
            write!(f, "ttl {} ", self.ttl)?;
        }
        if self.tos > 0 {
            write!(f, "tos {} ", self.tos)?;
        }
        if self.label > 0 {
            write!(f, "label 0x{:x} ", self.label)?;
        }
        if !self.learning {
            write!(f, "nolearning ")?;
        }
        write!(f, "ageing {} ", self.ageing)?;
        if self.limit > 0 {
            write!(f, "limit {} ", self.limit)?;
        }
        if self.proxy {
            write!(f, "proxy ")?;
        }
        if self.rsc {
            write!(f, "rsc ")?;
        }
        if self.l2miss {
            write!(f, "l2miss ")?;
        }
        if self.l3miss {
            write!(f, "l3miss ")?;
        }
        if self.collect_metadata {
            write!(f, "collect_md ")?;
        }
        if !self.udp_csum {
            write!(f, "noudpcsum ")?;
        }
        if self.udp_zero_csum6_tx {
            write!(f, "udp6zerocsumtx ")?;
        }
        if self.udp_zero_csum6_rx {
            write!(f, "udp6zerocsumrx ")?;
        }
        if self.remcsum_tx {
            write!(f, "remcsumtx ")?;
        }
        if self.remcsum_rx {
            write!(f, "remcsumrx ")?;
        }
        if self.gbp {
            write!(f, "gbp ")?;
        }
        if self.gpe {
            write!(f, "gpe ")?;
        }
        if self.remcsum_no_partial {
            write!(f, "remcsum_nopartial ")?;
        }
        if self.ttl_inherit {
            write!(f, "ttl_inherit ")?;
        }
        if self.df == 1 {
            write!(f, "df set ")?;
        } else if self.df == 2 {
            write!(f, "df inherit ")?;
        }
        if self.vnifilter {
            write!(f, "vnifilter ")?;
        }
        if !self.localbypass {
            write!(f, "nolocalbypass ")?;
        }
        if self.label_policy > 0 {
            write!(f, "label_policy {} ", self.label_policy)?;
        }
        if self.reserved_bits > 0 {
            write!(f, "reserved_bits 0x{:x}", self.reserved_bits)?;
        }
        Ok(())
    }
}
