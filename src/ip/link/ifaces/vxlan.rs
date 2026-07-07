// SPDX-License-Identifier: MIT

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use iproute_rs::CliError;
use rtnetlink::{
    LinkMessageBuilder, LinkVxlan,
    packet_route::link::{InfoKind, InfoVxlan, LinkInfo, VxlanDf},
};
use serde::Serialize;

use super::parse::extract_link_info;
use crate::link::LinkBaseConf;

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
    df: Option<String>,
    vnifilter: bool,
    localbypass: bool,
    label_policy: u32,
    reserved_bits: u64,
    mc_route: bool,
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
        let mut df = None;
        let mut vnifilter = false;
        let mut localbypass = true;
        let mut label_policy = 0;
        let mut reserved_bits = 0;
        let mut mc_route = false;

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
                InfoVxlan::Gbp => gbp = true,
                InfoVxlan::Gpe => gpe = true,
                InfoVxlan::RemCsumNoPartial => remcsum_no_partial = true,
                InfoVxlan::TtlInherit(v) => ttl_inherit = *v != 0,
                InfoVxlan::TtlInheritFlag => ttl_inherit = true,
                InfoVxlan::Df(v) => df = Some(v.to_string()),
                InfoVxlan::Vnifilter(v) => vnifilter = *v,
                InfoVxlan::Localbypass(v) => localbypass = *v,
                InfoVxlan::LabelPolicy(v) => label_policy = *v,
                InfoVxlan::ReservedBits(v) => reserved_bits = *v,
                InfoVxlan::McRoute(v) => mc_route = *v,
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
            mc_route,
        }
    }
}

fn write_bool_opt(
    f: &mut std::fmt::Formatter<'_>,
    key: &str,
    val: bool,
) -> std::fmt::Result {
    if val {
        write!(f, " {key}")
    } else {
        write!(f, " no{key}")
    }
}

impl std::fmt::Display for CliLinkInfoDataVxlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "id {}", self.id)?;
        if let Some(v) = self.group {
            write!(f, " group {v}")?;
        }
        if let Some(v) = self.group6 {
            write!(f, " group {v}")?;
        }
        if let Some(v) = self.local {
            write!(f, " local {v}")?;
        }
        if let Some(v) = self.local6 {
            write!(f, " local {v}")?;
        }
        if let Some(v) = &self.link_name {
            write!(f, " dev {v}")?;
        } else if let Some(v) = self.link {
            write!(f, " dev if{v}")?;
        }
        if let Some((low, high)) = self.port_range {
            write!(f, " srcport {low} {high}")?;
        }
        if self.port > 0 {
            write!(f, " dstport {}", self.port)?;
        }
        if self.tos > 0 {
            if self.tos == 1 {
                write!(f, " tos inherit")?;
            } else {
                write!(f, " tos {:#x}", self.tos)?;
            }
        }
        if self.ttl == 0 {
            if self.ttl_inherit {
                write!(f, " ttl inherit")?;
            } else {
                write!(f, " ttl auto")?;
            }
        } else {
            write!(f, " ttl {}", self.ttl)?;
        }
        if let Some(v) = self.df.as_ref()
            && v != "unset"
        {
            write!(f, " df {v}")?;
        }
        if self.label > 0 {
            write!(f, " flowlabel {:#x}", self.label)?;
        }
        if self.ageing == 0 {
            write!(f, " ageing none")?;
        } else {
            write!(f, " ageing {}", self.ageing)?;
        }
        if self.limit > 0 {
            write!(f, " maxaddr {}", self.limit)?;
        }
        if self.reserved_bits > 0 {
            write!(f, " reserved_bits {:#x}", self.reserved_bits)?;
        }
        if self.gbp {
            write!(f, " gbp")?;
        }
        if self.gpe {
            write!(f, " gpe")?;
        }
        if self.remcsum_no_partial {
            write!(f, " remcsum_nopartial")?;
        }
        if self.collect_metadata {
            write_bool_opt(f, "external", true)?;
        }
        if self.vnifilter {
            write_bool_opt(f, "vnifilter", true)?;
        }
        if !self.learning {
            write_bool_opt(f, "learning", false)?;
        }
        if self.proxy {
            write_bool_opt(f, "proxy", true)?;
        }
        if self.rsc {
            write_bool_opt(f, "rsc", true)?;
        }
        if self.l2miss {
            write_bool_opt(f, "l2miss", true)?;
        }
        if self.l3miss {
            write_bool_opt(f, "l3miss", true)?;
        }
        if !self.udp_csum {
            write_bool_opt(f, "udp_csum", false)?;
        }
        if self.udp_zero_csum6_tx {
            write_bool_opt(f, "udp_zero_csum6_tx", true)?;
        }
        if self.udp_zero_csum6_rx {
            write_bool_opt(f, "udp_zero_csum6_rx", true)?;
        }
        if self.remcsum_tx {
            write_bool_opt(f, "remcsum_tx", true)?;
        }
        if self.remcsum_rx {
            write_bool_opt(f, "remcsum_rx", true)?;
        }
        if !self.localbypass {
            write_bool_opt(f, "localbypass", false)?;
        }
        if self.mc_route {
            write_bool_opt(f, "mcroute", true)?;
        }
        if self.label_policy > 0 {
            write!(f, " label_policy {}", self.label_policy)?;
        }
        Ok(())
    }
}

fn parse_vxlan_df(s: &str) -> Result<VxlanDf, CliError> {
    match s {
        "unset" => Ok(VxlanDf::Unset),
        "set" => Ok(VxlanDf::Set),
        "inherit" => Ok(VxlanDf::Inherit),
        _ => Err(CliError::from(format!(
            "Invalid VXLAN df: {s}, supported: unset, set, inherit"
        ))),
    }
}

fn apply_vxlan_args<'a>(
    mut builder: LinkMessageBuilder<LinkVxlan>,
    iter: &mut impl Iterator<Item = &'a str>,
    vni: &mut Option<u32>,
    has_external: &mut bool,
) -> Result<LinkMessageBuilder<LinkVxlan>, CliError> {
    while let Some(key) = iter.next() {
        match key {
            "id" | "vni" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("VXLAN id requires a value"));
                };
                let val: u32 = v.parse().map_err(|_| {
                    CliError::from(format!("Invalid VXLAN id: {v}"))
                })?;
                if val >= 1u32 << 24 {
                    return Err(CliError::from(format!(
                        "Invalid VXLAN id: {v}, must be <= 16777215"
                    )));
                }
                builder = builder.id(val);
                *vni = Some(val);
            }
            "group" | "remote" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(format!(
                        "VXLAN {key} requires a value"
                    )));
                };
                // group and remote are aliases, both set IFLA_VXLAN_GROUP
                if let Ok(addr) = v.parse::<Ipv4Addr>() {
                    builder = builder.group(addr);
                } else if let Ok(addr) = v.parse::<Ipv6Addr>() {
                    builder = builder.group6(addr);
                } else {
                    return Err(CliError::from(format!(
                        "Invalid VXLAN {key} address: {v}"
                    )));
                }
            }
            "local" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("VXLAN local requires a value"));
                };
                if let Ok(addr) = v.parse::<Ipv4Addr>() {
                    builder = builder.local(addr);
                } else if let Ok(addr) = v.parse::<Ipv6Addr>() {
                    builder = builder.local6(addr);
                } else {
                    return Err(CliError::from(format!(
                        "Invalid VXLAN local address: {v}"
                    )));
                }
            }
            "dev" => {
                return Err(CliError::from(
                    "VXLAN dev is not supported for link set",
                ));
            }
            "ttl" | "hoplimit" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("VXLAN ttl requires a value"));
                };
                if v == "inherit" {
                    builder = builder.ttl_inherit();
                } else if v != "auto" {
                    let val: u8 = v.parse().map_err(|_| {
                        CliError::from(format!("Invalid VXLAN ttl: {v}"))
                    })?;
                    if val == 0 {
                        return Err(CliError::from(format!(
                            "Invalid VXLAN ttl: {v}, must be 1..255"
                        )));
                    }
                    builder = builder.ttl(val);
                }
            }
            "tos" | "dsfield" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("VXLAN tos requires a value"));
                };
                if v == "inherit" {
                    builder = builder.tos(1);
                } else {
                    let val: u8 = v.parse().map_err(|_| {
                        CliError::from(format!("Invalid VXLAN tos: {v}"))
                    })?;
                    builder = builder.tos(val);
                }
            }
            "df" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("VXLAN df requires a value"));
                };
                builder = builder.df(parse_vxlan_df(v)?);
            }
            "label" | "flowlabel" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("VXLAN label requires a value"));
                };
                let val: u32 = v.parse().map_err(|_| {
                    CliError::from(format!("Invalid VXLAN label: {v}"))
                })?;
                if val & 0xfff00000 != 0 {
                    return Err(CliError::from(format!(
                        "Invalid VXLAN label: {v}, must be <= 1048575"
                    )));
                }
                builder = builder.label(val);
            }
            "ageing" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "VXLAN ageing requires a value",
                    ));
                };
                if v == "none" {
                    builder = builder.ageing(0);
                } else {
                    let val: u32 = v.parse().map_err(|_| {
                        CliError::from(format!("Invalid VXLAN ageing: {v}"))
                    })?;
                    builder = builder.ageing(val);
                }
            }
            "maxaddress" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "VXLAN maxaddress requires a value",
                    ));
                };
                if v == "unlimited" {
                    builder = builder.limit(0);
                } else {
                    let val: u32 = v.parse().map_err(|_| {
                        CliError::from(format!("Invalid VXLAN maxaddress: {v}"))
                    })?;
                    builder = builder.limit(val);
                }
            }
            "srcport" | "port" => {
                let Some(min) = iter.next() else {
                    return Err(CliError::from(
                        "VXLAN srcport requires two values",
                    ));
                };
                let Some(max) = iter.next() else {
                    return Err(CliError::from(
                        "VXLAN srcport requires two values",
                    ));
                };
                let min_val: u16 = min.parse().map_err(|_| {
                    CliError::from(format!("Invalid VXLAN srcport min: {min}"))
                })?;
                let max_val: u16 = max.parse().map_err(|_| {
                    CliError::from(format!("Invalid VXLAN srcport max: {max}"))
                })?;
                builder = builder.port_range(min_val, max_val);
            }
            "dstport" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "VXLAN dstport requires a value",
                    ));
                };
                let val: u16 = v.parse().map_err(|_| {
                    CliError::from(format!("Invalid VXLAN dstport: {v}"))
                })?;
                builder = builder.port(val);
            }
            "learning" => builder = builder.learning(true),
            "nolearning" => builder = builder.learning(false),
            "proxy" => builder = builder.proxy(true),
            "noproxy" => builder = builder.proxy(false),
            "rsc" => builder = builder.rsc(true),
            "norsc" => builder = builder.rsc(false),
            "l2miss" => builder = builder.l2miss(true),
            "nol2miss" => builder = builder.l2miss(false),
            "l3miss" => builder = builder.l3miss(true),
            "nol3miss" => builder = builder.l3miss(false),
            "udpcsum" => builder = builder.udp_csum(true),
            "noudpcsum" => builder = builder.udp_csum(false),
            "udp6zerocsumtx" => builder = builder.udp_zero_csum6_tx(true),
            "noudp6zerocsumtx" => builder = builder.udp_zero_csum6_tx(false),
            "udp6zerocsumrx" => builder = builder.udp_zero_csum6_rx(true),
            "noudp6zerocsumrx" => builder = builder.udp_zero_csum6_rx(false),
            "remcsumtx" => builder = builder.remcsum_tx(true),
            "noremcsumtx" => builder = builder.remcsum_tx(false),
            "remcsumrx" => builder = builder.remcsum_rx(true),
            "noremcsumrx" => builder = builder.remcsum_rx(false),
            "localbypass" => builder = builder.localbypass(true),
            "nolocalbypass" => builder = builder.localbypass(false),
            "external" => {
                builder = builder.collect_metadata(true);
                *has_external = true;
            }
            "noexternal" => {
                builder = builder.collect_metadata(false);
            }
            "vnifilter" => builder = builder.vnifilter(true),
            "novnifilter" => builder = builder.vnifilter(false),
            "mcroute" => builder = builder.mc_route(true),
            "nomcroute" => builder = builder.mc_route(false),
            "gbp" => builder = builder.gbp(),
            "gpe" => builder = builder.gpe(),
            "reserved_bits" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "VXLAN reserved_bits requires a value",
                    ));
                };
                let val: u64 = v.parse().map_err(|_| {
                    CliError::from(format!("Invalid VXLAN reserved_bits: {v}"))
                })?;
                builder = builder.reserved_bits(val);
            }
            "label_policy" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "VXLAN label_policy requires a value",
                    ));
                };
                let val: u32 = v.parse().map_err(|_| {
                    CliError::from(format!("Invalid VXLAN label_policy: {v}"))
                })?;
                builder = builder.label_policy(val);
            }
            _ => {
                return Err(CliError::from(format!(
                    "Unknown VXLAN argument: {key}"
                )));
            }
        }
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) async fn apply_vxlan(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkVxlan>, CliError> {
        let mut builder = LinkMessageBuilder::<LinkVxlan>::new(&self.name);

        if let Some(ref dev_name) = self.link {
            let link_ifindex =
                self.get_ifindex_by_name(handle, dev_name).await?;
            builder = builder.dev(link_ifindex);
        }

        // filter out dev argument from iface_specific and resolve separately
        let mut filtered_args = Vec::new();
        let mut dev_name = None;
        {
            let mut iter = self.iface_specific.iter().peekable();
            while let Some(key) = iter.next() {
                if key == "dev" {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "VXLAN dev requires a value",
                        ));
                    };
                    dev_name = Some(v.clone());
                } else {
                    filtered_args.push(key.as_str());
                }
            }
        }

        if let Some(ref dev_name) = dev_name {
            let link_ifindex =
                self.get_ifindex_by_name(handle, dev_name).await?;
            builder = builder.dev(link_ifindex);
        }

        let mut vni = None;
        let mut has_external = false;

        {
            let mut iter = filtered_args.into_iter();
            builder = apply_vxlan_args(
                builder,
                &mut iter,
                &mut vni,
                &mut has_external,
            )?;
        }

        if has_external && vni.is_some() {
            return Err(CliError::from(
                "vxlan: both 'external' and vni cannot be specified",
            ));
        }

        if !has_external && vni.is_none() {
            return Err(CliError::from(
                "vxlan: missing virtual network identifier",
            ));
        }

        Ok(builder)
    }
}

pub(crate) struct IfaceVxlan;

impl IfaceVxlan {
    pub(crate) fn build_entries(
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder = LinkMessageBuilder::<LinkVxlan>::new_with_info_kind(
            InfoKind::Vxlan,
        );

        let mut vni = None;
        let mut has_external = false;

        let builder = {
            let mut iter = args.iter().map(|s| s.as_str());
            apply_vxlan_args(builder, &mut iter, &mut vni, &mut has_external)?
        };

        let infos = extract_link_info(builder.build());
        if infos.is_empty() {
            Ok(vec![LinkInfo::Kind(InfoKind::Vxlan)])
        } else {
            Ok(infos)
        }
    }

    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... vxlan id VNI
                [ { group | remote } IP_ADDRESS ]
                [ local ADDR ]
                [ ttl TTL ]
                [ tos TOS ]
                [ df DF ]
                [ flowlabel LABEL ]
                [ dev PHYS_DEV ]
                [ dstport PORT ]
                [ srcport MIN MAX ]
                [ reserved_bits VALUE ]
                [ [no]learning ]
                [ [no]proxy ]
                [ [no]rsc ]
                [ [no]l2miss ]
                [ [no]l3miss ]
                [ ageing SECONDS ]
                [ maxaddress NUMBER ]
                [ [no]udpcsum ]
                [ [no]udp6zerocsumtx ]
                [ [no]udp6zerocsumrx ]
                [ [no]remcsumtx ] [ [no]remcsumrx ]
                [ [no]localbypass ]
                [ [no]external ] [ gbp ] [ gpe ]
                [ [no]vnifilter ]
                [ [no]mcroute ]

Where:        VNI        := 0-16777215
        ADDR        := { IP_ADDRESS | any }
        TOS        := { NUMBER | inherit }
        TTL        := { 1..255 | auto | inherit }
        DF        := { unset | set | inherit }
        LABEL := 0-1048575
"
    }
}
