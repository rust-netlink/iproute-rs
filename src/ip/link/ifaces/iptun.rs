// SPDX-License-Identifier: MIT

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use iproute_rs::CliError;
use rtnetlink::{
    LinkIp6Tnl, LinkIpIp, LinkMessageBuilder,
    packet_route::{
        IpProtocol,
        link::{
            InfoIpTunnel, Ip6TunnelFlags, TunnelEncapFlags, TunnelEncapType,
        },
    },
};
use serde::Serialize;

use super::parse::parse_u16;
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataIpIp {
    #[serde(skip)]
    link: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "link")]
    link_name: Option<String>,
    remote: Option<IpAddr>,
    local: Option<IpAddr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    #[serde(skip)]
    proto: Option<IpProtocol>,
    pmtudisc: Option<bool>,
    fwmark: Option<u32>,
    #[serde(skip)]
    encap_type: Option<TunnelEncapType>,
    #[serde(skip)]
    encap_flags: Option<TunnelEncapFlags>,
    #[serde(skip)]
    encap_sport: Option<u16>,
    #[serde(skip)]
    encap_dport: Option<u16>,
    collect_metadata: bool,
    #[serde(skip)]
    encap_limit: Option<u8>,
    #[serde(skip)]
    flow_info: Option<u32>,
    #[serde(skip)]
    ipv6_flags: Option<Ip6TunnelFlags>,
}

impl CliLinkInfoDataIpIp {
    pub(crate) fn resolve_link(&mut self, index_2_name: &HashMap<u32, String>) {
        if let Some(idx) = self.link
            && let Some(name) = index_2_name.get(&idx)
        {
            self.link_name = Some(name.clone());
        }
    }
}

impl From<&[InfoIpTunnel]> for CliLinkInfoDataIpIp {
    fn from(info: &[InfoIpTunnel]) -> Self {
        let mut link = None;
        let mut remote = None;
        let mut local = None;
        let mut ttl = None;
        let mut tos = None;
        let mut proto = None;
        let mut pmtudisc = None;
        let mut fwmark = None;
        let mut encap_type = None;
        let mut encap_flags = None;
        let mut encap_sport = None;
        let mut encap_dport = None;
        let mut collect_metadata = false;
        let mut encap_limit = None;
        let mut flow_info = None;
        let mut ipv6_flags = None;

        for nla in info {
            match nla {
                InfoIpTunnel::Link(v) => link = Some(*v),
                InfoIpTunnel::Remote(v) => remote = Some(*v),
                InfoIpTunnel::Local(v) => local = Some(*v),
                InfoIpTunnel::Ttl(v) => ttl = Some(*v),
                InfoIpTunnel::Tos(v) => tos = Some(*v),
                InfoIpTunnel::Protocol(v) => proto = Some(*v),
                InfoIpTunnel::PMtuDisc(v) => pmtudisc = Some(*v),
                InfoIpTunnel::FwMark(v) => fwmark = Some(*v),
                InfoIpTunnel::EncapType(v) => encap_type = Some(*v),
                InfoIpTunnel::EncapFlags(v) => encap_flags = Some(*v),
                InfoIpTunnel::EncapSPort(v) => encap_sport = Some(*v),
                InfoIpTunnel::EncapDPort(v) => encap_dport = Some(*v),
                InfoIpTunnel::CollectMetadata => collect_metadata = true,
                InfoIpTunnel::EncapLimit(v) => encap_limit = Some(*v),
                InfoIpTunnel::FlowInfo(v) => flow_info = Some(*v),
                InfoIpTunnel::Ipv6Flags(v) => ipv6_flags = Some(*v),
                _ => (),
            }
        }

        Self {
            link,
            link_name: None,
            remote,
            local,
            ttl,
            tos,
            proto,
            pmtudisc,
            fwmark,
            encap_type,
            encap_flags,
            encap_sport,
            encap_dport,
            collect_metadata,
            encap_limit,
            flow_info,
            ipv6_flags,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataIpIp {
    #[allow(unused_assignments)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = "";
        macro_rules! emit {
            ($($arg:tt)*) => {{
                write!(f, "{}{}", sep, format_args!($($arg)*))?;
                sep = " ";
            }};
        }

        let is_ip6tnl = self.remote.as_ref().is_some_and(|a| a.is_ipv6())
            || self.local.as_ref().is_some_and(|a| a.is_ipv6());

        if self.collect_metadata {
            emit!("external");
        }

        if let Some(proto) = self.proto {
            match proto {
                IpProtocol::Ipip => {
                    if is_ip6tnl {
                        emit!("ipip6");
                    } else {
                        emit!("ipip");
                    }
                }
                IpProtocol::Ipv6 => {
                    if is_ip6tnl {
                        emit!("ip6ip6");
                    } else {
                        emit!("ip6ip");
                    }
                }
                _ => {
                    let v: u8 = proto.into();
                    if v == 137 {
                        emit!("mplsip");
                    } else if v == 0 {
                        emit!("any");
                    }
                }
            }
        }

        let addr_display = |addr: &IpAddr| match addr {
            IpAddr::V4(a) if a.is_unspecified() => "any".to_string(),
            IpAddr::V6(a) if a.is_unspecified() => "any".to_string(),
            _ => addr.to_string(),
        };

        if let Some(v) = &self.remote {
            emit!("remote {}", addr_display(v));
        } else {
            emit!("remote any");
        }
        if let Some(v) = &self.local {
            emit!("local {}", addr_display(v));
        } else {
            emit!("local any");
        }
        if let Some(v) = &self.link_name {
            emit!("dev {v}");
        } else if let Some(v) = self.link
            && v != 0
        {
            emit!("dev if{v}");
        }

        if is_ip6tnl {
            let ttl = self.ttl.unwrap_or(0);
            if ttl == 0 {
                emit!("hoplimit inherit");
            } else {
                emit!("hoplimit {ttl}");
            }

            let flags = self.ipv6_flags.unwrap_or(Ip6TunnelFlags::empty());
            if flags.contains(Ip6TunnelFlags::IgnEncapLimit) {
                emit!("encaplimit none");
            } else {
                emit!("encaplimit {}", self.encap_limit.unwrap_or(0));
            }

            if flags.contains(Ip6TunnelFlags::UseOrigTclass) {
                emit!("tclass inherit");
            } else {
                emit!(
                    "tclass 0x{:02x}",
                    (self.flow_info.unwrap_or(0) >> 20) as u8
                );
            }

            if flags.contains(Ip6TunnelFlags::UseOrigFlowlabel) {
                emit!("flowlabel inherit");
            } else {
                emit!(
                    "flowlabel 0x{:05x}",
                    self.flow_info.unwrap_or(0) & 0x000fffff
                );
            }

            if flags.contains(Ip6TunnelFlags::RcvDscpCopy) {
                emit!("dscp inherit");
            }

            if flags.contains(Ip6TunnelFlags::AllowLocalRemote) {
                emit!("allow-localremote");
            }
        } else {
            if let Some(ttl) = self.ttl {
                if ttl == 0 {
                    emit!("ttl inherit");
                } else {
                    emit!("ttl {ttl}");
                }
            } else {
                emit!("ttl inherit");
            }

            if let Some(tos) = self.tos {
                if tos == 0 {
                    // not printed
                } else if tos == 1 {
                    emit!("tos inherit");
                } else {
                    emit!("tos 0x{tos:x}");
                }
            }

            if let Some(pmtudisc) = self.pmtudisc {
                if pmtudisc {
                    emit!("pmtudisc");
                } else {
                    emit!("nopmtudisc");
                }
            } else {
                emit!("nopmtudisc");
            }
        }

        if is_ip6tnl
            && self
                .ipv6_flags
                .is_some_and(|f| f.contains(Ip6TunnelFlags::UseOrigFwMark))
        {
            emit!("fwmark inherit");
        } else if let Some(fwmark) = self.fwmark
            && fwmark != 0
        {
            emit!("fwmark 0x{fwmark:x}");
        }

        if let Some(encap) = self.encap_type
            && encap != TunnelEncapType::None
        {
            emit!("encap {encap}");
            match self.encap_sport {
                Some(0) | None => emit!("sport auto"),
                Some(v) => emit!("sport {v}"),
            }
            if let Some(v) = self.encap_dport {
                emit!("dport {v}");
            }
            if let Some(flags) = self.encap_flags {
                if flags.contains(TunnelEncapFlags::CSum) {
                    emit!("encap-csum");
                } else {
                    emit!("noencap-csum");
                }
                if flags.contains(TunnelEncapFlags::CSum6) {
                    emit!("encap-udp6-csum");
                } else {
                    emit!("noencap-udp6-csum");
                }
                if flags.contains(TunnelEncapFlags::RemCSum) {
                    emit!("encap-remcsum");
                } else {
                    emit!("noencap-remcsum");
                }
            }
        }

        Ok(())
    }
}

impl LinkBaseConf {
    pub(crate) async fn apply_iptun(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkIpIp>, CliError> {
        let mut builder = LinkIpIp::new(&self.name);
        let mut metadata = false;

        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            let mut next_val = || {
                iter.next().ok_or_else(|| {
                    CliError::from(format!("ipip {key} requires a value"))
                })
            };
            match key.as_str() {
                "local" => {
                    let v = next_val()?;
                    let addr: Ipv4Addr = parse_ip(v, "local")?;
                    builder = builder.local(addr);
                }
                "remote" => {
                    let v = next_val()?;
                    let addr: Ipv4Addr = parse_ip(v, "remote")?;
                    builder = builder.remote(addr);
                }
                "dev" => {
                    let v = next_val()?;
                    let ifindex = self.get_ifindex_by_name(handle, v).await?;
                    builder = builder.dev(ifindex);
                }
                "ttl" | "hoplimit" | "hlim" => {
                    let v = next_val()?;
                    match v.as_str() {
                        "inherit" => {
                            builder = builder.ttl(0);
                        }
                        _ => {
                            let ttl: u8 = v.parse().map_err(|_| {
                                CliError::from(format!("invalid TTL: {v}"))
                            })?;
                            builder = builder.ttl(ttl);
                        }
                    }
                }
                "tos" | "tclass" | "tc" | "dsfield" => {
                    let v = next_val()?;
                    match v.as_str() {
                        "inherit" => {
                            builder = builder.tos(1);
                        }
                        _ => {
                            let tos: u8 = parse_dsfield(v)?;
                            builder = builder.tos(tos);
                        }
                    }
                }
                "pmtudisc" => {
                    builder = builder.pmtudisc(true);
                }
                "nopmtudisc" => {
                    builder = builder.pmtudisc(false);
                }
                "mode" => {
                    let v = next_val()?;
                    match v.as_str() {
                        "ipip" | "ipv4/ipv4" | "ip4ip4" => {
                            builder = builder.protocol(IpProtocol::Ipip);
                        }
                        "mplsip" | "mpls/ipv4" => {
                            let proto = IpProtocol::from(137u8);
                            builder = builder.protocol(proto);
                        }
                        "any" | "any/ipv4" => {
                            let proto = IpProtocol::from(0u8);
                            builder = builder.protocol(proto);
                        }
                        _ => {
                            return Err(CliError::from(format!(
                                "Cannot guess tunnel mode: {v}"
                            )));
                        }
                    }
                }
                "external" => {
                    metadata = true;
                }
                "noencap" => {
                    builder = builder.encap_type(TunnelEncapType::None);
                }
                "encap" => {
                    let v = next_val()?;
                    match v.as_str() {
                        "fou" => {
                            builder = builder.encap_type(TunnelEncapType::Fou);
                        }
                        "gue" => {
                            builder = builder.encap_type(TunnelEncapType::Gue);
                        }
                        "none" => {
                            builder = builder.encap_type(TunnelEncapType::None);
                        }
                        _ => {
                            return Err(CliError::from(format!(
                                "Invalid encap type: {v}"
                            )));
                        }
                    }
                }
                "encap-sport" => {
                    let v = next_val()?;
                    if v == "auto" {
                        builder = builder.encap_sport(0);
                    } else {
                        let port = parse_u16(v, "encap-sport")?;
                        builder = builder.encap_sport(port);
                    }
                }
                "encap-dport" => {
                    let v = next_val()?;
                    let port = parse_u16(v, "encap-dport")?;
                    builder = builder.encap_dport(port);
                }
                "encap-csum" => {
                    let flags = TunnelEncapFlags::CSum;
                    builder = builder.encap_flags(flags);
                }
                "noencap-csum" => {
                    let flags = TunnelEncapFlags::empty();
                    builder = builder.encap_flags(flags);
                }
                "encap-udp6-csum" => {
                    let flags = TunnelEncapFlags::CSum6;
                    builder = builder.encap_flags(flags);
                }
                "noencap-udp6-csum" => {
                    let flags = TunnelEncapFlags::empty();
                    builder = builder.encap_flags(flags);
                }
                "encap-remcsum" => {
                    let flags = TunnelEncapFlags::RemCSum;
                    builder = builder.encap_flags(flags);
                }
                "noencap-remcsum" => {
                    let flags = TunnelEncapFlags::empty();
                    builder = builder.encap_flags(flags);
                }
                "fwmark" => {
                    let v = next_val()?;
                    let mark = if let Some(hex) = v.strip_prefix("0x") {
                        u32::from_str_radix(hex, 16)
                    } else {
                        v.parse()
                    };
                    let mark = mark.map_err(|_| {
                        CliError::from(format!("invalid fwmark: {v}"))
                    })?;
                    builder = builder.fwmark(mark);
                }
                _ => {
                    return Err(CliError::from(format!(
                        "Unknown ipip argument: {key}"
                    )));
                }
            }
        }

        if metadata {
            builder = builder.collect_metadata(true);
        }

        Ok(builder)
    }
}

fn parse_ip<T: FromStr>(s: &str, name: &str) -> Result<T, CliError>
where
    T::Err: std::fmt::Display,
{
    s.parse::<T>()
        .map_err(|e| CliError::from(format!("Invalid {name} address: {e}")))
}

fn parse_dsfield(s: &str) -> Result<u8, CliError> {
    if let Some(hex) = s.strip_prefix("0x") {
        u8::from_str_radix(hex, 16)
            .map_err(|_| CliError::from(format!("Invalid TOS value: {s}")))
    } else {
        s.parse::<u8>()
            .map_err(|_| CliError::from(format!("Invalid TOS value: {s}")))
    }
}

impl LinkBaseConf {
    pub(crate) async fn apply_ip6tnl(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkIp6Tnl>, CliError> {
        let mut builder = LinkIp6Tnl::new(&self.name);
        let mut metadata = false;

        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            let mut next_val = || {
                iter.next().ok_or_else(|| {
                    CliError::from(format!("ip6tnl {key} requires a value"))
                })
            };
            match key.as_str() {
                "local" => {
                    let v = next_val()?;
                    let addr: Ipv6Addr = parse_ip(v, "local")?;
                    builder = builder.local(addr);
                }
                "remote" => {
                    let v = next_val()?;
                    let addr: Ipv6Addr = parse_ip(v, "remote")?;
                    builder = builder.remote(addr);
                }
                "dev" => {
                    let v = next_val()?;
                    let ifindex = self.get_ifindex_by_name(handle, v).await?;
                    builder = builder.dev(ifindex);
                }
                "ttl" | "hoplimit" | "hlim" => {
                    let v = next_val()?;
                    match v.as_str() {
                        "inherit" => {
                            builder = builder.ttl(0);
                        }
                        _ => {
                            let ttl: u8 = v.parse().map_err(|_| {
                                CliError::from(format!("invalid TTL: {v}"))
                            })?;
                            builder = builder.ttl(ttl);
                        }
                    }
                }
                "encaplimit" => {
                    let v = next_val()?;
                    if v == "none" {
                        builder = builder
                            .set_flag(Ip6TunnelFlags::IgnEncapLimit, true);
                    } else {
                        let limit: u8 = v.parse().map_err(|_| {
                            CliError::from(format!("invalid encaplimit: {v}"))
                        })?;
                        builder = builder.encap_limit(limit);
                        builder = builder
                            .set_flag(Ip6TunnelFlags::IgnEncapLimit, false);
                    }
                }
                "tos" | "tclass" | "tc" | "dsfield" => {
                    let v = next_val()?;
                    if v == "inherit" {
                        builder = builder.tclass(None);
                    } else {
                        let uval: u8 = if let Some(hex) = v.strip_prefix("0x") {
                            u8::from_str_radix(hex, 16).map_err(|_| {
                                CliError::from(format!("invalid TClass: {v}"))
                            })?
                        } else {
                            v.parse::<u8>().map_err(|_| {
                                CliError::from(format!("invalid TClass: {v}"))
                            })?
                        };
                        builder = builder.tclass(Some(uval));
                    }
                }
                "flowlabel" | "fl" => {
                    let v = next_val()?;
                    if v == "inherit" {
                        builder = builder.flowlabel(None);
                    } else {
                        let uval = if let Some(hex) = v.strip_prefix("0x") {
                            u32::from_str_radix(hex, 16)
                        } else {
                            v.parse()
                        };
                        let uval = uval.map_err(|_| {
                            CliError::from(format!("invalid flowlabel: {v}"))
                        })?;
                        if uval > 0xfffff {
                            return Err(CliError::from(format!(
                                "invalid flowlabel: {v}"
                            )));
                        }
                        builder = builder.flowlabel(Some(uval));
                    }
                }
                "dscp" => {
                    let v = next_val()?;
                    if v != "inherit" {
                        return Err(CliError::from(format!(
                            "dscp only supports inherit, got {v}"
                        )));
                    }
                    builder =
                        builder.set_flag(Ip6TunnelFlags::RcvDscpCopy, true);
                }
                "allow-localremote" => {
                    builder = builder
                        .set_flag(Ip6TunnelFlags::AllowLocalRemote, true);
                }
                "noallow-localremote" => {
                    builder = builder
                        .set_flag(Ip6TunnelFlags::AllowLocalRemote, false);
                }
                "pmtudisc" => {
                    builder = builder.pmtudisc(true);
                }
                "nopmtudisc" => {
                    builder = builder.pmtudisc(false);
                }
                "mode" => {
                    let v = next_val()?;
                    match v.as_str() {
                        "ip6ip6" | "ipv6/ipv6" => {
                            builder = builder.protocol(IpProtocol::Ipv6);
                        }
                        "ipip6" | "ip4ip6" | "ip/ipv6" | "ipv4/ipv6" => {
                            builder = builder.protocol(IpProtocol::Ipip);
                        }
                        "any" | "any/ipv6" => {
                            let proto = IpProtocol::from(0u8);
                            builder = builder.protocol(proto);
                        }
                        _ => {
                            return Err(CliError::from(format!(
                                "Cannot guess tunnel mode: {v}"
                            )));
                        }
                    }
                }
                "external" => {
                    metadata = true;
                }
                "noencap" => {
                    builder = builder.encap_type(TunnelEncapType::None);
                }
                "encap" => {
                    let v = next_val()?;
                    match v.as_str() {
                        "fou" => {
                            builder = builder.encap_type(TunnelEncapType::Fou);
                        }
                        "gue" => {
                            builder = builder.encap_type(TunnelEncapType::Gue);
                        }
                        "none" => {
                            builder = builder.encap_type(TunnelEncapType::None);
                        }
                        _ => {
                            return Err(CliError::from(format!(
                                "Invalid encap type: {v}"
                            )));
                        }
                    }
                }
                "encap-sport" => {
                    let v = next_val()?;
                    if v == "auto" {
                        builder = builder.encap_sport(0);
                    } else {
                        let port = parse_u16(v, "encap-sport")?;
                        builder = builder.encap_sport(port);
                    }
                }
                "encap-dport" => {
                    let v = next_val()?;
                    let port = parse_u16(v, "encap-dport")?;
                    builder = builder.encap_dport(port);
                }
                "encap-csum" => {
                    let flags = TunnelEncapFlags::CSum;
                    builder = builder.encap_flags(flags);
                }
                "noencap-csum" => {
                    let flags = TunnelEncapFlags::empty();
                    builder = builder.encap_flags(flags);
                }
                "encap-udp6-csum" => {
                    let flags = TunnelEncapFlags::CSum6;
                    builder = builder.encap_flags(flags);
                }
                "noencap-udp6-csum" => {
                    let flags = TunnelEncapFlags::empty();
                    builder = builder.encap_flags(flags);
                }
                "encap-remcsum" => {
                    let flags = TunnelEncapFlags::RemCSum;
                    builder = builder.encap_flags(flags);
                }
                "noencap-remcsum" => {
                    let flags = TunnelEncapFlags::empty();
                    builder = builder.encap_flags(flags);
                }
                "fwmark" => {
                    let v = next_val()?;
                    if v == "inherit" {
                        builder = builder
                            .set_flag(Ip6TunnelFlags::UseOrigFwMark, true);
                        builder = builder.fwmark(0);
                    } else {
                        let mark = if let Some(hex) = v.strip_prefix("0x") {
                            u32::from_str_radix(hex, 16)
                        } else {
                            v.parse()
                        };
                        let mark = mark.map_err(|_| {
                            CliError::from(format!("invalid fwmark: {v}"))
                        })?;
                        builder = builder.fwmark(mark);
                        builder = builder
                            .set_flag(Ip6TunnelFlags::UseOrigFwMark, false);
                    }
                }
                _ => {
                    return Err(CliError::from(format!(
                        "Unknown ip6tnl argument: {key}"
                    )));
                }
            }
        }

        if metadata {
            builder = builder.collect_metadata(true);
        }

        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dsfield_hex() {
        assert_eq!(parse_dsfield("0x1e").unwrap(), 0x1e);
    }

    #[test]
    fn parse_dsfield_decimal() {
        assert_eq!(parse_dsfield("30").unwrap(), 30);
    }

    #[test]
    fn parse_dsfield_invalid() {
        assert!(parse_dsfield("xyz").is_err());
    }
}
