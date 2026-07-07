// SPDX-License-Identifier: MIT

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use iproute_rs::CliError;
use rtnetlink::{
    LinkGre, LinkGre6, LinkMessageBuilder,
    packet_route::link::{
        ErSpanDir, GreEncapFlags, GreEncapType, GreIOFlags, InfoGre, InfoGre6,
    },
};
use serde::Serialize;

use super::parse::parse_u16;
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataGre {
    #[serde(skip)]
    link: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "link")]
    link_name: Option<String>,
    remote: Option<IpAddr>,
    local: Option<IpAddr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    pmtudisc: Option<bool>,
    #[serde(skip_serializing_if = "is_false")]
    collect_metadata: bool,
    #[serde(skip)]
    iflags: GreIOFlags,
    #[serde(skip)]
    oflags: GreIOFlags,
    #[serde(skip)]
    ikey: Option<u32>,
    #[serde(skip)]
    okey: Option<u32>,
    fwmark: Option<u32>,
    #[serde(skip)]
    encap_type: Option<GreEncapType>,
    #[serde(skip)]
    encap_flags: Option<GreEncapFlags>,
    #[serde(skip)]
    encap_sport: Option<u16>,
    #[serde(skip)]
    encap_dport: Option<u16>,
    #[serde(skip)]
    encap_limit: Option<u8>,
    #[serde(skip)]
    flow_label: Option<u32>,
    #[serde(skip)]
    is_ip6: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    erspan_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    erspan_ver: Option<u8>,
    #[serde(skip)]
    erspan_dir: Option<ErSpanDir>,
    #[serde(skip_serializing_if = "Option::is_none")]
    erspan_hwid: Option<u16>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

impl CliLinkInfoDataGre {
    pub(crate) fn resolve_link(&mut self, index_2_name: &HashMap<u32, String>) {
        if let Some(idx) = self.link
            && let Some(name) = index_2_name.get(&idx)
        {
            self.link_name = Some(name.clone());
        }
    }
}

impl From<&[InfoGre]> for CliLinkInfoDataGre {
    fn from(info: &[InfoGre]) -> Self {
        let mut link = None;
        let mut remote = None;
        let mut local = None;
        let mut ttl = None;
        let mut tos = None;
        let mut pmtudisc = None;
        let mut collect_metadata = false;
        let mut iflags = GreIOFlags::empty();
        let mut oflags = GreIOFlags::empty();
        let mut ikey = None;
        let mut okey = None;
        let mut fwmark = None;
        let mut encap_type = None;
        let mut encap_flags = None;
        let mut encap_sport = None;
        let mut encap_dport = None;
        let encap_limit = None;
        let flow_label = None;
        let mut erspan_index = None;
        let mut erspan_ver = None;
        let mut erspan_dir = None;
        let mut erspan_hwid = None;

        for nla in info {
            match nla {
                InfoGre::Link(v) => link = Some(*v),
                InfoGre::Remote(v) => remote = Some(IpAddr::V4(*v)),
                InfoGre::Local(v) => local = Some(IpAddr::V4(*v)),
                InfoGre::Ttl(v) => ttl = Some(*v),
                InfoGre::Tos(v) => tos = Some(*v),
                InfoGre::PathMTUDiscovery(v) => pmtudisc = Some(*v),
                InfoGre::CollectMetadata => collect_metadata = true,
                InfoGre::IFlags(v) => iflags = *v,
                InfoGre::OFlags(v) => oflags = *v,
                InfoGre::IKey(v) => ikey = Some(*v),
                InfoGre::OKey(v) => okey = Some(*v),
                InfoGre::FwMask(v) => fwmark = Some(v.to_be()),
                InfoGre::EncapType(v) => encap_type = Some(*v),
                InfoGre::EncapFlags(v) => encap_flags = Some(*v),
                InfoGre::SourcePort(v) => encap_sport = Some(*v),
                InfoGre::DestinationPort(v) => encap_dport = Some(*v),
                InfoGre::ErSpanIndex(v) => erspan_index = Some(*v),
                InfoGre::ErSpanVer(v) => erspan_ver = Some(*v),
                InfoGre::ErSpanDir(v) => erspan_dir = Some(*v),
                InfoGre::ErSpanHwId(v) => erspan_hwid = Some(*v),
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
            pmtudisc,
            collect_metadata,
            iflags,
            oflags,
            ikey,
            okey,
            fwmark,
            encap_type,
            encap_flags,
            encap_sport,
            encap_dport,
            encap_limit,
            flow_label,
            is_ip6: false,
            erspan_index,
            erspan_ver,
            erspan_dir,
            erspan_hwid,
        }
    }
}

impl From<&[InfoGre6]> for CliLinkInfoDataGre {
    fn from(info: &[InfoGre6]) -> Self {
        let mut link = None;
        let mut remote = None;
        let mut local = None;
        let mut ttl = None;
        let mut tos = None;
        let pmtudisc = None;
        let mut collect_metadata = false;
        let mut iflags = GreIOFlags::empty();
        let mut oflags = GreIOFlags::empty();
        let mut ikey = None;
        let mut okey = None;
        let mut fwmark = None;
        let mut encap_type = None;
        let mut encap_flags = None;
        let mut encap_sport = None;
        let mut encap_dport = None;
        let mut encap_limit = None;
        let mut flow_label = None;
        let mut erspan_index = None;
        let mut erspan_ver = None;
        let mut erspan_dir = None;
        let mut erspan_hwid = None;

        for nla in info {
            match nla {
                InfoGre6::Link(v) => link = Some(*v),
                InfoGre6::Remote(v) => remote = Some(IpAddr::V6(*v)),
                InfoGre6::Local(v) => local = Some(IpAddr::V6(*v)),
                InfoGre6::Ttl(v) => ttl = Some(*v),
                InfoGre6::CollectMetadata => collect_metadata = true,
                InfoGre6::IFlags(v) => iflags = *v,
                InfoGre6::OFlags(v) => oflags = *v,
                InfoGre6::IKey(v) => ikey = Some(*v),
                InfoGre6::OKey(v) => okey = Some(*v),
                InfoGre6::FwMask(v) => fwmark = Some(*v),
                InfoGre6::Tos(v) => tos = Some(*v),
                InfoGre6::EncapType(v) => encap_type = Some(*v),
                InfoGre6::EncapFlags(v) => encap_flags = Some(*v),
                InfoGre6::SourcePort(v) => encap_sport = Some(*v),
                InfoGre6::DestinationPort(v) => encap_dport = Some(*v),
                InfoGre6::EncapLimit(v) => encap_limit = Some(*v),
                InfoGre6::FlowLabel(v) => flow_label = Some(*v),
                InfoGre6::ErSpanIndex(v) => erspan_index = Some(*v),
                InfoGre6::ErSpanVer(v) => erspan_ver = Some(*v),
                InfoGre6::ErSpanDir(v) => erspan_dir = Some(*v),
                InfoGre6::ErSpanHwId(v) => erspan_hwid = Some(*v),
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
            pmtudisc,
            collect_metadata,
            iflags,
            oflags,
            ikey,
            okey,
            fwmark,
            encap_type,
            encap_flags,
            encap_sport,
            encap_dport,
            encap_limit,
            flow_label,
            is_ip6: true,
            erspan_index,
            erspan_ver,
            erspan_dir,
            erspan_hwid,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataGre {
    #[allow(unused_assignments)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = "";
        macro_rules! emit {
            ($($arg:tt)*) => {{
                write!(f, "{}{}", sep, format_args!($($arg)*))?;
                sep = " ";
            }};
        }

        if self.collect_metadata {
            emit!("external");
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

        if self.is_ip6 {
            let ttl = self.ttl.unwrap_or(0);
            if ttl == 0 {
                emit!("hoplimit inherit");
            } else {
                emit!("hoplimit {ttl}");
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
        }

        if !self.is_ip6 {
            if let Some(tos) = self.tos {
                if tos == 0 {
                    // not printed
                } else if tos == 1 {
                    emit!("tos inherit");
                } else {
                    emit!("tos 0x{tos:x}");
                }
            }

            if let Some(pmtudisc) = self.pmtudisc
                && !pmtudisc
            {
                emit!("nopmtudisc");
            }
        }

        if self.is_ip6 {
            if let Some(limit) = self.encap_limit {
                emit!("encaplimit {limit}");
            }
            if let Some(flow) = self.flow_label {
                let tclass = (flow >> 20) & 0xff;
                emit!("tclass 0x{tclass:02x}");
                emit!("flowlabel 0x{:05x}", flow & 0xfffff);
            }
        }

        let ikey_str = self.ikey.map(key_to_str);
        let okey_str = self.okey.map(key_to_str);
        if self.iflags.contains(GreIOFlags::Key)
            && let Some(v) = &ikey_str
        {
            emit!("ikey {v}");
        }
        if self.oflags.contains(GreIOFlags::Key)
            && let Some(v) = &okey_str
        {
            emit!("okey {v}");
        }
        if self.iflags.contains(GreIOFlags::Seq) {
            emit!("iseq");
        }
        if self.oflags.contains(GreIOFlags::Seq) {
            emit!("oseq");
        }
        if self.iflags.contains(GreIOFlags::Checksum) {
            emit!("icsum");
        }
        if self.oflags.contains(GreIOFlags::Checksum) {
            emit!("ocsum");
        }

        if let Some(fwmark) = self.fwmark
            && fwmark != 0
        {
            emit!("fwmark 0x{fwmark:x}");
        }

        if let Some(encap) = self.encap_type
            && encap != GreEncapType::None
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
                if flags.contains(GreEncapFlags::Checksum) {
                    emit!("encap-csum");
                } else {
                    emit!("noencap-csum");
                }
                if flags.contains(GreEncapFlags::Checksum6) {
                    emit!("encap-udp6-csum");
                } else {
                    emit!("noencap-udp6-csum");
                }
                if flags.contains(GreEncapFlags::RemoteChecksum) {
                    emit!("encap-remcsum");
                } else {
                    emit!("noencap-remcsum");
                }
            }
        }

        if let Some(ver) = self.erspan_ver {
            if ver == 1
                && let Some(idx) = self.erspan_index
            {
                emit!("erspan_index {idx}");
            }
            emit!("erspan_ver {ver}");
            if ver == 2 {
                if let Some(dir) = self.erspan_dir {
                    match dir {
                        ErSpanDir::Ingress => emit!("erspan_dir ingress"),
                        ErSpanDir::Egress => emit!("erspan_dir egress"),
                        ErSpanDir::Other(v) => emit!("erspan_dir {v}"),
                        _ => (),
                    }
                }
                if let Some(hwid) = self.erspan_hwid {
                    emit!("erspan_hwid 0x{hwid:x}");
                }
            }
        }

        Ok(())
    }
}

fn key_to_str(key: u32) -> String {
    std::net::Ipv4Addr::from(key).to_string()
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
    pub(crate) async fn apply_gre(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkGre>, CliError> {
        let mut builder = LinkGre::new(&self.name);
        builder = build_gre_opts(builder, self, handle).await?;
        Ok(builder)
    }

    pub(crate) async fn apply_gretap(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkGre>, CliError> {
        let mut builder = LinkGre::new_gretap(&self.name);
        builder = build_gre_opts(builder, self, handle).await?;
        Ok(builder)
    }

    pub(crate) async fn apply_erspan(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkGre>, CliError> {
        let mut builder = LinkGre::new_erspan(&self.name);
        let flags = GreIOFlags::Key | GreIOFlags::Seq;
        builder = builder.erspan_ver(1).iflags(flags).oflags(flags);
        builder = build_gre_opts(builder, self, handle).await?;
        Ok(builder)
    }

    pub(crate) async fn apply_gre6(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkGre6>, CliError> {
        let mut builder = LinkGre6::new(&self.name);
        builder = build_gre6_opts(builder, self, handle).await?;
        Ok(builder)
    }

    pub(crate) async fn apply_gretap6(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkGre6>, CliError> {
        let mut builder = LinkGre6::new_gretap6(&self.name);
        builder = build_gre6_opts(builder, self, handle).await?;
        Ok(builder)
    }

    pub(crate) async fn apply_ip6erspan(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkGre6>, CliError> {
        let mut builder = LinkGre6::new_ip6erspan(&self.name);
        let flags = GreIOFlags::Key | GreIOFlags::Seq;
        builder = builder.erspan_ver(1).iflags(flags).oflags(flags);
        builder = build_gre6_opts(builder, self, handle).await?;
        Ok(builder)
    }
}

async fn build_gre_opts(
    mut builder: LinkMessageBuilder<LinkGre>,
    conf: &LinkBaseConf,
    handle: &rtnetlink::Handle,
) -> Result<LinkMessageBuilder<LinkGre>, CliError> {
    let mut metadata = false;

    let mut iter = conf.iface_specific.iter();
    while let Some(key) = iter.next() {
        let mut next_val = || {
            iter.next().ok_or_else(|| {
                CliError::from(format!("gre {key} requires a value"))
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
                let ifindex = conf.get_ifindex_by_name(handle, v).await?;
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
            "tos" | "tclass" | "dsfield" => {
                let v = next_val()?;
                match v.as_str() {
                    "inherit" => {
                        builder = builder.tos(1);
                    }
                    _ => {
                        let tos = parse_dsfield(v)?;
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
            "key" => {
                let v = next_val()?;
                let key: u32 = if v.contains('.') {
                    parse_ip::<Ipv4Addr>(v, "key")?.into()
                } else {
                    v.parse::<u32>().map_err(|_| {
                        CliError::from(format!("invalid key: {v}"))
                    })?
                };
                builder = builder
                    .ikey(key)
                    .iflags(GreIOFlags::Key)
                    .okey(key)
                    .oflags(GreIOFlags::Key);
            }
            "ikey" => {
                let v = next_val()?;
                let key: u32 = if v.contains('.') {
                    parse_ip::<Ipv4Addr>(v, "ikey")?.into()
                } else {
                    v.parse::<u32>().map_err(|_| {
                        CliError::from(format!("invalid ikey: {v}"))
                    })?
                };
                builder = builder.ikey(key).iflags(GreIOFlags::Key);
            }
            "okey" => {
                let v = next_val()?;
                let key: u32 = if v.contains('.') {
                    parse_ip::<Ipv4Addr>(v, "okey")?.into()
                } else {
                    v.parse::<u32>().map_err(|_| {
                        CliError::from(format!("invalid okey: {v}"))
                    })?
                };
                builder = builder.okey(key).oflags(GreIOFlags::Key);
            }
            "seq" => {
                builder =
                    builder.iflags(GreIOFlags::Seq).oflags(GreIOFlags::Seq);
            }
            "iseq" => {
                builder = builder.iflags(GreIOFlags::Seq);
            }
            "noseq" => {
                builder = builder
                    .iflags(GreIOFlags::empty())
                    .oflags(GreIOFlags::empty());
            }
            "noiseq" => {
                builder = builder.iflags(GreIOFlags::empty());
            }
            "oseq" => {
                builder = builder.oflags(GreIOFlags::Seq);
            }
            "nooseq" => {
                builder = builder.oflags(GreIOFlags::empty());
            }
            "csum" => {
                builder = builder
                    .iflags(GreIOFlags::Checksum)
                    .oflags(GreIOFlags::Checksum);
            }
            "icsum" => {
                builder = builder.iflags(GreIOFlags::Checksum);
            }
            "nocsum" => {
                builder = builder
                    .iflags(GreIOFlags::empty())
                    .oflags(GreIOFlags::empty());
            }
            "noicsum" => {
                builder = builder.iflags(GreIOFlags::empty());
            }
            "ocsum" => {
                builder = builder.oflags(GreIOFlags::Checksum);
            }
            "noocsum" => {
                builder = builder.oflags(GreIOFlags::empty());
            }
            "external" => {
                metadata = true;
            }
            "noencap" => {
                builder = builder.encap_type(GreEncapType::None);
            }
            "encap" => {
                let v = next_val()?;
                match v.as_str() {
                    "fou" => {
                        builder = builder.encap_type(GreEncapType::Fou);
                    }
                    "gue" => {
                        builder = builder.encap_type(GreEncapType::Gue);
                    }
                    "none" => {
                        builder = builder.encap_type(GreEncapType::None);
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
                builder = builder.encap_flags(GreEncapFlags::Checksum);
            }
            "noencap-csum" => {
                builder = builder.encap_flags(GreEncapFlags::empty());
            }
            "encap-udp6-csum" => {
                builder = builder.encap_flags(GreEncapFlags::Checksum6);
            }
            "noencap-udp6-csum" => {
                builder = builder.encap_flags(GreEncapFlags::empty());
            }
            "encap-remcsum" => {
                builder = builder.encap_flags(GreEncapFlags::RemoteChecksum);
            }
            "noencap-remcsum" => {
                builder = builder.encap_flags(GreEncapFlags::empty());
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
                builder = builder.fwmark(mark.to_be());
            }
            "ignore-df" | "noignore-df" => {}
            "erspan" => {
                let v = next_val()?;
                let idx: u32 = v.parse().map_err(|_| {
                    CliError::from(format!("invalid erspan index: {v}"))
                })?;
                if idx == 0 || idx & !((1 << 20) - 1) != 0 {
                    return Err(CliError::from(
                        "erspan index must be > 0 and <= 20-bit",
                    ));
                }
                builder = builder.erspan_index(idx);
            }
            "erspan_ver" => {
                let v = next_val()?;
                let ver: u8 = v.parse().map_err(|_| {
                    CliError::from(format!("invalid erspan version: {v}"))
                })?;
                if ver > 2 {
                    return Err(CliError::from("erspan version must be 0/1/2"));
                }
                builder = builder.erspan_ver(ver);
            }
            "erspan_dir" => {
                let v = next_val()?;
                match v.as_str() {
                    "ingress" => {
                        builder = builder.erspan_dir(ErSpanDir::Ingress);
                    }
                    "egress" => {
                        builder = builder.erspan_dir(ErSpanDir::Egress);
                    }
                    _ => {
                        return Err(CliError::from(format!(
                            "Invalid erspan direction: {v}"
                        )));
                    }
                }
            }
            "erspan_hwid" => {
                let v = next_val()?;
                let hwid = if let Some(hex) = v.strip_prefix("0x") {
                    u16::from_str_radix(hex, 16)
                } else {
                    v.parse()
                };
                let hwid = hwid.map_err(|_| {
                    CliError::from(format!("invalid erspan hwid: {v}"))
                })?;
                builder = builder.erspan_hwid(hwid);
            }
            _ => {
                return Err(CliError::from(format!(
                    "Unknown gre argument: {key}"
                )));
            }
        }
    }

    if metadata {
        builder = builder.collect_metadata(true);
    }

    Ok(builder)
}

async fn build_gre6_opts(
    mut builder: LinkMessageBuilder<LinkGre6>,
    conf: &LinkBaseConf,
    handle: &rtnetlink::Handle,
) -> Result<LinkMessageBuilder<LinkGre6>, CliError> {
    let mut metadata = false;

    let mut iter = conf.iface_specific.iter();
    while let Some(key) = iter.next() {
        let mut next_val = || {
            iter.next().ok_or_else(|| {
                CliError::from(format!("ip6gre {key} requires a value"))
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
                let ifindex = conf.get_ifindex_by_name(handle, v).await?;
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
                match v.as_str() {
                    "none" => {}
                    _ => {
                        let limit: u8 = v.parse().map_err(|_| {
                            CliError::from(format!("invalid encaplimit: {v}"))
                        })?;
                        builder = builder.encap_limit(limit);
                    }
                }
            }
            "tclass" => {
                let v = next_val()?;
                match v.as_str() {
                    "inherit" => {}
                    _ => {
                        let tclass = parse_dsfield(v)?;
                        builder = builder.flowlabel((tclass as u32) << 20);
                    }
                }
            }
            "flowlabel" | "fl" => {
                let v = next_val()?;
                match v.as_str() {
                    "inherit" => {}
                    _ => {
                        let uval = if let Some(hex) = v.strip_prefix("0x") {
                            u32::from_str_radix(hex, 16)
                        } else {
                            v.parse()
                        };
                        let uval = uval.map_err(|_| {
                            CliError::from(format!("invalid flowlabel: {v}"))
                        })?;
                        builder = builder.flowlabel(uval & 0xfffff);
                    }
                }
            }
            "key" => {
                let v = next_val()?;
                let key: u32 = v
                    .parse()
                    .map_err(|_| CliError::from(format!("invalid key: {v}")))?;
                builder = builder
                    .ikey(key)
                    .iflags(GreIOFlags::Key)
                    .okey(key)
                    .oflags(GreIOFlags::Key);
            }
            "ikey" => {
                let v = next_val()?;
                let key: u32 = v.parse().map_err(|_| {
                    CliError::from(format!("invalid ikey: {v}"))
                })?;
                builder = builder.ikey(key).iflags(GreIOFlags::Key);
            }
            "okey" => {
                let v = next_val()?;
                let key: u32 = v.parse().map_err(|_| {
                    CliError::from(format!("invalid okey: {v}"))
                })?;
                builder = builder.okey(key).oflags(GreIOFlags::Key);
            }
            "nokey" => {
                builder = builder
                    .ikey(0)
                    .iflags(GreIOFlags::empty())
                    .okey(0)
                    .oflags(GreIOFlags::empty());
            }
            "noikey" => {
                builder = builder.ikey(0).iflags(GreIOFlags::empty());
            }
            "nookey" => {
                builder = builder.okey(0).oflags(GreIOFlags::empty());
            }
            "seq" => {
                builder =
                    builder.iflags(GreIOFlags::Seq).oflags(GreIOFlags::Seq);
            }
            "iseq" => {
                builder = builder.iflags(GreIOFlags::Seq);
            }
            "noseq" => {
                builder = builder
                    .iflags(GreIOFlags::empty())
                    .oflags(GreIOFlags::empty());
            }
            "noiseq" => {
                builder = builder.iflags(GreIOFlags::empty());
            }
            "oseq" => {
                builder = builder.oflags(GreIOFlags::Seq);
            }
            "nooseq" => {
                builder = builder.oflags(GreIOFlags::empty());
            }
            "csum" => {
                builder = builder
                    .iflags(GreIOFlags::Checksum)
                    .oflags(GreIOFlags::Checksum);
            }
            "icsum" => {
                builder = builder.iflags(GreIOFlags::Checksum);
            }
            "nocsum" => {
                builder = builder
                    .iflags(GreIOFlags::empty())
                    .oflags(GreIOFlags::empty());
            }
            "noicsum" => {
                builder = builder.iflags(GreIOFlags::empty());
            }
            "ocsum" => {
                builder = builder.oflags(GreIOFlags::Checksum);
            }
            "noocsum" => {
                builder = builder.oflags(GreIOFlags::empty());
            }
            "external" => {
                metadata = true;
            }
            "noencap" => {
                builder = builder.encap_type(GreEncapType::None);
            }
            "encap" => {
                let v = next_val()?;
                match v.as_str() {
                    "fou" => {
                        builder = builder.encap_type(GreEncapType::Fou);
                    }
                    "gue" => {
                        builder = builder.encap_type(GreEncapType::Gue);
                    }
                    "none" => {
                        builder = builder.encap_type(GreEncapType::None);
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
                builder = builder.encap_flags(GreEncapFlags::Checksum);
            }
            "noencap-csum" => {
                builder = builder.encap_flags(GreEncapFlags::empty());
            }
            "encap-udp6-csum" => {
                builder = builder.encap_flags(GreEncapFlags::Checksum6);
            }
            "noencap-udp6-csum" => {
                builder = builder.encap_flags(GreEncapFlags::empty());
            }
            "encap-remcsum" => {
                builder = builder.encap_flags(GreEncapFlags::RemoteChecksum);
            }
            "noencap-remcsum" => {
                builder = builder.encap_flags(GreEncapFlags::empty());
            }
            "fwmark" => {
                let v = next_val()?;
                match v.as_str() {
                    "inherit" => {}
                    _ => {
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
                }
            }
            "erspan" => {
                let v = next_val()?;
                let idx: u32 = v.parse().map_err(|_| {
                    CliError::from(format!("invalid erspan index: {v}"))
                })?;
                if idx == 0 || idx & !((1 << 20) - 1) != 0 {
                    return Err(CliError::from(
                        "erspan index must be > 0 and <= 20-bit",
                    ));
                }
                builder = builder.erspan_index(idx);
            }
            "erspan_ver" => {
                let v = next_val()?;
                let ver: u8 = v.parse().map_err(|_| {
                    CliError::from(format!("invalid erspan version: {v}"))
                })?;
                if ver > 2 {
                    return Err(CliError::from("erspan version must be 0/1/2"));
                }
                builder = builder.erspan_ver(ver);
            }
            "erspan_dir" => {
                let v = next_val()?;
                match v.as_str() {
                    "ingress" => {
                        builder = builder.erspan_dir(ErSpanDir::Ingress);
                    }
                    "egress" => {
                        builder = builder.erspan_dir(ErSpanDir::Egress);
                    }
                    _ => {
                        return Err(CliError::from(format!(
                            "Invalid erspan direction: {v}"
                        )));
                    }
                }
            }
            "erspan_hwid" => {
                let v = next_val()?;
                let hwid = if let Some(hex) = v.strip_prefix("0x") {
                    u16::from_str_radix(hex, 16)
                } else {
                    v.parse()
                };
                let hwid = hwid.map_err(|_| {
                    CliError::from(format!("invalid erspan hwid: {v}"))
                })?;
                builder = builder.erspan_hwid(hwid);
            }
            _ => {
                return Err(CliError::from(format!(
                    "Unknown ip6gre argument: {key}"
                )));
            }
        }
    }

    if metadata {
        builder = builder.collect_metadata(true);
    }

    Ok(builder)
}

pub(crate) struct IfaceGre;

impl IfaceGre {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... gre              [ remote ADDR ]
                        [ local ADDR ]
                        [ [no][i|o]seq ]
                        [ [i|o]key KEY | no[i|o]key ]
                        [ [no][i|o]csum ]
                        [ ttl TTL ]
                        [ tos TOS ]
                        [ [no]pmtudisc ]
                        [ [no]ignore-df ]
                        [ dev PHYS_DEV ]
                        [ fwmark MARK ]
                        [ external ]
                        [ noencap ]
                        [ encap { fou | gue | none } ]
                        [ encap-sport PORT ]
                        [ encap-dport PORT ]
                        [ [no]encap-csum ]
                        [ [no]encap-csum6 ]
                        [ [no]encap-remcsum ]

Where:        ADDR := { IP_ADDRESS | any }
        TOS  := { NUMBER | inherit }
        TTL  := { 1..255 | inherit }
        KEY  := { DOTTED_QUAD | NUMBER }
        MARK := { 0x0..0xffffffff }
"
    }
}

pub(crate) struct IfaceGreTap;

impl IfaceGreTap {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... gretap           [ remote ADDR ]
                        [ local ADDR ]
                        [ [no][i|o]seq ]
                        [ [i|o]key KEY | no[i|o]key ]
                        [ [no][i|o]csum ]
                        [ ttl TTL ]
                        [ tos TOS ]
                        [ [no]pmtudisc ]
                        [ [no]ignore-df ]
                        [ dev PHYS_DEV ]
                        [ fwmark MARK ]
                        [ external ]
                        [ noencap ]
                        [ encap { fou | gue | none } ]
                        [ encap-sport PORT ]
                        [ encap-dport PORT ]
                        [ [no]encap-csum ]
                        [ [no]encap-csum6 ]
                        [ [no]encap-remcsum ]

Where:        ADDR := { IP_ADDRESS | any }
        TOS  := { NUMBER | inherit }
        TTL  := { 1..255 | inherit }
        KEY  := { DOTTED_QUAD | NUMBER }
        MARK := { 0x0..0xffffffff }
"
    }
}

pub(crate) struct IfaceGre6;

impl IfaceGre6 {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... ip6gre           [ remote ADDR ]
                        [ local ADDR ]
                        [ [no][i|o]seq ]
                        [ [i|o]key KEY | no[i|o]key ]
                        [ [no][i|o]csum ]
                        [ hoplimit TTL ]
                        [ encaplimit ELIM ]
                        [ tclass TCLASS ]
                        [ flowlabel FLOWLABEL ]
                        [ dscp inherit ]
                        [ dev PHYS_DEV ]
                        [ fwmark MARK ]
                        [ [no]allow-localremote ]
                        [ external ]
                        [ noencap ]
                        [ encap { fou | gue | none } ]
                        [ encap-sport PORT ]
                        [ encap-dport PORT ]
                        [ [no]encap-csum ]
                        [ [no]encap-csum6 ]
                        [ [no]encap-remcsum ]
                        [ erspan_ver version ]
                        [ erspan IDX ]
                        [ erspan_dir { ingress | egress } ]
                        [ erspan_hwid hwid ]

Where:        ADDR          := IPV6_ADDRESS
        TTL          := { 0..255 } (default=64)
        KEY          := { DOTTED_QUAD | NUMBER }
        ELIM          := { none | 0..255 }(default=4)
        TCLASS          := { 0x0..0xff | inherit }
        FLOWLABEL := { 0x0..0xfffff | inherit }
        MARK          := { 0x0..0xffffffff | inherit }
"
    }
}

pub(crate) struct IfaceGreTap6;

impl IfaceGreTap6 {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... ip6gretap        [ remote ADDR ]
                        [ local ADDR ]
                        [ [no][i|o]seq ]
                        [ [i|o]key KEY | no[i|o]key ]
                        [ [no][i|o]csum ]
                        [ hoplimit TTL ]
                        [ encaplimit ELIM ]
                        [ tclass TCLASS ]
                        [ flowlabel FLOWLABEL ]
                        [ dscp inherit ]
                        [ dev PHYS_DEV ]
                        [ fwmark MARK ]
                        [ [no]allow-localremote ]
                        [ external ]
                        [ noencap ]
                        [ encap { fou | gue | none } ]
                        [ encap-sport PORT ]
                        [ encap-dport PORT ]
                        [ [no]encap-csum ]
                        [ [no]encap-csum6 ]
                        [ [no]encap-remcsum ]
                        [ erspan_ver version ]
                        [ erspan IDX ]
                        [ erspan_dir { ingress | egress } ]
                        [ erspan_hwid hwid ]

Where:        ADDR          := IPV6_ADDRESS
        TTL          := { 0..255 } (default=64)
        KEY          := { DOTTED_QUAD | NUMBER }
        ELIM          := { none | 0..255 }(default=4)
        TCLASS          := { 0x0..0xff | inherit }
        FLOWLABEL := { 0x0..0xfffff | inherit }
        MARK          := { 0x0..0xffffffff | inherit }
"
    }
}

pub(crate) struct IfaceErSpan;

impl IfaceErSpan {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... erspan           [ remote ADDR ]
                        [ local ADDR ]
                        [ ttl TTL ]
                        [ tos TOS ]
                        [ [no]pmtudisc ]
                        [ dev PHYS_DEV ]
                        [ fwmark MARK ]
                        [ external ]
                        [ noencap ]
                        [ encap { fou | gue | none } ]
                        [ encap-sport PORT ]
                        [ encap-dport PORT ]
                        [ [no]encap-csum ]
                        [ [no]encap-csum6 ]
                        [ [no]encap-remcsum ]
                        [ erspan_ver version ]
                        [ erspan IDX ]
                        [ erspan_dir { ingress | egress } ]
                        [ erspan_hwid hwid ]

Where:        ADDR := { IP_ADDRESS | any }
        TOS  := { NUMBER | inherit }
        TTL  := { 1..255 | inherit }
        MARK := { 0x0..0xffffffff }
"
    }
}

pub(crate) struct IfaceIp6ErSpan;

impl IfaceIp6ErSpan {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... ip6erspan        [ remote ADDR ]
                        [ local ADDR ]
                        [ hoplimit TTL ]
                        [ encaplimit ELIM ]
                        [ tclass TCLASS ]
                        [ flowlabel FLOWLABEL ]
                        [ dscp inherit ]
                        [ dev PHYS_DEV ]
                        [ fwmark MARK ]
                        [ external ]
                        [ noencap ]
                        [ encap { fou | gue | none } ]
                        [ encap-sport PORT ]
                        [ encap-dport PORT ]
                        [ [no]encap-csum ]
                        [ [no]encap-csum6 ]
                        [ [no]encap-remcsum ]
                        [ erspan_ver version ]
                        [ erspan IDX ]
                        [ erspan_dir { ingress | egress } ]
                        [ erspan_hwid hwid ]

Where:        ADDR          := IPV6_ADDRESS
        TTL          := { 0..255 } (default=64)
        ELIM          := { none | 0..255 }(default=4)
        TCLASS          := { 0x0..0xff | inherit }
        FLOWLABEL := { 0x0..0xfffff | inherit }
        MARK          := { 0x0..0xffffffff | inherit }
"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gre_data() -> CliLinkInfoDataGre {
        CliLinkInfoDataGre {
            link: None,
            link_name: None,
            remote: None,
            local: None,
            ttl: None,
            tos: None,
            pmtudisc: None,
            collect_metadata: false,
            iflags: GreIOFlags::empty(),
            oflags: GreIOFlags::empty(),
            ikey: None,
            okey: None,
            fwmark: None,
            encap_type: None,
            encap_flags: None,
            encap_sport: None,
            encap_dport: None,
            encap_limit: None,
            flow_label: None,
            is_ip6: false,
            erspan_index: None,
            erspan_ver: None,
            erspan_dir: None,
            erspan_hwid: None,
        }
    }

    fn format_gre(data: CliLinkInfoDataGre) -> String {
        format!("{data}")
    }

    mod display {
        use super::*;

        #[test]
        fn test_erspan_v1_with_index() {
            let data = CliLinkInfoDataGre {
                erspan_ver: Some(1),
                erspan_index: Some(123),
                ..make_gre_data()
            };
            let out = format_gre(data);
            assert!(out.contains("erspan_ver 1"), "output: {out}");
            assert!(out.contains("erspan_index 123"), "output: {out}");
        }

        #[test]
        fn test_erspan_v2_ingress() {
            let data = CliLinkInfoDataGre {
                erspan_ver: Some(2),
                erspan_dir: Some(ErSpanDir::Ingress),
                erspan_hwid: Some(0x1a),
                ..make_gre_data()
            };
            let out = format_gre(data);
            assert!(out.contains("erspan_ver 2"), "output: {out}");
            assert!(out.contains("erspan_dir ingress"), "output: {out}");
            assert!(out.contains("erspan_hwid 0x1a"), "output: {out}");
        }

        #[test]
        fn test_erspan_v2_egress() {
            let data = CliLinkInfoDataGre {
                erspan_ver: Some(2),
                erspan_dir: Some(ErSpanDir::Egress),
                erspan_hwid: Some(0xff),
                ..make_gre_data()
            };
            let out = format_gre(data);
            assert!(out.contains("erspan_ver 2"), "output: {out}");
            assert!(out.contains("erspan_dir egress"), "output: {out}");
            assert!(out.contains("erspan_hwid 0xff"), "output: {out}");
        }

        #[test]
        fn test_erspan_v2_no_dir_no_hwid() {
            let data = CliLinkInfoDataGre {
                erspan_ver: Some(2),
                ..make_gre_data()
            };
            let out = format_gre(data);
            assert!(out.contains("erspan_ver 2"), "output: {out}");
            assert!(!out.contains("erspan_dir"), "output: {out}");
            assert!(!out.contains("erspan_hwid"), "output: {out}");
        }

        #[test]
        fn test_erspan_v1_no_index() {
            let data = CliLinkInfoDataGre {
                erspan_ver: Some(1),
                ..make_gre_data()
            };
            let out = format_gre(data);
            assert!(out.contains("erspan_ver 1"), "output: {out}");
            assert!(!out.contains("erspan_index"), "output: {out}");
        }

        #[test]
        fn test_gre_no_erspan_fields() {
            let data = make_gre_data();
            let out = format_gre(data);
            assert!(!out.contains("erspan"), "output: {out}");
        }

        #[test]
        fn test_erspan_v2_ip6() {
            let data = CliLinkInfoDataGre {
                is_ip6: true,
                erspan_ver: Some(2),
                erspan_dir: Some(ErSpanDir::Ingress),
                erspan_hwid: Some(0x2b),
                ..make_gre_data()
            };
            let out = format_gre(data);
            assert!(out.contains("erspan_ver 2"), "output: {out}");
            assert!(out.contains("erspan_dir ingress"), "output: {out}");
            assert!(out.contains("erspan_hwid 0x2b"), "output: {out}");
            assert!(out.contains("hoplimit"), "output: {out}");
        }
    }

    mod parse_info_gre {
        use std::net::Ipv4Addr;

        use super::*;

        #[test]
        fn test_parse_erspan_v1() {
            let nlas = vec![
                InfoGre::Remote(Ipv4Addr::new(10, 0, 0, 1)),
                InfoGre::Local(Ipv4Addr::new(192, 168, 1, 1)),
                InfoGre::Ttl(64),
                InfoGre::ErSpanVer(1),
                InfoGre::ErSpanIndex(123),
            ];
            let data = CliLinkInfoDataGre::from(nlas.as_slice());
            assert_eq!(data.erspan_ver, Some(1));
            assert_eq!(data.erspan_index, Some(123));
        }

        #[test]
        fn test_parse_erspan_v2() {
            let nlas = vec![
                InfoGre::Remote(Ipv4Addr::new(10, 0, 0, 1)),
                InfoGre::ErSpanVer(2),
                InfoGre::ErSpanDir(ErSpanDir::Ingress),
                InfoGre::ErSpanHwId(0x1a),
            ];
            let data = CliLinkInfoDataGre::from(nlas.as_slice());
            assert_eq!(data.erspan_ver, Some(2));
            assert_eq!(data.erspan_dir, Some(ErSpanDir::Ingress));
            assert_eq!(data.erspan_hwid, Some(0x1a));
        }

        #[test]
        fn test_parse_erspan_missing_all() {
            let nlas = vec![InfoGre::Remote(Ipv4Addr::new(10, 0, 0, 1))];
            let data = CliLinkInfoDataGre::from(nlas.as_slice());
            assert!(data.erspan_ver.is_none());
            assert!(data.erspan_index.is_none());
            assert!(data.erspan_dir.is_none());
            assert!(data.erspan_hwid.is_none());
        }
    }

    mod parse_info_gre6 {
        use std::net::Ipv6Addr;

        use super::*;

        #[test]
        fn test_parse_ip6erspan_v1() {
            let nlas = vec![
                InfoGre6::Remote(Ipv6Addr::LOCALHOST),
                InfoGre6::ErSpanVer(1),
                InfoGre6::ErSpanIndex(456),
            ];
            let data = CliLinkInfoDataGre::from(nlas.as_slice());
            assert_eq!(data.erspan_ver, Some(1));
            assert_eq!(data.erspan_index, Some(456));
            assert!(data.is_ip6);
        }

        #[test]
        fn test_parse_ip6erspan_v2() {
            let nlas = vec![
                InfoGre6::Remote(Ipv6Addr::LOCALHOST),
                InfoGre6::ErSpanVer(2),
                InfoGre6::ErSpanDir(ErSpanDir::Egress),
                InfoGre6::ErSpanHwId(0xff),
            ];
            let data = CliLinkInfoDataGre::from(nlas.as_slice());
            assert_eq!(data.erspan_ver, Some(2));
            assert_eq!(data.erspan_dir, Some(ErSpanDir::Egress));
            assert_eq!(data.erspan_hwid, Some(0xff));
        }

        #[test]
        fn test_parse_ip6erspan_missing_all() {
            let nlas = vec![InfoGre6::Remote(Ipv6Addr::LOCALHOST)];
            let data = CliLinkInfoDataGre::from(nlas.as_slice());
            assert!(data.erspan_ver.is_none());
            assert!(data.erspan_index.is_none());
            assert!(data.erspan_dir.is_none());
            assert!(data.erspan_hwid.is_none());
        }
    }
}
