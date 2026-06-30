// SPDX-License-Identifier: MIT

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use iproute_rs::CliError;
use rtnetlink::{
    LinkMessageBuilder, LinkVti, LinkVti6, packet_route::link::InfoVti,
};
use serde::Serialize;

use super::parse::parse_u32;
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataVti {
    #[serde(skip)]
    link: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "link")]
    link_name: Option<String>,
    remote: Option<IpAddr>,
    local: Option<IpAddr>,
    ikey: Option<u32>,
    okey: Option<u32>,
    fwmark: Option<u32>,
}

impl CliLinkInfoDataVti {
    pub(crate) fn resolve_link(&mut self, index_2_name: &HashMap<u32, String>) {
        if let Some(idx) = self.link
            && let Some(name) = index_2_name.get(&idx)
        {
            self.link_name = Some(name.clone());
        }
    }
}

impl From<&[InfoVti]> for CliLinkInfoDataVti {
    fn from(info: &[InfoVti]) -> Self {
        let mut link = None;
        let mut remote = None;
        let mut local = None;
        let mut ikey = None;
        let mut okey = None;
        let mut fwmark = None;

        for nla in info {
            match nla {
                InfoVti::Link(v) => link = Some(*v),
                InfoVti::Local(v) => local = Some(*v),
                InfoVti::Remote(v) => remote = Some(*v),
                InfoVti::IKey(v) => ikey = Some(*v),
                InfoVti::OKey(v) => okey = Some(*v),
                InfoVti::FwMark(v) => fwmark = Some(*v),
                _ => (),
            }
        }

        Self {
            link,
            link_name: None,
            remote,
            local,
            ikey,
            okey,
            fwmark,
        }
    }
}

fn u32_to_dotted_quad(val: u32) -> String {
    let b = val.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

impl std::fmt::Display for CliLinkInfoDataVti {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addr_display = |addr: &IpAddr| match addr {
            IpAddr::V4(a) if a.is_unspecified() => "any".to_string(),
            IpAddr::V6(a) if a.is_unspecified() => "any".to_string(),
            _ => addr.to_string(),
        };

        let remote = self
            .remote
            .as_ref()
            .map_or("any".to_string(), &addr_display);
        let local = self.local.as_ref().map_or("any".to_string(), addr_display);

        write!(f, "remote {remote} local {local}")?;
        if let Some(v) = &self.link_name {
            write!(f, " dev {v}")?;
        } else if let Some(v) = self.link
            && v != 0
        {
            write!(f, " dev if{v}")?;
        }
        if let Some(v) = self.ikey
            && v != 0
        {
            write!(f, " ikey {}", u32_to_dotted_quad(v))?;
        }
        if let Some(v) = self.okey
            && v != 0
        {
            write!(f, " okey {}", u32_to_dotted_quad(v))?;
        }
        if let Some(v) = self.fwmark
            && v != 0
        {
            write!(f, " fwmark 0x{v:x}")?;
        }

        Ok(())
    }
}

impl LinkBaseConf {
    pub(crate) async fn apply_vti(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkVti>, CliError> {
        let mut builder = LinkVti::new(&self.name);

        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            let mut next_val = || {
                iter.next().ok_or_else(|| {
                    CliError::from(format!("vti {key} requires a value"))
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
                "key" => {
                    let v = next_val()?;
                    let key = parse_key(v)?;
                    builder = builder.ikey(key);
                    builder = builder.okey(key);
                }
                "ikey" => {
                    let v = next_val()?;
                    let key = parse_key(v)?;
                    builder = builder.ikey(key);
                }
                "okey" => {
                    let v = next_val()?;
                    let key = parse_key(v)?;
                    builder = builder.okey(key);
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
                        "Unknown vti argument: {key}"
                    )));
                }
            }
        }

        Ok(builder)
    }

    pub(crate) async fn apply_vti6(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkVti6>, CliError> {
        let mut builder = LinkVti6::new(&self.name);

        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            let mut next_val = || {
                iter.next().ok_or_else(|| {
                    CliError::from(format!("vti6 {key} requires a value"))
                })
            };
            match key.as_str() {
                "local" => {
                    let v = next_val()?;
                    let addr = parse_ip::<std::net::Ipv6Addr>(v, "local")?;
                    builder = builder.local(addr);
                }
                "remote" => {
                    let v = next_val()?;
                    let addr = parse_ip::<std::net::Ipv6Addr>(v, "remote")?;
                    builder = builder.remote(addr);
                }
                "dev" => {
                    let v = next_val()?;
                    let ifindex = self.get_ifindex_by_name(handle, v).await?;
                    builder = builder.dev(ifindex);
                }
                "key" => {
                    let v = next_val()?;
                    let key = parse_key(v)?;
                    builder = builder.ikey(key);
                    builder = builder.okey(key);
                }
                "ikey" => {
                    let v = next_val()?;
                    let key = parse_key(v)?;
                    builder = builder.ikey(key);
                }
                "okey" => {
                    let v = next_val()?;
                    let key = parse_key(v)?;
                    builder = builder.okey(key);
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
                        "Unknown vti6 argument: {key}"
                    )));
                }
            }
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

fn parse_key(s: &str) -> Result<u32, CliError> {
    if s.contains('.') {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return Err(CliError::from(format!("Invalid key: {s}")));
        }
        let mut val = 0u32;
        for part in parts {
            let byte: u8 = part
                .parse()
                .map_err(|_| CliError::from(format!("Invalid key: {s}")))?;
            val = (val << 8) | byte as u32;
        }
        Ok(val)
    } else {
        parse_u32(s, "key")
    }
}

pub(crate) struct IfaceVti;

impl IfaceVti {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... vti           [ remote ADDR ]
                        [ local ADDR ]
                        [ [i|o]key KEY ]
                        [ dev PHYS_DEV ]
                        [ fwmark MARK ]

Where:        ADDR := { IP_ADDRESS }
        KEY  := { DOTTED_QUAD | NUMBER }
        MARK := { 0x0..0xffffffff }
"
    }
}

pub(crate) struct IfaceVti6;

impl IfaceVti6 {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... vti6          [ remote ADDR ]
                        [ local ADDR ]
                        [ [i|o]key KEY ]
                        [ dev PHYS_DEV ]
                        [ fwmark MARK ]

Where:        ADDR := { IPV6_ADDRESS }
        KEY  := { DOTTED_QUAD | NUMBER }
        MARK := { 0x0..0xffffffff }
"
    }
}
