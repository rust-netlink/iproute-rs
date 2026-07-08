// SPDX-License-Identifier: MIT

use std::{collections::HashMap, net::IpAddr};

use iproute_rs::CliError;
use rtnetlink::{
    LinkAmt, LinkMessageBuilder,
    packet_route::link::{AmtMode, InfoAmt, InfoKind, LinkInfo},
};
use serde::Serialize;

use super::parse::{extract_link_info, parse_u16, parse_u32};
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataAmt {
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discovery: Option<IpAddr>,
    #[serde(skip_serializing)]
    link: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "link")]
    link_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tunnels: Option<u32>,
}

impl CliLinkInfoDataAmt {
    pub(crate) fn resolve_link(&mut self, index_2_name: &HashMap<u32, String>) {
        if let Some(idx) = self.link
            && let Some(name) = index_2_name.get(&idx)
        {
            self.link_name = Some(name.clone());
        }
    }
}

impl From<&[InfoAmt]> for CliLinkInfoDataAmt {
    fn from(info: &[InfoAmt]) -> Self {
        let mut mode = None;
        let mut gateway_port = None;
        let mut relay_port = None;
        let mut local = None;
        let mut remote = None;
        let mut discovery = None;
        let mut link = None;
        let mut max_tunnels = None;
        for nla in info {
            match nla {
                InfoAmt::Mode(m) => {
                    mode = Some(*m);
                }
                InfoAmt::GatewayPort(p) => {
                    gateway_port = Some(*p);
                }
                InfoAmt::RelayPort(p) => {
                    relay_port = Some(*p);
                }
                InfoAmt::LocalIp(ip) => {
                    local = Some(*ip);
                }
                InfoAmt::RemoteIp(ip) => {
                    remote = Some(*ip);
                }
                InfoAmt::DiscoveryIp(ip) => {
                    discovery = Some(*ip);
                }
                InfoAmt::Link(idx) => {
                    link = Some(*idx);
                }
                InfoAmt::MaxTunnels(c) => {
                    max_tunnels = Some(*c);
                }
                _ => (),
            }
        }
        Self {
            mode: mode
                .as_ref()
                .map(|m| m.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            gateway_port,
            relay_port,
            local,
            remote,
            discovery,
            link,
            link_name: None,
            max_tunnels,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataAmt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mode)?;
        if let Some(p) = self.gateway_port {
            write!(f, " gateway_port {p}")?;
        }
        if let Some(p) = self.relay_port {
            write!(f, " relay_port {p}")?;
        }
        if let Some(ip) = &self.local {
            write!(f, " local {ip}")?;
        }
        if let Some(ip) = &self.remote {
            write!(f, " remote {ip}")?;
        }
        if let Some(ip) = &self.discovery {
            write!(f, " discovery {ip}")?;
        }
        if let Some(ref name) = self.link_name {
            write!(f, " dev {name}")?;
        }
        if let Some(c) = self.max_tunnels {
            write!(f, " max_tunnels {c}")?;
        }
        Ok(())
    }
}

fn apply_amt_args<'a>(
    mut builder: LinkMessageBuilder<LinkAmt>,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<LinkMessageBuilder<LinkAmt>, CliError> {
    let mut mode_set = false;
    while let Some(key) = iter.next() {
        match key {
            "mode" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("amt: mode requires a value"));
                };
                let mode = match v {
                    "gateway" => AmtMode::Gateway,
                    "relay" => AmtMode::Relay,
                    _ => {
                        return Err(CliError::from(format!(
                            "amt: invalid mode \"{v}\", must be \"gateway\" \
                             or \"relay\""
                        )));
                    }
                };
                builder = builder.mode(mode);
                mode_set = true;
            }
            "dev" => {
                return Err(CliError::from(
                    "amt: dev parameter must be resolved separately",
                ));
            }
            "relay_port" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "amt: relay_port requires a value",
                    ));
                };
                builder = builder.relay_port(parse_u16(v, "relay_port")?);
            }
            "gateway_port" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "amt: gateway_port requires a value",
                    ));
                };
                builder = builder.gateway_port(parse_u16(v, "gateway_port")?);
            }
            "local" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("amt: local requires a value"));
                };
                let ip: IpAddr = v.parse().map_err(|_| {
                    CliError::from(format!("amt: invalid local IP \"{v}\""))
                })?;
                builder = builder.local_ip(ip);
            }
            "remote" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("amt: remote requires a value"));
                };
                let ip: IpAddr = v.parse().map_err(|_| {
                    CliError::from(format!("amt: invalid remote IP \"{v}\""))
                })?;
                builder = builder.remote_ip(ip);
            }
            "discovery" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "amt: discovery requires a value",
                    ));
                };
                let ip: IpAddr = v.parse().map_err(|_| {
                    CliError::from(format!("amt: invalid discovery IP \"{v}\""))
                })?;
                builder = builder.discovery_ip(ip);
            }
            "max_tunnels" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "amt: max_tunnels requires a value",
                    ));
                };
                builder = builder.max_tunnels(parse_u32(v, "max_tunnels")?);
            }
            _ => {
                return Err(CliError::from(format!(
                    "amt: unknown option \"{key}\"",
                )));
            }
        }
    }
    if !mode_set {
        return Err(CliError::from("amt: missing required \"mode\" argument"));
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) async fn apply_amt(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkAmt>, CliError> {
        let mut builder = LinkMessageBuilder::<LinkAmt>::new(&self.name);

        let mut filtered_args = Vec::new();
        let mut dev_name = None;
        {
            let mut iter = self.iface_specific.iter().peekable();
            while let Some(key) = iter.next() {
                if key == "dev" {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "amt: dev requires a value",
                        ));
                    };
                    dev_name = Some(v.clone());
                } else {
                    filtered_args.push(key.as_str());
                    if let Some(v) = iter.peek() {
                        filtered_args.push(v.as_str());
                        iter.next();
                    }
                }
            }
        }

        if let Some(ref dev_name) = dev_name {
            let link_ifindex =
                self.get_ifindex_by_name(handle, dev_name).await?;
            builder = builder.dev(link_ifindex);
        }

        let mut iter = filtered_args.into_iter();
        builder = apply_amt_args(builder, &mut iter)?;

        Ok(builder)
    }
}

pub(crate) struct IfaceAmt;

impl IfaceAmt {
    pub(crate) async fn build_entries(
        handle: Option<&rtnetlink::Handle>,
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder =
            LinkMessageBuilder::<LinkAmt>::new_with_info_kind(InfoKind::Amt);

        let mut dev_name = None;
        let mut filtered_args = Vec::new();
        {
            let mut iter = args.iter().peekable();
            while let Some(key) = iter.next() {
                if key == "dev" {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "amt: dev requires a value",
                        ));
                    };
                    dev_name = Some(v.clone());
                } else {
                    filtered_args.push(key.as_str());
                    if let Some(v) = iter.peek() {
                        filtered_args.push(v.as_str());
                        iter.next();
                    }
                }
            }
        }

        let builder =
            if let (Some(handle), Some(dev_name)) = (handle, &dev_name) {
                let ifindex = resolve_ifindex_by_name(handle, dev_name).await?;
                builder.dev(ifindex)
            } else {
                builder
            };

        let mut iter = filtered_args.into_iter();
        let builder = apply_amt_args(builder, &mut iter)?;
        Ok(extract_link_info(builder.build()))
    }

    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        "Usage: ... amt\n               [ discovery IP_ADDRESS ]\n               [ mode MODE ]\n               [ local ADDR ]\n               [ dev PHYS_DEV ]\n               [ relay_port PORT ]\n               [ gateway_port PORT ]\n               [ max_tunnels NUMBER ]\n\nWhere: ADDR\t:= { IP_ADDRESS }\n       MODE\t:= { gateway | relay }\n"
    }
}

async fn resolve_ifindex_by_name(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, CliError> {
    use futures_util::TryStreamExt;
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device \"{name}\" does not exist"))
    })?;
    Ok(link.header.index)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rtnetlink::packet_route::link::{AmtMode, InfoAmt, InfoData, LinkInfo};

    use super::*;

    #[tokio::test]
    async fn test_build_entries_with_mode_only() {
        let infos =
            IfaceAmt::build_entries(None, &["mode".into(), "gateway".into()])
                .await
                .unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::Amt)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::Amt(vec![
            InfoAmt::Mode(AmtMode::Gateway),
        ]))));
    }

    #[tokio::test]
    async fn test_build_entries_with_mode_and_ports() {
        let infos = IfaceAmt::build_entries(
            None,
            &[
                "mode".into(),
                "relay".into(),
                "relay_port".into(),
                "1234".into(),
                "gateway_port".into(),
                "5678".into(),
            ],
        )
        .await
        .unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::Amt)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::Amt(vec![
            InfoAmt::Mode(AmtMode::Relay),
            InfoAmt::RelayPort(1234),
            InfoAmt::GatewayPort(5678),
        ]))));
    }

    #[tokio::test]
    async fn test_build_entries_with_ip_and_max_tunnels() {
        let infos = IfaceAmt::build_entries(
            None,
            &[
                "mode".into(),
                "gateway".into(),
                "local".into(),
                "10.0.0.1".into(),
                "discovery".into(),
                "10.0.0.2".into(),
                "max_tunnels".into(),
                "8".into(),
            ],
        )
        .await
        .unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::Amt)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::Amt(vec![
            InfoAmt::Mode(AmtMode::Gateway),
            InfoAmt::LocalIp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            InfoAmt::DiscoveryIp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            InfoAmt::MaxTunnels(8),
        ]))));
    }

    #[tokio::test]
    async fn test_build_entries_missing_mode() {
        let err = IfaceAmt::build_entries(None, &[]).await.unwrap_err();
        assert!(err.msg.contains("mode"), "{}", err.msg);
    }

    #[tokio::test]
    async fn test_build_entries_invalid_mode() {
        let err =
            IfaceAmt::build_entries(None, &["mode".into(), "invalid".into()])
                .await
                .unwrap_err();
        assert!(err.msg.contains("invalid mode"), "{}", err.msg);
    }

    #[tokio::test]
    async fn test_build_entries_missing_value() {
        let err = IfaceAmt::build_entries(None, &["mode".into()])
            .await
            .unwrap_err();
        assert!(err.msg.contains("requires a value"), "{}", err.msg);
    }

    #[test]
    fn test_amt_info_from_gateway() {
        let infos = vec![InfoAmt::Mode(AmtMode::Gateway)];
        let data = CliLinkInfoDataAmt::from(infos.as_slice());
        assert_eq!(data.mode, "gateway");
    }

    #[test]
    fn test_amt_info_from_relay_full() {
        let infos = vec![
            InfoAmt::Mode(AmtMode::Relay),
            InfoAmt::RelayPort(1234),
            InfoAmt::GatewayPort(5678),
            InfoAmt::LocalIp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            InfoAmt::DiscoveryIp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            InfoAmt::MaxTunnels(16),
        ];
        let data = CliLinkInfoDataAmt::from(infos.as_slice());
        assert_eq!(data.mode, "relay");
        assert_eq!(data.relay_port, Some(1234));
        assert_eq!(data.gateway_port, Some(5678));
        assert_eq!(data.local, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(
            data.discovery,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(data.max_tunnels, Some(16));
    }

    #[test]
    fn test_amt_display_gateway() {
        let infos = vec![InfoAmt::Mode(AmtMode::Gateway)];
        let data = CliLinkInfoDataAmt::from(infos.as_slice());
        let display = format!("{data}");
        assert_eq!(display, "gateway");
    }

    #[test]
    fn test_amt_display_relay_full() {
        let mut data = CliLinkInfoDataAmt::from(
            vec![
                InfoAmt::Mode(AmtMode::Relay),
                InfoAmt::RelayPort(1234),
                InfoAmt::MaxTunnels(8),
            ]
            .as_slice(),
        );
        data.link_name = Some("eth0".to_string());
        let display = format!("{data}");
        assert_eq!(display, "relay relay_port 1234 dev eth0 max_tunnels 8");
    }
}
