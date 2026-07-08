// SPDX-License-Identifier: MIT

use std::{collections::HashMap, os::unix::io::AsRawFd};

use futures_util::TryStreamExt;
use iproute_rs::{CliError, parse_mac_str};
use rtnetlink::{
    LinkDummy, LinkIfb, LinkMessageBuilder, LinkNetdevsim, LinkNlmon, LinkPfcp,
    LinkTeam, LinkTun, LinkVcan, LinkVirtWifi, LinkWireguard,
    packet_route::link::{InfoKind, LinkAttribute, LinkMessage},
};

use crate::link::CliLinkInfo;

pub(crate) struct LinkAddCommand;

impl LinkAddCommand {
    pub(crate) const CMD: &'static str = "add";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("add network device")
            .alias("a")
            .alias("ad")
            .arg(
                clap::Arg::new("options")
                    .action(clap::ArgAction::Append)
                    .trailing_var_arg(true),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<Vec<CliLinkInfo>, CliError> {
        let opts: Vec<String> = matches
            .get_many::<String>("options")
            .unwrap_or_default()
            .map(|o| o.to_string())
            .collect();

        let base_conf = LinkBaseConf::parse(opts)?;

        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        let nl_msg = match base_conf.iface_type {
            InfoKind::Amt => {
                base_conf.apply(base_conf.apply_amt(&handle).await?)?
            }
            InfoKind::Ipoib => base_conf.apply(base_conf.apply_ipoib()?)?,
            InfoKind::Dummy => {
                base_conf.apply(LinkDummy::new(&base_conf.name))?
            }
            InfoKind::Team => {
                base_conf.apply(LinkTeam::new(&base_conf.name))?
            }
            InfoKind::Nlmon => {
                base_conf.apply(LinkNlmon::new(&base_conf.name))?
            }
            InfoKind::Tun => base_conf.apply(LinkTun::new(&base_conf.name))?,
            InfoKind::Veth => base_conf.apply(base_conf.apply_veth()?)?,
            InfoKind::Vcan => {
                base_conf.apply(LinkVcan::new(&base_conf.name))?
            }
            InfoKind::Vlan => {
                base_conf.apply(base_conf.apply_vlan(&handle).await?)?
            }
            InfoKind::Bond => {
                base_conf.apply(base_conf.apply_bond(&handle).await?)?
            }
            InfoKind::Bridge => base_conf.apply(base_conf.apply_bridge()?)?,
            InfoKind::Hsr => {
                base_conf.apply(base_conf.apply_hsr(&handle).await?)?
            }
            InfoKind::Ifb => base_conf.apply(LinkIfb::new(&base_conf.name))?,
            InfoKind::Gtp => base_conf.apply(base_conf.apply_gtp(&handle)?)?,
            InfoKind::Netdevsim => {
                base_conf.apply(LinkNetdevsim::new(&base_conf.name))?
            }
            InfoKind::VirtWifi => {
                let mut builder = LinkVirtWifi::new(&base_conf.name);
                if let Some(ref link_name) = base_conf.link {
                    let link_ifindex = base_conf
                        .get_ifindex_by_name(&handle, link_name)
                        .await?;
                    builder = builder.link(link_ifindex);
                }
                base_conf.apply(builder)?
            }
            InfoKind::Wwan => {
                if base_conf.parentdev_name.is_none() {
                    return Err(CliError::from(
                        "wwan: missing required \"parentdev\" argument",
                    ));
                }
                base_conf.apply(base_conf.apply_wwan(&handle).await?)?
            }
            InfoKind::Netkit => base_conf.apply(base_conf.apply_netkit()?)?,
            InfoKind::Vrf => base_conf.apply(base_conf.apply_vrf()?)?,
            InfoKind::Vxcan => base_conf.apply(base_conf.apply_vxcan()?)?,
            InfoKind::Xfrm => {
                base_conf.apply(base_conf.apply_xfrm(&handle).await?)?
            }
            InfoKind::IpIp => {
                base_conf.apply(base_conf.apply_iptun(&handle).await?)?
            }
            InfoKind::SitTun => {
                base_conf.apply(base_conf.apply_sit(&handle).await?)?
            }
            InfoKind::Ip6Tnl => {
                base_conf.apply(base_conf.apply_ip6tnl(&handle).await?)?
            }
            InfoKind::IpVlan => {
                base_conf.apply(base_conf.apply_ipvlan(&handle).await?)?
            }
            InfoKind::IpVtap => {
                base_conf.apply(base_conf.apply_ipvtap(&handle).await?)?
            }
            InfoKind::MacVlan => {
                base_conf.apply(base_conf.apply_macvlan(&handle).await?)?
            }
            InfoKind::MacVtap => {
                base_conf.apply(base_conf.apply_macvtap(&handle).await?)?
            }
            InfoKind::MacSec => {
                base_conf.apply(base_conf.apply_macsec(&handle).await?)?
            }
            InfoKind::Geneve => {
                base_conf.apply(base_conf.apply_geneve(&handle).await?)?
            }
            InfoKind::BareUdp => base_conf.apply(base_conf.apply_bareudp()?)?,
            InfoKind::BatAdv => base_conf.apply(base_conf.apply_batadv()?)?,
            InfoKind::Can => base_conf.apply(base_conf.apply_can()?)?,
            InfoKind::Dsa => {
                base_conf.apply(base_conf.apply_dsa(&handle).await?)?
            }
            InfoKind::GreTun => {
                base_conf.apply(base_conf.apply_gre(&handle).await?)?
            }
            InfoKind::GreTap => {
                base_conf.apply(base_conf.apply_gretap(&handle).await?)?
            }
            InfoKind::GreTun6 => {
                base_conf.apply(base_conf.apply_gre6(&handle).await?)?
            }
            InfoKind::GreTap6 => {
                base_conf.apply(base_conf.apply_gretap6(&handle).await?)?
            }
            InfoKind::ErSpan => {
                base_conf.apply(base_conf.apply_erspan(&handle).await?)?
            }
            InfoKind::Ip6ErSpan => {
                base_conf.apply(base_conf.apply_ip6erspan(&handle).await?)?
            }
            InfoKind::Pfcp => {
                base_conf.apply(LinkPfcp::new(&base_conf.name))?
            }
            InfoKind::Vti => {
                base_conf.apply(base_conf.apply_vti(&handle).await?)?
            }
            InfoKind::Vti6 => {
                base_conf.apply(base_conf.apply_vti6(&handle).await?)?
            }
            InfoKind::RmNet => {
                if base_conf.link.is_none() {
                    return Err(CliError::from(
                        "rmnet: missing required \"link\" argument",
                    ));
                }
                base_conf.apply(base_conf.apply_rmnet(&handle).await?)?
            }
            InfoKind::Vxlan => {
                base_conf.apply(base_conf.apply_vxlan(&handle).await?)?
            }
            InfoKind::Wireguard => {
                base_conf.apply(LinkWireguard::new(&base_conf.name))?
            }
            t => {
                return Err(CliError::from(format!(
                    "Unsupported device type: {t}"
                )));
            }
        };

        handle.link().add(nl_msg).execute().await?;

        Ok(vec![])
    }
}

#[derive(Debug)]
pub(crate) struct LinkBaseConf {
    pub(crate) link: Option<String>,
    pub(crate) parentdev_name: Option<String>,
    pub(crate) name: String,
    pub(crate) address: Option<String>,
    pub(crate) broadcast: Option<String>,
    pub(crate) txqueuelen: Option<u32>,
    pub(crate) mtu: Option<u32>,
    pub(crate) index: Option<i32>,
    pub(crate) numtxqueues: Option<u32>,
    pub(crate) numrxqueues: Option<u32>,
    pub(crate) netns_pid: Option<u32>,
    pub(crate) netns_file: Option<std::fs::File>,
    pub(crate) iface_type: InfoKind,
    pub(crate) iface_specific: Vec<String>,
}

impl LinkBaseConf {
    fn apply<T>(
        &self,
        mut builder: LinkMessageBuilder<T>,
    ) -> Result<LinkMessage, CliError> {
        if let Some(v) = self.address.as_deref() {
            builder = builder.address(parse_mac_str(v)?)
        }
        if let Some(v) = self.broadcast.as_deref() {
            builder = builder.broadcast(parse_mac_str(v)?)
        }
        if let Some(v) = self.txqueuelen {
            builder = builder.txqueuelen(v);
        }
        if let Some(v) = self.mtu {
            builder = builder.mtu(v);
        }
        if let Some(v) = self.index {
            builder =
                builder.append_extra_attribute(LinkAttribute::NewIfIndex(v));
        }
        if let Some(v) = self.numtxqueues {
            builder =
                builder.append_extra_attribute(LinkAttribute::NumTxQueues(v));
        }
        if let Some(v) = self.numrxqueues {
            builder =
                builder.append_extra_attribute(LinkAttribute::NumRxQueues(v));
        }
        if let Some(v) = self.netns_pid {
            builder =
                builder.append_extra_attribute(LinkAttribute::NetNsPid(v));
        }
        if let Some(ref file) = self.netns_file {
            builder = builder.append_extra_attribute(LinkAttribute::NetNsFd(
                file.as_raw_fd(),
            ));
        }
        if let Some(v) = self.parentdev_name.as_deref() {
            builder = builder.append_extra_attribute(
                LinkAttribute::ParentDevName(v.to_string()),
            );
        }
        Ok(builder.build())
    }

    pub(crate) async fn get_ifindex_by_name(
        &self,
        handle: &rtnetlink::Handle,
        name: &str,
    ) -> Result<u32, CliError> {
        let mut links =
            handle.link().get().match_name(name.to_string()).execute();
        let link = links.try_next().await?.ok_or_else(|| {
            CliError::from(format!("Device \"{name}\" does not exist"))
        })?;
        Ok(link.header.index)
    }

    fn parse(args: Vec<String>) -> Result<Self, CliError> {
        if let Some(type_index) =
            args.as_slice().iter().position(|a| a.as_str() == "type")
            && args.len() > type_index + 1
        {
            let iface_type = InfoKind::from(args[type_index + 1].as_str());
            let mut base_args: Vec<&str> =
                args[..type_index].iter().map(|s| s.as_str()).collect();

            if base_args.is_empty() {
                return Err(CliError::from("interface name undefined"));
            }

            if !base_args.len().is_multiple_of(2) {
                // iproute2 indicate only `link DEVICE` can be defined before
                // name
                if base_args[0] == "link" && base_args.len() >= 3 {
                    base_args.insert(2, "name");
                } else {
                    // assume interface name is the first argument
                    base_args.insert(0, "name");
                }
            }

            let mut base_args_dict: HashMap<&str, &str> =
                base_args.chunks(2).map(|c| (c[0], c[1])).collect();

            let Some(name) =
                base_args_dict.remove("name").map(|s| s.to_string())
            else {
                return Err(CliError::from("interface name undefined"));
            };

            let address =
                base_args_dict.remove("address").map(|s| s.to_string());
            let broadcast = base_args_dict
                .remove("broadcast")
                .or_else(|| base_args_dict.remove("brd"))
                .map(|s| s.to_string());
            let txqueuelen = base_args_dict
                .remove("txqueuelen")
                .or_else(|| base_args_dict.remove("qlen"))
                .or_else(|| base_args_dict.remove("txqlen"))
                .map(|s| {
                    s.parse::<u32>().map_err(|_| {
                        CliError::from(format!(
                            "Invalid \"txqueuelen\" value: {s}"
                        ))
                    })
                })
                .transpose()?;
            let mtu = base_args_dict
                .remove("mtu")
                .map(|s| {
                    s.parse::<u32>().map_err(|_| {
                        CliError::from(format!("Invalid \"mtu\" value: {s}"))
                    })
                })
                .transpose()?;
            let index = base_args_dict
                .remove("index")
                .map(|s| {
                    let v = s.parse::<i32>().map_err(|_| {
                        CliError::from(format!("Invalid \"index\" value: {s}"))
                    })?;
                    if v <= 0 {
                        return Err(CliError::from(format!(
                            "Invalid \"index\" value: {s}"
                        )));
                    }
                    Ok(v)
                })
                .transpose()?;
            let numtxqueues = base_args_dict
                .remove("numtxqueues")
                .map(|s| {
                    s.parse::<u32>().map_err(|_| {
                        CliError::from(format!(
                            "Invalid \"numtxqueues\" value: {s}"
                        ))
                    })
                })
                .transpose()?;
            let numrxqueues = base_args_dict
                .remove("numrxqueues")
                .map(|s| {
                    s.parse::<u32>().map_err(|_| {
                        CliError::from(format!(
                            "Invalid \"numrxqueues\" value: {s}"
                        ))
                    })
                })
                .transpose()?;
            let link = base_args_dict.remove("link").map(|s| s.to_string());
            let parentdev_name =
                base_args_dict.remove("parentdev").map(|s| s.to_string());

            let mut netns_pid = None;
            let mut netns_file = None;
            if let Some(ns_val) = base_args_dict.remove("netns") {
                if let Ok(pid) = ns_val.parse::<u32>() {
                    netns_pid = Some(pid);
                } else if let Ok(file) =
                    std::fs::File::open(format!("/run/netns/{ns_val}"))
                {
                    netns_file = Some(file);
                } else {
                    return Err(CliError::from(format!(
                        "Cannot find network namespace \"{ns_val}\""
                    )));
                }
            }

            let iface_specific = if args.len() > type_index + 1 {
                args[type_index + 2..].to_vec()
            } else {
                Vec::new()
            };
            Ok(Self {
                name,
                address,
                broadcast,
                txqueuelen,
                mtu,
                index,
                numtxqueues,
                numrxqueues,
                netns_pid,
                netns_file,
                link,
                parentdev_name,
                iface_type,
                iface_specific,
            })
        } else {
            Err(CliError::from(
                "Not enough information: \"type\" argument is required",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(input: &[&str]) -> Vec<String> {
        input.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_basic_dummy() {
        let conf =
            LinkBaseConf::parse(args(&["eth0", "type", "dummy"])).unwrap();
        assert_eq!(conf.name, "eth0");
        assert_eq!(conf.iface_type, InfoKind::Dummy);
        assert!(conf.address.is_none());
        assert!(conf.link.is_none());
        assert!(conf.iface_specific.is_empty());
    }

    #[test]
    fn parse_with_address() {
        let conf = LinkBaseConf::parse(args(&[
            "name",
            "eth0",
            "address",
            "00:11:22:33:44:55",
            "type",
            "dummy",
        ]))
        .unwrap();
        assert_eq!(conf.name, "eth0");
        assert_eq!(conf.address.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(conf.iface_type, InfoKind::Dummy);
    }

    #[test]
    fn parse_with_link() {
        let conf = LinkBaseConf::parse(args(&[
            "link", "eth0", "name", "eth0.1", "type", "vlan", "id", "100",
        ]))
        .unwrap();
        assert_eq!(conf.name, "eth0.1");
        assert_eq!(conf.link.as_deref(), Some("eth0"));
        assert_eq!(conf.iface_type, InfoKind::Vlan);
        assert_eq!(conf.iface_specific, vec!["id", "100"]);
    }

    #[test]
    fn parse_link_no_name_fails() {
        let err = LinkBaseConf::parse(args(&["link", "eth0", "type", "dummy"]))
            .unwrap_err();
        assert!(err.msg.contains("name"));
    }

    #[test]
    fn parse_missing_type() {
        let err = LinkBaseConf::parse(args(&["eth0"])).unwrap_err();
        assert!(err.msg.contains("type"));
    }

    #[test]
    fn parse_type_at_end() {
        let err = LinkBaseConf::parse(args(&["eth0", "type"])).unwrap_err();
        assert!(err.msg.contains("type"));
    }

    #[test]
    fn parse_empty_args() {
        let err = LinkBaseConf::parse(args(&[])).unwrap_err();
        assert!(err.msg.contains("type"));
    }

    #[test]
    fn parse_no_name() {
        let err = LinkBaseConf::parse(args(&["type", "dummy"])).unwrap_err();
        assert!(err.msg.contains("name"));
    }

    #[test]
    fn parse_odd_args_without_link() {
        let conf =
            LinkBaseConf::parse(args(&["foo", "bar", "baz", "type", "dummy"]))
                .unwrap();
        assert_eq!(conf.name, "foo");
    }

    #[test]
    fn parse_gtp_basic() {
        let conf =
            LinkBaseConf::parse(args(&["gtp0", "type", "gtp", "role", "sgsn"]))
                .unwrap();
        assert_eq!(conf.name, "gtp0");
        assert_eq!(conf.iface_type, InfoKind::Gtp);
        assert_eq!(conf.iface_specific, vec!["role", "sgsn"]);
    }

    #[test]
    fn parse_gtp_full() {
        let conf = LinkBaseConf::parse(args(&[
            "gtp0",
            "type",
            "gtp",
            "role",
            "ggsn",
            "hsize",
            "2048",
            "restart_count",
            "5",
        ]))
        .unwrap();
        assert_eq!(conf.name, "gtp0");
        assert_eq!(conf.iface_type, InfoKind::Gtp);
        assert_eq!(
            conf.iface_specific,
            vec!["role", "ggsn", "hsize", "2048", "restart_count", "5"]
        );
    }

    #[test]
    fn parse_with_mtu() {
        let conf = LinkBaseConf::parse(args(&[
            "eth0", "mtu", "1500", "type", "dummy",
        ]))
        .unwrap();
        assert_eq!(conf.mtu, Some(1500));
    }

    #[test]
    fn parse_with_txqueuelen_aliases() {
        let conf = LinkBaseConf::parse(args(&[
            "eth0",
            "txqueuelen",
            "500",
            "type",
            "dummy",
        ]))
        .unwrap();
        assert_eq!(conf.txqueuelen, Some(500));

        let conf = LinkBaseConf::parse(args(&[
            "eth0", "qlen", "600", "type", "dummy",
        ]))
        .unwrap();
        assert_eq!(conf.txqueuelen, Some(600));

        let conf = LinkBaseConf::parse(args(&[
            "eth0", "txqlen", "700", "type", "dummy",
        ]))
        .unwrap();
        assert_eq!(conf.txqueuelen, Some(700));
    }

    #[test]
    fn parse_with_broadcast() {
        let conf = LinkBaseConf::parse(args(&[
            "eth0",
            "broadcast",
            "ff:ff:ff:ff:ff:ff",
            "type",
            "dummy",
        ]))
        .unwrap();
        assert_eq!(conf.broadcast.as_deref(), Some("ff:ff:ff:ff:ff:ff"));

        let conf = LinkBaseConf::parse(args(&[
            "eth0",
            "brd",
            "00:00:00:00:00:00",
            "type",
            "dummy",
        ]))
        .unwrap();
        assert_eq!(conf.broadcast.as_deref(), Some("00:00:00:00:00:00"));
    }

    #[test]
    fn parse_with_numtxqueues_numrxqueues() {
        let conf = LinkBaseConf::parse(args(&[
            "eth0",
            "numtxqueues",
            "8",
            "numrxqueues",
            "4",
            "type",
            "dummy",
        ]))
        .unwrap();
        assert_eq!(conf.numtxqueues, Some(8));
        assert_eq!(conf.numrxqueues, Some(4));
    }

    #[test]
    fn parse_with_index() {
        let conf = LinkBaseConf::parse(args(&[
            "eth0", "index", "100", "type", "dummy",
        ]))
        .unwrap();
        assert_eq!(conf.index, Some(100));
    }

    #[test]
    fn parse_invalid_index_zero() {
        let err =
            LinkBaseConf::parse(args(&["eth0", "index", "0", "type", "dummy"]))
                .unwrap_err();
        assert!(err.msg.contains("index"));
    }

    #[test]
    fn parse_with_netns_by_pid() {
        let conf =
            LinkBaseConf::parse(args(&["eth0", "netns", "1", "type", "dummy"]))
                .unwrap();
        assert_eq!(conf.netns_pid, Some(1));
        assert!(conf.netns_file.is_none());
    }

    #[test]
    fn parse_with_netns_by_name_nonexistent() {
        let err = LinkBaseConf::parse(args(&[
            "eth0",
            "netns",
            "nonexistent-ns-name",
            "type",
            "dummy",
        ]))
        .unwrap_err();
        assert!(err.msg.contains("net"));
    }
}
