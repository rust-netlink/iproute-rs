// SPDX-License-Identifier: MIT

use std::os::unix::io::AsRawFd;

use futures_util::TryStreamExt;
use iproute_rs::{CliError, parse_mac_str};
use rtnetlink::packet_route::link::{
    InfoKind, LinkAttribute, LinkFlags, LinkHeader, LinkInfo, LinkMessage,
    State,
};

use super::ifaces::{
    bond::IfaceBond,
    bridge::IfaceBridge,
    hsr::IfaceHsr,
    parse::{parse_on_off, parse_u32},
    vlan::IfaceVlan,
    vrf::IfaceVrf,
};
use crate::link::CliLinkInfo;

pub(crate) struct LinkSetCommand;

impl LinkSetCommand {
    pub(crate) const CMD: &'static str = "set";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("change device attributes")
            .alias("s")
            .alias("se")
            .alias("c")
            .alias("ch")
            .alias("change")
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

        let conf = LinkSetConf::parse(&opts)?;

        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        let mut header = LinkHeader::default();
        let mut attrs: Vec<LinkAttribute> = Vec::new();

        let ifindex = get_ifindex_by_name(&handle, &conf.dev).await?;
        header.index = ifindex;

        if let Some(v) = conf.up {
            if v {
                header.flags |= LinkFlags::Up;
            } else {
                header.flags.remove(LinkFlags::Up);
            }
            header.change_mask |= LinkFlags::Up;
        }

        if let Some(v) = conf.name {
            attrs.push(LinkAttribute::IfName(v));
        }
        if let Some(v) = conf.mtu {
            attrs.push(LinkAttribute::Mtu(v));
        }
        if let Some(v) = conf.address {
            attrs.push(LinkAttribute::Address(v));
        }
        if let Some(v) = conf.broadcast {
            attrs.push(LinkAttribute::Broadcast(v));
        }
        if let Some(v) = conf.txqueuelen {
            attrs.push(LinkAttribute::TxQueueLen(v));
        }
        if let Some(v) = conf.arp {
            if !v {
                header.flags |= LinkFlags::Noarp;
            }
            header.change_mask |= LinkFlags::Noarp;
        }
        if let Some(v) = conf.multicast {
            if v {
                header.flags |= LinkFlags::Multicast;
            }
            header.change_mask |= LinkFlags::Multicast;
        }
        if let Some(v) = conf.allmulticast {
            if v {
                header.flags |= LinkFlags::Allmulti;
            }
            header.change_mask |= LinkFlags::Allmulti;
        }
        if let Some(v) = conf.promisc {
            if v {
                header.flags |= LinkFlags::Promisc;
            }
            header.change_mask |= LinkFlags::Promisc;
        }
        if let Some(v) = conf.dynamic {
            if v {
                header.flags |= LinkFlags::Dynamic;
            }
            header.change_mask |= LinkFlags::Dynamic;
        }
        if let Some(v) = conf.notrailers {
            if v {
                header.flags.remove(LinkFlags::Notrailers);
            } else {
                header.flags |= LinkFlags::Notrailers;
            }
            header.change_mask |= LinkFlags::Notrailers;
        }
        if let Some(master) = conf.master {
            let ctrl_index = get_ifindex_by_name(&handle, &master).await?;
            attrs.push(LinkAttribute::Controller(ctrl_index));
        }
        if conf.nomaster {
            attrs.push(LinkAttribute::Controller(0));
        }
        if let Some(v) = conf.group {
            attrs.push(LinkAttribute::Group(v));
        }
        if let Some(v) = conf.netns_pid {
            attrs.push(LinkAttribute::NetNsPid(v));
        }
        if let Some(ref file) = conf.netns_file {
            attrs.push(LinkAttribute::NetNsFd(file.as_raw_fd()));
        }
        if let Some(v) = conf.protodown {
            attrs.push(LinkAttribute::ProtoDown(if v { 1 } else { 0 }));
        }
        if let Some(v) = conf.carrier {
            attrs.push(LinkAttribute::Carrier(if v { 1 } else { 0 }));
        }
        if let Some(v) = conf.state {
            attrs.push(LinkAttribute::OperState(v));
        }
        if let Some(v) = conf.alias {
            attrs.push(LinkAttribute::IfAlias(v));
        }

        if let Some(iface_type) = conf.iface_type {
            let link_infos =
                build_type_link_info(&handle, iface_type, &conf.iface_specific)
                    .await?;
            if !link_infos.is_empty() {
                attrs.push(LinkAttribute::LinkInfo(link_infos));
            }
        }

        let mut message = LinkMessage::default();
        message.header = header;
        message.attributes = attrs;
        handle.link().change(message).execute().await?;

        Ok(vec![])
    }
}

async fn get_ifindex_by_name(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, CliError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await?.ok_or_else(|| {
        CliError::from(format!("Device \"{name}\" does not exist"))
    })?;
    Ok(link.header.index)
}

#[derive(Debug)]
struct LinkSetConf {
    dev: String,
    up: Option<bool>,
    name: Option<String>,
    mtu: Option<u32>,
    address: Option<Vec<u8>>,
    broadcast: Option<Vec<u8>>,
    txqueuelen: Option<u32>,
    arp: Option<bool>,
    multicast: Option<bool>,
    allmulticast: Option<bool>,
    promisc: Option<bool>,
    dynamic: Option<bool>,
    notrailers: Option<bool>,
    master: Option<String>,
    nomaster: bool,
    group: Option<u32>,
    netns_pid: Option<u32>,
    netns_file: Option<std::fs::File>,
    protodown: Option<bool>,
    carrier: Option<bool>,
    state: Option<State>,
    alias: Option<String>,
    iface_type: Option<InfoKind>,
    iface_specific: Vec<String>,
}

impl LinkSetConf {
    fn parse(args: &[String]) -> Result<Self, CliError> {
        let mut dev = None;
        let mut up = None;
        let mut name = None;
        let mut mtu = None;
        let mut address = None;
        let mut broadcast = None;
        let mut txqueuelen = None;
        let mut arp = None;
        let mut multicast = None;
        let mut allmulticast = None;
        let mut promisc = None;
        let mut dynamic = None;
        let mut notrailers = None;
        let mut master = None;
        let mut nomaster = false;
        let mut group = None;
        let mut netns_pid = None;
        let mut netns_file = None;
        let mut protodown = None;
        let mut carrier = None;
        let mut state = None;
        let mut alias = None;
        let mut iface_type = None;
        let mut iface_specific = Vec::new();

        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "dev" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"dev\" requires a value"));
                    };
                    dev = Some(v.clone());
                }
                "up" => up = Some(true),
                "down" => up = Some(false),
                "name" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"name\" requires a value",
                        ));
                    };
                    name = Some(v.clone());
                }
                "mtu" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"mtu\" requires a value"));
                    };
                    mtu = Some(parse_u32(v, "mtu")?);
                }
                "address" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"address\" requires a value",
                        ));
                    };
                    address = Some(parse_mac_str(v)?);
                }
                "broadcast" | "brd" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"broadcast\" requires a value",
                        ));
                    };
                    broadcast = Some(parse_mac_str(v)?);
                }
                "txqueuelen" | "qlen" | "txqlen" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"txqueuelen\" requires a value",
                        ));
                    };
                    txqueuelen = Some(parse_u32(v, "txqueuelen")?);
                }
                "arp" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"arp\" requires a value"));
                    };
                    arp = Some(parse_on_off(v)?);
                }
                "multicast" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"multicast\" requires a value",
                        ));
                    };
                    multicast = Some(parse_on_off(v)?);
                }
                "allmulticast" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"allmulticast\" requires a value",
                        ));
                    };
                    allmulticast = Some(parse_on_off(v)?);
                }
                "promisc" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"promisc\" requires a value",
                        ));
                    };
                    promisc = Some(parse_on_off(v)?);
                }
                "dynamic" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"dynamic\" requires a value",
                        ));
                    };
                    dynamic = Some(parse_on_off(v)?);
                }
                "trailers" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"trailers\" requires a value",
                        ));
                    };
                    notrailers = Some(parse_on_off(v)?);
                }
                "master" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"master\" requires a value",
                        ));
                    };
                    master = Some(v.clone());
                }
                "vrf" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"vrf\" requires a value"));
                    };
                    master = Some(v.clone());
                }
                "nomaster" => nomaster = true,
                "group" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"group\" requires a value",
                        ));
                    };
                    group = Some(parse_u32(v, "group")?);
                }
                "netns" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"netns\" requires a value",
                        ));
                    };
                    if let Ok(pid) = v.parse::<u32>() {
                        netns_pid = Some(pid);
                    } else if let Ok(file) =
                        std::fs::File::open(format!("/run/netns/{v}"))
                    {
                        netns_file = Some(file);
                    } else {
                        return Err(CliError::from(format!(
                            "Cannot find network namespace \"{v}\""
                        )));
                    }
                }
                "protodown" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"protodown\" requires a value",
                        ));
                    };
                    protodown = Some(parse_on_off(v)?);
                }
                "carrier" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"carrier\" requires a value",
                        ));
                    };
                    carrier = Some(parse_on_off(v)?);
                }
                "state" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"state\" requires a value",
                        ));
                    };
                    state = Some(
                        v.parse::<State>()
                            .map_err(|e| CliError::from(format!("{e}")))?,
                    );
                }
                "alias" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"alias\" requires a value",
                        ));
                    };
                    alias = Some(v.clone());
                }
                "type" => {
                    let Some(kind_str) = iter.next() else {
                        return Err(CliError::from(
                            "\"type\" requires a value",
                        ));
                    };
                    iface_type = Some(InfoKind::from(kind_str.as_str()));
                    iface_specific = iter.cloned().collect();
                    break;
                }
                _ => {
                    if dev.is_none() {
                        dev = Some(arg.clone());
                    } else {
                        return Err(CliError::from(format!(
                            "Unknown argument: {arg}"
                        )));
                    }
                }
            }
        }

        let dev =
            dev.ok_or_else(|| CliError::from("Device name is required"))?;

        Ok(Self {
            dev,
            up,
            name,
            mtu,
            address,
            broadcast,
            txqueuelen,
            arp,
            multicast,
            allmulticast,
            promisc,
            dynamic,
            notrailers,
            master,
            nomaster,
            group,
            netns_pid,
            netns_file,
            protodown,
            carrier,
            state,
            alias,
            iface_type,
            iface_specific,
        })
    }
}

fn build_kind_only(kind: InfoKind) -> Vec<LinkInfo> {
    vec![LinkInfo::Kind(kind)]
}

fn clean_extracted(infos: &mut Vec<LinkInfo>, kind: InfoKind) {
    if infos.is_empty() {
        infos.push(LinkInfo::Kind(kind));
    } else if !infos.iter().any(|i| matches!(i, LinkInfo::Kind(_))) {
        infos.insert(0, LinkInfo::Kind(kind));
    }
}

async fn build_type_link_info(
    _handle: &rtnetlink::Handle,
    kind: InfoKind,
    args: &[String],
) -> Result<Vec<LinkInfo>, CliError> {
    match kind {
        InfoKind::Dummy
        | InfoKind::Nlmon
        | InfoKind::Vcan
        | InfoKind::Netdevsim
        | InfoKind::Veth
        | InfoKind::Vxcan
        | InfoKind::Xfrm
        | InfoKind::MacSec
        | InfoKind::Geneve
        | InfoKind::GreTun
        | InfoKind::GreTap
        | InfoKind::GreTun6
        | InfoKind::GreTap6
        | InfoKind::IpIp
        | InfoKind::Ip6Tnl => Ok(build_kind_only(kind)),
        InfoKind::Vlan => {
            let mut infos = IfaceVlan::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::Bond => {
            let mut infos = IfaceBond::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::Bridge => {
            let mut infos = IfaceBridge::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::Hsr => {
            let mut infos = IfaceHsr::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::Netkit => Ok(build_kind_only(InfoKind::Netkit)),
        InfoKind::Vrf => {
            let mut infos = IfaceVrf::build_entries(args)?;
            clean_extracted(&mut infos, kind);
            Ok(infos)
        }
        InfoKind::IpVlan => Ok(build_kind_only(InfoKind::IpVlan)),
        InfoKind::IpVtap => Ok(build_kind_only(InfoKind::IpVtap)),
        InfoKind::MacVlan => Ok(build_kind_only(InfoKind::MacVlan)),
        InfoKind::MacVtap => Ok(build_kind_only(InfoKind::MacVtap)),
        _ => Err(CliError::from(format!("Unsupported device type: {kind}"))),
    }
}
