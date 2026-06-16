// SPDX-License-Identifier: MIT

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use iproute_rs::{CliError, mac_to_string, parse_mac_str};
use rtnetlink::{
    LinkBond, LinkMessageBuilder,
    packet_route::link::{
        BondAdSelect, BondAllPortActive, BondArpAllTargets, BondArpValidate,
        BondFailOverMac, BondLacpRate, BondMode, BondPrimaryReselect,
        BondXmitHashPolicy, InfoBond, InfoBondPort, InfoKind, LinkInfo,
    },
};
use serde::Serialize;

use super::parse::{
    extract_link_info, parse_on_off_01, parse_u8, parse_u16, parse_u32,
};
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataBond {
    mode: String,
    miimon: u32,
    updelay: u32,
    downdelay: u32,
    peer_notify_delay: u32,
    use_carrier: u8,
    arp_interval: u32,
    arp_missed_max: u8,
    arp_validate: Option<String>,
    arp_all_targets: String,
    primary_reselect: String,
    fail_over_mac: String,
    xmit_hash_policy: String,
    resend_igmp: u32,
    num_peer_notif: u8,
    all_slaves_active: u8,
    min_links: u32,
    lp_interval: u32,
    packets_per_slave: u32,
    ad_lacp_active: String,
    ad_lacp_rate: String,
    coupled_control: bool,
    broadcast_neighbor: bool,
    ad_select: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ad_actor_sys_prio: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ad_user_port_key: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ad_actor_system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arp_ip_target: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ns_ip6_target: Option<Vec<String>>,
    tlb_dynamic_lb: u8,
}

impl From<&[InfoBond]> for CliLinkInfoDataBond {
    fn from(info: &[InfoBond]) -> Self {
        let mut mode = String::new();
        let mut miimon = 0;
        let mut updelay = 0;
        let mut downdelay = 0;
        let mut peer_notify_delay = 0;
        let mut use_carrier = 0;
        let mut arp_interval = 0;
        let mut arp_missed_max = 0;
        let mut arp_validate = None;
        let mut arp_all_targets = String::new();
        let mut primary_reselect = String::new();
        let mut fail_over_mac = String::new();
        let mut xmit_hash_policy = String::new();
        let mut resend_igmp = 0;
        let mut num_peer_notif = 0;
        let mut all_slaves_active = 0;
        let mut min_links = 0;
        let mut lp_interval = 0;
        let mut packets_per_slave = 0;
        let mut ad_lacp_active = String::new();
        let mut ad_lacp_rate = String::new();
        let mut coupled_control = false;
        let mut broadcast_neighbor = false;
        let mut ad_select = String::new();
        let mut ad_actor_sys_prio = None;
        let mut ad_user_port_key = None;
        let mut ad_actor_system = None;
        let mut arp_ip_target = None;
        let mut ns_ip6_target = None;
        let mut tlb_dynamic_lb = 0;

        for nla in info {
            use rtnetlink::packet_route::link::InfoBond;
            match nla {
                InfoBond::Mode(v) => mode = v.to_string(),
                InfoBond::MiiMon(v) => miimon = *v,
                InfoBond::UpDelay(v) => updelay = *v,
                InfoBond::DownDelay(v) => downdelay = *v,
                InfoBond::PeerNotifDelay(v) => peer_notify_delay = *v,
                InfoBond::UseCarrier(v) => use_carrier = *v as u8,
                InfoBond::ArpInterval(v) => arp_interval = *v,
                InfoBond::MissedMax(v) => arp_missed_max = *v,
                InfoBond::ArpValidate(v) => {
                    if matches!(v, BondArpValidate::None) {
                        arp_validate = None
                    } else {
                        arp_validate = Some(v.to_string())
                    }
                }
                InfoBond::ArpAllTargets(v) => arp_all_targets = v.to_string(),
                InfoBond::PrimaryReselect(v) => {
                    primary_reselect = v.to_string()
                }
                InfoBond::FailOverMac(v) => fail_over_mac = v.to_string(),
                InfoBond::XmitHashPolicy(v) => xmit_hash_policy = v.to_string(),
                InfoBond::ResendIgmp(v) => resend_igmp = *v,
                InfoBond::NumPeerNotif(v) => num_peer_notif = *v,
                InfoBond::AllPortsActive(v) => {
                    all_slaves_active = if *v == BondAllPortActive::Delivered {
                        1
                    } else {
                        0
                    };
                }
                InfoBond::MinLinks(v) => min_links = *v,
                InfoBond::LpInterval(v) => lp_interval = *v,
                InfoBond::PacketsPerPort(v) => packets_per_slave = *v,
                InfoBond::AdLacpActive(v) => {
                    ad_lacp_active = if *v { "on" } else { "off" }.to_string()
                }
                InfoBond::AdLacpRate(v) => ad_lacp_rate = v.to_string(),
                InfoBond::AdSelect(v) => ad_select = v.to_string(),
                InfoBond::AdActorSysPrio(v) => {
                    ad_actor_sys_prio = Some(*v);
                }
                InfoBond::AdUserPortKey(v) => {
                    ad_user_port_key = Some(*v);
                }
                InfoBond::AdActorSystem(bytes) => {
                    ad_actor_system = Some(mac_to_string(bytes));
                }
                InfoBond::TlbDynamicLb(v) => tlb_dynamic_lb = *v as u8,
                InfoBond::CoupledControl(v) => coupled_control = *v,
                InfoBond::BroadcastNeigh(v) => broadcast_neighbor = *v,
                InfoBond::ArpIpTarget(addrs) => {
                    arp_ip_target =
                        Some(addrs.iter().map(|a| a.to_string()).collect());
                }
                InfoBond::NsIp6Target(addrs) => {
                    ns_ip6_target =
                        Some(addrs.iter().map(|a| a.to_string()).collect());
                }
                _ => (), /* println!("Remains {:?}", nla) */
            }
        }

        Self {
            mode,
            miimon,
            updelay,
            downdelay,
            peer_notify_delay,
            use_carrier,
            arp_interval,
            arp_missed_max,
            arp_validate,
            arp_all_targets,
            primary_reselect,
            fail_over_mac,
            xmit_hash_policy,
            resend_igmp,
            num_peer_notif,
            all_slaves_active,
            min_links,
            lp_interval,
            packets_per_slave,
            ad_lacp_active,
            ad_lacp_rate,
            ad_select,
            ad_actor_sys_prio,
            ad_user_port_key,
            ad_actor_system,
            arp_ip_target,
            ns_ip6_target,
            tlb_dynamic_lb,
            coupled_control,
            broadcast_neighbor,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataBond {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let on_off = |val: bool| if val { "on" } else { "off" };

        let arp_validate =
            self.arp_validate.as_ref().map_or("none", |s| s.as_str());

        write!(f, "mode {}", self.mode)?;
        write!(f, " miimon {}", self.miimon)?;
        write!(f, " updelay {}", self.updelay)?;
        write!(f, " downdelay {}", self.downdelay)?;
        write!(f, " peer_notify_delay {}", self.peer_notify_delay)?;
        write!(f, " use_carrier {}", self.use_carrier)?;
        write!(f, " arp_interval {}", self.arp_interval)?;
        write!(f, " arp_missed_max {}", self.arp_missed_max)?;
        if let Some(ref targets) = self.arp_ip_target
            && !targets.is_empty()
        {
            write!(f, " arp_ip_target {}", targets.join(","))?;
        }
        if let Some(ref targets) = self.ns_ip6_target
            && !targets.is_empty()
        {
            write!(f, " ns_ip6_target {}", targets.join(","))?;
        }
        write!(f, " arp_validate {}", arp_validate)?;
        write!(f, " arp_all_targets {}", self.arp_all_targets)?;
        write!(f, " primary_reselect {}", self.primary_reselect)?;
        write!(f, " fail_over_mac {}", self.fail_over_mac)?;
        write!(f, " xmit_hash_policy {}", self.xmit_hash_policy)?;
        write!(f, " resend_igmp {}", self.resend_igmp)?;
        write!(f, " num_grat_arp {}", self.num_peer_notif)?;
        write!(f, " all_slaves_active {}", self.all_slaves_active)?;
        write!(f, " min_links {}", self.min_links)?;
        write!(f, " lp_interval {}", self.lp_interval)?;
        write!(f, " packets_per_slave {}", self.packets_per_slave)?;
        write!(f, " lacp_active {}", self.ad_lacp_active)?;
        write!(f, " lacp_rate {}", self.ad_lacp_rate)?;
        write!(f, " coupled_control {}", on_off(self.coupled_control))?;
        write!(f, " broadcast_neighbor {}", on_off(self.broadcast_neighbor))?;
        write!(f, " ad_select {}", self.ad_select)?;
        if let Some(v) = self.ad_actor_sys_prio {
            write!(f, " ad_actor_sys_prio {v}")?;
        }
        if let Some(v) = self.ad_user_port_key {
            write!(f, " ad_user_port_key {v}")?;
        }
        if let Some(ref v) = self.ad_actor_system {
            write!(f, " ad_actor_system {v}")?;
        }
        write!(f, " tlb_dynamic_lb {}", self.tlb_dynamic_lb)?;

        Ok(())
    }
}

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataBondPort {
    state: String,
    mii_status: String,
    link_failure_count: u32,
    perm_hwaddr: String,
    queue_id: u16,
    prio: i32,
}

impl From<&[InfoBondPort]> for CliLinkInfoDataBondPort {
    fn from(info: &[InfoBondPort]) -> Self {
        let mut state = String::new();
        let mut mii_status = String::new();
        let mut link_failure_count = 0;
        let mut perm_hwaddr = String::new();
        let mut queue_id = 0;
        let mut prio = 0;

        for nla in info {
            match nla {
                InfoBondPort::BondPortState(v) => {
                    state = v.to_string().to_uppercase();
                }
                InfoBondPort::LinkFailureCount(l) => link_failure_count = *l,
                InfoBondPort::MiiStatus(s) => {
                    mii_status = s.to_string().to_uppercase();
                }
                InfoBondPort::PermHwaddr(hwa) => {
                    perm_hwaddr = mac_to_string(hwa)
                }
                InfoBondPort::Prio(p) => prio = *p,
                InfoBondPort::QueueId(q) => queue_id = *q,
                _ => {}
            }
        }

        Self {
            state,
            mii_status,
            link_failure_count,
            perm_hwaddr,
            queue_id,
            prio,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataBondPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "state {}", self.state)?;
        write!(f, " mii_status {}", self.mii_status)?;
        write!(f, " link_failure_count {}", self.link_failure_count)?;
        write!(f, " perm_hwaddr {}", self.perm_hwaddr)?;
        write!(f, " queue_id {}", self.queue_id)?;
        write!(f, " prio {}", self.prio)?;

        Ok(())
    }
}

fn apply_bond_args<'a>(
    mut builder: LinkMessageBuilder<LinkBond>,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<LinkMessageBuilder<LinkBond>, CliError> {
    while let Some(key) = iter.next() {
        let Some(v) = iter.next() else {
            return Err(CliError::from(format!("bond {key} requires a value")));
        };
        match key {
            "mode" => {
                let mode = v.parse::<BondMode>().map_err(|e| {
                    CliError::from(format!("Unknown bond mode: {v}: {e}"))
                })?;
                builder = builder.mode(mode);
            }
            "miimon" => {
                builder = builder.miimon(parse_u32(v, "miimon")?);
            }
            "updelay" => {
                builder = builder.updelay(parse_u32(v, "updelay")?);
            }
            "downdelay" => {
                builder = builder.downdelay(parse_u32(v, "downdelay")?);
            }
            "peer_notify_delay" => {
                builder = builder
                    .peer_notif_delay(parse_u32(v, "peer_notify_delay")?);
            }
            "use_carrier" => {
                builder = builder.use_carrier(parse_on_off_01(v)?);
            }
            "arp_interval" => {
                builder = builder.arp_interval(parse_u32(v, "arp_interval")?);
            }
            "arp_validate" => {
                let val = v.parse::<BondArpValidate>().map_err(|e| {
                    CliError::from(format!("Invalid arp_validate: {v}: {e}"))
                })?;
                builder = builder.arp_validate(val);
            }
            "arp_all_targets" => {
                let val = v.parse::<BondArpAllTargets>().map_err(|e| {
                    CliError::from(format!("Invalid arp_all_targets: {v}: {e}"))
                })?;
                builder = builder.arp_all_targets(val);
            }
            "arp_ip_target" => {
                let addrs: Vec<Ipv4Addr> = v
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        Ipv4Addr::from_str(s).map_err(|_| {
                            CliError::from(format!(
                                "Invalid arp_ip_target address: {s}"
                            ))
                        })
                    })
                    .collect::<Result<_, _>>()?;
                builder = builder.arp_ip_target(addrs);
            }
            "ns_ip6_target" => {
                let addrs: Vec<Ipv6Addr> = v
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        Ipv6Addr::from_str(s).map_err(|_| {
                            CliError::from(format!(
                                "Invalid ns_ip6_target address: {s}"
                            ))
                        })
                    })
                    .collect::<Result<_, _>>()?;
                builder = builder.ns_ip6_target(addrs);
            }
            "primary_reselect" => {
                let val = v.parse::<BondPrimaryReselect>().map_err(|e| {
                    CliError::from(format!(
                        "Invalid primary_reselect: {v}: {e}"
                    ))
                })?;
                builder = builder.primary_reselect(val);
            }
            "fail_over_mac" => {
                let val = v.parse::<BondFailOverMac>().map_err(|e| {
                    CliError::from(format!("Invalid fail_over_mac: {v}: {e}"))
                })?;
                builder = builder.fail_over_mac(val);
            }
            "xmit_hash_policy" => {
                let val = v.parse::<BondXmitHashPolicy>().map_err(|e| {
                    CliError::from(format!(
                        "Invalid xmit_hash_policy: {v}: {e}"
                    ))
                })?;
                builder = builder.xmit_hash_policy(val);
            }
            "resend_igmp" => {
                builder = builder.resend_igmp(parse_u32(v, "resend_igmp")?);
            }
            "num_grat_arp" | "num_unsol_na" => {
                builder = builder.num_peer_notif(parse_u8(v, key)?);
            }
            "all_slaves_active" | "all_ports_active" => {
                let val = v.parse::<BondAllPortActive>().map_err(|e| {
                    CliError::from(format!(
                        "Invalid all_slaves_active: {v}: {e}"
                    ))
                })?;
                builder = builder.all_ports_active(val);
            }
            "min_links" => {
                builder = builder.min_links(parse_u32(v, "min_links")?);
            }
            "lp_interval" => {
                builder = builder.lp_interval(parse_u32(v, "lp_interval")?);
            }
            "packets_per_slave" | "packets_per_port" => {
                builder = builder
                    .packets_per_port(parse_u32(v, "packets_per_slave")?);
            }
            "tlb_dynamic_lb" => {
                builder = builder.tlb_dynamic_lb(parse_on_off_01(v)?);
            }
            "lacp_rate" | "ad_lacp_rate" => {
                let val = v.parse::<BondLacpRate>().map_err(|e| {
                    CliError::from(format!("Invalid lacp_rate: {v}: {e}"))
                })?;
                builder = builder.ad_lacp_rate(val);
            }
            "lacp_active" | "ad_lacp_active" => {
                builder = builder.ad_lacp_active(parse_on_off_01(v)?);
            }
            "coupled_control" => {
                builder = builder.append_info_data(InfoBond::CoupledControl(
                    parse_on_off_01(v)?,
                ));
            }
            "broadcast_neighbor" => {
                builder = builder.append_info_data(InfoBond::BroadcastNeigh(
                    parse_on_off_01(v)?,
                ));
            }
            "ad_select" => {
                let val = v.parse::<BondAdSelect>().map_err(|e| {
                    CliError::from(format!("Invalid ad_select: {v}: {e}"))
                })?;
                builder = builder.ad_select(val);
            }
            "ad_user_port_key" => {
                builder =
                    builder.ad_user_port_key(parse_u16(v, "ad_user_port_key")?);
            }
            "ad_actor_sys_prio" => {
                builder = builder
                    .ad_actor_sys_prio(parse_u16(v, "ad_actor_sys_prio")?);
            }
            "ad_actor_system" => {
                let mac = parse_mac_str(v)?;
                if mac.len() != 6 {
                    return Err(CliError::from(
                        "ad_actor_system requires a 6-byte MAC address",
                    ));
                }
                let mut addr = [0u8; 6];
                addr.copy_from_slice(&mac);
                builder = builder.ad_actor_system(addr);
            }
            "arp_missed_max" => {
                builder = builder.missed_max(parse_u8(v, "arp_missed_max")?);
            }
            _ => {
                return Err(CliError::from(format!(
                    "Unknown bond argument: {key}"
                )));
            }
        }
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) async fn apply_bond(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkBond>, CliError> {
        let mut builder = LinkBond::new(&self.name);

        let mut remaining: Vec<&str> = Vec::new();
        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            match key.as_str() {
                "active_slave" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "bond active_slave requires a value",
                        ));
                    };
                    let ifindex = self.get_ifindex_by_name(handle, v).await?;
                    builder = builder.active_port(ifindex);
                }
                "primary" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "bond primary requires a value",
                        ));
                    };
                    let ifindex = self.get_ifindex_by_name(handle, v).await?;
                    builder = builder.primary(ifindex);
                }
                _ => {
                    remaining.push(key);
                    if let Some(v) = iter.next() {
                        remaining.push(v);
                    }
                }
            }
        }

        let mut remaining_iter = remaining.into_iter();
        builder = apply_bond_args(builder, &mut remaining_iter)?;
        Ok(builder)
    }
}

pub(crate) fn build_bond_entries(
    args: &[String],
) -> Result<Vec<LinkInfo>, CliError> {
    let builder =
        LinkMessageBuilder::<LinkBond>::new_with_info_kind(InfoKind::Bond);
    let mut iter = args.iter().map(|s| s.as_str());
    let builder = apply_bond_args(builder, &mut iter)?;
    Ok(extract_link_info(builder.build()))
}

pub(crate) struct IfaceBond;

impl IfaceBond {
    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... bond [ mode BONDMODE ] [ active_slave SLAVE_DEV ]
                [ clear_active_slave ] [ miimon MIIMON ]
                [ updelay UPDELAY ] [ downdelay DOWNDELAY ]
                [ peer_notify_delay DELAY ]
                [ use_carrier USE_CARRIER ]
                [ arp_interval ARP_INTERVAL ]
                [ arp_validate ARP_VALIDATE ]
                [ arp_all_targets ARP_ALL_TARGETS ]
                [ arp_ip_target [ ARP_IP_TARGET, ... ] ]
                [ ns_ip6_target [ NS_IP6_TARGET, ... ] ]
                [ primary SLAVE_DEV ]
                [ primary_reselect PRIMARY_RESELECT ]
                [ fail_over_mac FAIL_OVER_MAC ]
                [ xmit_hash_policy XMIT_HASH_POLICY ]
                [ resend_igmp RESEND_IGMP ]
                [ num_grat_arp|num_unsol_na NUM_GRAT_ARP|NUM_UNSOL_NA ]
                [ all_slaves_active ALL_SLAVES_ACTIVE ]
                [ min_links MIN_LINKS ]
                [ lp_interval LP_INTERVAL ]
                [ packets_per_slave PACKETS_PER_SLAVE ]
                [ tlb_dynamic_lb TLB_DYNAMIC_LB ]
                [ lacp_rate LACP_RATE ]
                [ lacp_active LACP_ACTIVE]
                [ coupled_control COUPLED_CONTROL ]
                [ broadcast_neighbor BROADCAST_NEIGHBOR ]
                [ ad_select AD_SELECT ]
                [ ad_user_port_key PORTKEY ]
                [ ad_actor_sys_prio SYSPRIO ]
                [ ad_actor_system LLADDR ]
                [ arp_missed_max MISSED_MAX ]

BONDMODE := balance-rr|active-backup|balance-xor|broadcast|802.3ad|balance-tlb|balance-alb
ARP_VALIDATE := none|active|backup|all|filter|filter_active|filter_backup
ARP_ALL_TARGETS := any|all
PRIMARY_RESELECT := always|better|failure
FAIL_OVER_MAC := none|active|follow
XMIT_HASH_POLICY := layer2|layer2+3|layer3+4|encap2+3|encap3+4|vlan+srcmac
LACP_ACTIVE := off|on
LACP_RATE := slow|fast
AD_SELECT := stable|bandwidth|count
COUPLED_CONTROL := off|on
BROADCAST_NEIGHBOR := off|on
"
    }
}
