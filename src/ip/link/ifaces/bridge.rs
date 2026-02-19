// SPDX-License-Identifier: MIT

use iproute_rs::mac_to_string;
use rtnetlink::packet_route::link::{
    BridgePortState, InfoBridge, InfoBridgePort, VlanProtocol,
};
use serde::Serialize;

// Additional bridge constants not yet in netlink-packet-route
const IFLA_BR_FDB_N_LEARNED: u16 = 48;
const IFLA_BR_FDB_MAX_LEARNED: u16 = 49;
const IFLA_BR_NO_LL_LEARN: u16 = 51;
const IFLA_BR_VLAN_MCAST_SNOOPING: u16 = 52;
const IFLA_BR_MST_ENABLED: u16 = 53;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataBridge {
    forward_delay: u32,
    hello_time: u32,
    max_age: u32,
    ageing_time: u32,
    stp_state: u32,
    priority: u16,
    vlan_filtering: u8,
    vlan_protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bridge_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_id: Option<String>,
    root_port: u16,
    root_path_cost: u32,
    topology_change: u8,
    topology_change_detected: u8,
    hello_timer: u64,
    tcn_timer: u64,
    topology_change_timer: u64,
    gc_timer: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    fdb_n_learned: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fdb_max_learned: Option<u32>,
    vlan_default_pvid: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    vlan_stats_enabled: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vlan_stats_per_port: Option<u8>,
    group_fwd_mask: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    group_addr: String,
    mcast_snooping: u8,
    no_linklocal_learn: u8,
    mcast_vlan_snooping: u8,
    mst_enabled: u8,
    mcast_router: u8,
    mcast_query_use_ifaddr: u8,
    mcast_querier: u8,
    mcast_hash_elasticity: u32,
    mcast_hash_max: u32,
    mcast_last_member_cnt: u32,
    mcast_startup_query_cnt: u32,
    mcast_last_member_intvl: u64,
    mcast_membership_intvl: u64,
    mcast_querier_intvl: u64,
    mcast_query_intvl: u64,
    mcast_query_response_intvl: u64,
    mcast_startup_query_intvl: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcast_stats_enabled: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcast_igmp_version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcast_mld_version: Option<u8>,
    nf_call_iptables: u8,
    nf_call_ip6tables: u8,
    nf_call_arptables: u8,
}

impl From<&[InfoBridge]> for CliLinkInfoDataBridge {
    fn from(info: &[InfoBridge]) -> Self {
        use rtnetlink::packet_route::link::InfoBridge;

        let mut forward_delay = 0;
        let mut hello_time = 0;
        let mut max_age = 0;
        let mut ageing_time = 0;
        let mut stp_state = 0;
        let mut priority = 0;
        let mut vlan_filtering = 0;
        let mut vlan_protocol = String::new();
        let mut bridge_id = None;
        let mut root_id = None;
        let mut root_port = 0;
        let mut root_path_cost = 0;
        let mut topology_change = 0;
        let mut topology_change_detected = 0;
        let mut hello_timer = 0;
        let mut tcn_timer = 0;
        let mut topology_change_timer = 0;
        let mut gc_timer = 0;
        let mut group_fwd_mask_val = 0u16;
        let mut group_addr = String::new();
        let mut mcast_router = 0;
        let mut mcast_snooping = 0;
        let mut mcast_query_use_ifaddr = 0;
        let mut mcast_querier = 0;
        let mut mcast_hash_elasticity = 0;
        let mut mcast_hash_max = 0;
        let mut mcast_last_member_cnt = 0;
        let mut mcast_startup_query_cnt = 0;
        let mut mcast_last_member_intvl = 0;
        let mut mcast_membership_intvl = 0;
        let mut mcast_querier_intvl = 0;
        let mut mcast_query_intvl = 0;
        let mut mcast_query_response_intvl = 0;
        let mut mcast_startup_query_intvl = 0;
        let mut nf_call_iptables = 0;
        let mut nf_call_ip6tables = 0;
        let mut nf_call_arptables = 0;
        let mut vlan_default_pvid = 0;
        let mut vlan_stats_enabled = None;
        let mut vlan_stats_per_port = None;
        let mut mcast_stats_enabled = None;
        let mut mcast_igmp_version = None;
        let mut mcast_mld_version = None;
        let mut fdb_n_learned = None;
        let mut fdb_max_learned = None;
        let mut no_linklocal_learn = 0;
        let mut mcast_vlan_snooping = 0;
        let mut mst_enabled = 0;

        for nla in info {
            match nla {
                InfoBridge::ForwardDelay(v) => forward_delay = *v,
                InfoBridge::HelloTime(v) => hello_time = *v,
                InfoBridge::MaxAge(v) => max_age = *v,
                InfoBridge::AgeingTime(v) => ageing_time = *v,
                InfoBridge::StpState(v) => stp_state = (*v).into(),
                InfoBridge::Priority(v) => priority = *v,
                InfoBridge::VlanFiltering(v) => {
                    vlan_filtering = if *v { 1 } else { 0 }
                }
                InfoBridge::VlanProtocol(v) => {
                    vlan_protocol = match v {
                        VlanProtocol::Ieee8021Q => "802.1Q".to_string(),
                        VlanProtocol::Ieee8021Ad => "802.1ad".to_string(),
                        _ => format!("0x{:x}", u16::from(*v)),
                    };
                }
                InfoBridge::BridgeId(v) => {
                    bridge_id = Some(format_bridge_id(v.priority, v.address));
                }
                InfoBridge::RootId(v) => {
                    root_id = Some(format_bridge_id(v.priority, v.address));
                }
                InfoBridge::RootPort(v) => root_port = *v,
                InfoBridge::RootPathCost(v) => root_path_cost = *v,
                InfoBridge::TopologyChange(v) => topology_change = *v,
                InfoBridge::TopologyChangeDetected(v) => {
                    topology_change_detected = *v
                }
                InfoBridge::HelloTimer(v) => hello_timer = *v,
                InfoBridge::TcnTimer(v) => tcn_timer = *v,
                InfoBridge::TopologyChangeTimer(v) => {
                    topology_change_timer = *v
                }
                InfoBridge::GcTimer(v) => gc_timer = *v,
                InfoBridge::GroupFwdMask(v) => group_fwd_mask_val = *v,
                InfoBridge::GroupAddr(v) => group_addr = mac_to_string(v),
                InfoBridge::MulticastRouter(v) => mcast_router = (*v).into(),
                InfoBridge::MulticastSnooping(v) => {
                    mcast_snooping = (*v).into()
                }
                InfoBridge::MulticastQueryUseIfaddr(v) => {
                    mcast_query_use_ifaddr = (*v).into()
                }
                InfoBridge::MulticastQuerier(v) => mcast_querier = (*v).into(),
                InfoBridge::MulticastHashElasticity(v) => {
                    mcast_hash_elasticity = *v
                }
                InfoBridge::MulticastHashMax(v) => mcast_hash_max = *v,
                InfoBridge::MulticastLastMemberCount(v) => {
                    mcast_last_member_cnt = *v
                }
                InfoBridge::MulticastStartupQueryCount(v) => {
                    mcast_startup_query_cnt = *v
                }
                InfoBridge::MulticastLastMemberInterval(v) => {
                    mcast_last_member_intvl = *v
                }
                InfoBridge::MulticastMembershipInterval(v) => {
                    mcast_membership_intvl = *v
                }
                InfoBridge::MulticastQuerierInterval(v) => {
                    mcast_querier_intvl = *v
                }
                InfoBridge::MulticastQueryInterval(v) => mcast_query_intvl = *v,
                InfoBridge::MulticastQueryResponseInterval(v) => {
                    mcast_query_response_intvl = *v
                }
                InfoBridge::MulticastStartupQueryInterval(v) => {
                    mcast_startup_query_intvl = *v
                }
                InfoBridge::NfCallIpTables(v) => nf_call_iptables = (*v).into(),
                InfoBridge::NfCallIp6Tables(v) => {
                    nf_call_ip6tables = (*v).into()
                }
                InfoBridge::NfCallArpTables(v) => {
                    nf_call_arptables = (*v).into()
                }
                InfoBridge::VlanDefaultPvid(v) => vlan_default_pvid = *v,
                InfoBridge::VlanStatsEnabled(v) => {
                    vlan_stats_enabled = Some((*v).into())
                }
                InfoBridge::VlanStatsPerPort(v) => {
                    vlan_stats_per_port = Some((*v).into())
                }
                InfoBridge::MulticastStatsEnabled(v) => {
                    mcast_stats_enabled = Some((*v).into())
                }
                InfoBridge::MulticastIgmpVersion(v) => {
                    mcast_igmp_version = Some(*v)
                }
                InfoBridge::MulticastMldVersion(v) => {
                    mcast_mld_version = Some(*v)
                }
                InfoBridge::Other(nla) => {
                    use rtnetlink::packet_core::Nla;
                    match nla.kind() {
                        IFLA_BR_FDB_N_LEARNED => {
                            let mut val = [0u8; 4];
                            nla.emit_value(&mut val);
                            fdb_n_learned = Some(u32::from_ne_bytes(val));
                        }
                        IFLA_BR_FDB_MAX_LEARNED => {
                            let mut val = [0u8; 4];
                            nla.emit_value(&mut val);
                            fdb_max_learned = Some(u32::from_ne_bytes(val));
                        }
                        IFLA_BR_NO_LL_LEARN => {
                            let mut val = [0u8; 1];
                            nla.emit_value(&mut val);
                            no_linklocal_learn = val[0];
                        }
                        IFLA_BR_VLAN_MCAST_SNOOPING => {
                            let mut val = [0u8; 1];
                            nla.emit_value(&mut val);
                            mcast_vlan_snooping = val[0];
                        }
                        IFLA_BR_MST_ENABLED => {
                            let mut val = [0u8; 1];
                            nla.emit_value(&mut val);
                            mst_enabled = val[0];
                        }
                        _ => (),
                    }
                }
                _ => (),
            }
        }

        let group_fwd_mask = format!("{}", group_fwd_mask_val);

        Self {
            forward_delay,
            hello_time,
            max_age,
            ageing_time,
            stp_state,
            priority,
            vlan_filtering,
            vlan_protocol,
            bridge_id,
            root_id,
            root_port,
            root_path_cost,
            topology_change,
            topology_change_detected,
            hello_timer,
            tcn_timer,
            topology_change_timer,
            gc_timer,
            fdb_n_learned,
            fdb_max_learned,
            vlan_default_pvid,
            vlan_stats_enabled,
            vlan_stats_per_port,
            group_fwd_mask,
            group_addr,
            mcast_snooping,
            no_linklocal_learn,
            mcast_vlan_snooping,
            mst_enabled,
            mcast_router,
            mcast_query_use_ifaddr,
            mcast_querier,
            mcast_hash_elasticity,
            mcast_hash_max,
            mcast_last_member_cnt,
            mcast_startup_query_cnt,
            mcast_last_member_intvl,
            mcast_membership_intvl,
            mcast_querier_intvl,
            mcast_query_intvl,
            mcast_query_response_intvl,
            mcast_startup_query_intvl,
            mcast_stats_enabled,
            mcast_igmp_version,
            mcast_mld_version,
            nf_call_iptables,
            nf_call_ip6tables,
            nf_call_arptables,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "forward_delay {} ", self.forward_delay)?;
        write!(f, "hello_time {} ", self.hello_time)?;
        write!(f, "max_age {} ", self.max_age)?;
        write!(f, "ageing_time {} ", self.ageing_time)?;
        write!(f, "stp_state {} ", self.stp_state)?;
        write!(f, "priority {} ", self.priority)?;
        write!(f, "vlan_filtering {} ", self.vlan_filtering)?;
        write!(f, "vlan_protocol {} ", self.vlan_protocol)?;
        if let Some(bid) = &self.bridge_id {
            write!(f, "bridge_id {} ", bid)?;
        }
        if let Some(rid) = &self.root_id {
            write!(f, "designated_root {} ", rid)?;
        }
        write!(f, "root_port {} ", self.root_port)?;
        write!(f, "root_path_cost {} ", self.root_path_cost)?;
        write!(f, "topology_change {} ", self.topology_change)?;
        write!(
            f,
            "topology_change_detected {} ",
            self.topology_change_detected
        )?;
        write!(f, "hello_timer {} ", format_bridge_timer(self.hello_timer))?;
        write!(f, "tcn_timer {} ", format_bridge_timer(self.tcn_timer))?;
        write!(
            f,
            "topology_change_timer {} ",
            format_bridge_timer(self.topology_change_timer)
        )?;
        write!(f, "gc_timer {} ", format_bridge_timer(self.gc_timer))?;
        if let Some(v) = self.fdb_n_learned {
            write!(f, "fdb_n_learned {} ", v)?;
        }
        if let Some(v) = self.fdb_max_learned {
            write!(f, "fdb_max_learned {} ", v)?;
        }
        write!(f, "vlan_default_pvid {} ", self.vlan_default_pvid)?;
        if let Some(v) = self.vlan_stats_enabled {
            write!(f, "vlan_stats_enabled {} ", v)?;
        }
        if let Some(v) = self.vlan_stats_per_port {
            write!(f, "vlan_stats_per_port {} ", v)?;
        }
        let mask_val: u16 = self.group_fwd_mask.parse().unwrap_or(0);
        if mask_val == 0 {
            write!(f, "group_fwd_mask {} ", mask_val)?;
        } else {
            write!(f, "group_fwd_mask {:#x} ", mask_val)?;
        }
        if !self.group_addr.is_empty() {
            write!(f, "group_address {} ", self.group_addr)?;
        }
        write!(f, "mcast_snooping {} ", self.mcast_snooping)?;
        write!(f, "no_linklocal_learn {} ", self.no_linklocal_learn)?;
        write!(f, "mcast_vlan_snooping {} ", self.mcast_vlan_snooping)?;
        write!(f, "mst_enabled {} ", self.mst_enabled)?;
        write!(f, "mcast_router {} ", self.mcast_router)?;
        write!(f, "mcast_query_use_ifaddr {} ", self.mcast_query_use_ifaddr)?;
        write!(f, "mcast_querier {} ", self.mcast_querier)?;
        write!(f, "mcast_hash_elasticity {} ", self.mcast_hash_elasticity)?;
        write!(f, "mcast_hash_max {} ", self.mcast_hash_max)?;
        write!(f, "mcast_last_member_count {} ", self.mcast_last_member_cnt)?;
        write!(
            f,
            "mcast_startup_query_count {} ",
            self.mcast_startup_query_cnt
        )?;
        write!(
            f,
            "mcast_last_member_interval {} ",
            self.mcast_last_member_intvl
        )?;
        write!(
            f,
            "mcast_membership_interval {} ",
            self.mcast_membership_intvl
        )?;
        write!(f, "mcast_querier_interval {} ", self.mcast_querier_intvl)?;
        write!(f, "mcast_query_interval {} ", self.mcast_query_intvl)?;
        write!(
            f,
            "mcast_query_response_interval {} ",
            self.mcast_query_response_intvl
        )?;
        write!(
            f,
            "mcast_startup_query_interval {} ",
            self.mcast_startup_query_intvl
        )?;
        if let Some(v) = self.mcast_stats_enabled {
            write!(f, "mcast_stats_enabled {} ", v)?;
        }
        if let Some(v) = self.mcast_igmp_version {
            write!(f, "mcast_igmp_version {} ", v)?;
        }
        if let Some(v) = self.mcast_mld_version {
            write!(f, "mcast_mld_version {} ", v)?;
        }
        write!(f, "nf_call_iptables {} ", self.nf_call_iptables)?;
        write!(f, "nf_call_ip6tables {} ", self.nf_call_ip6tables)?;
        write!(f, "nf_call_arptables {}", self.nf_call_arptables)?;
        Ok(())
    }
}

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataBridgePort {
    state: String,
    priority: u32,
    cost: u32,
    hairpin: bool,
    guard: bool,
    root_block: bool,
    fastleave: bool,
    learning: bool,
    flood: bool,
    id: String,
    no: String,
    designated_port: u32,
    designated_cost: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    bridge_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_id: Option<String>,
    hold_timer: u64,
    message_age_timer: u64,
    forward_delay_timer: u64,
    topology_change_ack: u8,
    config_pending: u8,
    proxy_arp: bool,
    proxy_arp_wifi: bool,
    multicast_router: u8,
    mcast_flood: bool,
    bcast_flood: bool,
    mcast_to_unicast: bool,
    neigh_suppress: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    neigh_vlan_suppress: Option<bool>,
    group_fwd_mask: String,
    group_fwd_mask_str: String,
    vlan_tunnel: bool,
    isolated: bool,
    locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mab: Option<bool>,
}

impl From<&[InfoBridgePort]> for CliLinkInfoDataBridgePort {
    fn from(info: &[InfoBridgePort]) -> Self {
        let mut state = String::new();
        let mut priority = 0;
        let mut cost = 0;
        let mut hairpin = false;
        let mut guard = false;
        let mut root_block = false;
        let mut fastleave = false;
        let mut learning = false;
        let mut flood = false;
        let mut id = String::new();
        let mut no = String::new();
        let mut designated_port = 0;
        let mut designated_cost = 0;
        let mut bridge_id = None;
        let mut root_id = None;
        let mut hold_timer = 0;
        let mut message_age_timer = 0;
        let mut forward_delay_timer = 0;
        let mut topology_change_ack = 0;
        let mut config_pending = 0;
        let mut proxy_arp = false;
        let mut proxy_arp_wifi = false;
        let mut multicast_router = 0;
        let mut mcast_flood = false;
        let mut bcast_flood = false;
        let mut mcast_to_unicast = false;
        let mut neigh_suppress = false;
        let mut neigh_vlan_suppress = None;
        let mut group_fwd_mask: u16 = 0;
        let mut vlan_tunnel = false;
        let mut isolated = false;
        let mut locked = false;
        let mut mab = None;

        for nla in info {
            match nla {
                InfoBridgePort::State(v) => {
                    state = match v {
                        BridgePortState::Disabled => "disabled".to_string(),
                        BridgePortState::Listening => "listening".to_string(),
                        BridgePortState::Learning => "learning".to_string(),
                        BridgePortState::Forwarding => "forwarding".to_string(),
                        BridgePortState::Blocking => "blocking".to_string(),
                        BridgePortState::Other(n) => format!("{}", n),
                        _ => "unknown".to_string(),
                    };
                }
                InfoBridgePort::Priority(v) => priority = *v as u32,
                InfoBridgePort::Cost(v) => cost = *v,
                InfoBridgePort::HairpinMode(v) => hairpin = *v,
                InfoBridgePort::Guard(v) => guard = *v,
                InfoBridgePort::Protect(v) => root_block = *v,
                InfoBridgePort::FastLeave(v) => fastleave = *v,
                InfoBridgePort::Learning(v) => learning = *v,
                InfoBridgePort::UnicastFlood(v) => flood = *v,
                InfoBridgePort::PortId(v) => id = format!("{:#x}", v),
                InfoBridgePort::PortNumber(v) => no = format!("{:#x}", v),
                InfoBridgePort::DesignatedPort(v) => {
                    designated_port = *v as u32
                }
                InfoBridgePort::DesignatedCost(v) => {
                    designated_cost = *v as u32
                }
                InfoBridgePort::BridgeId(v) => {
                    bridge_id = Some(format_bridge_id(v.priority, v.address));
                }
                InfoBridgePort::RootId(v) => {
                    root_id = Some(format_bridge_id(v.priority, v.address));
                }
                InfoBridgePort::HoldTimer(v) => hold_timer = *v,
                InfoBridgePort::MessageAgeTimer(v) => message_age_timer = *v,
                InfoBridgePort::ForwardDelayTimer(v) => {
                    forward_delay_timer = *v
                }
                InfoBridgePort::TopologyChangeAck(v) => {
                    topology_change_ack = if *v { 1 } else { 0 }
                }
                InfoBridgePort::ConfigPending(v) => {
                    config_pending = if *v { 1 } else { 0 }
                }
                InfoBridgePort::ProxyARP(v) => proxy_arp = *v,
                InfoBridgePort::ProxyARPWifi(v) => proxy_arp_wifi = *v,
                InfoBridgePort::MulticastRouter(v) => {
                    multicast_router = (*v).into()
                }
                InfoBridgePort::MulticastFlood(v) => mcast_flood = *v,
                InfoBridgePort::BroadcastFlood(v) => bcast_flood = *v,
                InfoBridgePort::MulticastToUnicast(v) => mcast_to_unicast = *v,
                InfoBridgePort::NeighSupress(v) => neigh_suppress = *v,
                InfoBridgePort::NeighVlanSuppress(v) => {
                    neigh_vlan_suppress = Some(*v)
                }
                InfoBridgePort::GroupFwdMask(v) => group_fwd_mask = *v,
                InfoBridgePort::VlanTunnel(v) => vlan_tunnel = *v,
                InfoBridgePort::Isolated(v) => isolated = *v,
                InfoBridgePort::Locked(v) => locked = *v,
                InfoBridgePort::Mab(v) => mab = Some(*v),
                _ => (),
            }
        }

        let group_fwd_mask_str = if group_fwd_mask == 0 {
            "0x0".to_string()
        } else {
            format!("{:#x}", group_fwd_mask)
        };

        let group_fwd_mask_string = format!("{}", group_fwd_mask);

        Self {
            state,
            priority,
            cost,
            hairpin,
            guard,
            root_block,
            fastleave,
            learning,
            flood,
            id,
            no,
            designated_port,
            designated_cost,
            bridge_id,
            root_id,
            hold_timer,
            message_age_timer,
            forward_delay_timer,
            topology_change_ack,
            config_pending,
            proxy_arp,
            proxy_arp_wifi,
            multicast_router,
            mcast_flood,
            bcast_flood,
            mcast_to_unicast,
            neigh_suppress,
            neigh_vlan_suppress,
            group_fwd_mask: group_fwd_mask_string,
            group_fwd_mask_str,
            vlan_tunnel,
            isolated,
            locked,
            mab,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataBridgePort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let on_off = |val: bool| if val { "on" } else { "off" };

        write!(f, "state {} ", self.state)?;
        write!(f, "priority {} ", self.priority)?;
        write!(f, "cost {} ", self.cost)?;
        write!(f, "hairpin {} ", on_off(self.hairpin))?;
        write!(f, "guard {} ", on_off(self.guard))?;
        write!(f, "root_block {} ", on_off(self.root_block))?;
        write!(f, "fastleave {} ", on_off(self.fastleave))?;
        write!(f, "learning {} ", on_off(self.learning))?;
        write!(f, "flood {} ", on_off(self.flood))?;
        write!(f, "port_id {} ", self.id)?;
        write!(f, "port_no {} ", self.no)?;
        write!(f, "designated_port {} ", self.designated_port)?;
        write!(f, "designated_cost {} ", self.designated_cost)?;
        if let Some(bid) = &self.bridge_id {
            write!(f, "designated_bridge {} ", bid)?;
        }
        if let Some(rid) = &self.root_id {
            write!(f, "designated_root {} ", rid)?;
        }
        write!(f, "hold_timer {} ", format_bridge_timer(self.hold_timer))?;
        write!(
            f,
            "message_age_timer {} ",
            format_bridge_timer(self.message_age_timer)
        )?;
        write!(
            f,
            "forward_delay_timer {} ",
            format_bridge_timer(self.forward_delay_timer)
        )?;
        write!(f, "topology_change_ack {} ", self.topology_change_ack)?;
        write!(f, "config_pending {} ", self.config_pending)?;
        write!(f, "proxy_arp {} ", on_off(self.proxy_arp))?;
        write!(f, "proxy_arp_wifi {} ", on_off(self.proxy_arp_wifi))?;
        write!(f, "mcast_router {} ", self.multicast_router)?;
        write!(f, "mcast_fast_leave {} ", on_off(self.fastleave))?;
        write!(f, "mcast_flood {} ", on_off(self.mcast_flood))?;
        write!(f, "bcast_flood {} ", on_off(self.bcast_flood))?;
        write!(f, "mcast_to_unicast {} ", on_off(self.mcast_to_unicast))?;
        write!(f, "neigh_suppress {} ", on_off(self.neigh_suppress))?;
        if let Some(v) = self.neigh_vlan_suppress {
            write!(f, "neigh_vlan_suppress {} ", on_off(v))?;
        } else {
            write!(f, "neigh_vlan_suppress off ")?;
        }
        write!(f, "group_fwd_mask {} ", self.group_fwd_mask)?;
        write!(f, "group_fwd_mask_str {} ", self.group_fwd_mask_str)?;
        write!(f, "vlan_tunnel {} ", on_off(self.vlan_tunnel))?;
        write!(f, "isolated {} ", on_off(self.isolated))?;
        write!(f, "locked {} ", on_off(self.locked))?;
        if let Some(v) = self.mab {
            write!(f, "mab {}", on_off(v))?;
        } else {
            write!(f, "mab off")?;
        }

        Ok(())
    }
}

fn format_bridge_timer(v: u64) -> String {
    let seconds = v as f64 / 100.0;
    format!("{:>7.2}", seconds)
}

/// Format bridge ID to match iproute2's format:
/// Priority is 4 hex digits, MAC address bytes use minimal formatting (no
/// leading zeros for bytes < 0x10)
fn format_bridge_id(priority: u16, mac_bytes: [u8; 6]) -> String {
    format!(
        "{:04x}.{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        priority,
        mac_bytes[0],
        mac_bytes[1],
        mac_bytes[2],
        mac_bytes[3],
        mac_bytes[4],
        mac_bytes[5]
    )
}
