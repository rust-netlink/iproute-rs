use rtnetlink::packet_route::link::{InfoData, InfoPortData, LinkInfo};
use serde::Serialize;

use iproute_rs::mac_to_string;

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

const VLAN_FLAG_REORDER_HDR: u32 = 0x1;
const VLAN_FLAG_GVRP: u32 = 0x2;
const VLAN_FLAG_LOOSE_BINDING: u32 = 0x4;
const VLAN_FLAG_MVRP: u32 = 0x8;

// Additional bridge constants not yet in netlink-packet-route
const IFLA_BR_FDB_N_LEARNED: u16 = 48;
const IFLA_BR_FDB_MAX_LEARNED: u16 = 49;
const IFLA_BR_NO_LL_LEARN: u16 = 51;
const IFLA_BR_VLAN_MCAST_SNOOPING: u16 = 52;
const IFLA_BR_MST_ENABLED: u16 = 53;

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum CliLinkInfoData {
    Vlan {
        protocol: String,
        id: u16,
        flags: Vec<String>,
    },
    BridgeSlave {
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
    },
    Bridge {
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
    },
}

impl CliLinkInfoData {
    fn new_from_port_data(info_port_data: &InfoPortData) -> Self {
        match info_port_data {
            InfoPortData::BridgePort(info_bridge_port) => {
                use rtnetlink::packet_route::link::BridgePortState;
                use rtnetlink::packet_route::link::InfoBridgePort;

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

                for nla in info_bridge_port {
                    match nla {
                        InfoBridgePort::State(v) => {
                            state = match v {
                                BridgePortState::Disabled => {
                                    "disabled".to_string()
                                }
                                BridgePortState::Listening => {
                                    "listening".to_string()
                                }
                                BridgePortState::Learning => {
                                    "learning".to_string()
                                }
                                BridgePortState::Forwarding => {
                                    "forwarding".to_string()
                                }
                                BridgePortState::Blocking => {
                                    "blocking".to_string()
                                }
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
                        InfoBridgePort::PortNumber(v) => {
                            no = format!("{:#x}", v)
                        }
                        InfoBridgePort::DesignatedPort(v) => {
                            designated_port = *v as u32
                        }
                        InfoBridgePort::DesignatedCost(v) => {
                            designated_cost = *v as u32
                        }
                        InfoBridgePort::BridgeId(v) => {
                            bridge_id =
                                Some(format_bridge_id(v.priority, v.address));
                        }
                        InfoBridgePort::RootId(v) => {
                            root_id =
                                Some(format_bridge_id(v.priority, v.address));
                        }
                        InfoBridgePort::HoldTimer(v) => hold_timer = *v,
                        InfoBridgePort::MessageAgeTimer(v) => {
                            message_age_timer = *v
                        }
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
                            use rtnetlink::packet_route::link::BridgePortMulticastRouter;
                            multicast_router = match v {
                                BridgePortMulticastRouter::Disabled => 0,
                                BridgePortMulticastRouter::TempQuery => 1,
                                BridgePortMulticastRouter::Perm => 2,
                                BridgePortMulticastRouter::Temp => 3,
                                BridgePortMulticastRouter::Other(n) => *n,
                                _ => 0,
                            };
                        }
                        InfoBridgePort::MulticastFlood(v) => mcast_flood = *v,
                        InfoBridgePort::BroadcastFlood(v) => bcast_flood = *v,
                        InfoBridgePort::MulticastToUnicast(v) => {
                            mcast_to_unicast = *v
                        }
                        InfoBridgePort::NeighSupress(v) => neigh_suppress = *v,
                        InfoBridgePort::NeighVlanSupress(v) => {
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

                Self::BridgeSlave {
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
            _ => todo!("Other port types not yet implemented"),
        }
    }

    fn new(info_data: &InfoData) -> Self {
        match info_data {
            InfoData::Bridge(info_bridge) => {
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

                for nla in info_bridge {
                    match nla {
                        InfoBridge::ForwardDelay(v) => forward_delay = *v,
                        InfoBridge::HelloTime(v) => hello_time = *v,
                        InfoBridge::MaxAge(v) => max_age = *v,
                        InfoBridge::AgeingTime(v) => ageing_time = *v,
                        InfoBridge::StpState(v) => stp_state = *v,
                        InfoBridge::Priority(v) => priority = *v,
                        InfoBridge::VlanFiltering(v) => {
                            vlan_filtering = if *v { 1 } else { 0 }
                        }
                        InfoBridge::VlanProtocol(v) => {
                            vlan_protocol = match v {
                                0x8100 => "802.1Q".to_string(),
                                0x88a8 => "802.1ad".to_string(),
                                _ => format!("0x{:x}", v),
                            };
                        }
                        InfoBridge::BridgeId(v) => {
                            bridge_id =
                                Some(format_bridge_id(v.priority, v.address));
                        }
                        InfoBridge::RootId(v) => {
                            root_id =
                                Some(format_bridge_id(v.priority, v.address));
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
                        InfoBridge::GroupAddr(v) => {
                            group_addr = mac_to_string(v)
                        }
                        InfoBridge::MulticastRouter(v) => mcast_router = *v,
                        InfoBridge::MulticastSnooping(v) => mcast_snooping = *v,
                        InfoBridge::MulticastQueryUseIfaddr(v) => {
                            mcast_query_use_ifaddr = *v
                        }
                        InfoBridge::MulticastQuerier(v) => mcast_querier = *v,
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
                        InfoBridge::MulticastQueryInterval(v) => {
                            mcast_query_intvl = *v
                        }
                        InfoBridge::MulticastQueryResponseInterval(v) => {
                            mcast_query_response_intvl = *v
                        }
                        InfoBridge::MulticastStartupQueryInterval(v) => {
                            mcast_startup_query_intvl = *v
                        }
                        InfoBridge::NfCallIpTables(v) => nf_call_iptables = *v,
                        InfoBridge::NfCallIp6Tables(v) => {
                            nf_call_ip6tables = *v
                        }
                        InfoBridge::NfCallArpTables(v) => {
                            nf_call_arptables = *v
                        }
                        InfoBridge::VlanDefaultPvid(v) => {
                            vlan_default_pvid = *v
                        }
                        InfoBridge::VlanStatsEnabled(v) => {
                            vlan_stats_enabled = Some(*v)
                        }
                        InfoBridge::VlanStatsPerHost(v) => {
                            vlan_stats_per_port = Some(*v)
                        }
                        InfoBridge::MulticastStatsEnabled(v) => {
                            mcast_stats_enabled = Some(*v)
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
                                    fdb_n_learned =
                                        Some(u32::from_ne_bytes(val));
                                }
                                IFLA_BR_FDB_MAX_LEARNED => {
                                    let mut val = [0u8; 4];
                                    nla.emit_value(&mut val);
                                    fdb_max_learned =
                                        Some(u32::from_ne_bytes(val));
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

                Self::Bridge {
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
            InfoData::Tun(_info_tun) => todo!(),
            InfoData::Vlan(info_vlan) => {
                use rtnetlink::packet_route::link::InfoVlan;
                let mut id = 0;
                let mut flags = Vec::new();
                let mut protocol = String::new();

                for nla in info_vlan {
                    match nla {
                        InfoVlan::Id(v) => id = *v,
                        InfoVlan::Flags((flags_val, _)) => {
                            if flags_val & VLAN_FLAG_REORDER_HDR != 0 {
                                flags.push("REORDER_HDR".to_string());
                            }
                            if flags_val & VLAN_FLAG_GVRP != 0 {
                                flags.push("GVRP".to_string());
                            }
                            if flags_val & VLAN_FLAG_LOOSE_BINDING != 0 {
                                flags.push("LOOSE_BINDING".to_string());
                            }
                            if flags_val & VLAN_FLAG_MVRP != 0 {
                                flags.push("MVRP".to_string());
                            }
                        }
                        InfoVlan::Protocol(v) => {
                            protocol = v.to_string().to_uppercase();
                        }
                        _ => (),
                    }
                }

                Self::Vlan {
                    id,
                    flags,
                    protocol,
                }
            }
            InfoData::Veth(_info_veth) => todo!(),
            InfoData::Vxlan(_info_vxlan) => todo!(),
            InfoData::Bond(_info_bond) => todo!(),
            InfoData::IpVlan(_info_ip_vlan) => todo!(),
            InfoData::IpVtap(_info_ip_vtap) => todo!(),
            InfoData::MacVlan(_info_mac_vlan) => todo!(),
            InfoData::MacVtap(_info_mac_vtap) => todo!(),
            InfoData::GreTap(_info_gre_tap) => todo!(),
            InfoData::GreTap6(_info_gre_tap6) => todo!(),
            InfoData::SitTun(_info_sit_tun) => todo!(),
            InfoData::GreTun(_info_gre_tun) => todo!(),
            InfoData::GreTun6(_info_gre_tun6) => todo!(),
            InfoData::Vti(_info_vti) => todo!(),
            InfoData::Vrf(_info_vrf) => todo!(),
            InfoData::Gtp(_info_gtp) => todo!(),
            InfoData::Ipoib(_info_ipoib) => todo!(),
            InfoData::Xfrm(_info_xfrm) => todo!(),
            InfoData::MacSec(_info_mac_sec) => todo!(),
            InfoData::Hsr(_info_hsr) => todo!(),
            InfoData::Geneve(_info_geneve) => todo!(),
            InfoData::Other(_items) => todo!(),
            _ => todo!(),
        }
    }
}

impl std::fmt::Display for CliLinkInfoData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliLinkInfoData::Vlan {
                id,
                flags,
                protocol,
            } => {
                write!(f, "protocol {} ", protocol)?;
                write!(f, "id {} ", id)?;
                if !flags.is_empty() {
                    write!(f, "<{}>", flags.as_slice().join(","))?;
                }
            }
            CliLinkInfoData::BridgeSlave {
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
                group_fwd_mask,
                group_fwd_mask_str,
                vlan_tunnel,
                isolated,
                locked,
                mab,
            } => {
                let format_timer = |val: u64| -> String {
                    let seconds = val as f64 / 100.0;
                    format!("{:>7.2}", seconds)
                };

                let on_off = |val: bool| if val { "on" } else { "off" };

                write!(f, "state {} ", state)?;
                write!(f, "priority {} ", priority)?;
                write!(f, "cost {} ", cost)?;
                write!(f, "hairpin {} ", on_off(*hairpin))?;
                write!(f, "guard {} ", on_off(*guard))?;
                write!(f, "root_block {} ", on_off(*root_block))?;
                write!(f, "fastleave {} ", on_off(*fastleave))?;
                write!(f, "learning {} ", on_off(*learning))?;
                write!(f, "flood {} ", on_off(*flood))?;
                write!(f, "port_id {} ", id)?;
                write!(f, "port_no {} ", no)?;
                write!(f, "designated_port {} ", designated_port)?;
                write!(f, "designated_cost {} ", designated_cost)?;
                if let Some(bid) = bridge_id {
                    write!(f, "designated_bridge {} ", bid)?;
                }
                if let Some(rid) = root_id {
                    write!(f, "designated_root {} ", rid)?;
                }
                write!(f, "hold_timer {} ", format_timer(*hold_timer))?;
                write!(
                    f,
                    "message_age_timer {} ",
                    format_timer(*message_age_timer)
                )?;
                write!(
                    f,
                    "forward_delay_timer {} ",
                    format_timer(*forward_delay_timer)
                )?;
                write!(f, "topology_change_ack {} ", topology_change_ack)?;
                write!(f, "config_pending {} ", config_pending)?;
                write!(f, "proxy_arp {} ", on_off(*proxy_arp))?;
                write!(f, "proxy_arp_wifi {} ", on_off(*proxy_arp_wifi))?;
                write!(f, "mcast_router {} ", multicast_router)?;
                write!(f, "mcast_fast_leave {} ", on_off(*fastleave))?;
                write!(f, "mcast_flood {} ", on_off(*mcast_flood))?;
                write!(f, "bcast_flood {} ", on_off(*bcast_flood))?;
                write!(f, "mcast_to_unicast {} ", on_off(*mcast_to_unicast))?;
                write!(f, "neigh_suppress {} ", on_off(*neigh_suppress))?;
                if let Some(v) = neigh_vlan_suppress {
                    write!(f, "neigh_vlan_suppress {} ", on_off(*v))?;
                } else {
                    write!(f, "neigh_vlan_suppress off ")?;
                }
                write!(f, "group_fwd_mask {} ", group_fwd_mask)?;
                write!(f, "group_fwd_mask_str {} ", group_fwd_mask_str)?;
                write!(f, "vlan_tunnel {} ", on_off(*vlan_tunnel))?;
                write!(f, "isolated {} ", on_off(*isolated))?;
                write!(f, "locked {} ", on_off(*locked))?;
                if let Some(v) = mab {
                    write!(f, "mab {}", on_off(*v))?;
                } else {
                    write!(f, "mab off")?;
                }
            }
            CliLinkInfoData::Bridge {
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
            } => {
                let format_timer = |val: u64| -> String {
                    let seconds = val as f64 / 100.0;
                    format!("{:>7.2}", seconds)
                };

                write!(f, "forward_delay {} ", forward_delay)?;
                write!(f, "hello_time {} ", hello_time)?;
                write!(f, "max_age {} ", max_age)?;
                write!(f, "ageing_time {} ", ageing_time)?;
                write!(f, "stp_state {} ", stp_state)?;
                write!(f, "priority {} ", priority)?;
                write!(f, "vlan_filtering {} ", vlan_filtering)?;
                write!(f, "vlan_protocol {} ", vlan_protocol)?;
                if let Some(bid) = bridge_id {
                    write!(f, "bridge_id {} ", bid)?;
                }
                if let Some(rid) = root_id {
                    write!(f, "designated_root {} ", rid)?;
                }
                write!(f, "root_port {} ", root_port)?;
                write!(f, "root_path_cost {} ", root_path_cost)?;
                write!(f, "topology_change {} ", topology_change)?;
                write!(
                    f,
                    "topology_change_detected {} ",
                    topology_change_detected
                )?;
                write!(f, "hello_timer {} ", format_timer(*hello_timer))?;
                write!(f, "tcn_timer {} ", format_timer(*tcn_timer))?;
                write!(
                    f,
                    "topology_change_timer {} ",
                    format_timer(*topology_change_timer)
                )?;
                write!(f, "gc_timer {} ", format_timer(*gc_timer))?;
                if let Some(v) = fdb_n_learned {
                    write!(f, "fdb_n_learned {} ", v)?;
                }
                if let Some(v) = fdb_max_learned {
                    write!(f, "fdb_max_learned {} ", v)?;
                }
                write!(f, "vlan_default_pvid {} ", vlan_default_pvid)?;
                if let Some(v) = vlan_stats_enabled {
                    write!(f, "vlan_stats_enabled {} ", v)?;
                }
                if let Some(v) = vlan_stats_per_port {
                    write!(f, "vlan_stats_per_port {} ", v)?;
                }
                let mask_val: u16 = group_fwd_mask.parse().unwrap_or(0);
                if mask_val == 0 {
                    write!(f, "group_fwd_mask {} ", mask_val)?;
                } else {
                    write!(f, "group_fwd_mask {:#x} ", mask_val)?;
                }
                if !group_addr.is_empty() {
                    write!(f, "group_address {} ", group_addr)?;
                }
                write!(f, "mcast_snooping {} ", mcast_snooping)?;
                write!(f, "no_linklocal_learn {} ", no_linklocal_learn)?;
                write!(f, "mcast_vlan_snooping {} ", mcast_vlan_snooping)?;
                write!(f, "mst_enabled {} ", mst_enabled)?;
                write!(f, "mcast_router {} ", mcast_router)?;
                write!(
                    f,
                    "mcast_query_use_ifaddr {} ",
                    mcast_query_use_ifaddr
                )?;
                write!(f, "mcast_querier {} ", mcast_querier)?;
                write!(f, "mcast_hash_elasticity {} ", mcast_hash_elasticity)?;
                write!(f, "mcast_hash_max {} ", mcast_hash_max)?;
                write!(
                    f,
                    "mcast_last_member_count {} ",
                    mcast_last_member_cnt
                )?;
                write!(
                    f,
                    "mcast_startup_query_count {} ",
                    mcast_startup_query_cnt
                )?;
                write!(
                    f,
                    "mcast_last_member_interval {} ",
                    mcast_last_member_intvl
                )?;
                write!(
                    f,
                    "mcast_membership_interval {} ",
                    mcast_membership_intvl
                )?;
                write!(f, "mcast_querier_interval {} ", mcast_querier_intvl)?;
                write!(f, "mcast_query_interval {} ", mcast_query_intvl)?;
                write!(
                    f,
                    "mcast_query_response_interval {} ",
                    mcast_query_response_intvl
                )?;
                write!(
                    f,
                    "mcast_startup_query_interval {} ",
                    mcast_startup_query_intvl
                )?;
                if let Some(v) = mcast_stats_enabled {
                    write!(f, "mcast_stats_enabled {} ", v)?;
                }
                if let Some(v) = mcast_igmp_version {
                    write!(f, "mcast_igmp_version {} ", v)?;
                }
                if let Some(v) = mcast_mld_version {
                    write!(f, "mcast_mld_version {} ", v)?;
                }
                write!(f, "nf_call_iptables {} ", nf_call_iptables)?;
                write!(f, "nf_call_ip6tables {} ", nf_call_ip6tables)?;
                write!(f, "nf_call_arptables {}", nf_call_arptables)?;
            }
        }

        Ok(())
    }
}

#[derive(Serialize)]
pub(crate) struct CliLinkInfoKindNData {
    pub(crate) info_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) info_data: Option<CliLinkInfoData>,
}

impl std::fmt::Display for CliLinkInfoKindNData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\n    ")?;
        write!(f, "{} ", self.info_kind)?;
        if let Some(data) = &self.info_data {
            write!(f, "{data} ")?;
        }
        Ok(())
    }
}

impl CliLinkInfoKindNData {
    pub fn new(link_info: &[LinkInfo]) -> Option<Self> {
        let mut info_kind = String::new();
        let mut info_data = Option::None;

        for nla in link_info {
            match nla {
                LinkInfo::Kind(t) => {
                    info_kind = t.to_string();
                }
                LinkInfo::Data(data) => {
                    info_data = Some(CliLinkInfoData::new(data));
                }
                LinkInfo::PortKind(_t) => {
                    // Don't overwrite existing kind, we need to track both
                    // but skip this for now - we'll handle it separately
                }
                LinkInfo::PortData(_data) => {
                    // Skip port data in this structure - it's handled
                    // separately
                }
                _ => (),
            }
        }

        Some(CliLinkInfoKindNData {
            info_kind,
            info_data,
        })
    }

    pub fn new_slave(link_info: &[LinkInfo]) -> Option<Self> {
        let mut port_kind = String::new();
        let mut port_data = Option::None;

        for nla in link_info {
            match nla {
                LinkInfo::PortKind(t) => {
                    port_kind = t.to_string();
                }
                LinkInfo::PortData(data) => {
                    port_data = Some(CliLinkInfoData::new_from_port_data(data));
                }
                _ => (),
            }
        }

        if port_kind.is_empty() {
            None
        } else {
            // Return just the port_kind without _slave suffix
            // The caller will decide how to use it
            Some(CliLinkInfoKindNData {
                info_kind: port_kind,
                info_data: port_data,
            })
        }
    }
}
