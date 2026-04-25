// SPDX-License-Identifier: MIT

use iproute_rs::mac_to_string;
use rtnetlink::packet_route::link::{
    BondAdSelect, BondAllPortActive, BondArpValidate, BondLacpRate,
    BondPortState, InfoBond, InfoBondPort, MiiStatus,
};
use serde::Serialize;

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
                InfoBond::AdLacpRate(v) => {
                    ad_lacp_rate = if matches!(*v, BondLacpRate::Fast) {
                        "fast"
                    } else {
                        "slow"
                    }
                    .to_string()
                }
                InfoBond::AdSelect(v) => {
                    ad_select = match *v {
                        BondAdSelect::Stable => "stable",
                        BondAdSelect::Bandwidth => "bandwidth",
                        BondAdSelect::Count => "count",
                        _ => "unknown",
                    }
                    .to_string()
                }
                InfoBond::TlbDynamicLb(v) => tlb_dynamic_lb = *v as u8,
                InfoBond::CoupledControl(v) => coupled_control = *v,
                InfoBond::BroadcastNeigh(v) => broadcast_neighbor = *v,
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

        write!(f, "mode {} ", self.mode)?;
        write!(f, "miimon {} ", self.miimon)?;
        write!(f, "updelay {} ", self.updelay)?;
        write!(f, "downdelay {} ", self.downdelay)?;
        write!(f, "peer_notify_delay {} ", self.peer_notify_delay)?;
        write!(f, "use_carrier {} ", self.use_carrier)?;
        write!(f, "arp_interval {} ", self.arp_interval)?;
        write!(f, "arp_missed_max {} ", self.arp_missed_max)?;
        write!(f, "arp_validate {} ", arp_validate)?;
        write!(f, "arp_all_targets {} ", self.arp_all_targets)?;
        write!(f, "primary_reselect {} ", self.primary_reselect)?;
        write!(f, "fail_over_mac {} ", self.fail_over_mac)?;
        write!(f, "xmit_hash_policy {} ", self.xmit_hash_policy)?;
        write!(f, "resend_igmp {} ", self.resend_igmp)?;
        write!(f, "num_grat_arp {} ", self.num_peer_notif)?;
        write!(f, "all_slaves_active {} ", self.all_slaves_active)?;
        write!(f, "min_links {} ", self.min_links)?;
        write!(f, "lp_interval {} ", self.lp_interval)?;
        write!(f, "packets_per_slave {} ", self.packets_per_slave)?;
        write!(f, "lacp_active {} ", self.ad_lacp_active)?;
        write!(f, "lacp_rate {} ", self.ad_lacp_rate)?;
        write!(f, "coupled_control {} ", on_off(self.coupled_control))?;
        write!(f, "broadcast_neighbor {} ", on_off(self.broadcast_neighbor))?;
        write!(f, "ad_select {} ", self.ad_select)?;
        write!(f, "tlb_dynamic_lb {}", self.tlb_dynamic_lb)?;

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
                    state = match v {
                        BondPortState::Active => "ACTIVE".to_string(),
                        BondPortState::Backup => "BACKUP".to_string(),
                        BondPortState::Other(n) => format!("{}", n),
                        _ => "unknown".to_string(),
                    };
                }
                InfoBondPort::LinkFailureCount(l) => link_failure_count = *l,
                InfoBondPort::MiiStatus(s) => {
                    mii_status = match s {
                        MiiStatus::Up => "UP".to_string(),
                        MiiStatus::Down => "DOWN".to_string(),
                        MiiStatus::Other(n) => format!("{}", n),
                        _ => "unknown".to_string(),
                    };
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
        write!(f, "state {} ", self.state)?;
        write!(f, "mii_status {} ", self.mii_status)?;
        write!(f, "link_failure_count {} ", self.link_failure_count)?;
        write!(f, "perm_hwaddr {} ", self.perm_hwaddr)?;
        write!(f, "queue_id {} ", self.queue_id)?;
        write!(f, "prio {}", self.prio)?;

        Ok(())
    }
}
