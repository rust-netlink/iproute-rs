// SPDX-License-Identifier: MIT

use std::ffi::CStr;

use rtnetlink::packet_core::DefaultNla;
use rtnetlink::{
    packet_core::Nla as _,
    packet_route::link::{AfSpecInet6, AfSpecUnspec, LinkAttribute},
};
use serde::Serialize;

use crate::link::link_info::{CliLinkInfoData, CliLinkInfoKindNData};

#[derive(Serialize)]
struct CliLinkInfoCombined {
    info_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    info_data: Option<CliLinkInfoData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    info_slave_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    info_slave_data: Option<CliLinkInfoData>,
}

impl std::fmt::Display for CliLinkInfoCombined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\n    ")?;
        write!(f, "{} ", self.info_kind)?;
        if let Some(data) = &self.info_data {
            write!(f, "{data} ")?;
        }

        if let Some(slave_kind) = &self.info_slave_kind {
            write!(f, "\n    {}_slave ", slave_kind)?;
            if let Some(slave_data) = &self.info_slave_data {
                write!(f, "{slave_data} ")?;
            }
        }
        Ok(())
    }
}

// Use constants until support is added to netlink-packet-route
const IFLA_PARENT_DEV_NAME: u16 = 56;
const IFLA_PARENT_DEV_BUS_NAME: u16 = 57;
const IFLA_GRO_MAX_SIZE: u16 = 58;
const IFLA_TSO_MAX_SIZE: u16 = 59;
const IFLA_TSO_MAX_SEGS: u16 = 60;
const IFLA_ALLMULTI: u16 = 61;
const IFLA_GSO_IPV4_MAX_SIZE: u16 = 63;
const IFLA_GRO_IPV4_MAX_SIZE: u16 = 64;

fn get_addr_gen_mode(af_spec_unspec: &[AfSpecUnspec]) -> String {
    af_spec_unspec
        .iter()
        .filter_map(|s| {
            let AfSpecUnspec::Inet6(v) = s else {
                return None;
            };
            v.iter()
                .filter_map(|i| {
                    if let AfSpecInet6::AddrGenMode(mode) = i {
                        Some(mode)
                    } else {
                        None
                    }
                })
                .next()
        })
        .next()
        .map(|i| i.to_string())
        .unwrap_or_default()
}
fn default_nla_to_string(default_nla: &DefaultNla) -> String {
    let val_len = default_nla.value_len();
    let mut val = vec![0u8; val_len];
    default_nla.emit_value(&mut val);
    CStr::from_bytes_with_nul(&val)
        .expect("String nla to be nul-terminated and not contain interior nuls")
        .to_str()
        .expect("To be valid UTF-8")
        .to_string()
}

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDetails {
    promiscuity: u32,
    allmulti: u32,
    min_mtu: u32,
    max_mtu: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    linkinfo: Option<CliLinkInfoCombined>,
    #[serde(skip_serializing_if = "String::is_empty")]
    inet6_addr_gen_mode: String,
    num_tx_queues: u32,
    num_rx_queues: u32,
    gso_max_size: u32,
    gso_max_segs: u32,
    tso_max_size: u32,
    tso_max_segs: u32,
    gro_max_size: u32,
    gso_ipv4_max_size: u32,
    gro_ipv4_max_size: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    parentbus: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    parentdev: String,
}

impl CliLinkInfoDetails {
    pub fn new(nl_attrs: &[LinkAttribute]) -> Self {
        let mut linkinfo = None;
        let mut promiscuity = 0;
        let mut allmulti = 0;
        let mut min_mtu = 0;
        let mut max_mtu = 0;
        let mut num_tx_queues = 0;
        let mut num_rx_queues = 0;
        let mut gso_max_size = 0;
        let mut gso_max_segs = 0;
        let mut tso_max_size = 0;
        let mut tso_max_segs = 0;
        let mut gro_max_size = 0;
        let mut gso_ipv4_max_size = 0;
        let mut gro_ipv4_max_size = 0;
        let mut inet6_addr_gen_mode = String::new();
        let mut parentbus = String::new();
        let mut parentdev = String::new();

        for nl_attr in nl_attrs {
            match nl_attr {
                LinkAttribute::Promiscuity(p) => promiscuity = *p,
                LinkAttribute::MinMtu(m) => min_mtu = *m,
                LinkAttribute::MaxMtu(m) => max_mtu = *m,
                LinkAttribute::AfSpecUnspec(a) => {
                    inet6_addr_gen_mode = get_addr_gen_mode(a)
                }
                LinkAttribute::NumTxQueues(n) => num_tx_queues = *n,
                LinkAttribute::NumRxQueues(n) => num_rx_queues = *n,
                LinkAttribute::GsoMaxSize(g) => gso_max_size = *g,
                LinkAttribute::GsoMaxSegs(g) => gso_max_segs = *g,
                LinkAttribute::Other(default_nla) => match default_nla.kind() {
                    IFLA_PARENT_DEV_BUS_NAME => {
                        parentbus = default_nla_to_string(default_nla);
                    }
                    IFLA_PARENT_DEV_NAME => {
                        parentdev = default_nla_to_string(default_nla);
                    }
                    IFLA_GRO_MAX_SIZE => {
                        let mut val = [0u8; 4];
                        default_nla.emit_value(&mut val);
                        gro_max_size = u32::from_ne_bytes(val);
                    }
                    IFLA_TSO_MAX_SIZE => {
                        let mut val = [0u8; 4];
                        default_nla.emit_value(&mut val);
                        tso_max_size = u32::from_ne_bytes(val);
                    }
                    IFLA_TSO_MAX_SEGS => {
                        let mut val = [0u8; 4];
                        default_nla.emit_value(&mut val);
                        tso_max_segs = u32::from_ne_bytes(val);
                    }
                    IFLA_ALLMULTI => {
                        let mut val = [0u8; 4];
                        default_nla.emit_value(&mut val);
                        allmulti = u32::from_ne_bytes(val);
                    }
                    IFLA_GSO_IPV4_MAX_SIZE => {
                        let mut val = [0u8; 4];
                        default_nla.emit_value(&mut val);
                        gso_ipv4_max_size = u32::from_ne_bytes(val);
                    }
                    IFLA_GRO_IPV4_MAX_SIZE => {
                        let mut val = [0u8; 4];
                        default_nla.emit_value(&mut val);
                        gro_ipv4_max_size = u32::from_ne_bytes(val);
                    }
                    _ => { /* println!("Remains {:?}", default_nla); */ }
                },
                LinkAttribute::LinkInfo(info) => {
                    let main_info = CliLinkInfoKindNData::new(info);
                    let slave_info = CliLinkInfoKindNData::new_slave(info);

                    // Combine main info and slave info into one structure
                    if let Some(main) = main_info {
                        let (slave_kind, slave_data) =
                            if let Some(slave) = slave_info {
                                (Some(slave.info_kind), slave.info_data)
                            } else {
                                (None, None)
                            };

                        linkinfo = Some(CliLinkInfoCombined {
                            info_kind: main.info_kind,
                            info_data: main.info_data,
                            info_slave_kind: slave_kind,
                            info_slave_data: slave_data,
                        });
                    }
                }
                _ => {
                    // println!("Remains {:?}", nl_attr);
                }
            }
        }

        Self {
            promiscuity,
            allmulti,
            min_mtu,
            max_mtu,
            linkinfo,
            inet6_addr_gen_mode,
            num_tx_queues,
            num_rx_queues,
            gso_max_size,
            gso_max_segs,
            tso_max_size,
            tso_max_segs,
            gro_max_size,
            gso_ipv4_max_size,
            gro_ipv4_max_size,
            parentbus,
            parentdev,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            " promiscuity {} allmulti {} minmtu {} maxmtu {} ",
            self.promiscuity, self.allmulti, self.min_mtu, self.max_mtu,
        )?;

        if let Some(linkinfo) = &self.linkinfo {
            write!(f, "{linkinfo}")?;
        }

        write!(
            f,
            "addrgenmode {} numtxqueues {} numrxqueues {} gso_max_size {} \
             gso_max_segs {} tso_max_size {} tso_max_segs {} gro_max_size {} \
             gso_ipv4_max_size {} gro_ipv4_max_size {} ",
            self.inet6_addr_gen_mode,
            self.num_tx_queues,
            self.num_rx_queues,
            self.gso_max_size,
            self.gso_max_segs,
            self.tso_max_size,
            self.tso_max_segs,
            self.gro_max_size,
            self.gso_ipv4_max_size,
            self.gro_ipv4_max_size,
        )?;

        if !self.parentbus.is_empty() {
            write!(f, "parentbus {} ", self.parentbus)?;
        }
        if !self.parentdev.is_empty() {
            write!(f, "parentdev {} ", self.parentdev)?;
        }

        Ok(())
    }
}
