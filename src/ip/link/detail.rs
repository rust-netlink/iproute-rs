// SPDX-License-Identifier: MIT

use rtnetlink::packet_route::link::{AfSpecInet6, AfSpecUnspec, LinkAttribute};
use serde::Serialize;

use crate::link::link_info::CliLinkInfo;

fn should_skip_netns_immutable(val: &Option<bool>) -> bool {
    matches!(val, None | Some(false))
}

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

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDetail {
    promiscuity: u32,
    allmulti: u32,
    min_mtu: u32,
    max_mtu: u32,
    #[serde(
        skip_serializing_if = "should_skip_netns_immutable",
        rename = "netns-immutable"
    )]
    netns_immutable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    linkinfo: Option<CliLinkInfo>,
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

impl CliLinkInfoDetail {
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
        let mut netns_immutable = None;

        for nl_attr in nl_attrs {
            match nl_attr {
                LinkAttribute::Promiscuity(p) => promiscuity = *p,
                LinkAttribute::AllMulticast(a) => allmulti = *a,
                LinkAttribute::MinMtu(m) => min_mtu = *m,
                LinkAttribute::MaxMtu(m) => max_mtu = *m,
                LinkAttribute::AfSpecUnspec(a) => {
                    inet6_addr_gen_mode = get_addr_gen_mode(a)
                }
                LinkAttribute::NumTxQueues(n) => num_tx_queues = *n,
                LinkAttribute::NumRxQueues(n) => num_rx_queues = *n,
                LinkAttribute::GsoMaxSize(g) => gso_max_size = *g,
                LinkAttribute::GsoMaxSegs(g) => gso_max_segs = *g,
                LinkAttribute::TsoMaxSize(t) => tso_max_size = *t,
                LinkAttribute::TsoMaxSegs(t) => tso_max_segs = *t,
                LinkAttribute::GroMaxSize(g) => gro_max_size = *g,
                LinkAttribute::GsoIpv4MaxSize(g) => gso_ipv4_max_size = *g,
                LinkAttribute::GroIpv4MaxSize(g) => gro_ipv4_max_size = *g,
                LinkAttribute::NetnsImmutable(v) => netns_immutable = Some(*v),
                LinkAttribute::ParentDevName(n) => parentdev = n.clone(),
                LinkAttribute::ParentDevBusName(n) => parentbus = n.clone(),
                LinkAttribute::LinkInfo(info) => {
                    linkinfo = info.as_slice().try_into().ok();
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
            netns_immutable,
            parentbus,
            parentdev,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            " promiscuity {} allmulti {} minmtu {} maxmtu {} ",
            self.promiscuity, self.allmulti, self.min_mtu, self.max_mtu,
        )?;

        if self.netns_immutable == Some(true) {
            write!(f, "netns-immutable ")?;
        }

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
