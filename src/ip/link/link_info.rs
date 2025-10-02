use rtnetlink::packet_route::link::{InfoData, LinkInfo};
use serde::Serialize;

const VLAN_FLAG_REORDER_HDR: u32 = 0x1;
const VLAN_FLAG_GVRP: u32 = 0x2;
const VLAN_FLAG_LOOSE_BINDING: u32 = 0x4;
const VLAN_FLAG_MVRP: u32 = 0x8;

#[derive(Serialize)]
#[serde(untagged)]
enum CliLinkInfoData {
    Vlan {
        protocol: String,
        id: u16,
        flags: Vec<String>,
    },
}

impl CliLinkInfoData {
    fn new(info_data: &InfoData) -> Self {
        match info_data {
            InfoData::Bridge(_info_bridge) => todo!(),
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
        }

        Ok(())
    }
}

#[derive(Serialize)]
pub(crate) struct CliLinkInfoKindNData {
    info_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    info_data: Option<CliLinkInfoData>,
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
                _ => (),
            }
        }

        Some(CliLinkInfoKindNData {
            info_kind,
            info_data,
        })
    }
}
