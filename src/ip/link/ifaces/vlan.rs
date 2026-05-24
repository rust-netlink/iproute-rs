// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkMessageBuilder, LinkVlan, QosMapping,
    packet_route::link::{InfoVlan, VlanFlags, VlanProtocol, VlanQosMapping},
};
use serde::Serialize;

use crate::link::LinkBaseConf;

#[derive(Serialize, Default)]
pub(crate) struct CliLinkInfoDataVlan {
    protocol: String,
    id: u16,
    flags: Vec<String>,
    ingress_qos: Vec<String>,
    egress_qos: Vec<String>,
}

impl From<&[InfoVlan]> for CliLinkInfoDataVlan {
    fn from(info: &[InfoVlan]) -> Self {
        let mut id = 0;
        let mut flags = Vec::new();
        let mut protocol = String::new();
        let mut ingress_qos = Vec::new();
        let mut egress_qos = Vec::new();

        for nla in info {
            match nla {
                InfoVlan::Id(v) => id = *v,
                InfoVlan::Flags((flags_val, _)) => {
                    if flags_val.contains(VlanFlags::ReorderHdr) {
                        flags.push("REORDER_HDR".to_string());
                    }
                    if flags_val.contains(VlanFlags::Gvrp) {
                        flags.push("GVRP".to_string());
                    }
                    if flags_val.contains(VlanFlags::LooseBinding) {
                        flags.push("LOOSE_BINDING".to_string());
                    }
                    if flags_val.contains(VlanFlags::Mvrp) {
                        flags.push("MVRP".to_string());
                    }
                    if flags_val.contains(VlanFlags::BridgeBinding) {
                        flags.push("BRIDGE_BINDING".to_string());
                    }
                }
                InfoVlan::Protocol(v) => {
                    protocol = match v {
                        VlanProtocol::Ieee8021Q => "802.1Q".to_string(),
                        VlanProtocol::Ieee8021Ad => "802.1ad".to_string(),
                        _ => v.to_string(),
                    };
                }
                InfoVlan::IngressQos(mappings) => {
                    for mapping in mappings {
                        if let VlanQosMapping::Mapping(from, to) = mapping {
                            ingress_qos.push(format!("{from}:{to}"));
                        }
                    }
                }
                InfoVlan::EgressQos(mappings) => {
                    for mapping in mappings {
                        if let VlanQosMapping::Mapping(from, to) = mapping {
                            egress_qos.push(format!("{from}:{to}"));
                        }
                    }
                }
                _ => (),
            }
        }

        Self {
            id,
            flags,
            protocol,
            ingress_qos,
            egress_qos,
        }
    }
}

impl LinkBaseConf {
    pub(crate) async fn apply_vlan(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkVlan>, CliError> {
        let link_name = self
            .link
            .as_deref()
            .ok_or_else(|| CliError::from("VLAN requires link device"))?;

        let link_ifindex = self.get_ifindex_by_name(handle, link_name).await?;

        let mut builder =
            LinkMessageBuilder::<LinkVlan>::new(&self.name).link(link_ifindex);
        let mut vlan_id = None;
        let mut ingress_qos = Vec::new();
        let mut egress_qos = Vec::new();
        let mut flags = VlanFlags::empty();
        let mut flag_mask = VlanFlags::empty();

        macro_rules! set_flag {
            ($v:expr, $flag:ident) => {
                match $v.as_str() {
                    "on" => {
                        flags |= VlanFlags::$flag;
                        flag_mask |= VlanFlags::$flag;
                    }
                    "off" => {
                        flag_mask |= VlanFlags::$flag;
                    }
                    _ => {
                        return Err(CliError::from(format!(
                            "{} must be on or off, got {}",
                            stringify!($flag),
                            $v
                        )));
                    }
                }
            };
        }

        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            match key.as_str() {
                "id" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("VLAN id requires a value"));
                    };
                    let id = v.parse::<u16>().map_err(|_| {
                        CliError::from(format!("Invalid VLAN id: {v}"))
                    })?;
                    builder = builder.id(id);
                    vlan_id = Some(id);
                }
                "protocol" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "VLAN protocol requires a value",
                        ));
                    };
                    let proto = match v.to_lowercase().as_str() {
                        "802.1q" => VlanProtocol::Ieee8021Q,
                        "802.1ad" => VlanProtocol::Ieee8021Ad,
                        _ => {
                            return Err(CliError::from(format!(
                                "Unknown VLAN protocol: {v}"
                            )));
                        }
                    };
                    builder = builder.protocol(proto);
                }
                "reorder_hdr" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "reorder_hdr requires a value",
                        ));
                    };
                    set_flag!(v, ReorderHdr);
                }
                "gvrp" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("gvrp requires a value"));
                    };
                    set_flag!(v, Gvrp);
                }
                "mvrp" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("mvrp requires a value"));
                    };
                    set_flag!(v, Mvrp);
                }
                "loose_binding" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "loose_binding requires a value",
                        ));
                    };
                    set_flag!(v, LooseBinding);
                }
                "bridge_binding" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "bridge_binding requires a value",
                        ));
                    };
                    set_flag!(v, BridgeBinding);
                }
                "ingress-qos-map" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "ingress-qos-map requires a from:to mapping",
                        ));
                    };
                    let (from, to) = parse_qos_map(v)?;
                    ingress_qos.push(QosMapping { from, to });
                }
                "egress-qos-map" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "egress-qos-map requires a from:to mapping",
                        ));
                    };
                    let (from, to) = parse_qos_map(v)?;
                    egress_qos.push(QosMapping { from, to });
                }
                _ => {
                    return Err(CliError::from(format!(
                        "Unknown VLAN argument: {key}"
                    )));
                }
            }
        }

        let Some(_) = vlan_id else {
            return Err(CliError::from("VLAN id is required"));
        };

        if flag_mask != VlanFlags::empty() {
            builder = builder.flags(flags, flag_mask);
        }

        if !ingress_qos.is_empty() || !egress_qos.is_empty() {
            builder = builder.qos(ingress_qos, egress_qos);
        }

        Ok(builder)
    }
}

fn parse_qos_map(s: &str) -> Result<(u32, u32), CliError> {
    let Some((from, to)) = s.split_once(':') else {
        return Err(CliError::from(format!(
            "Invalid QoS mapping, expected from:to, got {s}"
        )));
    };
    let from = from.parse::<u32>().map_err(|_| {
        CliError::from(format!("Invalid QoS map 'from' value: {from}"))
    })?;
    let to = to.parse::<u32>().map_err(|_| {
        CliError::from(format!("Invalid QoS map 'to' value: {to}"))
    })?;
    Ok((from, to))
}

impl std::fmt::Display for CliLinkInfoDataVlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "protocol {} id {}", self.protocol, self.id)?;
        if !self.flags.is_empty() {
            write!(f, " <{}>", self.flags.as_slice().join(","))?;
        }
        Ok(())
    }
}
