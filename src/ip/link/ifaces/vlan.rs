// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkMessageBuilder, LinkVlan, QosMapping,
    packet_route::link::{
        InfoKind, InfoVlan, LinkInfo, VlanFlags, VlanProtocol, VlanQosMapping,
    },
};
use serde::Serialize;

use super::parse::extract_link_info;
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
                InfoVlan::Protocol(v) => protocol = v.to_string(),
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

fn apply_vlan_args<'a>(
    mut builder: LinkMessageBuilder<LinkVlan>,
    iter: &mut impl Iterator<Item = &'a str>,
    vlan_id: &mut Option<u16>,
    flags: &mut VlanFlags,
    flag_mask: &mut VlanFlags,
    ingress_qos: &mut Vec<QosMapping>,
    egress_qos: &mut Vec<QosMapping>,
) -> Result<LinkMessageBuilder<LinkVlan>, CliError> {
    macro_rules! set_flag {
        ($v:expr, $flag:ident) => {
            match $v {
                "on" => {
                    *flags |= VlanFlags::$flag;
                    *flag_mask |= VlanFlags::$flag;
                }
                "off" => {
                    *flag_mask |= VlanFlags::$flag;
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

    while let Some(key) = iter.next() {
        let Some(v) = iter.next() else {
            return Err(CliError::from(format!("VLAN {key} requires a value")));
        };
        match key {
            "id" => {
                let id = v.parse::<u16>().map_err(|_| {
                    CliError::from(format!("Invalid VLAN id: {v}"))
                })?;
                builder = builder.id(id);
                *vlan_id = Some(id);
            }
            "protocol" => {
                let proto = v.parse::<VlanProtocol>().map_err(|e| {
                    CliError::from(format!("Unknown VLAN protocol: {v}: {e}"))
                })?;
                builder = builder.protocol(proto);
            }
            "reorder_hdr" => {
                set_flag!(v, ReorderHdr);
            }
            "gvrp" => {
                set_flag!(v, Gvrp);
            }
            "mvrp" => {
                set_flag!(v, Mvrp);
            }
            "loose_binding" => {
                set_flag!(v, LooseBinding);
            }
            "bridge_binding" => {
                set_flag!(v, BridgeBinding);
            }
            "ingress-qos-map" => {
                let (from, to) = parse_qos_map(v)?;
                ingress_qos.push(QosMapping { from, to });
            }
            "egress-qos-map" => {
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
    Ok(builder)
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

        let builder =
            LinkMessageBuilder::<LinkVlan>::new(&self.name).link(link_ifindex);
        let mut vlan_id = None;
        let mut flags = VlanFlags::empty();
        let mut flag_mask = VlanFlags::empty();
        let mut ingress_qos = Vec::new();
        let mut egress_qos = Vec::new();

        let mut builder = {
            let mut iter = self.iface_specific.iter().map(|s| s.as_str());
            apply_vlan_args(
                builder,
                &mut iter,
                &mut vlan_id,
                &mut flags,
                &mut flag_mask,
                &mut ingress_qos,
                &mut egress_qos,
            )?
        };

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

pub(crate) struct IfaceVlan;

impl IfaceVlan {
    pub(crate) fn build_entries(
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder =
            LinkMessageBuilder::<LinkVlan>::new_with_info_kind(InfoKind::Vlan);

        let mut vlan_id = None;
        let mut flags = VlanFlags::empty();
        let mut flag_mask = VlanFlags::empty();
        let mut ingress_qos = Vec::new();
        let mut egress_qos = Vec::new();

        let mut builder = {
            let mut iter = args.iter().map(|s| s.as_str());
            apply_vlan_args(
                builder,
                &mut iter,
                &mut vlan_id,
                &mut flags,
                &mut flag_mask,
                &mut ingress_qos,
                &mut egress_qos,
            )?
        };

        if flag_mask != VlanFlags::empty() {
            builder = builder.flags(flags, flag_mask);
        }

        if !ingress_qos.is_empty() || !egress_qos.is_empty() {
            builder = builder.qos(ingress_qos, egress_qos);
        }

        let infos = extract_link_info(builder.build());
        if infos.is_empty() {
            Ok(vec![LinkInfo::Kind(InfoKind::Vlan)])
        } else {
            Ok(infos)
        }
    }

    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        r"Usage: ... vlan id VLANID
                [ protocol VLANPROTO ]
                [ reorder_hdr { on | off } ]
                [ gvrp { on | off } ]
                [ mvrp { on | off } ]
                [ loose_binding { on | off } ]
                [ bridge_binding { on | off } ]
                [ ingress-qos-map QOS-MAP ]
                [ egress-qos-map QOS-MAP ]

VLANID := 0-4095
VLANPROTO: [ 802.1Q | 802.1ad ]
QOS-MAP := [ QOS-MAP ] QOS-MAPPING
QOS-MAPPING := FROM:TO
"
    }
}

impl std::fmt::Display for CliLinkInfoDataVlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "protocol {} id {}", self.protocol, self.id)?;
        if !self.flags.is_empty() {
            write!(f, " <{}>", self.flags.as_slice().join(","))?;
        }
        if !self.ingress_qos.is_empty() {
            write!(
                f,
                "\n      ingress-qos-map {{ {} }}",
                self.ingress_qos.join(" ")
            )?;
        }
        if !self.egress_qos.is_empty() {
            write!(
                f,
                "\n      egress-qos-map {{ {} }}",
                self.egress_qos.join(" ")
            )?;
        }
        Ok(())
    }
}


