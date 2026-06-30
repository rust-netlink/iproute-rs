// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkMessageBuilder, LinkRmNet,
    packet_route::link::{InfoKind, InfoRmNet, LinkInfo, RmNetFlags},
};
use serde::Serialize;

use super::parse::{extract_link_info, parse_on_off, parse_u16};
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataRmNet {
    mux_id: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<Vec<String>>,
}

impl From<&[InfoRmNet]> for CliLinkInfoDataRmNet {
    fn from(info: &[InfoRmNet]) -> Self {
        let mut mux_id = 0;
        let mut flags: Option<Vec<String>> = None;
        for nla in info {
            match nla {
                InfoRmNet::MuxId(v) => mux_id = *v,
                InfoRmNet::Flags(f) => {
                    let mut v = Vec::new();
                    if f.flags.contains(RmNetFlags::IngressDeaggregation) {
                        v.push("INGRESS_DEAGGREGATION".into());
                    }
                    if f.flags.contains(RmNetFlags::IngressCommands) {
                        v.push("INGRESS_MAP_COMMANDS".into());
                    }
                    if f.flags.contains(RmNetFlags::IngressMapCksumV4) {
                        v.push("INGRESS_MAP_CKSUMV4".into());
                    }
                    if f.flags.contains(RmNetFlags::EgressMapCksumV4) {
                        v.push("EGRESS_MAP_CKSUMV4".into());
                    }
                    if f.flags.contains(RmNetFlags::IngressMapCksumV5) {
                        v.push("INGRESS_MAP_CKSUMV5".into());
                    }
                    if f.flags.contains(RmNetFlags::EgressMapCksumV5) {
                        v.push("EGRESS_MAP_CKSUMV5".into());
                    }
                    flags = Some(v);
                }
                _ => {}
            }
        }
        Self { mux_id, flags }
    }
}

impl std::fmt::Display for CliLinkInfoDataRmNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mux_id {}", self.mux_id)?;
        if let Some(flags) = &self.flags
            && !flags.is_empty()
        {
            write!(f, " <{}>", flags.join(","))?;
        }
        Ok(())
    }
}

fn apply_rmnet_args<'a>(
    mut builder: LinkMessageBuilder<LinkRmNet>,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<LinkMessageBuilder<LinkRmNet>, CliError> {
    let mut mux_id_set = false;
    let mut flags = RmNetFlags::empty();
    let mut mask = RmNetFlags::empty();
    while let Some(key) = iter.next() {
        match key {
            "mux_id" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("\"mux_id\" requires a value"));
                };
                builder = builder.mux_id(parse_u16(v, "mux_id")?);
                mux_id_set = true;
            }
            "ingress-deaggregation" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "\"ingress-deaggregation\" requires a value",
                    ));
                };
                let val = parse_on_off(v)?;
                mask |= RmNetFlags::IngressDeaggregation;
                if val {
                    flags |= RmNetFlags::IngressDeaggregation;
                } else {
                    flags &= !RmNetFlags::IngressDeaggregation;
                }
            }
            "ingress-commands" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "\"ingress-commands\" requires a value",
                    ));
                };
                let val = parse_on_off(v)?;
                mask |= RmNetFlags::IngressCommands;
                if val {
                    flags |= RmNetFlags::IngressCommands;
                } else {
                    flags &= !RmNetFlags::IngressCommands;
                }
            }
            "ingress-mapv4-checksum" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "\"ingress-mapv4-checksum\" requires a value",
                    ));
                };
                let val = parse_on_off(v)?;
                mask |= RmNetFlags::IngressMapCksumV4;
                if val {
                    flags |= RmNetFlags::IngressMapCksumV4;
                } else {
                    flags &= !RmNetFlags::IngressMapCksumV4;
                }
            }
            "egress-mapv4-checksum" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "\"egress-mapv4-checksum\" requires a value",
                    ));
                };
                let val = parse_on_off(v)?;
                mask |= RmNetFlags::EgressMapCksumV4;
                if val {
                    flags |= RmNetFlags::EgressMapCksumV4;
                } else {
                    flags &= !RmNetFlags::EgressMapCksumV4;
                }
            }
            "ingress-mapv5-checksum" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "\"ingress-mapv5-checksum\" requires a value",
                    ));
                };
                let val = parse_on_off(v)?;
                mask |= RmNetFlags::IngressMapCksumV5;
                if val {
                    flags |= RmNetFlags::IngressMapCksumV5;
                } else {
                    flags &= !RmNetFlags::IngressMapCksumV5;
                }
            }
            "egress-mapv5-checksum" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "\"egress-mapv5-checksum\" requires a value",
                    ));
                };
                let val = parse_on_off(v)?;
                mask |= RmNetFlags::EgressMapCksumV5;
                if val {
                    flags |= RmNetFlags::EgressMapCksumV5;
                } else {
                    flags &= !RmNetFlags::EgressMapCksumV5;
                }
            }
            _ => {
                return Err(CliError::from(format!(
                    "rmnet: unknown option \"{key}\"",
                )));
            }
        }
    }
    if !mux_id_set {
        return Err(CliError::from(
            "rmnet: missing required \"mux_id\" argument",
        ));
    }
    if !mask.is_empty() {
        builder = builder.flags(flags, mask);
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) async fn apply_rmnet(
        &self,
        handle: &rtnetlink::Handle,
    ) -> Result<LinkMessageBuilder<LinkRmNet>, CliError> {
        let mut remaining: Vec<&str> = Vec::new();
        let mut iter = self.iface_specific.iter();
        while let Some(key) = iter.next() {
            remaining.push(key);
            if let Some(v) = iter.next() {
                remaining.push(v);
            }
        }

        let mut builder = LinkMessageBuilder::<LinkRmNet>::new(&self.name);
        if let Some(ref link_name) = self.link {
            let link_ifindex =
                self.get_ifindex_by_name(handle, link_name).await?;
            builder = builder.link(link_ifindex);
        }
        let mut remaining_iter = remaining.into_iter();
        apply_rmnet_args(builder, &mut remaining_iter)
    }
}

pub(crate) struct IfaceRmNet;

impl IfaceRmNet {
    pub(crate) fn build_entries(
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder = LinkMessageBuilder::<LinkRmNet>::new_with_info_kind(
            InfoKind::RmNet,
        );
        let mut iter = args.iter().map(|s| s.as_str());
        let builder = apply_rmnet_args(builder, &mut iter)?;
        Ok(extract_link_info(builder.build()))
    }

    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        "Usage: ... rmnet mux_id MUXID\n\
         \t\t[ ingress-deaggregation { on | off } ]\n\
         \t\t[ ingress-commands { on | off } ]\n\
         \t\t[ ingress-mapv4-checksum { on | off } ]\n\
         \t\t[ egress-mapv4-checksum { on | off } ]\n\
         \t\t[ ingress-mapv5-checksum { on | off } ]\n\
         \t\t[ egress-mapv5-checksum { on | off } ]\n\
         \n\
         Where: MUXID := 1-254\n"
    }
}

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::link::{
        InfoData, InfoRmNet, InfoRmNetFlags, LinkInfo,
    };

    use super::*;

    #[test]
    fn test_build_entries_with_mux_id() {
        let infos =
            IfaceRmNet::build_entries(&["mux_id".into(), "42".into()]).unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::RmNet)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::RmNet(vec![
            InfoRmNet::MuxId(42),
        ]))));
    }

    #[test]
    fn test_build_entries_missing_mux_id() {
        let err = IfaceRmNet::build_entries(&[]).unwrap_err();
        assert!(err.msg.contains("mux_id"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_missing_value() {
        let err = IfaceRmNet::build_entries(&["mux_id".into()]).unwrap_err();
        assert!(err.msg.contains("requires a value"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_with_flags() {
        let infos = IfaceRmNet::build_entries(&[
            "mux_id".into(),
            "10".into(),
            "ingress-deaggregation".into(),
            "on".into(),
            "ingress-mapv4-checksum".into(),
            "off".into(),
        ])
        .unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::RmNet)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::RmNet(vec![
            InfoRmNet::MuxId(10),
            InfoRmNet::Flags(InfoRmNetFlags::new(
                RmNetFlags::IngressDeaggregation,
                RmNetFlags::IngressDeaggregation
                    | RmNetFlags::IngressMapCksumV4,
            )),
        ]))));
    }

    #[test]
    fn test_rmnet_info_from_mux_id() {
        let infos = vec![InfoRmNet::MuxId(42)];
        let data = CliLinkInfoDataRmNet::from(infos.as_slice());
        assert_eq!(data.mux_id, 42);
    }

    #[test]
    fn test_rmnet_display() {
        let infos = vec![InfoRmNet::MuxId(100)];
        let data = CliLinkInfoDataRmNet::from(infos.as_slice());
        let display = format!("{data}");
        assert_eq!(display, "mux_id 100");
    }

    #[test]
    fn test_rmnet_display_with_flags() {
        let infos = vec![
            InfoRmNet::MuxId(10),
            InfoRmNet::Flags(InfoRmNetFlags::new(
                RmNetFlags::IngressDeaggregation | RmNetFlags::EgressMapCksumV4,
                RmNetFlags::empty(),
            )),
        ];
        let data = CliLinkInfoDataRmNet::from(infos.as_slice());
        let display = format!("{data}");
        assert_eq!(
            display,
            "mux_id 10 <INGRESS_DEAGGREGATION,EGRESS_MAP_CKSUMV4>"
        );
    }

    #[test]
    fn test_rmnet_unknown_option() {
        let err = IfaceRmNet::build_entries(&[
            "mux_id".into(),
            "10".into(),
            "unknown".into(),
        ])
        .unwrap_err();
        assert!(err.msg.contains("unknown option"), "{}", err.msg);
    }

    #[test]
    fn test_rmnet_invalid_flag_value() {
        let err = IfaceRmNet::build_entries(&[
            "mux_id".into(),
            "10".into(),
            "ingress-deaggregation".into(),
            "invalid".into(),
        ])
        .unwrap_err();
        assert!(err.msg.contains("Invalid value"), "{}", err.msg);
    }
}
