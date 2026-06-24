// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkBareudp, LinkMessageBuilder,
    packet_route::{
        EthernetProtocol,
        link::{InfoBareUdp, InfoKind, LinkInfo},
    },
};
use serde::Serialize;

use super::parse::{extract_link_info, parse_u16};
use crate::link::LinkBaseConf;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_MPLS_UC: u16 = 0x8847;
const ETH_P_MPLS_MC: u16 = 0x8848;

const ETHERTYPE_NAMES: &[(u16, &str)] = &[
    (ETH_P_IP, "ip"),
    (ETH_P_IPV6, "ipv6"),
    (ETH_P_MPLS_UC, "mpls_uc"),
    (ETH_P_MPLS_MC, "mpls_mc"),
];

const ETHERTYPE_INPUT_ALIASES: &[(&str, u16)] = &[("ipv4", ETH_P_IP)];

fn ethertype_to_name(ethertype: &EthernetProtocol) -> String {
    let v = ethertype.value();
    for &(val, name) in ETHERTYPE_NAMES {
        if val == v {
            return name.to_string();
        }
    }
    format!("{v:#x}")
}

fn name_to_ethertype(s: &str) -> Result<EthernetProtocol, CliError> {
    for &(val, name) in ETHERTYPE_NAMES {
        if name == s {
            return Ok(EthernetProtocol::from(val));
        }
    }
    for &(name, val) in ETHERTYPE_INPUT_ALIASES {
        if name == s {
            return Ok(EthernetProtocol::from(val));
        }
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let val = u16::from_str_radix(hex, 16)
            .map_err(|_| CliError::from(format!("Invalid ethertype: {s}")))?;
        Ok(EthernetProtocol::from(val))
    } else {
        let val = s
            .parse::<u16>()
            .map_err(|_| CliError::from(format!("Invalid ethertype: {s}")))?;
        Ok(EthernetProtocol::from(val))
    }
}

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataBareudp {
    dstport: u16,
    ethertype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    srcportmin: Option<u16>,
    multiproto: bool,
}

impl From<&[InfoBareUdp]> for CliLinkInfoDataBareudp {
    fn from(info: &[InfoBareUdp]) -> Self {
        let mut dstport = 0;
        let mut ethertype = EthernetProtocol::from(0u16);
        let mut srcportmin = None;
        let mut multiproto = false;
        for nla in info {
            match nla {
                InfoBareUdp::Port(v) => dstport = *v,
                InfoBareUdp::Ethertype(v) => ethertype = *v,
                InfoBareUdp::SrcPortMin(v) => srcportmin = Some(*v),
                InfoBareUdp::MultiprotoMode => multiproto = true,
                _ => {}
            }
        }
        Self {
            dstport,
            ethertype: ethertype_to_name(&ethertype),
            srcportmin,
            multiproto,
        }
    }
}

impl std::fmt::Display for CliLinkInfoDataBareudp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dstport {} ethertype {}", self.dstport, self.ethertype)?;
        if let Some(v) = self.srcportmin {
            write!(f, " srcportmin {v}")?;
        }
        if self.multiproto {
            write!(f, " multiproto")?;
        } else {
            write!(f, " nomultiproto")?;
        }
        Ok(())
    }
}

fn apply_bareudp_args(
    mut builder: LinkMessageBuilder<LinkBareudp>,
    iter: &mut impl Iterator<Item = impl AsRef<str>>,
) -> Result<LinkMessageBuilder<LinkBareudp>, CliError> {
    let mut dstport_set = false;
    let mut ethertype_set = false;
    while let Some(key) = iter.next() {
        match key.as_ref() {
            "dstport" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("\"dstport\" requires a value"));
                };
                let port = parse_u16(v.as_ref(), "dstport")?;
                builder = builder.dstport(port);
                dstport_set = true;
            }
            "ethertype" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "\"ethertype\" requires a value",
                    ));
                };
                let ethertype = name_to_ethertype(v.as_ref())?;
                builder = builder.ethertype(ethertype);
                ethertype_set = true;
            }
            "srcportmin" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "\"srcportmin\" requires a value",
                    ));
                };
                let port = parse_u16(v.as_ref(), "srcportmin")?;
                builder = builder.srcportmin(port);
            }
            "multiproto" => {
                builder = builder.multiproto();
            }
            "nomultiproto" => {}
            _ => {
                return Err(CliError::from(format!(
                    "bareudp: unknown option \"{}\"",
                    key.as_ref(),
                )));
            }
        }
    }
    if !dstport_set {
        return Err(CliError::from(
            "bareudp: missing required \"dstport\" argument",
        ));
    }
    if !ethertype_set {
        return Err(CliError::from(
            "bareudp: missing required \"ethertype\" argument",
        ));
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) fn apply_bareudp(
        &self,
    ) -> Result<LinkMessageBuilder<LinkBareudp>, CliError> {
        let builder = LinkMessageBuilder::<LinkBareudp>::new(&self.name);
        let mut iter = self.iface_specific.iter();
        apply_bareudp_args(builder, &mut iter)
    }
}

pub(crate) struct IfaceBareudp;

impl IfaceBareudp {
    pub(crate) fn build_entries(
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder = LinkMessageBuilder::<LinkBareudp>::new_with_info_kind(
            InfoKind::BareUdp,
        );
        let mut iter = args.iter();
        let builder = apply_bareudp_args(builder, &mut iter)?;
        Ok(extract_link_info(builder.build()))
    }

    pub(crate) fn print_help() -> &'static str {
        "Usage: ... bareudp dstport PORT\n\t\tethertype PROTO\n\t\t[ \
         srcportmin PORT ]\n\t\t[ [no]multiproto ]\n\nWhere:\tPORT  := \
         UDP_PORT\n\tPROTO := ETHERTYPE\n\nNote: ETHERTYPE can be given as \
         number or as protocol name (\"ipv4\", \"ipv6\",\n      \"mpls_uc\", \
         etc.).\n"
    }
}

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::{
        EthernetProtocol,
        link::{InfoBareUdp, InfoData},
    };

    use super::*;

    #[test]
    fn test_ethertype_lookup() {
        assert_eq!(
            name_to_ethertype("ip").unwrap(),
            EthernetProtocol::from(ETH_P_IP)
        );
        assert_eq!(
            name_to_ethertype("ipv4").unwrap(),
            EthernetProtocol::from(ETH_P_IP)
        );
        assert_eq!(
            name_to_ethertype("ipv6").unwrap(),
            EthernetProtocol::from(ETH_P_IPV6)
        );
        assert_eq!(
            name_to_ethertype("mpls_uc").unwrap(),
            EthernetProtocol::from(ETH_P_MPLS_UC)
        );
        assert_eq!(
            name_to_ethertype("mpls_mc").unwrap(),
            EthernetProtocol::from(ETH_P_MPLS_MC)
        );
        assert_eq!(
            name_to_ethertype("0x0800").unwrap(),
            EthernetProtocol::from(ETH_P_IP)
        );
        assert!(name_to_ethertype("unknown").is_err());
    }

    #[test]
    fn test_ethertype_reverse() {
        assert_eq!(ethertype_to_name(&EthernetProtocol::from(ETH_P_IP)), "ip");
        assert_eq!(
            ethertype_to_name(&EthernetProtocol::from(ETH_P_IPV6)),
            "ipv6"
        );
        assert_eq!(
            ethertype_to_name(&EthernetProtocol::from(ETH_P_MPLS_UC)),
            "mpls_uc"
        );
        assert_eq!(
            ethertype_to_name(&EthernetProtocol::from(ETH_P_MPLS_MC)),
            "mpls_mc"
        );
    }

    #[test]
    fn test_build_entries_basic() {
        let infos = IfaceBareudp::build_entries(&[
            "dstport".into(),
            "6635".into(),
            "ethertype".into(),
            "mpls_uc".into(),
        ])
        .unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::BareUdp)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::BareUdp(vec![
            InfoBareUdp::Port(6635),
            InfoBareUdp::Ethertype(EthernetProtocol::from(ETH_P_MPLS_UC)),
        ]))));
    }

    #[test]
    fn test_build_entries_full() {
        let infos = IfaceBareudp::build_entries(&[
            "dstport".into(),
            "6635".into(),
            "ethertype".into(),
            "ipv4".into(),
            "srcportmin".into(),
            "1024".into(),
            "multiproto".into(),
        ])
        .unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::BareUdp)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::BareUdp(vec![
            InfoBareUdp::Port(6635),
            InfoBareUdp::Ethertype(EthernetProtocol::from(ETH_P_IP)),
            InfoBareUdp::SrcPortMin(1024),
            InfoBareUdp::MultiprotoMode,
        ]))));
    }

    #[test]
    fn test_build_entries_missing_dstport() {
        let err =
            IfaceBareudp::build_entries(&["ethertype".into(), "ipv4".into()])
                .unwrap_err();
        assert!(err.msg.contains("dstport"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_missing_ethertype() {
        let err =
            IfaceBareudp::build_entries(&["dstport".into(), "6635".into()])
                .unwrap_err();
        assert!(err.msg.contains("ethertype"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_invalid_ethertype() {
        let err = IfaceBareudp::build_entries(&[
            "dstport".into(),
            "6635".into(),
            "ethertype".into(),
            "bogus".into(),
        ])
        .unwrap_err();
        assert!(err.msg.contains("Invalid ethertype"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_missing_value() {
        let err = IfaceBareudp::build_entries(&["dstport".into()]).unwrap_err();
        assert!(err.msg.contains("requires a value"), "{}", err.msg);
    }

    #[test]
    fn test_bareudp_info_display() {
        let infos = vec![
            InfoBareUdp::Port(6635),
            InfoBareUdp::Ethertype(EthernetProtocol::from(ETH_P_MPLS_UC)),
        ];
        let data = CliLinkInfoDataBareudp::from(infos.as_slice());
        let display = format!("{data}");
        assert_eq!(display, "dstport 6635 ethertype mpls_uc nomultiproto");
    }

    #[test]
    fn test_bareudp_info_display_full() {
        let infos = vec![
            InfoBareUdp::Port(6635),
            InfoBareUdp::Ethertype(EthernetProtocol::from(ETH_P_IP)),
            InfoBareUdp::SrcPortMin(1024),
            InfoBareUdp::MultiprotoMode,
        ];
        let data = CliLinkInfoDataBareudp::from(infos.as_slice());
        let display = format!("{data}");
        assert_eq!(
            display,
            "dstport 6635 ethertype ip srcportmin 1024 multiproto"
        );
    }
}
