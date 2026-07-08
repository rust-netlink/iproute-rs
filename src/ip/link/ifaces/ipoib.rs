// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use rtnetlink::{
    LinkIpoib, LinkMessageBuilder,
    packet_route::link::{InfoIpoib, InfoKind, IpoibMode, LinkInfo},
};
use serde::Serialize;

use super::parse::extract_link_info;
use crate::link::LinkBaseConf;

#[derive(Serialize)]
pub(crate) struct CliLinkInfoDataIpoib {
    #[serde(skip_serializing_if = "Option::is_none", rename = "key")]
    pkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    umcast: Option<String>,
}

impl From<&[InfoIpoib]> for CliLinkInfoDataIpoib {
    fn from(info: &[InfoIpoib]) -> Self {
        let mut pkey = None;
        let mut mode = None;
        let mut umcast = None;
        for nla in info {
            match nla {
                InfoIpoib::Pkey(v) => {
                    pkey = Some(format!("0x{:04x}", v));
                }
                InfoIpoib::Mode(m) => {
                    mode = Some(ipoib_mode_to_str(*m));
                }
                InfoIpoib::UmCast(v) => {
                    umcast = Some(format!("{:04x}", v));
                }
                _ => {}
            }
        }
        Self { pkey, mode, umcast }
    }
}

impl std::fmt::Display for CliLinkInfoDataIpoib {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref pkey) = self.pkey {
            write!(f, "pkey {}", pkey)?;
        }
        if let Some(ref mode) = self.mode {
            write!(f, " mode {}", mode)?;
        }
        if let Some(ref umcast) = self.umcast {
            write!(f, " umcast {}", umcast)?;
        }
        Ok(())
    }
}

fn ipoib_mode_to_str(m: IpoibMode) -> String {
    match m {
        IpoibMode::Datagram => "datagram".to_string(),
        IpoibMode::Connected => "connected".to_string(),
        IpoibMode::Other(d) => d.to_string(),
        _ => "unknown".to_string(),
    }
}

fn parse_u16_hex(s: &str, name: &str) -> Result<u16, CliError> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16)
            .map_err(|_| CliError::from(format!("Invalid {name} value: {s}")))
    } else {
        s.parse::<u16>()
            .map_err(|_| CliError::from(format!("Invalid {name} value: {s}")))
    }
}

fn apply_ipoib_args<'a>(
    mut builder: LinkMessageBuilder<LinkIpoib>,
    iter: &mut impl Iterator<Item = &'a str>,
) -> Result<LinkMessageBuilder<LinkIpoib>, CliError> {
    while let Some(key) = iter.next() {
        match key {
            "pkey" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("ipoib: pkey requires a value"));
                };
                builder = builder.pkey(parse_u16_hex(v, "pkey")?);
            }
            "mode" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from("ipoib: mode requires a value"));
                };
                let mode = match v {
                    "datagram" => IpoibMode::Datagram,
                    "connected" => IpoibMode::Connected,
                    _ => {
                        return Err(CliError::from(format!(
                            "ipoib: invalid mode \"{v}\", must be \
                             \"datagram\" or \"connected\""
                        )));
                    }
                };
                builder = builder.mode(mode);
            }
            "umcast" => {
                let Some(v) = iter.next() else {
                    return Err(CliError::from(
                        "ipoib: umcast requires a value",
                    ));
                };
                builder = builder.umcast(parse_u16_hex(v, "umcast")?);
            }
            _ => {
                return Err(CliError::from(format!(
                    "ipoib: unknown option \"{key}\"",
                )));
            }
        }
    }
    Ok(builder)
}

impl LinkBaseConf {
    pub(crate) fn apply_ipoib(
        &self,
    ) -> Result<LinkMessageBuilder<LinkIpoib>, CliError> {
        let builder = LinkMessageBuilder::<LinkIpoib>::new(&self.name);
        let mut iter = self.iface_specific.iter().map(|s| s.as_str());
        apply_ipoib_args(builder, &mut iter)
    }
}

pub(crate) struct IfaceIpoib;

impl IfaceIpoib {
    pub(crate) fn build_entries(
        args: &[String],
    ) -> Result<Vec<LinkInfo>, CliError> {
        let builder = LinkMessageBuilder::<LinkIpoib>::new_with_info_kind(
            InfoKind::Ipoib,
        );
        let mut iter = args.iter().map(|s| s.as_str());
        let builder = apply_ipoib_args(builder, &mut iter)?;
        Ok(extract_link_info(builder.build()))
    }

    #[rustfmt::skip]
    pub(crate) fn print_help() -> &'static str {
        "Usage: ... ipoib [ pkey PKEY ]\n                 [ mode {datagram | connected} ]\n                 [ umcast {0|1} ]\n\nPKEY  := 0x8001-0xffff\n"
    }
}

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::link::{
        InfoData, InfoIpoib, IpoibMode, LinkInfo,
    };

    use super::*;

    #[test]
    fn test_build_entries_with_pkey() {
        let infos =
            IfaceIpoib::build_entries(&["pkey".into(), "0x8001".into()])
                .unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::Ipoib)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::Ipoib(vec![
            InfoIpoib::Pkey(0x8001),
        ]))));
    }

    #[test]
    fn test_build_entries_with_mode() {
        let infos =
            IfaceIpoib::build_entries(&["mode".into(), "connected".into()])
                .unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::Ipoib)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::Ipoib(vec![
            InfoIpoib::Mode(IpoibMode::Connected),
        ]))));
    }

    #[test]
    fn test_build_entries_with_all_params() {
        let infos = IfaceIpoib::build_entries(&[
            "pkey".into(),
            "0x8001".into(),
            "mode".into(),
            "datagram".into(),
            "umcast".into(),
            "1".into(),
        ])
        .unwrap();
        assert!(infos.contains(&LinkInfo::Kind(InfoKind::Ipoib)));
        assert!(infos.contains(&LinkInfo::Data(InfoData::Ipoib(vec![
            InfoIpoib::Pkey(0x8001),
            InfoIpoib::Mode(IpoibMode::Datagram),
            InfoIpoib::UmCast(1),
        ]))));
    }

    #[test]
    fn test_build_entries_unknown_option() {
        let err = IfaceIpoib::build_entries(&["foo".into(), "bar".into()])
            .unwrap_err();
        assert!(err.msg.contains("unknown option"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_missing_value() {
        let err = IfaceIpoib::build_entries(&["pkey".into()]).unwrap_err();
        assert!(err.msg.contains("requires a value"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_invalid_mode() {
        let err = IfaceIpoib::build_entries(&["mode".into(), "invalid".into()])
            .unwrap_err();
        assert!(err.msg.contains("invalid mode"), "{}", err.msg);
    }

    #[test]
    fn test_build_entries_pkey_decimal() {
        let infos = IfaceIpoib::build_entries(&["pkey".into(), "32769".into()])
            .unwrap();
        assert!(infos.contains(&LinkInfo::Data(InfoData::Ipoib(vec![
            InfoIpoib::Pkey(32769),
        ]))));
    }

    #[test]
    fn test_ipoib_info_from_all() {
        let infos = vec![
            InfoIpoib::Pkey(0x8001),
            InfoIpoib::Mode(IpoibMode::Connected),
            InfoIpoib::UmCast(1),
        ];
        let data = CliLinkInfoDataIpoib::from(infos.as_slice());
        assert_eq!(data.pkey.as_deref(), Some("0x8001"));
        assert_eq!(data.mode.as_deref(), Some("connected"));
        assert_eq!(data.umcast.as_deref(), Some("0001"));
    }

    #[test]
    fn test_ipoib_display_all() {
        let infos = vec![
            InfoIpoib::Pkey(0x8001),
            InfoIpoib::Mode(IpoibMode::Connected),
            InfoIpoib::UmCast(1),
        ];
        let data = CliLinkInfoDataIpoib::from(infos.as_slice());
        let display = format!("{data}");
        assert_eq!(display, "pkey 0x8001 mode connected umcast 0001");
    }

    #[test]
    fn test_ipoib_display_pkey_only() {
        let infos = vec![InfoIpoib::Pkey(0x8001)];
        let data = CliLinkInfoDataIpoib::from(infos.as_slice());
        let display = format!("{data}");
        assert_eq!(display, "pkey 0x8001");
    }
}
