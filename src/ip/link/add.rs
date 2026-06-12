// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use futures_util::TryStreamExt;
use iproute_rs::{CliError, parse_mac_str};
use rtnetlink::{
    LinkDummy, LinkMessageBuilder, LinkNlmon,
    packet_route::link::{InfoKind, LinkMessage},
};

use crate::link::CliLinkInfo;

pub(crate) struct LinkAddCommand;

impl LinkAddCommand {
    pub(crate) const CMD: &'static str = "add";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("add network device")
            .alias("a")
            .arg(
                clap::Arg::new("options")
                    .action(clap::ArgAction::Append)
                    .trailing_var_arg(true),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<Vec<CliLinkInfo>, CliError> {
        let opts: Vec<String> = matches
            .get_many::<String>("options")
            .unwrap_or_default()
            .map(|o| o.to_string())
            .collect();

        let base_conf = LinkBaseConf::parse(opts)?;

        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        let nl_msg = match base_conf.iface_type {
            InfoKind::Dummy => {
                base_conf.apply(LinkDummy::new(&base_conf.name))?
            }
            InfoKind::Nlmon => {
                base_conf.apply(LinkNlmon::new(&base_conf.name))?
            }
            InfoKind::Veth => base_conf.apply(base_conf.apply_veth()?)?,
            InfoKind::Vlan => {
                base_conf.apply(base_conf.apply_vlan(&handle).await?)?
            }
            InfoKind::Bond => {
                base_conf.apply(base_conf.apply_bond(&handle).await?)?
            }
            InfoKind::Bridge => base_conf.apply(base_conf.apply_bridge()?)?,
            InfoKind::Hsr => {
                base_conf.apply(base_conf.apply_hsr(&handle).await?)?
            }
            InfoKind::Netkit => base_conf.apply(base_conf.apply_netkit()?)?,
            InfoKind::IpIp => {
                base_conf.apply(base_conf.apply_iptun(&handle).await?)?
            }
            InfoKind::Ip6Tnl => {
                base_conf.apply(base_conf.apply_ip6tnl(&handle).await?)?
            }
            t => {
                return Err(CliError::from(format!(
                    "Unsupported device type: {t}"
                )));
            }
        };

        handle.link().add(nl_msg).execute().await?;

        Ok(vec![])
    }
}

#[derive(Debug)]
pub(crate) struct LinkBaseConf {
    pub(crate) link: Option<String>,
    pub(crate) name: String,
    pub(crate) address: Option<String>,
    pub(crate) iface_type: InfoKind,
    pub(crate) iface_specific: Vec<String>,
}

impl LinkBaseConf {
    fn apply<T>(
        &self,
        mut builder: LinkMessageBuilder<T>,
    ) -> Result<LinkMessage, CliError> {
        if let Some(v) = self.address.as_deref() {
            builder = builder.address(parse_mac_str(v)?)
        }
        Ok(builder.build())
    }

    pub(crate) async fn get_ifindex_by_name(
        &self,
        handle: &rtnetlink::Handle,
        name: &str,
    ) -> Result<u32, CliError> {
        let mut links =
            handle.link().get().match_name(name.to_string()).execute();
        let link = links.try_next().await?.ok_or_else(|| {
            CliError::from(format!("Device \"{name}\" does not exist"))
        })?;
        Ok(link.header.index)
    }

    fn parse(args: Vec<String>) -> Result<Self, CliError> {
        if let Some(type_index) =
            args.as_slice().iter().position(|a| a.as_str() == "type")
            && args.len() > type_index + 1
        {
            let iface_type = InfoKind::from(args[type_index + 1].as_str());
            let mut base_args: Vec<&str> =
                args[..type_index].iter().map(|s| s.as_str()).collect();

            if base_args.is_empty() {
                return Err(CliError::from("interface name undefined"));
            }

            if !base_args.len().is_multiple_of(2) {
                // iproute2 indicate only `link DEVICE` can be defined before
                // name
                if base_args[0] == "link" && base_args.len() >= 3 {
                    base_args.insert(2, "name");
                } else {
                    // assume interface name is the first argument
                    base_args.insert(0, "name");
                }
            }

            let mut base_args_dict: HashMap<&str, &str> =
                base_args.chunks(2).map(|c| (c[0], c[1])).collect();

            let Some(name) =
                base_args_dict.remove("name").map(|s| s.to_string())
            else {
                return Err(CliError::from("interface name undefined"));
            };

            let address =
                base_args_dict.remove("address").map(|s| s.to_string());
            let link = base_args_dict.remove("link").map(|s| s.to_string());

            let iface_specific = if args.len() > type_index + 1 {
                args[type_index + 2..].to_vec()
            } else {
                Vec::new()
            };
            Ok(Self {
                name,
                address,
                link,
                iface_type,
                iface_specific,
            })
        } else {
            Err(CliError::from(
                "Not enough information: \"type\" argument is required",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(input: &[&str]) -> Vec<String> {
        input.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_basic_dummy() {
        let conf =
            LinkBaseConf::parse(args(&["eth0", "type", "dummy"])).unwrap();
        assert_eq!(conf.name, "eth0");
        assert_eq!(conf.iface_type, InfoKind::Dummy);
        assert!(conf.address.is_none());
        assert!(conf.link.is_none());
        assert!(conf.iface_specific.is_empty());
    }

    #[test]
    fn parse_with_address() {
        let conf = LinkBaseConf::parse(args(&[
            "name",
            "eth0",
            "address",
            "00:11:22:33:44:55",
            "type",
            "dummy",
        ]))
        .unwrap();
        assert_eq!(conf.name, "eth0");
        assert_eq!(conf.address.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(conf.iface_type, InfoKind::Dummy);
    }

    #[test]
    fn parse_with_link() {
        let conf = LinkBaseConf::parse(args(&[
            "link", "eth0", "name", "eth0.1", "type", "vlan", "id", "100",
        ]))
        .unwrap();
        assert_eq!(conf.name, "eth0.1");
        assert_eq!(conf.link.as_deref(), Some("eth0"));
        assert_eq!(conf.iface_type, InfoKind::Vlan);
        assert_eq!(conf.iface_specific, vec!["id", "100"]);
    }

    #[test]
    fn parse_link_no_name_fails() {
        let err = LinkBaseConf::parse(args(&["link", "eth0", "type", "dummy"]))
            .unwrap_err();
        assert!(err.msg.contains("name"));
    }

    #[test]
    fn parse_missing_type() {
        let err = LinkBaseConf::parse(args(&["eth0"])).unwrap_err();
        assert!(err.msg.contains("type"));
    }

    #[test]
    fn parse_type_at_end() {
        let err = LinkBaseConf::parse(args(&["eth0", "type"])).unwrap_err();
        assert!(err.msg.contains("type"));
    }

    #[test]
    fn parse_empty_args() {
        let err = LinkBaseConf::parse(args(&[])).unwrap_err();
        assert!(err.msg.contains("type"));
    }

    #[test]
    fn parse_no_name() {
        let err = LinkBaseConf::parse(args(&["type", "dummy"])).unwrap_err();
        assert!(err.msg.contains("name"));
    }

    #[test]
    fn parse_odd_args_without_link() {
        let conf =
            LinkBaseConf::parse(args(&["foo", "bar", "baz", "type", "dummy"]))
                .unwrap();
        assert_eq!(conf.name, "foo");
    }
}
