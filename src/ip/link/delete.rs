// SPDX-License-Identifier: MIT

use futures_util::TryStreamExt;
use iproute_rs::CliError;

use crate::link::CliLinkInfo;

pub(crate) struct LinkDeleteCommand;

impl LinkDeleteCommand {
    pub(crate) const CMD: &'static str = "delete";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("delete virtual link")
            .alias("del")
            .alias("d")
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

        let conf = LinkDeleteConf::parse(&opts)?;

        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        match conf.target {
            DeleteTarget::Device(name) => {
                let ifindex = get_ifindex_by_name(&handle, &name).await?;
                handle.link().del(ifindex).execute().await?;
            }
            DeleteTarget::Group(group) => {
                let mut links = handle.link().get().execute();
                while let Some(link) = links.try_next().await? {
                    let group_val = link
                        .attributes
                        .iter()
                        .find_map(|a| {
                            if let rtnetlink::packet_route::link::LinkAttribute::Group(
                                v,
                            ) = a
                            {
                                Some(*v)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);

                    if group_val == group {
                        handle.link().del(link.header.index).execute().await?;
                    }
                }
            }
        }

        Ok(vec![])
    }
}

#[derive(Debug)]
enum DeleteTarget {
    Device(String),
    Group(u32),
}

#[derive(Debug)]
struct LinkDeleteConf {
    target: DeleteTarget,
}

impl LinkDeleteConf {
    fn parse(args: &[String]) -> Result<Self, CliError> {
        let mut dev = None;
        let mut group = None;

        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "dev" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"dev\" requires a value"));
                    };
                    dev = Some(v.clone());
                }
                "group" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"group\" requires a value",
                        ));
                    };
                    group = Some(parse_u32(v, "group")?);
                }
                "type" => {
                    // iproute2 accepts and validates type argument for
                    // compatibility but does not use it when deleting.
                    // Consume the type value and any remaining args.
                    break;
                }
                _ => {
                    if dev.is_none() && group.is_none() {
                        dev = Some(arg.clone());
                    } else {
                        return Err(CliError::from(format!(
                            "Unknown argument: {arg}"
                        )));
                    }
                }
            }
        }

        if let Some(name) = dev {
            Ok(Self {
                target: DeleteTarget::Device(name),
            })
        } else if let Some(group) = group {
            Ok(Self {
                target: DeleteTarget::Group(group),
            })
        } else {
            Err(CliError::from("Device name or group is required"))
        }
    }
}

fn parse_u32(val: &str, name: &str) -> Result<u32, CliError> {
    val.parse::<u32>().map_err(|_| {
        CliError::from(format!(
            "\"{name}\" requires a numeric value: got \"{val}\""
        ))
    })
}

async fn get_ifindex_by_name(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, CliError> {
    let mut links = handle.link().get().execute();
    while let Some(link) = links.try_next().await? {
        let link_name = link.attributes.iter().find_map(|a| {
            if let rtnetlink::packet_route::link::LinkAttribute::IfName(n) = a {
                Some(n.as_str())
            } else {
                None
            }
        });
        if link_name == Some(name) {
            return Ok(link.header.index);
        }
    }
    Err(CliError::from(format!("Device \"{name}\" does not exist")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_device_bare() {
        let conf = LinkDeleteConf::parse(&[String::from("eth0")]).unwrap();
        assert!(matches!(
            conf.target,
            DeleteTarget::Device(ref n) if n == "eth0"
        ));
    }

    #[test]
    fn parse_device_with_dev() {
        let conf =
            LinkDeleteConf::parse(&["dev".into(), "eth0".into()]).unwrap();
        assert!(matches!(
            conf.target,
            DeleteTarget::Device(ref n) if n == "eth0"
        ));
    }

    #[test]
    fn parse_device_with_type() {
        let conf = LinkDeleteConf::parse(&[
            "eth0".into(),
            "type".into(),
            "dummy".into(),
        ])
        .unwrap();
        assert!(matches!(
            conf.target,
            DeleteTarget::Device(ref n) if n == "eth0"
        ));
    }

    #[test]
    fn parse_dev_with_type() {
        let conf = LinkDeleteConf::parse(&[
            "dev".into(),
            "eth0".into(),
            "type".into(),
            "veth".into(),
            "peer".into(),
            "name".into(),
            "foo".into(),
        ])
        .unwrap();
        assert!(matches!(
            conf.target,
            DeleteTarget::Device(ref n) if n == "eth0"
        ));
    }

    #[test]
    fn parse_group() {
        let conf =
            LinkDeleteConf::parse(&["group".into(), "42".into()]).unwrap();
        assert!(matches!(conf.target, DeleteTarget::Group(g) if g == 42));
    }

    #[test]
    fn parse_group_with_type() {
        let conf = LinkDeleteConf::parse(&[
            "group".into(),
            "0".into(),
            "type".into(),
            "dummy".into(),
        ])
        .unwrap();
        assert!(matches!(conf.target, DeleteTarget::Group(g) if g == 0));
    }

    #[test]
    fn parse_group_with_type_and_args() {
        let conf = LinkDeleteConf::parse(&[
            "group".into(),
            "0".into(),
            "type".into(),
            "vlan".into(),
            "id".into(),
            "100".into(),
        ])
        .unwrap();
        assert!(matches!(conf.target, DeleteTarget::Group(g) if g == 0));
    }

    #[test]
    fn parse_missing_dev_value() {
        let err = LinkDeleteConf::parse(&["dev".into()]).unwrap_err();
        assert!(err.msg.contains("dev"));
    }

    #[test]
    fn parse_missing_group_value() {
        let err = LinkDeleteConf::parse(&["group".into()]).unwrap_err();
        assert!(err.msg.contains("group"));
    }

    #[test]
    fn parse_empty_args() {
        let err = LinkDeleteConf::parse(&[]).unwrap_err();
        assert!(err.msg.contains("Device name or group"));
    }

    #[test]
    fn parse_group_and_dev() {
        // iproute2 accepts both; dev takes priority over group
        let conf = LinkDeleteConf::parse(&[
            "dev".into(),
            "eth0".into(),
            "group".into(),
            "42".into(),
        ])
        .unwrap();
        assert!(matches!(
            conf.target,
            DeleteTarget::Device(ref n) if n == "eth0"
        ));
    }

    #[test]
    fn parse_invalid_group_value() {
        let err =
            LinkDeleteConf::parse(&["group".into(), "abc".into()]).unwrap_err();
        assert!(err.msg.contains("numeric"));
    }
}
