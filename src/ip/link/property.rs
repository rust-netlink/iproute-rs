// SPDX-License-Identifier: MIT

use futures_util::TryStreamExt;
use iproute_rs::CliError;

use crate::link::CliLinkInfo;

pub(crate) struct LinkPropertyCommand;

impl LinkPropertyCommand {
    pub(crate) const CMD: &'static str = "property";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("network device properties")
            .subcommand(
                clap::Command::new("add").about("add property").arg(
                    clap::Arg::new("options")
                        .action(clap::ArgAction::Append)
                        .trailing_var_arg(true),
                ),
            )
            .subcommand(
                clap::Command::new("del")
                    .about("delete property")
                    .alias("delete")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<Vec<CliLinkInfo>, CliError> {
        if let Some(matches) = matches.subcommand_matches("add") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();

            handle_property_add(opts).await?;
        } else if let Some(matches) = matches.subcommand_matches("del") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();

            handle_property_del(opts).await?;
        }

        Ok(vec![])
    }
}

#[derive(Debug)]
struct PropertyConf {
    dev: String,
    altnames: Vec<String>,
}

impl PropertyConf {
    fn parse(args: &[String]) -> Result<Self, CliError> {
        let mut iter = args.iter().peekable();
        let mut dev: Option<String> = None;
        let mut altnames: Vec<String> = Vec::new();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "dev" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"dev\" requires a value"));
                    };
                    dev = Some(v.clone());
                }
                "altname" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"altname\" requires a value",
                        ));
                    };
                    altnames.push(v.clone());
                }
                _ => {
                    if dev.is_none() {
                        dev = Some(arg.clone());
                    } else {
                        return Err(CliError::from(format!(
                            "Unknown argument: {arg}"
                        )));
                    }
                }
            }
        }

        let Some(dev) = dev else {
            return Err(CliError::from("\"dev\" is required"));
        };

        if altnames.is_empty() {
            return Err(CliError::from("\"altname\" is required"));
        }

        Ok(Self { dev, altnames })
    }
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

fn altnames_str(altnames: &[String]) -> Vec<&str> {
    altnames.iter().map(String::as_str).collect()
}

async fn handle_property_add(opts: Vec<String>) -> Result<(), CliError> {
    let conf = PropertyConf::parse(&opts)?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let ifindex = get_ifindex_by_name(&handle, &conf.dev).await?;

    handle
        .link()
        .property_add(ifindex)
        .alt_ifname(&altnames_str(&conf.altnames))
        .execute()
        .await?;

    Ok(())
}

async fn handle_property_del(opts: Vec<String>) -> Result<(), CliError> {
    let conf = PropertyConf::parse(&opts)?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let ifindex = get_ifindex_by_name(&handle, &conf.dev).await?;

    handle
        .link()
        .property_del(ifindex)
        .alt_ifname(&altnames_str(&conf.altnames))
        .execute()
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_property_add() {
        let conf = PropertyConf::parse(&[
            "dev".into(),
            "eth0".into(),
            "altname".into(),
            "foo".into(),
        ])
        .unwrap();
        assert_eq!(conf.dev, "eth0");
        assert_eq!(conf.altnames, vec!["foo"]);
    }

    #[test]
    fn parse_property_add_multiple_altnames() {
        let conf = PropertyConf::parse(&[
            "dev".into(),
            "eth0".into(),
            "altname".into(),
            "foo".into(),
            "altname".into(),
            "bar".into(),
        ])
        .unwrap();
        assert_eq!(conf.dev, "eth0");
        assert_eq!(conf.altnames, vec!["foo", "bar"]);
    }

    #[test]
    fn parse_property_add_dev_first() {
        let conf = PropertyConf::parse(&[
            "eth0".into(),
            "altname".into(),
            "foo".into(),
        ])
        .unwrap();
        assert_eq!(conf.dev, "eth0");
        assert_eq!(conf.altnames, vec!["foo"]);
    }

    #[test]
    fn parse_missing_dev() {
        let err =
            PropertyConf::parse(&["altname".into(), "foo".into()]).unwrap_err();
        assert!(err.msg.contains("dev"));
    }

    #[test]
    fn parse_missing_altname() {
        let err =
            PropertyConf::parse(&["dev".into(), "eth0".into()]).unwrap_err();
        assert!(err.msg.contains("altname"));
    }

    #[test]
    fn parse_missing_dev_value() {
        let err = PropertyConf::parse(&["dev".into()]).unwrap_err();
        assert!(err.msg.contains("dev"));
    }

    #[test]
    fn parse_missing_altname_value() {
        let err = PropertyConf::parse(&[
            "dev".into(),
            "eth0".into(),
            "altname".into(),
        ])
        .unwrap_err();
        assert!(err.msg.contains("altname"));
    }

    #[test]
    fn parse_empty_args() {
        let err = PropertyConf::parse(&[]).unwrap_err();
        assert!(err.msg.contains("dev"));
    }

    #[test]
    fn parse_unknown_arg() {
        let err = PropertyConf::parse(&[
            "dev".into(),
            "eth0".into(),
            "altname".into(),
            "foo".into(),
            "bar".into(),
        ])
        .unwrap_err();
        assert!(err.msg.contains("bar"));
    }
}
