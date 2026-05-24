// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use iproute_rs::{CliError, parse_mac_str};
use rtnetlink::{
    LinkDummy, LinkMessageBuilder,
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

        let nl_msg = match base_conf.iface_type {
            InfoKind::Dummy => {
                base_conf.apply(LinkDummy::new(&base_conf.name))?
            }
            t => {
                return Err(CliError::from(format!(
                    "Unsupported device type: {t}"
                )));
            }
        };

        let (connection, handle, _) = rtnetlink::new_connection()?;

        tokio::spawn(connection);
        handle.link().add(nl_msg).execute().await?;

        Ok(vec![])
    }
}

#[derive(Debug)]
struct LinkBaseConf {
    // link: Option<String>,
    name: String,
    address: Option<String>,
    iface_type: InfoKind,
    _iface_specific: Vec<String>,
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

            let _iface_specific = if args.len() > type_index + 1 {
                args[type_index + 2..].to_vec()
            } else {
                Vec::new()
            };
            Ok(Self {
                name,
                address,
                iface_type,
                _iface_specific,
            })
        } else {
            Err(CliError::from(
                "Not enough information: \"type\" argument is required",
            ))
        }
    }
}
