// SPDX-License-Identifier: MIT

use rtnetlink::packet_route::AddressFamily;

use super::{
    add::{handle_add, handle_delete, handle_flush},
    show::{CliAddrLabel, handle_show},
};
use crate::CliError;

pub(crate) struct AddrLabelCommand;

impl AddrLabelCommand {
    pub(crate) const CMD: &'static str = "addrlabel";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("label IPv6 addresses")
            .alias("addrlabe")
            .alias("addrlab")
            .alias("addrla")
            .alias("addrl")
            .subcommand_required(false)
            .disable_help_subcommand(true)
            .subcommand(
                clap::Command::new("show")
                    .about("list address labels")
                    .alias("sho")
                    .alias("sh")
                    .alias("s")
                    .alias("list")
                    .alias("li")
                    .alias("lst")
                    .alias("ls")
                    .alias("l")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("add")
                    .about("add address label")
                    .alias("a")
                    .alias("ad")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("delete")
                    .about("delete address label")
                    .alias("delet")
                    .alias("dele")
                    .alias("del")
                    .alias("d")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("flush")
                    .about("flush address labels")
                    .alias("flu")
                    .alias("flus")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("help")
                    .about("print help message")
                    .alias("h")
                    .alias("he")
                    .alias("hel")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
        preferred_family: Option<AddressFamily>,
    ) -> Result<Vec<CliAddrLabel>, CliError> {
        if let Some(matches) = matches.subcommand_matches("add") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            handle_add(&opts, preferred_family).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("delete") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            handle_delete(&opts, preferred_family).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("flush") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            if !opts.is_empty() {
                return Err(CliError::from(
                    "\"ip addrlabel flush\" does not allow extra arguments",
                ));
            }
            handle_flush(preferred_family).await?;
            Ok(vec![])
        } else if matches.subcommand_matches("help").is_some() {
            // iproute2 `usage()` prints the usage message to stderr and
            // exits with the code 255.
            Err(CliError {
                code: 255,
                msg: concat!(
                    "Usage: ip addrlabel { add | del } prefix PREFIX [ dev \
                     DEV ] [ label LABEL ]\n",
                    "       ip addrlabel [ list | flush | help ]",
                )
                .to_string(),
            })
        } else if let Some(matches) = matches.subcommand_matches("show") {
            let opts: Vec<&str> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(String::as_str)
                .collect();
            if !opts.is_empty() {
                return Err(CliError::from(
                    "\"ip addrlabel show\" does not take any arguments.",
                ));
            }
            handle_show(preferred_family).await
        } else {
            handle_show(preferred_family).await
        }
    }
}
