// SPDX-License-Identifier: MIT

use super::{
    add::{handle_add, handle_modify, AddressModifyOp},
    show::handle_show,
};
use crate::{CliError, link::CliLinkInfo};

pub(crate) struct AddressCommand;

impl AddressCommand {
    pub(crate) const CMD: &'static str = "address";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("network address configuration")
            .alias("addres")
            .alias("addre")
            .alias("addr")
            .alias("add")
            .alias("ad")
            .alias("a")
            .subcommand_required(false)
            .subcommand(
                clap::Command::new("show")
                    .about("show links' addresses")
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
                    .about("add address to link")
                    .alias("a")
                    .alias("ad")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("delete").about("delete address from link"),
            )
            .subcommand(
                clap::Command::new("change")
                    .about("change device attributes")
                    .alias("chg")
                    .alias("set")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("replace")
                    .alias("repl")
                    .alias("repla")
                    .alias("replac")
                    .about("replace existing address")
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
            handle_add(&opts).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("change") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            handle_modify(&opts, AddressModifyOp::Change).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("replace") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            handle_modify(&opts, AddressModifyOp::Replace).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("show") {
            let opts: Vec<&str> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(String::as_str)
                .collect();
            handle_show(&opts, matches.get_flag("DETAILS")).await
        } else {
            handle_show(&[], matches.get_flag("DETAILS")).await
        }
    }
}
