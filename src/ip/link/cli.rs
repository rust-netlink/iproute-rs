// SPDX-License-Identifier: MIT

use iproute_rs::CliError;

use super::show::{CliLinkInfo, handle_show};

pub(crate) struct LinkCommand;

impl LinkCommand {
    pub(crate) const CMD: &'static str = "link";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("network device configuration")
            .subcommand_required(false)
            .subcommand(
                clap::Command::new("show")
                    .about("show links")
                    .alias("list")
                    .alias("lst")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("add").about("add virtual link").arg(
                    clap::Arg::new("options")
                        .action(clap::ArgAction::Append)
                        .trailing_var_arg(true),
                ),
            )
            .subcommand(
                clap::Command::new("delete").about("delete virtual link"),
            )
            .subcommand(
                clap::Command::new("change")
                    .alias("set")
                    .about("change device attributes"),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<Vec<CliLinkInfo>, CliError> {
        if let Some(matches) = matches.subcommand_matches("add") {
            println!("HAHA {matches:?}");
            todo!()
        } else if let Some(matches) = matches.subcommand_matches("show") {
            let opts: Vec<&str> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(String::as_str)
                .collect();
            handle_show(&opts).await
        } else {
            handle_show(&[]).await
        }
    }
}
