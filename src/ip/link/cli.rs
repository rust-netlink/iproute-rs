// SPDX-License-Identifier: MIT

use iproute_rs::{CliError, OutputFormat};

use super::show::handle_show;

pub(crate) struct LinkCommand;

impl LinkCommand {
    pub(crate) const CMD: &'static str = "link";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("network device configuration")
            .subcommand_required(false)
            .subcommand(
                clap::Command::new("show").about("show links").arg(
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
        fmt: OutputFormat,
    ) -> Result<String, CliError> {
        if let Some(matches) = matches.subcommand_matches("add") {
            let opts: Vec<&String> =
                matches.get_many::<String>("options").unwrap().collect();

            println!("HAHA {:?}", opts);
            todo!()
        } else if let Some(matches) = matches.subcommand_matches("show") {
            handle_show(matches, fmt).await
        } else {
            handle_show(matches, fmt).await
        }
    }
}
