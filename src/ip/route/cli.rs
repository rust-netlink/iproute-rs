// SPDX-License-Identifier: MIT

use rtnetlink::packet_route::AddressFamily;

use super::{
    delete::handle_delete,
    flush::handle_flush,
    get::handle_get,
    modify::{
        handle_modify_add, handle_modify_append, handle_modify_change,
        handle_modify_replace,
    },
    save::{handle_restore, handle_save, handle_showdump},
    show::{CliRouteInfo, handle_show},
};
use crate::CliError;

pub(crate) struct RouteCommand;

impl RouteCommand {
    pub(crate) const CMD: &'static str = "route";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("routing table management")
            .alias("ro")
            .alias("r")
            .subcommand_required(false)
            .disable_help_subcommand(true)
            .subcommand(
                clap::Command::new("show")
                    .about("show routing table")
                    .alias("list")
                    .alias("lst")
                    .alias("ls")
                    .alias("sh")
                    .alias("sho")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("flush")
                    .about("flush routing table")
                    .alias("f")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("add")
                    .about("add a route")
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
                    .about("delete a route")
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
                clap::Command::new("change")
                    .about("change a route")
                    .alias("chg")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("replace")
                    .about("replace a route")
                    .alias("repl")
                    .alias("repla")
                    .alias("replac")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("get")
                    .about("get a single route")
                    .alias("g")
                    .alias("ge")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("append")
                    .about("append a route")
                    .alias("ap")
                    .alias("app")
                    .alias("appe")
                    .alias("appen")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("save")
                    .about("save routing table to stdout")
                    .alias("sav")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("restore")
                    .about("restore routing table from stdin")
                    .alias("rest")
                    .alias("resto")
                    .alias("restor"),
            )
            .subcommand(
                clap::Command::new("showdump")
                    .alias("showdum")
                    .about("display routes from a dump file"),
            )
            .subcommand(
                clap::Command::new("help")
                    .about("print help message")
                    .alias("h")
                    .alias("he")
                    .alias("hel"),
            )
    }

    fn print_help() {
        let msg = concat!(
            "Usage: ip route { list | flush } SELECTOR\n",
            "       ip route save SELECTOR\n",
            "       ip route restore\n",
            "       ip route showdump\n",
            "       ip route get ROUTE_GET_ROUTE_ID\n",
            "       ip route { add | del | change | replace | prepend } \
             ROUTE\n",
            "SELECTOR := [ root PREFIX ] [ match PREFIX ] [ exact PREFIX ] [ \
             table TABLE_ID ]\n",
            "           [ vrf NAME ] [ proto RTPROTO ] [ type TYPE ] [ scope \
             SCOPE ]\n",
            "ROUTE := NODE_SPEC [ INFO_SPEC ]\n",
            "NODE_SPEC := [ TYPE ] PREFIX [ tos TOS ]\n",
            "            [ table TABLE_ID ] [ proto RTPROTO ]\n",
            "            [ scope SCOPE ] [ metric METRIC ]\n",
            "INFO_SPEC := { NH | nhid ID } OPTIONS\n",
            "NH := [ encap ENCAP ] [ via [ FAMILY ] ADDRESS ]\n",
            "           [ dev DEV ] [ weight NUMBER ] [ onlink ]\n",
            "           [ nhflags FLAGS ]\n",
            "PATH := [ via [ FAMILY ] ADDRESS ] [ dev DEV ] [ weight NUMBER \
             ]\n",
            "        [ nhflags FLAGS ]\n",
            "       nexthop via [ FAMILY ] ADDRESS dev DEV [ weight NUMBER ]\n",
            "OPTIONS := [ FLAG-LIST ] [ mtu NUMBER ] [ window NUMBER ]\n",
            "           [ rtt TIME ] [ rttvar TIME ] [ reordering NUMBER ]\n",
            "           [ rto_min TIME ] [ hoplimit NUMBER ] [ initcwnd \
             NUMBER ]\n",
            "           [ initrwnd NUMBER ] [ features FEATURES ] [ quickack \
             1|0 ]\n",
            "           [ congctl NAME ] [ pref low | medium | high ]\n",
            "           [ expires TIME ] [ fastopen_no_cookie 1|0 ]\n",
            "           [ FH ] [ encap ENCAP ]\n",
            "TYPE := { unicast | local | broadcast | multicast | throw |\n",
            "         unreachable | prohibit | blackhole | nat |\n",
            "         anycast }\n",
            "TABLE_ID := [ local | main | default | all | NUMBER ]\n",
            "SCOPE := [ host | link | global | NUMBER ]\n",
            "FLAG-LIST := [ FLAG-LIST ] FLAG\n",
            "FLAG := [ onlink ]\n",
            "FH := [ mpls LABEL ] [ ttl NUMBER ]\n",
            "ENCAP := [ ENCAP_TYPE ] ENCAP_INFO\n",
            "ENCAP_TYPE := [ mpls | ip | ip6 | seg6 | seg6local | rpl | ioam6 \
             | xfrm ]\n",
            "ENCAP_INFO := [ MPLS_OPTS | SEG6_OPTS | ... ]\n",
            "MPLS_OPTS := mpls LABEL [ ttl NUMBER ]\n",
            "SEG6_OPTS := mode SRTYPE segs SEG_LIST\n",
            "SEG6LOCAL_OPTS := mode SRTYPE [... ]\n",
        );
        eprint!("{}", msg);
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
        preferred_family: Option<AddressFamily>,
    ) -> Result<Vec<CliRouteInfo>, CliError> {
        if let Some(matches) = matches.subcommand_matches("add") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            if opts.is_empty() {
                Self::print_help();
                return Ok(vec![]);
            }
            handle_modify_add(&opts, preferred_family).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("delete") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            if opts.is_empty() {
                Self::print_help();
                return Ok(vec![]);
            }
            handle_delete(&opts, preferred_family).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("change") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            if opts.is_empty() {
                Self::print_help();
                return Ok(vec![]);
            }
            handle_modify_change(&opts, preferred_family).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("append") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            if opts.is_empty() {
                Self::print_help();
                return Ok(vec![]);
            }
            handle_modify_append(&opts, preferred_family).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("replace") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            if opts.is_empty() {
                Self::print_help();
                return Ok(vec![]);
            }
            handle_modify_replace(&opts, preferred_family).await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("get") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            handle_get(&opts, preferred_family).await
        } else if let Some(matches) = matches.subcommand_matches("save") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            handle_save(&opts).await?;
            Ok(vec![])
        } else if matches.subcommand_matches("restore").is_some() {
            handle_restore().await?;
            Ok(vec![])
        } else if matches.subcommand_matches("showdump").is_some() {
            handle_showdump().await?;
            Ok(vec![])
        } else if matches.subcommand_matches("help").is_some() {
            Self::print_help();
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("flush") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(|o| o.to_string())
                .collect();
            handle_flush(
                &opts,
                preferred_family,
                matches.get_count("DETAILS") > 0,
            )
            .await?;
            Ok(vec![])
        } else if let Some(matches) = matches.subcommand_matches("show") {
            let opts: Vec<&str> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(String::as_str)
                .collect();
            handle_show(
                &opts,
                preferred_family,
                matches.get_count("DETAILS") > 0,
            )
            .await
        } else {
            handle_show(&[], preferred_family, matches.get_count("DETAILS") > 0)
                .await
        }
    }
}
