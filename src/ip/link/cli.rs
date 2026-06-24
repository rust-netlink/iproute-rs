// SPDX-License-Identifier: MIT

use iproute_rs::{CanDisplay, CanOutput, CliError};
use serde::Serialize;

use super::{
    add::LinkAddCommand,
    afstats::{AfstatsOutput, handle_afstats},
    delete::LinkDeleteCommand,
    ifaces::{
        bareudp::IfaceBareudp,
        batadv::IfaceBatAdv,
        bond::IfaceBond,
        bridge::IfaceBridge,
        geneve::IfaceGeneve,
        gre::{IfaceGre, IfaceGre6, IfaceGreTap, IfaceGreTap6},
        gtp::IfaceGtp,
        hsr::IfaceHsr,
        ifb::IfaceIfb,
        iptun::{IfaceIp6Tnl, IfaceIpIp, IfaceSit},
        ipvlan::{IfaceIpVlan, IfaceIpVtap},
        mac_vlan::{IfaceMacVlan, IfaceMacVtap},
        macsec::IfaceMacSec,
        netkit::IfaceNetkit,
        simple::{
            IfaceDummy, IfaceNetdevsim, IfaceNlmon, IfaceVcan, IfaceVirtWifi,
        },
        team::IfaceTeam,
        veth::IfaceVeth,
        vlan::IfaceVlan,
        vrf::IfaceVrf,
        vxcan::IfaceVxcan,
        vxlan::IfaceVxlan,
        wwan::IfaceWwan,
        xfrm::IfaceXfrm,
    },
    property::LinkPropertyCommand,
    set::LinkSetCommand,
    show::{CliLinkInfo, handle_show},
    xstats::{XstatsOutput, handle_xstats},
};

pub(crate) enum LinkOutput {
    Show(Vec<CliLinkInfo>),
    Xstats(XstatsOutput),
    Afstats(AfstatsOutput),
}

impl Serialize for LinkOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            LinkOutput::Show(v) => v.serialize(serializer),
            LinkOutput::Xstats(v) => v.serialize(serializer),
            LinkOutput::Afstats(v) => v.serialize(serializer),
        }
    }
}

impl CanDisplay for LinkOutput {
    fn gen_string(&self) -> String {
        match self {
            LinkOutput::Show(v) => v.gen_string(),
            LinkOutput::Xstats(v) => v.gen_string(),
            LinkOutput::Afstats(v) => v.gen_string(),
        }
    }

    fn to_json_string(&self) -> String {
        match self {
            LinkOutput::Show(v) => v.to_json_string(),
            LinkOutput::Xstats(v) => v.to_json_string(),
            LinkOutput::Afstats(v) => v.to_json_string(),
        }
    }
}

impl CanOutput for LinkOutput {}

pub(crate) struct LinkCommand;

impl LinkCommand {
    pub(crate) const CMD: &'static str = "link";

    pub(crate) fn gen_command() -> clap::Command {
        clap::Command::new(Self::CMD)
            .about("network device configuration")
            .disable_help_subcommand(true)
            .alias("lin")
            .alias("li")
            .alias("l")
            .subcommand_required(false)
            .subcommand(
                clap::Command::new("show")
                    .about("show links")
                    .alias("list")
                    .alias("lst")
                    .alias("ls")
                    .alias("li")
                    .alias("l")
                    .alias("sh")
                    .alias("sho")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(LinkAddCommand::gen_command())
            .subcommand(LinkDeleteCommand::gen_command())
            .subcommand(LinkSetCommand::gen_command())
            .subcommand(LinkPropertyCommand::gen_command())
            .subcommand(
                clap::Command::new("xstats")
                    .about("show extended statistics")
                    .alias("x")
                    .alias("xs")
                    .alias("xst")
                    .alias("xsta")
                    .alias("xstat")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("afstats")
                    .about("show address-family specific statistics")
                    .alias("af")
                    .alias("afs")
                    .alias("afst")
                    .alias("afsta")
                    .alias("afstat")
                    .arg(
                        clap::Arg::new("options")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
            .subcommand(
                clap::Command::new("help")
                    .about("show help for link type")
                    .alias("h")
                    .alias("he")
                    .alias("hel")
                    .arg(
                        clap::Arg::new("type")
                            .action(clap::ArgAction::Append)
                            .trailing_var_arg(true),
                    ),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<LinkOutput, CliError> {
        if let Some(matches) = matches.subcommand_matches(LinkAddCommand::CMD) {
            LinkAddCommand::handle(matches).await?;
            Ok(LinkOutput::Show(vec![]))
        } else if let Some(matches) =
            matches.subcommand_matches(LinkDeleteCommand::CMD)
        {
            LinkDeleteCommand::handle(matches).await?;
            Ok(LinkOutput::Show(vec![]))
        } else if let Some(matches) =
            matches.subcommand_matches(LinkSetCommand::CMD)
        {
            LinkSetCommand::handle(matches).await?;
            Ok(LinkOutput::Show(vec![]))
        } else if let Some(matches) =
            matches.subcommand_matches(LinkPropertyCommand::CMD)
        {
            LinkPropertyCommand::handle(matches).await?;
            Ok(LinkOutput::Show(vec![]))
        } else if let Some(matches) = matches.subcommand_matches("xstats") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .cloned()
                .collect();
            handle_xstats(&opts).await.map(LinkOutput::Xstats)
        } else if let Some(matches) = matches.subcommand_matches("afstats") {
            let opts: Vec<String> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .cloned()
                .collect();
            handle_afstats(&opts).await.map(LinkOutput::Afstats)
        } else if let Some(matches) = matches.subcommand_matches("help") {
            let opts: Vec<&str> = matches
                .get_many::<String>("type")
                .unwrap_or_default()
                .map(String::as_str)
                .collect();
            print_link_type_help(&opts)?;
            Ok(LinkOutput::Show(vec![]))
        } else if let Some(matches) = matches.subcommand_matches("show") {
            let opts: Vec<&str> = matches
                .get_many::<String>("options")
                .unwrap_or_default()
                .map(String::as_str)
                .collect();
            handle_show(&opts, matches.get_flag("DETAILS"))
                .await
                .map(LinkOutput::Show)
        } else {
            handle_show(&[], matches.get_flag("DETAILS"))
                .await
                .map(LinkOutput::Show)
        }
    }
}

fn print_link_type_help(args: &[&str]) -> Result<(), CliError> {
    print!(
        "{}",
        if let Some(type_name) = args.first() {
            match *type_name {
                "vlan" => IfaceVlan::print_help(),
                "veth" => IfaceVeth::print_help(),
                "vxcan" => IfaceVxcan::print_help(),
                "dummy" => IfaceDummy::print_help(),
                "nlmon" => IfaceNlmon::print_help(),
                "vcan" => IfaceVcan::print_help(),
                "netdevsim" => IfaceNetdevsim::print_help(),
                "team" => IfaceTeam::print_help(),
                "virt_wifi" => IfaceVirtWifi::print_help(),
                "bond" => IfaceBond::print_help(),
                "bridge" => IfaceBridge::print_help(),
                "hsr" => IfaceHsr::print_help(),
                "ifb" => IfaceIfb::print_help(),
                "vrf" => IfaceVrf::print_help(),
                "macvlan" => IfaceMacVlan::print_help(),
                "macvtap" => IfaceMacVtap::print_help(),
                "ipvlan" => IfaceIpVlan::print_help(),
                "ipvtap" => IfaceIpVtap::print_help(),
                "geneve" => IfaceGeneve::print_help(),
                "gre" => IfaceGre::print_help(),
                "gretap" => IfaceGreTap::print_help(),
                "gtp" => IfaceGtp::print_help(),
                "ip6gre" => IfaceGre6::print_help(),
                "ip6gretap" => IfaceGreTap6::print_help(),
                "ipip" => IfaceIpIp::print_help(),
                "ip6tnl" => IfaceIp6Tnl::print_help(),
                "macsec" => IfaceMacSec::print_help(),
                "netkit" => IfaceNetkit::print_help(),
                "bareudp" => IfaceBareudp::print_help(),
                "batadv" => IfaceBatAdv::print_help(),
                "vxlan" => IfaceVxlan::print_help(),
                "wwan" => IfaceWwan::print_help(),
                "xfrm" => IfaceXfrm::print_help(),
                "sit" => IfaceSit::print_help(),
                unknown => {
                    return Err(CliError::from(format!(
                        "Unknown device type: {unknown}"
                    )));
                }
            }
        } else {
            print_generic_help()
        }
    );
    Ok(())
}

#[rustfmt::skip]
fn print_generic_help() -> &'static str {
    r"Usage: ip link add [link DEV | parentdev NAME] [ name ] NAME
                    [ txqueuelen PACKETS ]
                    [ address LLADDR ]
                    [ broadcast LLADDR ]
                    [ mtu MTU ] [index IDX ]
                    [ numtxqueues QUEUE_COUNT ]
                    [ numrxqueues QUEUE_COUNT ]
                    [ netns { PID | NETNSNAME | NETNSFILE } ]
                    type TYPE [ ARGS ]

        ip link delete { DEVICE | dev DEVICE | group DEVGROUP } type TYPE [ ARGS ]

        ip link { set | change } { DEVICE | dev DEVICE | group DEVGROUP }
                        [ { up | down } ]
                        [ type TYPE ARGS ]
                [ arp { on | off } ]
                [ dynamic { on | off } ]
                [ multicast { on | off } ]
                [ allmulticast { on | off } ]
                [ promisc { on | off } ]
                [ trailers { on | off } ]
                [ carrier { on | off } ]
                [ txqueuelen PACKETS ]
                [ name NEWNAME ]
                [ address LLADDR ]
                [ broadcast LLADDR ]
                [ mtu MTU ]
                [ netns { PID | NETNSNAME | NETNSFILE } ]
                [ link-netns NAME | link-netnsid ID ]
                [ alias NAME ]
                [ vf NUM [ mac LLADDR ]
                         [ vlan VLANID [ qos VLAN-QOS ] [ proto VLAN-PROTO ] ]
                         [ rate TXRATE ]
                         [ max_tx_rate TXRATE ]
                         [ min_tx_rate TXRATE ]
                         [ spoofchk { on | off} ]
                         [ query_rss { on | off} ]
                         [ state { auto | enable | disable} ]
                         [ trust { on | off} ]
                         [ node_guid EUI64 ]
                         [ port_guid EUI64 ] ]
                [ { xdp | xdpgeneric | xdpdrv | xdpoffload } { off |
                          object FILE [ { section | program } NAME ] [ verbose ] |
                          pinned FILE } ]
                [ master DEVICE ][ vrf NAME ]
                [ nomaster ]
                [ addrgenmode { eui64 | none | stable_secret | random } ]
                [ protodown { on | off } ]
                [ protodown_reason PREASON { on | off } ]
                [ gso_max_size BYTES ] [ gso_ipv4_max_size BYTES ] [ gso_max_segs PACKETS ]
                [ gro_max_size BYTES ] [ gro_ipv4_max_size BYTES ]

        ip link show [ DEVICE | group GROUP ] [ { up | down } ] [master DEV] [vrf NAME]
                [type TYPE] [nomaster] [ novf ]

        ip link xstats type TYPE [ ARGS ]

        ip link afstats [ dev DEVICE ]
        ip link property add dev DEVICE [ altname NAME .. ]
        ip link property del dev DEVICE [ altname NAME .. ]

        ip link help [ TYPE ]

TYPE := { amt | bareudp | bond | bond_slave | bridge | bridge_slave |
          dsa | dummy | erspan | geneve | gre | gretap | gtp | hsr |
          ifb | ip6erspan | ip6gre | ip6gretap | ip6tnl |
          ipip | ipoib | ipvlan | ipvtap |
          macsec | macvlan | macvtap | netdevsim |
          netkit | nlmon | pfcp | rmnet | sit | team | team_slave |
          vcan | veth | vlan | vrf | vti | vxcan | vxlan | wwan |
          xfrm | virt_wifi }
"
}
