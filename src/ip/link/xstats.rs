use std::{collections::HashMap, fmt::Write};

use futures_util::stream::{StreamExt, TryStreamExt};
use iproute_rs::{CanDisplay, CanOutput, CliError};
use rtnetlink::{
    packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage},
    packet_route::{
        AddressFamily, RouteNetlinkMessage,
        stats::{
            Bond3adStats, BondXstat, BridgeMcastStats, BridgeStpXstats,
            BridgeXstat, LinkXstatGroup, StatsAttribute, StatsHeader,
            StatsMessage,
        },
    },
};
use serde::Serialize;

fn is_valid_filter_for_type(link_type: &str, token: &str) -> bool {
    match link_type {
        "bridge" | "bridge_slave" => {
            matches!(token, "igmp" | "mcast" | "stp")
        }
        "bond" | "bond_slave" => {
            matches!(token, "lacp" | "802.3ad")
        }
        _ => false,
    }
}

fn filter_matches(
    last_filter: Option<&str>,
    xstat_type: &str,
    alt_type: &str,
) -> bool {
    match last_filter {
        None => true,
        Some(f) => f == xstat_type || f == alt_type,
    }
}

#[derive(Default)]
struct XstatsConfig {
    link_type: String,
    last_filter: Option<String>,
    filter_dev: Option<String>,
}

fn parse_xstats_args(args: &[String]) -> Result<XstatsConfig, CliError> {
    let mut config = XstatsConfig::default();
    let mut iter = args.iter().peekable();

    match iter.peek() {
        None => {
            return Err(CliError::from("xstats: missing argument\n"));
        }
        Some(arg) if *arg == "help" => {
            print_xstats_help("");
            std::process::exit(0);
        }
        Some(arg) if *arg != "type" => {
            return Err(CliError::from(format!(
                "xstats: unknown argument \"{arg}\"\n"
            )));
        }
        _ => {}
    }

    iter.next();
    config.link_type = iter
        .next()
        .ok_or_else(|| CliError::from("xstats: missing link type\n"))?
        .clone();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "igmp" | "mcast" | "stp" | "lacp" | "802.3ad" => {
                if !is_valid_filter_for_type(&config.link_type, arg) {
                    return Err(CliError::from(format!(
                        "xstats: unknown argument \"{arg}\"\n"
                    )));
                }
                config.last_filter = Some(arg.to_string());
            }
            "dev" => {
                config.filter_dev = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::from("xstats: \"dev\" requires a value\n")
                        })?
                        .clone(),
                );
            }
            "help" => {
                print_xstats_help(&config.link_type);
                std::process::exit(0);
            }
            unknown => {
                return Err(CliError::from(format!(
                    "xstats: unknown argument \"{unknown}\"\n"
                )));
            }
        }
    }

    Ok(config)
}

fn print_xstats_help(link_type: &str) {
    match link_type {
        "bridge" | "bridge_slave" => {
            println!("Usage: ... {} [ igmp ] [ dev DEVICE ]", link_type);
        }
        "bond" | "bond_slave" => {
            println!("Usage: ... {} [ 802.3ad ] [ dev DEVICE ]", link_type);
        }
        _ => {
            println!("Usage: ... xstats type TYPE [ ARGS ]");
        }
    }
}

async fn build_ifindex_map(
    handle: &mut rtnetlink::Handle,
) -> Result<HashMap<u32, String>, CliError> {
    let mut links = handle.link().get().execute();
    let mut map = HashMap::new();
    while let Some(link) = links.try_next().await? {
        let name = link
            .attributes
            .iter()
            .find_map(|attr| match attr {
                rtnetlink::packet_route::link::LinkAttribute::IfName(n) => {
                    Some(n.clone())
                }
                _ => None,
            })
            .unwrap_or_default();
        map.insert(link.header.index, name);
    }
    Ok(map)
}

fn filter_mask_for_type(link_type: &str) -> u32 {
    if link_type.ends_with("_slave") { 4 } else { 2 }
}

// ===== Serializable output structs matching iproute2 JSON output =====

#[derive(Serialize)]
struct IgmpQueries {
    rx_v1: u64,
    rx_v2: u64,
    rx_v3: u64,
    tx_v1: u64,
    tx_v2: u64,
    tx_v3: u64,
}

#[derive(Serialize)]
struct IgmpReports {
    rx_v1: u64,
    rx_v2: u64,
    rx_v3: u64,
    tx_v1: u64,
    tx_v2: u64,
    tx_v3: u64,
}

#[derive(Serialize)]
struct IgmpLeaves {
    rx: u64,
    tx: u64,
}

#[derive(Serialize)]
struct MldQueries {
    rx_v1: u64,
    rx_v2: u64,
    tx_v1: u64,
    tx_v2: u64,
}

#[derive(Serialize)]
struct MldReports {
    rx_v1: u64,
    rx_v2: u64,
    tx_v1: u64,
    tx_v2: u64,
}

#[derive(Serialize)]
struct MldLeaves {
    rx: u64,
    tx: u64,
}

#[derive(Serialize)]
struct BridgeMulticast {
    #[serde(rename = "igmp_queries")]
    igmp_queries: IgmpQueries,
    #[serde(rename = "igmp_reports")]
    igmp_reports: IgmpReports,
    #[serde(rename = "igmp_leaves")]
    igmp_leaves: IgmpLeaves,
    #[serde(rename = "igmp_parse_errors")]
    igmp_parse_errors: u64,
    #[serde(rename = "mld_queries")]
    mld_queries: MldQueries,
    #[serde(rename = "mld_reports")]
    mld_reports: MldReports,
    #[serde(rename = "mld_leaves")]
    mld_leaves: MldLeaves,
    #[serde(rename = "mld_parse_errors")]
    mld_parse_errors: u64,
}

#[derive(Serialize)]
struct BridgeStp {
    #[serde(rename = "rx_bpdu")]
    rx_bpdu: u64,
    #[serde(rename = "tx_bpdu")]
    tx_bpdu: u64,
    #[serde(rename = "rx_tcn")]
    rx_tcn: u64,
    #[serde(rename = "tx_tcn")]
    tx_tcn: u64,
    #[serde(rename = "transition_blk")]
    transition_blk: u64,
    #[serde(rename = "transition_fwd")]
    transition_fwd: u64,
}

#[derive(Serialize)]
struct Bond3ad {
    #[serde(rename = "lacpdu_rx")]
    lacpdu_rx: u64,
    #[serde(rename = "lacpdu_tx")]
    lacpdu_tx: u64,
    #[serde(rename = "lacpdu_unknown_rx")]
    lacpdu_unknown_rx: u64,
    #[serde(rename = "lacpdu_illegal_rx")]
    lacpdu_illegal_rx: u64,
    #[serde(rename = "marker_rx")]
    marker_rx: u64,
    #[serde(rename = "marker_tx")]
    marker_tx: u64,
    #[serde(rename = "marker_response_rx")]
    marker_resp_rx: u64,
    #[serde(rename = "marker_response_tx")]
    marker_resp_tx: u64,
    #[serde(rename = "marker_unknown_rx")]
    marker_unknown_rx: u64,
}

#[derive(Serialize)]
pub(crate) struct CliXstatsInfo {
    #[serde(rename = "ifname")]
    pub(crate) ifname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    multicast: Option<BridgeMulticast>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stp: Option<BridgeStp>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "802.3ad")]
    threead: Option<Bond3ad>,
}

// ===== Build serializable structs from netlink types =====

fn build_bridge_mcast(m: &BridgeMcastStats) -> BridgeMulticast {
    BridgeMulticast {
        igmp_queries: IgmpQueries {
            rx_v1: m.igmp_v1queries_rx,
            rx_v2: m.igmp_v2queries_rx,
            rx_v3: m.igmp_v3queries_rx,
            tx_v1: m.igmp_v1queries_tx,
            tx_v2: m.igmp_v2queries_tx,
            tx_v3: m.igmp_v3queries_tx,
        },
        igmp_reports: IgmpReports {
            rx_v1: m.igmp_v1reports_rx,
            rx_v2: m.igmp_v2reports_rx,
            rx_v3: m.igmp_v3reports_rx,
            tx_v1: m.igmp_v1reports_tx,
            tx_v2: m.igmp_v2reports_tx,
            tx_v3: m.igmp_v3reports_tx,
        },
        igmp_leaves: IgmpLeaves {
            rx: m.igmp_leaves_rx,
            tx: m.igmp_leaves_tx,
        },
        igmp_parse_errors: m.igmp_parse_errors,
        mld_queries: MldQueries {
            rx_v1: m.mld_v1queries_rx,
            rx_v2: m.mld_v2queries_rx,
            tx_v1: m.mld_v1queries_tx,
            tx_v2: m.mld_v2queries_tx,
        },
        mld_reports: MldReports {
            rx_v1: m.mld_v1reports_rx,
            rx_v2: m.mld_v2reports_rx,
            tx_v1: m.mld_v1reports_tx,
            tx_v2: m.mld_v2reports_tx,
        },
        mld_leaves: MldLeaves {
            rx: m.mld_leaves_rx,
            tx: m.mld_leaves_tx,
        },
        mld_parse_errors: m.mld_parse_errors,
    }
}

fn build_bridge_stp(s: &BridgeStpXstats) -> BridgeStp {
    BridgeStp {
        rx_bpdu: s.rx_bpdu,
        tx_bpdu: s.tx_bpdu,
        rx_tcn: s.rx_tcn,
        tx_tcn: s.tx_tcn,
        transition_blk: s.transition_blk,
        transition_fwd: s.transition_fwd,
    }
}

fn build_bond_3ad(s: &Bond3adStats) -> Bond3ad {
    Bond3ad {
        lacpdu_rx: s.lacpdu_rx.unwrap_or(0),
        lacpdu_tx: s.lacpdu_tx.unwrap_or(0),
        lacpdu_unknown_rx: s.lacpdu_unknown_rx.unwrap_or(0),
        lacpdu_illegal_rx: s.lacpdu_illegal_rx.unwrap_or(0),
        marker_rx: s.marker_rx.unwrap_or(0),
        marker_tx: s.marker_tx.unwrap_or(0),
        marker_resp_rx: s.marker_resp_rx.unwrap_or(0),
        marker_resp_tx: s.marker_resp_tx.unwrap_or(0),
        marker_unknown_rx: s.marker_unknown_rx.unwrap_or(0),
    }
}

fn build_xstats_info(
    msg: &StatsMessage,
    link_type: &str,
    last_filter: Option<&str>,
    ifindex_map: &HashMap<u32, String>,
) -> Option<CliXstatsInfo> {
    let ifindex = msg.header.ifindex;
    let ifname = ifindex_map
        .get(&ifindex)
        .cloned()
        .unwrap_or_else(|| "<unknown>".to_string());

    let mut multicast = None;
    let mut stp = None;
    let mut threead = None;

    for attr in &msg.attributes {
        let groups: &[LinkXstatGroup] = match attr {
            StatsAttribute::LinkXstats(g) => {
                if link_type.ends_with("_slave") {
                    continue;
                }
                g.as_slice()
            }
            StatsAttribute::LinkXstatsPort(g) => {
                if !link_type.ends_with("_slave") {
                    continue;
                }
                g.as_slice()
            }
            _ => continue,
        };

        for group in groups {
            match group {
                LinkXstatGroup::Bridge(xstats) => {
                    for xstat in xstats {
                        match xstat {
                            BridgeXstat::Mcast(m) => {
                                if !filter_matches(last_filter, "mcast", "igmp")
                                {
                                    continue;
                                }
                                multicast = Some(build_bridge_mcast(m));
                            }
                            BridgeXstat::Stp(s) => {
                                if !filter_matches(last_filter, "stp", "stp") {
                                    continue;
                                }
                                stp = Some(build_bridge_stp(s));
                            }
                            BridgeXstat::Vlan(_) | BridgeXstat::Other(_, _) => {
                            }
                            _ => {}
                        }
                    }
                }
                LinkXstatGroup::Bond(xstats) => {
                    for xstat in xstats {
                        if let BondXstat::Threead(s) = xstat {
                            if !filter_matches(last_filter, "lacp", "802.3ad") {
                                continue;
                            }
                            threead = Some(build_bond_3ad(s));
                        }
                    }
                }
                LinkXstatGroup::Other(_, _) => {}
                _ => {}
            }
        }
    }

    if multicast.is_none() && stp.is_none() && threead.is_none() {
        let has_xstats = msg.attributes.iter().any(|attr| {
            matches!(
                attr,
                StatsAttribute::LinkXstats(_)
                    | StatsAttribute::LinkXstatsPort(_)
            )
        });
        if !has_xstats {
            return None;
        }
    }

    Some(CliXstatsInfo {
        ifname,
        multicast,
        stp,
        threead,
    })
}

// ===== CLI output (matching iproute2 format) =====

fn write_bridge_multicast(s: &mut String, m: &BridgeMulticast) {
    writeln!(s, "                    IGMP queries:").ok();
    writeln!(
        s,
        "                      RX: v1 {} v2 {} v3 {}",
        m.igmp_queries.rx_v1, m.igmp_queries.rx_v2, m.igmp_queries.rx_v3
    )
    .ok();
    writeln!(
        s,
        "                      TX: v1 {} v2 {} v3 {}",
        m.igmp_queries.tx_v1, m.igmp_queries.tx_v2, m.igmp_queries.tx_v3
    )
    .ok();
    writeln!(s, "                    IGMP reports:").ok();
    writeln!(
        s,
        "                      RX: v1 {} v2 {} v3 {}",
        m.igmp_reports.rx_v1, m.igmp_reports.rx_v2, m.igmp_reports.rx_v3
    )
    .ok();
    writeln!(
        s,
        "                      TX: v1 {} v2 {} v3 {}",
        m.igmp_reports.tx_v1, m.igmp_reports.tx_v2, m.igmp_reports.tx_v3
    )
    .ok();
    writeln!(
        s,
        "                    IGMP leaves: RX: {} TX: {}",
        m.igmp_leaves.rx, m.igmp_leaves.tx
    )
    .ok();
    writeln!(
        s,
        "                    IGMP parse errors: {}",
        m.igmp_parse_errors
    )
    .ok();
    writeln!(s, "                    MLD queries:").ok();
    writeln!(
        s,
        "                      RX: v1 {} v2 {}",
        m.mld_queries.rx_v1, m.mld_queries.rx_v2
    )
    .ok();
    writeln!(
        s,
        "                      TX: v1 {} v2 {}",
        m.mld_queries.tx_v1, m.mld_queries.tx_v2
    )
    .ok();
    writeln!(s, "                    MLD reports:").ok();
    writeln!(
        s,
        "                      RX: v1 {} v2 {}",
        m.mld_reports.rx_v1, m.mld_reports.rx_v2
    )
    .ok();
    writeln!(
        s,
        "                      TX: v1 {} v2 {}",
        m.mld_reports.tx_v1, m.mld_reports.tx_v2
    )
    .ok();
    writeln!(
        s,
        "                    MLD leaves: RX: {} TX: {}",
        m.mld_leaves.rx, m.mld_leaves.tx
    )
    .ok();
    writeln!(
        s,
        "                    MLD parse errors: {}",
        m.mld_parse_errors
    )
    .ok();
}

fn write_bridge_stp(s: &mut String, stp: &BridgeStp) {
    writeln!(
        s,
        "                    STP BPDU:  RX: {} TX: {}",
        stp.rx_bpdu, stp.tx_bpdu
    )
    .ok();
    writeln!(
        s,
        "                    STP TCN:   RX: {} TX: {}",
        stp.rx_tcn, stp.tx_tcn
    )
    .ok();
    writeln!(
        s,
        "                    STP Transitions: Blocked: {} Forwarding: {}",
        stp.transition_blk, stp.transition_fwd
    )
    .ok();
}

fn write_bond_3ad(s: &mut String, bond: &Bond3ad) {
    writeln!(s, "                    LACPDU Rx {}", bond.lacpdu_rx).ok();
    writeln!(s, "                    LACPDU Tx {}", bond.lacpdu_tx).ok();
    writeln!(
        s,
        "                    LACPDU Unknown type Rx {}",
        bond.lacpdu_unknown_rx
    )
    .ok();
    writeln!(
        s,
        "                    LACPDU Illegal Rx {}",
        bond.lacpdu_illegal_rx
    )
    .ok();
    writeln!(s, "                    Marker Rx {}", bond.marker_rx).ok();
    writeln!(s, "                    Marker Tx {}", bond.marker_tx).ok();
    writeln!(
        s,
        "                    Marker response Rx {}",
        bond.marker_resp_rx
    )
    .ok();
    writeln!(
        s,
        "                    Marker response Tx {}",
        bond.marker_resp_tx
    )
    .ok();
    writeln!(
        s,
        "                    Marker unknown type Rx {}",
        bond.marker_unknown_rx
    )
    .ok();
}

impl CanDisplay for CliXstatsInfo {
    fn gen_string(&self) -> String {
        let mut s = String::new();
        writeln!(s, "{:16}", self.ifname).ok();
        if let Some(ref mcast) = self.multicast {
            write_bridge_multicast(&mut s, mcast);
        }
        if let Some(ref stp) = self.stp {
            write_bridge_stp(&mut s, stp);
        }
        if let Some(ref bond) = self.threead {
            write_bond_3ad(&mut s, bond);
        }
        if s.ends_with('\n') {
            s.pop();
        }
        s
    }
}

impl CanOutput for CliXstatsInfo {}

#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct XstatsOutput(pub(crate) Vec<CliXstatsInfo>);

impl CanDisplay for XstatsOutput {
    fn gen_string(&self) -> String {
        self.0
            .iter()
            .map(|info| info.gen_string())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl CanOutput for XstatsOutput {}

pub(crate) async fn handle_xstats(
    args: &[String],
) -> Result<XstatsOutput, CliError> {
    let config = parse_xstats_args(args)?;

    let (connection, mut handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    match config.link_type.as_str() {
        "bridge" | "bridge_slave" | "bond" | "bond_slave" => {}
        _ => {
            return Err(CliError::from(format!(
                "xstats: link type {} doesn't support xstats\n",
                config.link_type
            )));
        }
    }

    let ifindex_map = build_ifindex_map(&mut handle).await?;

    let filter_dev_ifindex = config.filter_dev.as_ref().and_then(|dev| {
        ifindex_map
            .iter()
            .find(|(_, name)| name.as_str() == dev)
            .map(|(idx, _)| *idx)
    });

    let mut stats_msg = StatsMessage::default();
    stats_msg.header = StatsHeader {
        family: AddressFamily::Unspec,
        ifindex: filter_dev_ifindex.unwrap_or(0),
        filter_mask: filter_mask_for_type(&config.link_type),
    };

    let mut nl_msg =
        NetlinkMessage::from(RouteNetlinkMessage::GetStats(stats_msg));
    nl_msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut response = handle.request(nl_msg).map_err(|e| {
        CliError::from(format!("Cannot send dump request: {e}"))
    })?;

    let mut results = Vec::new();

    while let Some(msg) = response.next().await {
        match msg.payload {
            rtnetlink::packet_core::NetlinkPayload::InnerMessage(
                RouteNetlinkMessage::NewStats(stats),
            ) => {
                if let Some(filter_idx) = filter_dev_ifindex
                    && stats.header.ifindex != filter_idx
                {
                    continue;
                }
                if let Some(info) = build_xstats_info(
                    &stats,
                    &config.link_type,
                    config.last_filter.as_deref(),
                    &ifindex_map,
                ) {
                    results.push(info);
                }
            }
            rtnetlink::packet_core::NetlinkPayload::Error(err) => {
                eprintln!("xstats: {err}");
            }
            rtnetlink::packet_core::NetlinkPayload::Done(_) => break,
            _ => {}
        }
    }

    Ok(XstatsOutput(results))
}
