use std::{collections::HashMap, fmt::Write};

use futures_util::stream::TryStreamExt;
use iproute_rs::{CanDisplay, CanOutput, CliError};
use rtnetlink::packet_route::stats::{self, StatsAttribute};
use serde::Serialize;

#[derive(Default)]
struct AfstatsConfig {
    filter_dev: Option<String>,
}

fn parse_afstats_args(args: &[String]) -> Result<AfstatsConfig, CliError> {
    let mut config = AfstatsConfig::default();
    let mut iter = args.iter().peekable();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "dev" => {
                config.filter_dev = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::from("\"dev\" requires a value")
                        })?
                        .clone(),
                );
            }
            "help" => {
                print_afstats_help();
                std::process::exit(0);
            }
            unknown => {
                return Err(CliError::from(format!(
                    "Command \"{unknown}\" is unknown, try \"ip link help\"."
                )));
            }
        }
    }

    Ok(config)
}

fn print_afstats_help() {
    println!("Usage: ip link afstats [ dev DEVICE ]");
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

// ---------------------------------------------------------------------------
// JSON output structs matching iproute2 format
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct MplsRx {
    bytes: u64,
    packets: u64,
    errors: u64,
    dropped: u64,
    noroute: u64,
}

#[derive(Serialize)]
struct MplsTx {
    bytes: u64,
    packets: u64,
    errors: u64,
    dropped: u64,
}

#[derive(Serialize)]
struct MplsJson {
    rx: MplsRx,
    tx: MplsTx,
}

fn build_mpls_json(s: &stats::MplsLinkStats) -> MplsJson {
    MplsJson {
        rx: MplsRx {
            bytes: s.rx_bytes,
            packets: s.rx_packets,
            errors: s.rx_errors,
            dropped: s.rx_dropped,
            noroute: s.rx_noroute,
        },
        tx: MplsTx {
            bytes: s.tx_bytes,
            packets: s.tx_packets,
            errors: s.tx_errors,
            dropped: s.tx_dropped,
        },
    }
}

// ---------------------------------------------------------------------------
// Serializable output structs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(crate) struct CliAfstatsInfo {
    ifindex: u32,
    ifname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mpls: Option<MplsJson>,
}

impl CliAfstatsInfo {
    fn to_json_fragment(&self) -> String {
        let mut s = String::new();
        write!(
            s,
            "\"ifindex\":{},\"ifname\":\"{}\"",
            self.ifindex, self.ifname
        )
        .ok();
        if let Some(ref mpls) = self.mpls {
            write!(
                s,
                ",\"rx\":{{\"bytes\":{},\"packets\":{},\"errors\":{},\"\
                 dropped\":{},\"noroute\":{}}},\"tx\":{{\"bytes\":{},\"\
                 packets\":{},\"errors\":{},\"dropped\":{}}}",
                mpls.rx.bytes,
                mpls.rx.packets,
                mpls.rx.errors,
                mpls.rx.dropped,
                mpls.rx.noroute,
                mpls.tx.bytes,
                mpls.tx.packets,
                mpls.tx.errors,
                mpls.tx.dropped,
            )
            .ok();
        }
        s
    }
}

impl CanDisplay for CliAfstatsInfo {
    fn gen_string(&self) -> String {
        let mut s = String::new();
        write!(s, "{}:{}", self.ifindex, self.ifname).ok();
        s.push('\n');

        if let Some(ref mpls) = self.mpls {
            s.push_str("    mpls:\n");
            write_mpls_stats(&mut s, mpls);
            s.push('\n');
        }

        s
    }
}

impl CanOutput for CliAfstatsInfo {}

fn num_digits(v: u64) -> usize {
    if v == 0 {
        return 1;
    }
    let mut n = 0;
    let mut val = v;
    while val > 0 {
        n += 1;
        val /= 10;
    }
    n
}

fn size_columns(cols: &mut [usize], vals: &[u64]) {
    for (i, &val) in vals.iter().enumerate() {
        if i >= cols.len() {
            break;
        }
        let digits = num_digits(val);
        if digits > cols[i] {
            cols[i] = digits;
        }
    }
}

fn write_mpls_stats(s: &mut String, stats: &MplsJson) {
    let mut cols = vec![
        "*X: bytes".len(),
        "packets".len(),
        "errors".len(),
        "dropped".len(),
        "noroute".len(),
    ];

    size_columns(
        &mut cols,
        &[
            stats.rx.bytes,
            stats.rx.packets,
            stats.rx.errors,
            stats.rx.dropped,
            stats.rx.noroute,
        ],
    );
    size_columns(
        &mut cols,
        &[
            stats.tx.bytes,
            stats.tx.packets,
            stats.tx.errors,
            stats.tx.dropped,
            0,
        ],
    );

    let indent = "        ";

    writeln!(
        s,
        "{indent}RX: {:>w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$}",
        "bytes",
        "packets",
        "errors",
        "dropped",
        "noroute",
        w0 = cols[0] - 4,
        w1 = cols[1],
        w2 = cols[2],
        w3 = cols[3],
        w4 = cols[4],
    )
    .ok();

    write!(
        s,
        "{indent}{:>w0$} {:>w1$} {:>w2$} {:>w3$} {:>w4$} ",
        stats.rx.bytes,
        stats.rx.packets,
        stats.rx.errors,
        stats.rx.dropped,
        stats.rx.noroute,
        w0 = cols[0],
        w1 = cols[1],
        w2 = cols[2],
        w3 = cols[3],
        w4 = cols[4],
    )
    .ok();
    s.push('\n');

    writeln!(
        s,
        "{indent}TX: {:>w0$} {:>w1$} {:>w2$} {:>w3$}",
        "bytes",
        "packets",
        "errors",
        "dropped",
        w0 = cols[0] - 4,
        w1 = cols[1],
        w2 = cols[2],
        w3 = cols[3],
    )
    .ok();

    write!(
        s,
        "{indent}{:>w0$} {:>w1$} {:>w2$} {:>w3$} ",
        stats.tx.bytes,
        stats.tx.packets,
        stats.tx.errors,
        stats.tx.dropped,
        w0 = cols[0],
        w1 = cols[1],
        w2 = cols[2],
        w3 = cols[3],
    )
    .ok();
}

// ---------------------------------------------------------------------------
// Output wrapper
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct AfstatsOutput(pub(crate) Vec<CliAfstatsInfo>);

impl CanDisplay for AfstatsOutput {
    fn gen_string(&self) -> String {
        let s: String = self.0.iter().map(|info| info.gen_string()).collect();
        s.trim_end_matches('\n').to_string()
    }

    fn to_json_string(&self) -> String {
        let parts: Vec<String> =
            self.0.iter().map(|info| info.to_json_fragment()).collect();
        format!("[{}]", parts.join(","))
    }
}

impl CanOutput for AfstatsOutput {}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------

pub(crate) async fn handle_afstats(
    args: &[String],
) -> Result<AfstatsOutput, CliError> {
    let config = parse_afstats_args(args)?;

    let (connection, mut handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let ifindex_map = build_ifindex_map(&mut handle).await?;

    let filter_dev_ifindex = config.filter_dev.as_ref().and_then(|dev| {
        ifindex_map
            .iter()
            .find(|(_, name)| name.as_str() == dev)
            .map(|(idx, _)| *idx)
    });

    if let Some(dev_filter) = config.filter_dev.as_ref()
        && filter_dev_ifindex.is_none()
    {
        return Err(CliError::from(format!(
            "Device \"{dev_filter}\" does not exist."
        )));
    }

    let mut afstats_req = handle.link().afstats();
    if let Some(idx) = filter_dev_ifindex {
        afstats_req = afstats_req.match_index(idx);
    }
    let mut response = afstats_req.execute();

    let mut results = Vec::new();

    while let Some(stats) = response.try_next().await? {
        if let Some(filter_idx) = filter_dev_ifindex
            && stats.header.ifindex != filter_idx
        {
            continue;
        }

        let has_afspec = stats.attributes.iter().any(|attr| {
            matches!(attr, StatsAttribute::AfSpec(afspec) if !afspec.0.is_empty())
        });
        if !has_afspec {
            continue;
        }

        let ifname = ifindex_map
            .get(&stats.header.ifindex)
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());

        let mpls = stats.attributes.iter().find_map(|attr| {
            if let StatsAttribute::AfSpec(afspec) = attr {
                afspec.0.iter().find_map(|stat| match stat {
                    stats::AfSpecStat::Mpls(m) => Some(build_mpls_json(m)),
                    _ => None,
                })
            } else {
                None
            }
        });

        results.push(CliAfstatsInfo {
            ifindex: stats.header.ifindex,
            ifname,
            mpls,
        });
    }

    Ok(AfstatsOutput(results))
}
