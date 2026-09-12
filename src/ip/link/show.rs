// SPDX-License-Identifier: MIT

use std::{collections::HashMap, fmt::Write, os::fd::AsRawFd};

use futures_util::stream::{StreamExt, TryStreamExt};
use iproute_rs::{
    CanDisplay, CanOutput, CliColor, CliError, mac_to_string, write_with_color,
};
use rtnetlink::packet_route::link::{
    LinkAttribute, LinkExtentMask, LinkFlags, LinkInfo, LinkLayerType,
    LinkMessage, LinkVfInfo, Prop, Stats, Stats64, VfInfo, VfInfoBroadcast,
    VfInfoMac, VfLinkState, VfStats as NlVfStats, VfVlan, VlanProtocol,
};
use serde::Serialize;

use super::{super::address::CliAddressInfo, flags::link_flags_to_string};
use crate::link::detail::CliLinkInfoDetail;

#[derive(Serialize, Default)]
pub(crate) struct CliLinkInfo {
    #[serde(skip)]
    brief: bool,
    #[serde(skip)]
    oneline: bool,
    ifindex: u32,
    #[serde(skip)]
    raw_flags: LinkFlags,
    /// Lower link of this interface: `Some(None)` means the kernel reported
    /// link index 0, which iproute2 displays as `@NONE` and serializes as
    /// `"link": null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    link: Option<Option<String>>,
    #[serde(skip)]
    link_index: Option<u32>,
    ifname: String,
    flags: Vec<String>,
    mtu: u32,
    qdisc: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "master")]
    controller: Option<String>,
    #[serde(skip)]
    controller_ifindex: Option<u32>,
    operstate: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    linkmode: String,
    group: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    txqlen: Option<u32>,
    link_type: String,
    #[serde(skip)]
    is_point_2_point: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    broadcast: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    permaddr: String,
    #[serde(skip)]
    link_netns: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_netnsid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    details: Option<CliLinkInfoDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    stats: Option<CliLinkStats>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    altnames: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    addr_info: Option<Vec<CliAddressInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vfinfo_list: Option<Vec<CliVfInfo>>,
    #[serde(skip)]
    num_vf: Option<u32>,
    #[serde(skip)]
    kind: String,
}

#[derive(Debug, Clone, Default, Serialize)]
struct CliVfInfo {
    #[serde(rename = "vf")]
    vf_id: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    broadcast: Option<String>,
    #[serde(skip)]
    is_point_2_point: bool,
    // Legacy single VLAN
    #[serde(skip_serializing_if = "Option::is_none")]
    vlan: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qos: Option<u32>,
    // VLAN list (QinQ)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    vlan_list: Vec<CliVfVlanEntry>,
    // Rate
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_rate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tx_rate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_tx_rate: Option<u32>,
    // Features
    #[serde(skip_serializing_if = "Option::is_none")]
    spoofchk: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_rss_en: Option<bool>,
    // InfiniBand GUIDs
    #[serde(skip_serializing_if = "Option::is_none")]
    node_guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port_guid: Option<String>,
    // Stats (only shown with -s)
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<CliVfStats>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct CliVfVlanEntry {
    vlan: u32,
    qos: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct CliVfStats {
    rx: CliVfRxStats,
    tx: CliVfTxStats,
}

#[derive(Debug, Clone, Default, Serialize)]
struct CliVfRxStats {
    bytes: u64,
    packets: u64,
    multicast: u64,
    broadcast: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dropped: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct CliVfTxStats {
    #[serde(rename = "tx_bytes")]
    bytes: u64,
    #[serde(rename = "tx_packets")]
    packets: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dropped: Option<u64>,
}

/// RX/TX statistics of a link, collected from `IFLA_STATS64` or the legacy
/// `IFLA_STATS` attribute when `ip link show -s` is used.
struct CliLinkStats {
    /// Whether the values were collected from `IFLA_STATS64`. iproute2 uses
    /// `stats64` as JSON key for `IFLA_STATS64` and `stats` for
    /// `IFLA_STATS`.
    is_stats64: bool,
    /// Whether `-s -s` was requested, which asks for the detailed error
    /// counters.
    detailed: bool,
    rx: CliLinkRxStats,
    tx: CliLinkTxStats,
}

#[derive(Default)]
struct CliLinkRxStats {
    bytes: u64,
    packets: u64,
    errors: u64,
    dropped: u64,
    over_errors: u64,
    multicast: u64,
    compressed: Option<u64>,
    length_errors: Option<u64>,
    crc_errors: Option<u64>,
    frame_errors: Option<u64>,
    fifo_errors: Option<u64>,
    missed_errors: Option<u64>,
    nohandler: Option<u64>,
    otherhost: Option<u64>,
}

#[derive(Default)]
struct CliLinkTxStats {
    bytes: u64,
    packets: u64,
    errors: u64,
    dropped: u64,
    carrier_errors: u64,
    collisions: u64,
    compressed: Option<u64>,
    aborted_errors: Option<u64>,
    fifo_errors: Option<u64>,
    window_errors: Option<u64>,
    heartbeat_errors: Option<u64>,
    carrier_changes: Option<u64>,
}

/// The `ip -j` output of iproute2 nests the RX/TX counters under `stats64`
/// or `stats`, depending on the netlink attribute the kernel provided.
impl Serialize for CliLinkStats {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        #[derive(Serialize)]
        struct Body<'a> {
            rx: &'a CliLinkRxStats,
            tx: &'a CliLinkTxStats,
        }

        let body = Body {
            rx: &self.rx,
            tx: &self.tx,
        };
        let mut map = serializer.serialize_map(Some(1))?;
        if self.is_stats64 {
            map.serialize_entry("stats64", &body)?;
        } else {
            map.serialize_entry("stats", &body)?;
        }
        map.end()
    }
}

impl Serialize for CliLinkRxStats {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("bytes", &self.bytes)?;
        map.serialize_entry("packets", &self.packets)?;
        map.serialize_entry("errors", &self.errors)?;
        map.serialize_entry("dropped", &self.dropped)?;
        map.serialize_entry("over_errors", &self.over_errors)?;
        map.serialize_entry("multicast", &self.multicast)?;
        if let Some(v) = self.compressed {
            map.serialize_entry("compressed", &v)?;
        }
        if let Some(v) = self.length_errors {
            map.serialize_entry("length_errors", &v)?;
        }
        if let Some(v) = self.crc_errors {
            map.serialize_entry("crc_errors", &v)?;
        }
        if let Some(v) = self.frame_errors {
            map.serialize_entry("frame_errors", &v)?;
        }
        if let Some(v) = self.fifo_errors {
            map.serialize_entry("fifo_errors", &v)?;
        }
        if let Some(v) = self.missed_errors {
            map.serialize_entry("missed_errors", &v)?;
        }
        if let Some(v) = self.nohandler {
            map.serialize_entry("nohandler", &v)?;
        }
        if let Some(v) = self.otherhost {
            map.serialize_entry("otherhost", &v)?;
        }
        map.end()
    }
}

impl Serialize for CliLinkTxStats {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("bytes", &self.bytes)?;
        map.serialize_entry("packets", &self.packets)?;
        map.serialize_entry("errors", &self.errors)?;
        map.serialize_entry("dropped", &self.dropped)?;
        map.serialize_entry("carrier_errors", &self.carrier_errors)?;
        map.serialize_entry("collisions", &self.collisions)?;
        if let Some(v) = self.compressed {
            map.serialize_entry("compressed", &v)?;
        }
        if let Some(v) = self.aborted_errors {
            map.serialize_entry("aborted_errors", &v)?;
        }
        if let Some(v) = self.fifo_errors {
            map.serialize_entry("fifo_errors", &v)?;
        }
        if let Some(v) = self.window_errors {
            map.serialize_entry("window_errors", &v)?;
        }
        if let Some(v) = self.heartbeat_errors {
            map.serialize_entry("heartbeat_errors", &v)?;
        }
        if let Some(v) = self.carrier_changes {
            map.serialize_entry("carrier_changes", &v)?;
        }
        map.end()
    }
}

/// Counter values of `IFLA_STATS64` and the legacy `IFLA_STATS` in a common
/// u64 representation.
#[derive(Default)]
struct CliLinkStatsValues {
    rx_bytes: u64,
    rx_packets: u64,
    rx_errors: u64,
    rx_dropped: u64,
    rx_over_errors: u64,
    rx_missed_errors: u64,
    multicast: u64,
    rx_compressed: u64,
    rx_length_errors: u64,
    rx_crc_errors: u64,
    rx_frame_errors: u64,
    rx_fifo_errors: u64,
    rx_nohandler: u64,
    rx_otherhost_dropped: u64,
    tx_bytes: u64,
    tx_packets: u64,
    tx_errors: u64,
    tx_dropped: u64,
    tx_carrier_errors: u64,
    collisions: u64,
    tx_compressed: u64,
    tx_aborted_errors: u64,
    tx_fifo_errors: u64,
    tx_window_errors: u64,
    tx_heartbeat_errors: u64,
}

impl From<&Stats64> for CliLinkStatsValues {
    fn from(s: &Stats64) -> Self {
        Self {
            rx_bytes: s.rx_bytes,
            rx_packets: s.rx_packets,
            rx_errors: s.rx_errors,
            rx_dropped: s.rx_dropped,
            rx_over_errors: s.rx_over_errors,
            rx_missed_errors: s.rx_missed_errors,
            multicast: s.multicast,
            rx_compressed: s.rx_compressed,
            rx_length_errors: s.rx_length_errors,
            rx_crc_errors: s.rx_crc_errors,
            rx_frame_errors: s.rx_frame_errors,
            rx_fifo_errors: s.rx_fifo_errors,
            rx_nohandler: s.rx_nohandler,
            rx_otherhost_dropped: s.rx_otherhost_dropped,
            tx_bytes: s.tx_bytes,
            tx_packets: s.tx_packets,
            tx_errors: s.tx_errors,
            tx_dropped: s.tx_dropped,
            tx_carrier_errors: s.tx_carrier_errors,
            collisions: s.collisions,
            tx_compressed: s.tx_compressed,
            tx_aborted_errors: s.tx_aborted_errors,
            tx_fifo_errors: s.tx_fifo_errors,
            tx_window_errors: s.tx_window_errors,
            tx_heartbeat_errors: s.tx_heartbeat_errors,
        }
    }
}

impl From<&Stats> for CliLinkStatsValues {
    fn from(s: &Stats) -> Self {
        Self {
            rx_bytes: s.rx_bytes.into(),
            rx_packets: s.rx_packets.into(),
            rx_errors: s.rx_errors.into(),
            rx_dropped: s.rx_dropped.into(),
            rx_over_errors: s.rx_over_errors.into(),
            rx_missed_errors: s.rx_missed_errors.into(),
            multicast: s.multicast.into(),
            rx_compressed: s.rx_compressed.into(),
            rx_length_errors: s.rx_length_errors.into(),
            rx_crc_errors: s.rx_crc_errors.into(),
            rx_frame_errors: s.rx_frame_errors.into(),
            rx_fifo_errors: s.rx_fifo_errors.into(),
            rx_nohandler: s.rx_nohandler.into(),
            // `IFLA_STATS` has no `rx_otherhost_dropped` counter.
            rx_otherhost_dropped: 0,
            tx_bytes: s.tx_bytes.into(),
            tx_packets: s.tx_packets.into(),
            tx_errors: s.tx_errors.into(),
            tx_dropped: s.tx_dropped.into(),
            tx_carrier_errors: s.tx_carrier_errors.into(),
            collisions: s.collisions.into(),
            tx_compressed: s.tx_compressed.into(),
            tx_aborted_errors: s.tx_aborted_errors.into(),
            tx_fifo_errors: s.tx_fifo_errors.into(),
            tx_window_errors: s.tx_window_errors.into(),
            tx_heartbeat_errors: s.tx_heartbeat_errors.into(),
        }
    }
}

impl CliLinkStats {
    /// `show_stats` is the number of `-s` given by the user: iproute2 only
    /// displays the detailed error counters (and its JSON counterparts) when
    /// `-s -s` is used.
    fn new(
        values: CliLinkStatsValues,
        is_stats64: bool,
        show_stats: u8,
        carrier_changes: Option<u32>,
    ) -> Self {
        let detailed = show_stats > 1;
        Self {
            is_stats64,
            detailed,
            rx: CliLinkRxStats {
                bytes: values.rx_bytes,
                packets: values.rx_packets,
                errors: values.rx_errors,
                dropped: values.rx_dropped,
                over_errors: values.rx_over_errors,
                multicast: values.multicast,
                compressed: (values.rx_compressed != 0)
                    .then_some(values.rx_compressed),
                length_errors: detailed.then_some(values.rx_length_errors),
                crc_errors: detailed.then_some(values.rx_crc_errors),
                frame_errors: detailed.then_some(values.rx_frame_errors),
                fifo_errors: detailed.then_some(values.rx_fifo_errors),
                missed_errors: detailed.then_some(values.rx_missed_errors),
                nohandler: (detailed && values.rx_nohandler != 0)
                    .then_some(values.rx_nohandler),
                otherhost: (detailed && values.rx_otherhost_dropped != 0)
                    .then_some(values.rx_otherhost_dropped),
            },
            tx: CliLinkTxStats {
                bytes: values.tx_bytes,
                packets: values.tx_packets,
                errors: values.tx_errors,
                dropped: values.tx_dropped,
                carrier_errors: values.tx_carrier_errors,
                collisions: values.collisions,
                compressed: (values.tx_compressed != 0)
                    .then_some(values.tx_compressed),
                aborted_errors: detailed.then_some(values.tx_aborted_errors),
                fifo_errors: detailed.then_some(values.tx_fifo_errors),
                window_errors: detailed.then_some(values.tx_window_errors),
                heartbeat_errors: detailed
                    .then_some(values.tx_heartbeat_errors),
                carrier_changes: match (detailed, carrier_changes) {
                    (true, Some(v)) => Some(v.into()),
                    _ => None,
                },
            },
        }
    }
}

/// Update each column width with the number of digits of the values, the
/// same way iproute2 `size_columns()` does.
fn size_columns(cols: &mut [usize; 8], values: &[u64]) {
    for (col, value) in cols.iter_mut().zip(values) {
        let width = match value {
            0 => 1,
            v => v.ilog10() as usize + 1,
        };
        *col = (*col).max(width);
    }
}

impl std::fmt::Display for CliLinkStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rx = &self.rx;
        let tx = &self.tx;
        // Initial widths are the header string lengths, see iproute2
        // `print_stats64()`.
        let mut cols = [10usize, 7, 6, 7, 7, 7, 10, 9];

        size_columns(
            &mut cols,
            &[
                rx.bytes,
                rx.packets,
                rx.errors,
                rx.dropped,
                rx.missed_errors.unwrap_or(0),
                rx.multicast,
                rx.compressed.unwrap_or(0),
                0,
            ],
        );
        if self.detailed {
            size_columns(
                &mut cols,
                &[
                    0,
                    rx.length_errors.unwrap_or(0),
                    rx.crc_errors.unwrap_or(0),
                    rx.frame_errors.unwrap_or(0),
                    rx.fifo_errors.unwrap_or(0),
                    rx.over_errors,
                    rx.nohandler.unwrap_or(0),
                    rx.otherhost.unwrap_or(0),
                ],
            );
        }
        size_columns(
            &mut cols,
            &[
                tx.bytes,
                tx.packets,
                tx.errors,
                tx.dropped,
                tx.carrier_errors,
                tx.collisions,
                tx.compressed.unwrap_or(0),
                0,
            ],
        );
        if self.detailed {
            size_columns(
                &mut cols,
                &[
                    0,
                    0,
                    tx.aborted_errors.unwrap_or(0),
                    tx.fifo_errors.unwrap_or(0),
                    tx.window_errors.unwrap_or(0),
                    tx.heartbeat_errors.unwrap_or(0),
                    tx.carrier_changes.unwrap_or(0),
                    0,
                ],
            );
        }

        write!(f, "\n    RX: ")?;
        write!(f, "{:>width$}", "bytes", width = cols[0] - 4)?;
        write!(f, " {:>width$}", "packets", width = cols[1])?;
        write!(f, " {:>width$}", "errors", width = cols[2])?;
        write!(f, " {:>width$}", "dropped", width = cols[3])?;
        write!(f, " {:>width$}", "missed", width = cols[4])?;
        write!(f, " {:>width$}", "mcast", width = cols[5])?;
        write!(
            f,
            " {:>width$}",
            if rx.compressed.is_some() {
                "compressed"
            } else {
                ""
            },
            width = cols[6],
        )?;
        write!(f, "\n    ")?;
        write!(f, "{:>width$} ", rx.bytes, width = cols[0])?;
        write!(f, "{:>width$} ", rx.packets, width = cols[1])?;
        write!(f, "{:>width$} ", rx.errors, width = cols[2])?;
        write!(f, "{:>width$} ", rx.dropped, width = cols[3])?;
        write!(
            f,
            "{:>width$} ",
            rx.missed_errors.unwrap_or(0),
            width = cols[4],
        )?;
        write!(f, "{:>width$} ", rx.multicast, width = cols[5])?;
        if let Some(compressed) = rx.compressed {
            write!(f, "{compressed:>width$} ", width = cols[6])?;
        }

        if self.detailed {
            write!(f, "\n    RX errors:")?;
            write!(f, "{:>width$}", "", width = cols[0] - 10)?;
            write!(f, " {:>width$}", "length", width = cols[1])?;
            write!(f, " {:>width$}", "crc", width = cols[2])?;
            write!(f, " {:>width$}", "frame", width = cols[3])?;
            write!(f, " {:>width$}", "fifo", width = cols[4])?;
            write!(f, " {:>width$}", "overrun", width = cols[5])?;
            if rx.nohandler.is_some() {
                write!(f, "{:>width$}", " nohandler", width = cols[6] + 1)?;
            }
            if rx.otherhost.is_some() {
                write!(f, "{:>width$}", " otherhost", width = cols[7] + 1)?;
            }
            write!(f, "\n{:>width$}", "", width = cols[0] + 5)?;
            write!(
                f,
                "{:>width$} ",
                rx.length_errors.unwrap_or(0),
                width = cols[1],
            )?;
            write!(
                f,
                "{:>width$} ",
                rx.crc_errors.unwrap_or(0),
                width = cols[2],
            )?;
            write!(
                f,
                "{:>width$} ",
                rx.frame_errors.unwrap_or(0),
                width = cols[3],
            )?;
            write!(
                f,
                "{:>width$} ",
                rx.fifo_errors.unwrap_or(0),
                width = cols[4],
            )?;
            write!(f, "{:>width$} ", rx.over_errors, width = cols[5])?;
            if let Some(nohandler) = rx.nohandler {
                write!(f, "{nohandler:>width$} ", width = cols[6])?;
            }
            if let Some(otherhost) = rx.otherhost {
                write!(f, "{otherhost:>width$} ", width = cols[7])?;
            }
        }

        write!(f, "\n    TX: ")?;
        write!(f, "{:>width$}", "bytes", width = cols[0] - 4)?;
        write!(f, " {:>width$}", "packets", width = cols[1])?;
        write!(f, " {:>width$}", "errors", width = cols[2])?;
        write!(f, " {:>width$}", "dropped", width = cols[3])?;
        write!(f, " {:>width$}", "carrier", width = cols[4])?;
        write!(f, " {:>width$}", "collsns", width = cols[5])?;
        write!(
            f,
            " {:>width$}",
            if tx.compressed.is_some() {
                "compressed"
            } else {
                ""
            },
            width = cols[6],
        )?;
        write!(f, "\n    ")?;
        write!(f, "{:>width$} ", tx.bytes, width = cols[0])?;
        write!(f, "{:>width$} ", tx.packets, width = cols[1])?;
        write!(f, "{:>width$} ", tx.errors, width = cols[2])?;
        write!(f, "{:>width$} ", tx.dropped, width = cols[3])?;
        write!(f, "{:>width$} ", tx.carrier_errors, width = cols[4])?;
        write!(f, "{:>width$} ", tx.collisions, width = cols[5])?;
        if let Some(compressed) = tx.compressed {
            write!(f, "{compressed:>width$} ", width = cols[6])?;
        }

        if self.detailed {
            write!(f, "\n    TX errors:")?;
            write!(f, "{:>width$}", "", width = cols[0] - 10)?;
            write!(f, " {:>width$}", "aborted", width = cols[1])?;
            write!(f, " {:>width$}", "fifo", width = cols[2])?;
            write!(f, " {:>width$}", "window", width = cols[3])?;
            write!(f, " {:>width$}", "heartbt", width = cols[4])?;
            write!(
                f,
                " {:>width$}",
                if tx.carrier_changes.is_some() {
                    "transns"
                } else {
                    ""
                },
                width = cols[5],
            )?;
            write!(f, "\n{:>width$}", "", width = cols[0] + 5)?;
            write!(
                f,
                "{:>width$} ",
                tx.aborted_errors.unwrap_or(0),
                width = cols[1],
            )?;
            write!(
                f,
                "{:>width$} ",
                tx.fifo_errors.unwrap_or(0),
                width = cols[2],
            )?;
            write!(
                f,
                "{:>width$} ",
                tx.window_errors.unwrap_or(0),
                width = cols[3],
            )?;
            write!(
                f,
                "{:>width$} ",
                tx.heartbeat_errors.unwrap_or(0),
                width = cols[4],
            )?;
            if let Some(carrier_changes) = tx.carrier_changes {
                write!(f, "{carrier_changes:>width$} ", width = cols[5])?;
            }
        }

        Ok(())
    }
}

impl CliLinkInfo {
    fn remove_link_mode(&mut self) {
        self.linkmode = String::new();
    }

    fn remove_inet6_addr_gen_mode(&mut self) {
        if let Some(d) = self.details.as_mut() {
            d.remove_inet6_addr_gen_mode();
        }
    }

    fn initialize_addr_info(&mut self) {
        self.addr_info = Some(vec![]);
    }

    // For `ip address show`, we want to remove some details that are not
    // present in the original ip command.
    pub fn show_only_addr_details(&mut self) {
        self.initialize_addr_info();
        self.remove_link_mode();
        self.remove_inet6_addr_gen_mode();
    }

    pub fn set_brief(&mut self, brief: bool) {
        self.brief = brief;
    }

    pub fn set_oneline(&mut self, oneline: bool) {
        self.oneline = oneline;
    }
}

impl std::fmt::Display for CliLinkInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.brief {
            // Brief mode: interface name (16 chars), state (14 chars), then
            // addresses
            write!(f, "{:<16} ", self.ifname)?;

            // State with color and padding (14 chars + 1 space = 15 total)
            if self.operstate == "UP" {
                write_with_color!(
                    f,
                    CliColor::StateUp,
                    "{:<15}",
                    self.operstate
                )?;
            } else if self.operstate == "DOWN" {
                write_with_color!(
                    f,
                    CliColor::StateDown,
                    "{:<15}",
                    self.operstate
                )?;
            } else {
                write!(f, "{:<15}", self.operstate)?;
            }

            // Addresses on the same line (no MAC address in brief mode for ip
            // address)
            if let Some(addr_info) = &self.addr_info {
                for addr in addr_info {
                    write!(f, "{} ", addr)?;
                }
            }
            // Don't add extra newline - the formatter will add one
            return Ok(());
        }

        write!(f, "{}: ", self.ifindex)?;
        let link = if let Some(link_name) = &self.link {
            // iproute2 prints `@NONE` when the kernel reports link index 0.
            let display_name =
                link_name.clone().unwrap_or_else(|| "NONE".to_string());
            format!("@{display_name}")
        } else if let Some(link_index) = self.link_index {
            if link_index == 0 {
                "@NONE".to_string()
            } else {
                format!("@if{link_index}")
            }
        } else {
            String::new()
        };

        write_with_color!(f, CliColor::IfaceName, "{}{link}: ", self.ifname)?;
        write!(
            f,
            "<{}> mtu {} qdisc {} ",
            self.flags.as_slice().join(","),
            self.mtu,
            self.qdisc,
        )?;
        if let Some(ctrl) = self.controller.as_ref() {
            write!(f, "master {ctrl} ")?;
        }
        write!(f, "state ")?;
        if self.operstate == "UP" {
            write_with_color!(f, CliColor::StateUp, "{} ", self.operstate)?;
        } else if self.operstate == "DOWN" {
            write_with_color!(f, CliColor::StateDown, "{} ", self.operstate)?;
        } else {
            write!(f, "{} ", self.operstate)?;
        }

        if !self.linkmode.is_empty() {
            write!(f, "mode {} ", self.linkmode)?;
        }
        write!(f, "group {} ", self.group)?;

        if let Some(v) = self.txqlen {
            write!(f, "qlen {v}")?;
        }
        write!(f, "\n    ")?;
        write!(f, "link/{} ", self.link_type)?;
        if !self.address.is_empty() {
            write_with_color!(f, CliColor::Mac, "{}", self.address)?;
            write!(f, " ")?;
            if self.is_point_2_point {
                write!(f, "peer ")?;
            } else {
                write!(f, "brd ")?;
            }
            write_with_color!(f, CliColor::Mac, "{}", self.broadcast)?;
        }
        if !self.permaddr.is_empty() {
            // Previous one did not add space because it does not know whether
            // they are more options
            write!(f, " ")?;
            write!(f, "permaddr ")?;
            write_with_color!(f, CliColor::Mac, "{}", self.permaddr)?;
        }

        if !self.link_netns.is_empty() {
            // Previous one did not add space because it does not know whether
            // they are more options
            write!(f, " ")?;
            write!(f, "link-netns {} ", self.link_netns)?;
        } else if let Some(netns_id) = self.link_netnsid {
            // Previous one did not add space because it does not know whether
            // they are more options
            write!(f, " ")?;
            write!(f, "link-netnsid {netns_id} ")?;
        }

        if let Some(details) = &self.details {
            write!(f, "{details}")?;
        }

        if let Some(stats) = &self.stats {
            write!(f, "{stats}")?;
        }

        for altname in &self.altnames {
            write!(f, "\n    altname {altname}")?;
        }

        if let Some(addr_info) = &self.addr_info {
            if self.brief {
                // In brief mode, print all addresses on the same line
                for addr in addr_info {
                    write!(f, " {}", addr)?;
                }
                writeln!(f)?;
            } else {
                for addr in addr_info {
                    write!(f, "\n    {}", addr)?;
                }
            }
        }

        if let Some(vfinfo_list) = &self.vfinfo_list {
            for vf in vfinfo_list {
                write!(f, "{vf}")?;
            }
        }

        Ok(())
    }
}

impl CanDisplay for CliLinkInfo {
    fn gen_string(&self) -> String {
        let output = self.to_string();
        if self.oneline {
            // iproute2 replaces the newline of every continuation line with
            // a backslash for `-o`.
            output.replace('\n', "\\")
        } else {
            output
        }
    }
}

impl CanOutput for CliLinkInfo {}

struct LinkShowFilter {
    dev_name: Option<String>,
    group: Option<String>,
    up_or_down: Option<bool>,
    master: Option<String>,
    vrf: Option<String>,
    link_type: Option<String>,
    nomaster: bool,
    novf: bool,
}

impl LinkShowFilter {
    fn parse(opts: &[&str]) -> Result<Self, CliError> {
        let mut dev_name = None;
        let mut group = None;
        let mut up_or_down = None;
        let mut master = None;
        let mut vrf = None;
        let mut link_type = None;
        let mut nomaster = false;
        let mut novf = false;

        let mut iter = opts.iter();
        while let Some(arg) = iter.next() {
            match *arg {
                "dev" | "name" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"dev\" requires a value"));
                    };
                    dev_name = Some(v.to_string());
                }
                "group" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"group\" requires a value",
                        ));
                    };
                    group = Some(v.to_string());
                }
                "up" => up_or_down = Some(true),
                "down" => up_or_down = Some(false),
                "master" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"master\" requires a value",
                        ));
                    };
                    master = Some(v.to_string());
                }
                "vrf" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from("\"vrf\" requires a value"));
                    };
                    vrf = Some(v.to_string());
                }
                "type" => {
                    let Some(v) = iter.next() else {
                        return Err(CliError::from(
                            "\"type\" requires a value",
                        ));
                    };
                    link_type = Some(v.to_string());
                }
                "nomaster" => nomaster = true,
                "novf" => novf = true,
                _ => {
                    if dev_name.is_none() {
                        dev_name = Some(arg.to_string());
                    }
                }
            }
        }

        Ok(Self {
            dev_name,
            group,
            up_or_down,
            master,
            vrf,
            link_type,
            nomaster,
            novf,
        })
    }

    fn apply(&self, ifaces: &mut Vec<CliLinkInfo>) {
        if let Some(ref name) = self.dev_name {
            ifaces.retain(|i| i.ifname == *name);
        }

        if let Some(ref g) = self.group {
            ifaces.retain(|i| {
                if i.group == *g {
                    return true;
                }
                if let Ok(id) = g.parse::<u32>() {
                    return resolve_ip_link_group_name(id) == i.group;
                }
                false
            });
        }

        if let Some(up) = self.up_or_down {
            let iff_up = LinkFlags::Up.bits();
            if up {
                ifaces.retain(|i| (i.raw_flags.bits() & iff_up) != 0);
            } else {
                ifaces.retain(|i| (i.raw_flags.bits() & iff_up) == 0);
            }
        }

        if let Some(ref m) = self.master {
            ifaces.retain(|i| i.controller.as_deref() == Some(m));
        }

        if let Some(ref v) = self.vrf {
            ifaces.retain(|i| i.controller.as_deref() == Some(v));
        }

        if let Some(ref t) = self.link_type {
            ifaces.retain(|i| {
                // iproute2 filters by IFLA_INFO_KIND (not ARPHRD link layer
                // type)
                if !i.kind.is_empty() {
                    return i.kind == *t;
                }
                i.link_type == *t
            });
        }

        if self.nomaster {
            ifaces.retain(|i| i.controller.is_none());
        }
    }
}

pub(crate) async fn handle_show(
    opts: &[&str],
    include_details: bool,
    statistics: u8,
    oneline: bool,
) -> Result<Vec<CliLinkInfo>, CliError> {
    let filter = LinkShowFilter::parse(opts)?;

    let (connection, handle, _) = rtnetlink::new_connection()?;

    tokio::spawn(connection);

    let mut link_get = handle.link().get();
    if !filter.novf {
        link_get = link_get.set_filter_mask(
            rtnetlink::packet_route::AddressFamily::Unspec,
            vec![LinkExtentMask::Vf],
        );
    }
    let link_get_handle = link_get;

    let mut links = link_get_handle.execute();
    let mut ifaces: Vec<CliLinkInfo> = Vec::new();

    while let Some(nl_msg) = links.try_next().await? {
        ifaces.push(
            parse_nl_msg_to_iface(nl_msg, include_details, statistics).await?,
        );
    }

    resolve_controller_and_link_names(&mut ifaces);
    resolve_netns_names(&mut ifaces).await?;

    if oneline {
        for iface in ifaces.iter_mut() {
            iface.set_oneline(true);
        }
    }

    // In order to resolve interface index to interface name and netns name,
    // we cannot use kernel side interface filter, but need to dump everything,
    // then filter here
    filter.apply(&mut ifaces);

    Ok(ifaces)
}

impl CliLinkInfo {
    pub(crate) fn get_ifindex(&self) -> u32 {
        self.ifindex
    }

    pub(crate) fn add_address(&mut self, addr_info: CliAddressInfo) {
        self.addr_info.get_or_insert_default().push(addr_info);
    }
}

/// HACK: Adjust ARPHRD type names from crate to match iproute2.
/// The crate uses different names than iproute2 for some link types.
fn normalize_link_type(link_type: &str) -> String {
    match link_type {
        "ipgre" => "gre".to_string(),
        "ip6gre" => "gre6".to_string(),
        "rawip" => "[519]".to_string(),
        // iproute2 names `ARPHRD_TUNNEL` `ipip`, devices of type vti reuse
        // this ARPHRD.
        "tunnel" => "ipip".to_string(),
        _ => link_type.to_string(),
    }
}

pub(crate) async fn parse_nl_msg_to_iface(
    nl_msg: LinkMessage,
    include_details: bool,
    statistics: u8,
) -> Result<CliLinkInfo, CliError> {
    let raw_flags = nl_msg.header.flags;
    let link_layer_type_raw = nl_msg.header.link_layer_type;
    let mut ret = CliLinkInfo {
        ifindex: nl_msg.header.index,
        raw_flags,
        flags: link_flags_to_string(raw_flags),
        link_type: normalize_link_type(
            &link_layer_type_raw.to_string().to_lowercase(),
        ),
        is_point_2_point: raw_flags.contains(LinkFlags::Pointopoint),
        vfinfo_list: None,
        ..Default::default()
    };

    // Always parse link info to get the correct info_kind for tunnel interfaces
    let link_info: Option<crate::link::link_info::CliLinkInfo> =
        nl_msg.attributes.iter().find_map(|attr| {
            if let LinkAttribute::LinkInfo(info) = attr {
                info.as_slice().try_into().ok()
            } else {
                None
            }
        });

    ret.details =
        include_details.then(|| CliLinkInfoDetail::new(&nl_msg.attributes));

    let link_layer_type = nl_msg.header.link_layer_type;

    // For some tunnel interfaces, use the info_kind as the link_type
    // This ensures consistency with iproute2 behavior
    // Note: ip6gre uses ARPHRD-based name "gre6"
    //       gretap/erspan use ARPHRD-based name "ether" (ARPHRD_ETHER)
    if let Some(ref linkinfo) = link_info
        && !linkinfo.info_kind.is_empty()
    {
        let kind = &linkinfo.info_kind;
        if matches!(link_layer_type, LinkLayerType::Sit) || *kind == "gre" {
            ret.link_type.clone_from(kind);
        }
    }

    let mut temp_permaddr = String::new();
    let mut stats64: Option<Stats64> = None;
    let mut stats32: Option<Stats> = None;
    let mut carrier_changes: Option<u32> = None;

    for nl_attr in nl_msg.attributes {
        match nl_attr {
            LinkAttribute::IfName(name) => ret.ifname = name,
            LinkAttribute::Mtu(mtu) => ret.mtu = mtu,
            LinkAttribute::Address(mac) => ret.address = mac_to_string(&mac),
            LinkAttribute::Broadcast(mac) => {
                ret.broadcast = mac_to_string(&mac)
            }
            LinkAttribute::PermAddress(mac) => {
                temp_permaddr = mac_to_string(&mac)
            }
            LinkAttribute::Qdisc(qdisc) => ret.qdisc = qdisc,
            LinkAttribute::OperState(state) => {
                ret.operstate = state.to_string()
            }
            LinkAttribute::TxQueueLen(v) if v > 0 => ret.txqlen = Some(v),
            LinkAttribute::Group(v) => {
                ret.group = resolve_ip_link_group_name(v)
            }
            LinkAttribute::Mode(v) => ret.linkmode = v.to_string(),
            LinkAttribute::Controller(d) => ret.controller_ifindex = Some(d),
            LinkAttribute::Link(i) => ret.link_index = Some(i),
            LinkAttribute::LinkNetNsId(i) => ret.link_netnsid = Some(i),
            LinkAttribute::PropList(props) => {
                for prop in props {
                    if let Prop::AltIfName(altname) = prop {
                        ret.altnames.push(altname);
                    }
                }
            }
            LinkAttribute::VfInfoList(list) => {
                let mut vfs: Vec<CliVfInfo> = list
                    .into_iter()
                    .map(|vf| parse_vf_info(vf, statistics > 0))
                    .collect();
                for vf in vfs.iter_mut() {
                    vf.is_point_2_point = ret.is_point_2_point;
                }
                ret.vfinfo_list = Some(vfs);
            }
            LinkAttribute::NumVf(n) => ret.num_vf = Some(n),
            LinkAttribute::Stats64(s) if statistics > 0 => stats64 = Some(s),
            LinkAttribute::Stats(s) if statistics > 0 => stats32 = Some(s),
            LinkAttribute::CarrierChanges(v) => carrier_changes = Some(v),
            LinkAttribute::LinkInfo(infos) => {
                for info in &infos {
                    if let LinkInfo::Kind(k) = info {
                        ret.kind = k.to_string();
                    }
                }
            }
            _ => {}
        }
    }

    // Like iproute2 `get_rtnl_link_stats_rta()`, prefer `IFLA_STATS64` over
    // the legacy `IFLA_STATS` attribute.
    if statistics > 0 {
        if let Some(s) = stats64 {
            ret.stats = Some(CliLinkStats::new(
                CliLinkStatsValues::from(&s),
                true,
                statistics,
                carrier_changes,
            ));
        } else if let Some(s) = stats32 {
            ret.stats = Some(CliLinkStats::new(
                CliLinkStatsValues::from(&s),
                false,
                statistics,
                carrier_changes,
            ));
        }
    }

    // Only set permaddr if it differs from the current address
    if !temp_permaddr.is_empty() && temp_permaddr != ret.address {
        ret.permaddr = temp_permaddr;
    }

    Ok(ret)
}

fn parse_vf_info(vf: LinkVfInfo, show_stats: bool) -> CliVfInfo {
    let mut info = CliVfInfo::default();
    let mut vlan_vlan_id = None;
    let mut vlan_qos = None;
    let mut vlan_list = Vec::new();
    let mut tx_rate_val = None;
    let mut max_tx_rate_val = None;
    let mut min_tx_rate_val = None;
    let mut has_stats = false;
    let mut stats_rx = CliVfRxStats::default();
    let mut stats_tx = CliVfTxStats::default();

    for attr in vf.0 {
        match attr {
            VfInfo::Mac(m) => {
                info.vf_id = m.vf_id;
                info.mac = format_vf_mac(&m);
            }
            VfInfo::Broadcast(b) => {
                info.broadcast = Some(format_vf_broadcast(&b));
            }
            VfInfo::Vlan(v) => {
                vlan_vlan_id = if v.vlan_id != 0 {
                    Some(v.vlan_id)
                } else {
                    None
                };
                vlan_qos = if v.qos != 0 { Some(v.qos) } else { None };
            }
            VfInfo::Rate(r) => {
                info.vf_id = r.vf_id;
                if r.max_tx_rate != 0 {
                    max_tx_rate_val = Some(r.max_tx_rate);
                }
                if r.min_tx_rate != 0 {
                    min_tx_rate_val = Some(r.min_tx_rate);
                }
            }
            VfInfo::TxRate(t) => {
                info.vf_id = t.vf_id;
                if t.rate != 0 {
                    tx_rate_val = Some(t.rate);
                }
            }
            VfInfo::SpoofCheck(s) => {
                info.vf_id = s.vf_id;
                if s.enabled {
                    info.spoofchk = Some(true);
                } else {
                    info.spoofchk = Some(false);
                }
            }
            VfInfo::LinkState(ls) => {
                info.vf_id = ls.vf_id;
                info.link_state = Some(match ls.state {
                    VfLinkState::Auto => "auto".into(),
                    VfLinkState::Enable => "enable".into(),
                    VfLinkState::Disable => "disable".into(),
                    VfLinkState::Other(v) => v.to_string(),
                    _ => "unknown".into(),
                });
            }
            VfInfo::RssQueryEn(q) => {
                info.vf_id = q.vf_id;
                info.query_rss_en = Some(q.enabled);
            }
            VfInfo::Trust(t) => {
                info.vf_id = t.vf_id;
                info.trust = Some(t.enabled);
            }
            VfInfo::IbNodeGuid(g) => {
                info.vf_id = g.vf_id;
                info.node_guid = Some(format_guid(g.guid));
            }
            VfInfo::IbPortGuid(g) => {
                info.vf_id = g.vf_id;
                info.port_guid = Some(format_guid(g.guid));
            }
            VfInfo::VlanList(list) => {
                for entry in list {
                    if let VfVlan::Info(v) = entry {
                        if v.vlan_id == 0 {
                            continue;
                        }
                        let protocol = if v.protocol == VlanProtocol::Ieee8021Q
                        {
                            None
                        } else {
                            Some(v.protocol.to_string())
                        };
                        vlan_list.push(CliVfVlanEntry {
                            vlan: v.vlan_id,
                            qos: v.qos,
                            protocol,
                        });
                    }
                }
            }
            VfInfo::Stats(stats) => {
                has_stats = true;
                for stat in stats {
                    match stat {
                        NlVfStats::RxPackets(v) => stats_rx.packets = v,
                        NlVfStats::TxPackets(v) => stats_tx.packets = v,
                        NlVfStats::RxBytes(v) => stats_rx.bytes = v,
                        NlVfStats::TxBytes(v) => stats_tx.bytes = v,
                        NlVfStats::Broadcast(v) => stats_rx.broadcast = v,
                        NlVfStats::Multicast(v) => stats_rx.multicast = v,
                        NlVfStats::RxDropped(v) => stats_rx.dropped = Some(v),
                        NlVfStats::TxDropped(v) => stats_tx.dropped = Some(v),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    // Use VLAN list if present, otherwise legacy single VLAN
    if !vlan_list.is_empty() {
        info.vlan_list = vlan_list;
    } else {
        info.vlan = vlan_vlan_id;
        info.qos = vlan_qos;
    }

    info.tx_rate = tx_rate_val;
    info.max_tx_rate = max_tx_rate_val;
    info.min_tx_rate = min_tx_rate_val;

    // iproute2 only shows VF statistics with `-s`.
    if show_stats && has_stats {
        info.stats = Some(CliVfStats {
            rx: stats_rx,
            tx: stats_tx,
        });
    }

    info
}

fn format_vf_mac(m: &VfInfoMac) -> String {
    let len = if m.mac[6..].iter().all(|&b| b == 0) && m.mac[5] != 0 {
        // Ethernet: 6 bytes if byte 6+ are zero
        6
    } else {
        // InfiniBand: use all non-zero bytes, but at most 20
        let nonzero = m
            .mac
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        nonzero.clamp(6, 20)
    };
    mac_to_string(&m.mac[..len])
}

fn format_vf_broadcast(b: &VfInfoBroadcast) -> String {
    let len = if b.addr[6..].iter().all(|&b| b == 0) && b.addr[5] != 0 {
        6
    } else {
        let nonzero = b
            .addr
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        nonzero.clamp(6, 20)
    };
    mac_to_string(&b.addr[..len])
}

fn format_guid(guid: u64) -> String {
    let guid_be = guid.to_be_bytes();
    let mut s = String::with_capacity(23);
    for (i, &b) in guid_be.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        write!(s, "{b:02x}").unwrap();
    }
    s
}

impl std::fmt::Display for CliVfInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\n    vf {}     link/ether {}", self.vf_id, self.mac)?;

        if let Some(ref bc) = self.broadcast {
            if self.is_point_2_point {
                write!(f, " peer {bc}")?;
            } else {
                write!(f, " brd {bc}")?;
            }
        }

        if !self.vlan_list.is_empty() {
            for entry in &self.vlan_list {
                write!(f, ", vlan {}", entry.vlan)?;
                if entry.qos != 0 {
                    write!(f, ", qos {}", entry.qos)?;
                }
                if let Some(ref proto) = entry.protocol {
                    write!(f, ", vlan protocol {proto}")?;
                }
            }
        } else {
            if let Some(vlan) = self.vlan {
                write!(f, ", vlan {vlan}")?;
            }
            if let Some(qos) = self.qos {
                write!(f, ", qos {qos}")?;
            }
        }

        if let Some(rate) = self.tx_rate {
            write!(f, ", tx rate {rate} (Mbps)")?;
        }
        if let Some(max) = self.max_tx_rate {
            write!(f, ", max_tx_rate {max}Mbps")?;
        }
        if let Some(min) = self.min_tx_rate {
            write!(f, ", min_tx_rate {min}Mbps")?;
        }

        if let Some(ref sc) = self.spoofchk {
            if *sc {
                write!(f, ", spoof checking on")?;
            } else {
                write!(f, ", spoof checking off")?;
            }
        }

        if let Some(ref ng) = self.node_guid {
            write!(f, ", NODE_GUID {ng}")?;
        }
        if let Some(ref pg) = self.port_guid {
            write!(f, ", PORT_GUID {pg}")?;
        }

        if let Some(ref ls) = self.link_state {
            write!(f, ", link-state {ls}")?;
        }

        if let Some(ref tr) = self.trust {
            if *tr {
                write!(f, ", trust on")?;
            } else {
                write!(f, ", trust off")?;
            }
        }

        if let Some(ref rss) = self.query_rss_en {
            if *rss {
                write!(f, ", query_rss on")?;
            } else {
                write!(f, ", query_rss off")?;
            }
        }

        if let Some(ref stats) = self.stats {
            write!(f, "\n    RX: bytes  packets  mcast   bcast ")?;
            if stats.rx.dropped.is_some() {
                write!(f, "  dropped ")?;
            }
            write!(
                f,
                "\n    {:>10} {:>8} {:>7} {:>7}",
                stats.rx.bytes,
                stats.rx.packets,
                stats.rx.multicast,
                stats.rx.broadcast,
            )?;
            if let Some(dropped) = stats.rx.dropped {
                write!(f, " {dropped:>8} ")?;
            } else {
                write!(f, " ")?;
            }
            write!(f, "\n    TX: bytes  packets ")?;
            if stats.tx.dropped.is_some() {
                write!(f, "  dropped ")?;
            }
            write!(f, "\n    {:>10} {:>8}", stats.tx.bytes, stats.tx.packets,)?;
            if let Some(dropped) = stats.tx.dropped {
                write!(f, " {dropped:>8} ")?;
            } else {
                write!(f, " ")?;
            }
        }

        Ok(())
    }
}

/// Try to resolve a netns id to its name using rtnetlink.
/// If not found, returns the id as a string.
async fn get_netns_id_from_fd(
    handle: &mut rtnetlink::Handle,
    fd: u32,
) -> Option<i32> {
    let mut nsid_msg = rtnetlink::packet_route::nsid::NsidMessage::default();
    nsid_msg
        .attributes
        .push(rtnetlink::packet_route::nsid::NsidAttribute::Fd(fd));
    let mut nsid_req = rtnetlink::packet_core::NetlinkMessage::new(
        rtnetlink::packet_core::NetlinkHeader::default(),
        rtnetlink::packet_core::NetlinkPayload::InnerMessage(
            rtnetlink::packet_route::RouteNetlinkMessage::GetNsId(nsid_msg),
        ),
    );
    nsid_req.header.flags = rtnetlink::packet_core::NLM_F_REQUEST;

    let mut netns = handle.request(nsid_req.clone()).unwrap();

    if let Some(msg) = netns.next().await {
        let rtnetlink::packet_core::NetlinkPayload::InnerMessage(
            rtnetlink::packet_route::RouteNetlinkMessage::NewNsId(payload),
        ) = msg.payload
        else {
            return None;
        };
        for attr in payload.attributes {
            if let rtnetlink::packet_route::nsid::NsidAttribute::Id(id) = attr {
                return Some(id);
            }
        }
    }

    None
}

fn resolve_ip_link_group_name(id: u32) -> String {
    // TODO: Read `/usr/share/iproute2/group` and `/etc/iproute2/group`
    match id {
        0 => "default".into(),
        _ => id.to_string(),
    }
}

async fn resolve_netns_names(
    links: &mut [CliLinkInfo],
) -> Result<(), CliError> {
    let (conn, mut handle, _) = match rtnetlink::new_connection() {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    tokio::spawn(conn);

    let dir = match std::fs::read_dir("/run/netns") {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };

    let mut id_to_name: HashMap<i32, String> = HashMap::new();
    for entry in dir.flatten() {
        let name = entry.file_name().into_string().unwrap_or_default();
        let file = match std::fs::File::open(entry.path()) {
            Ok(f) => f,
            Err(_) => continue,
        };

        if let Some(id) =
            get_netns_id_from_fd(&mut handle, file.as_raw_fd() as u32).await
        {
            id_to_name.insert(id, name);
        }
    }

    for link in links.iter_mut() {
        if let Some(link_netns_id) = link.link_netnsid
            && let Some(name) = id_to_name.get(&link_netns_id)
        {
            link.link_netns = name.to_string();
        }
    }

    Ok(())
}

fn resolve_controller_and_link_names(links: &mut [CliLinkInfo]) {
    let index_2_name: HashMap<u32, String> = links
        .iter()
        .map(|l| (l.ifindex, l.ifname.to_string()))
        .collect();
    let index_2_flags: HashMap<u32, LinkFlags> =
        links.iter().map(|l| (l.ifindex, l.raw_flags)).collect();
    for link in links.iter_mut() {
        if let Some(ctrl_ifindex) = link.controller_ifindex
            && let Some(name) = index_2_name.get(&ctrl_ifindex)
        {
            link.controller = Some(name.to_string());
        }
        if let Some(link_ifindex) = link.link_index {
            if link_ifindex > 0 {
                let name = if let Some(name) = index_2_name.get(&link_ifindex)
                    && link.link_netnsid.is_none()
                {
                    name.clone()
                } else {
                    format!("if{link_ifindex}")
                };
                link.link = Some(Some(name));
            } else {
                // iproute2 serializes link index 0 as `"link": null`, the
                // text output is `@NONE`.
                link.link = Some(None);
            }
            link.link_index = None;
        }

        // Compute M-DOWN: if linked interface is not UP, append "M-DOWN"
        // to flags, matching iproute2 behavior (print_link_flags mdown param).
        if let Some(Some(ref link_name)) = link.link
            && let Some((&linked_ifindex, _)) =
                index_2_name.iter().find(|(_, name)| *name == link_name)
            && let Some(linked_flags) = index_2_flags.get(&linked_ifindex)
            && !linked_flags.contains(LinkFlags::Up)
        {
            link.flags.push("M-DOWN".into());
        }

        // Resolve link ifindex (VxLAN, HSR, etc.) to interface name
        if let Some(ref mut details) = link.details {
            details.resolve_link(&index_2_name);
        }
    }
}
