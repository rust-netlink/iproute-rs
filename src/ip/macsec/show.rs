// SPDX-License-Identifier: MIT

use std::{ffi::CStr, fmt};

use iproute_rs::{CanDisplay, CanOutput, CliError};
use nl_macsec::{
    MacSecCipherId, MacSecOffload, MacSecValidate, MacsecConfig,
    MacsecRxScConfig, MacsecRxScStats, MacsecSaConfig, MacsecSaStats,
    MacsecSecyStats, MacsecTxScStats, new_connection,
};
use serde::Serialize;

use super::{add::resolve_ifindex, cli::usage_error};

const SECY_STATS_NAMES: &[&str] = &[
    "OutPktsUntagged",
    "InPktsUntagged",
    "OutPktsTooLong",
    "InPktsNoTag",
    "InPktsBadTag",
    "InPktsUnknownSCI",
    "InPktsNoSCI",
    "InPktsOverrun",
];

const TXSC_STATS_NAMES: &[&str] = &[
    "OutPktsProtected",
    "OutPktsEncrypted",
    "OutOctetsProtected",
    "OutOctetsEncrypted",
];

const RXSC_STATS_NAMES: &[&str] = &[
    "InOctetsValidated",
    "InOctetsDecrypted",
    "InPktsUnchecked",
    "InPktsDelayed",
    "InPktsOK",
    "InPktsInvalid",
    "InPktsLate",
    "InPktsNotValid",
    "InPktsNotUsingSA",
    "InPktsUnusedSA",
];

const TXSA_STATS_NAMES: &[&str] = &["OutPktsProtected", "OutPktsEncrypted"];

const RXSA_STATS_NAMES: &[&str] = &[
    "InPktsOK",
    "InPktsInvalid",
    "InPktsNotValid",
    "InPktsNotUsingSA",
    "InPktsUnusedSA",
];

#[derive(Clone, Default)]
struct Stats(Vec<(&'static str, u64)>);

impl Stats {
    fn push(&mut self, name: &'static str, value: u64) {
        self.0.push((name, value));
    }

    fn get(&self, name: &str) -> Option<u64> {
        self.0
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for Stats {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer
            .collect_map(self.0.iter().map(|(name, value)| (*name, *value)))
    }
}

#[derive(Serialize)]
pub(crate) struct CliMacsecSa {
    an: u8,
    pn: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssci: Option<String>,
    active: bool,
    key: String,
    #[serde(flatten)]
    stats: Stats,
    #[serde(skip)]
    ssci_raw: Option<u32>,
    #[serde(skip)]
    is_xpn: bool,
    #[serde(skip)]
    tx: bool,
}

impl CliMacsecSa {
    fn fmt_with_prefix(
        &self,
        f: &mut fmt::Formatter<'_>,
        prefix: &str,
    ) -> fmt::Result {
        write!(f, "{prefix}{}: PN {},", self.an, self.pn)?;
        if self.is_xpn
            && let Some(ssci) = self.ssci_raw
        {
            write!(f, "SSCI {ssci:08x}")?;
        }
        writeln!(f, " state {}, key {}", on_off(self.active), self.key)?;
        if !self.stats.is_empty() {
            let names = if self.tx {
                TXSA_STATS_NAMES
            } else {
                RXSA_STATS_NAMES
            };
            fmt_stats(f, "    ", names, &self.stats)?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct CliMacsecRxsc {
    sci: String,
    active: bool,
    #[serde(flatten)]
    stats: Stats,
    sa_list: Vec<CliMacsecSa>,
    #[serde(skip)]
    sci_raw: u64,
}

impl CliMacsecRxsc {
    fn fmt_with_prefix(
        &self,
        f: &mut fmt::Formatter<'_>,
        prefix: &str,
    ) -> fmt::Result {
        writeln!(
            f,
            "{prefix}RXSC: {:016x}, state {}",
            self.sci_raw,
            on_off(self.active)
        )?;
        if !self.stats.is_empty() {
            fmt_stats(f, prefix, RXSC_STATS_NAMES, &self.stats)?;
        }
        for sa in &self.sa_list {
            sa.fmt_with_prefix(f, "        ")?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub(crate) struct CliMacsec {
    ifindex: u32,
    ifname: String,
    protect: bool,
    validate: String,
    sc: bool,
    sa: bool,
    encrypt: bool,
    send_sci: bool,
    end_station: bool,
    scb: bool,
    replay: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    window: Option<u32>,
    cipher_suite: String,
    icv_length: u8,
    sci: String,
    encoding_sa: u8,
    #[serde(flatten)]
    secy_stats: Stats,
    #[serde(flatten)]
    txsc_stats: Stats,
    sa_list: Vec<CliMacsecSa>,
    rx_sc: Vec<CliMacsecRxsc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offload: Option<String>,
    #[serde(skip)]
    sci_raw: u64,
    #[serde(skip)]
    oneline: bool,
}

impl fmt::Display for CliMacsec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sep = if self.oneline { "\\" } else { "\n" };
        write!(
            f,
            "{}: {}: protect {} validate {} sc {} sa {} encrypt {} send_sci \
             {} end_station {} scb {} replay {} ",
            self.ifindex,
            self.ifname,
            on_off(self.protect),
            self.validate,
            on_off(self.sc),
            on_off(self.sa),
            on_off(self.encrypt),
            on_off(self.send_sci),
            on_off(self.end_station),
            on_off(self.scb),
            on_off(self.replay),
        )?;
        if let Some(window) = self.window {
            write!(f, "window {window} ")?;
        }
        write!(f, "{sep}    cipher suite: {},", self.cipher_suite)?;
        writeln!(f, " using ICV length {}", self.icv_length)?;

        writeln!(
            f,
            "    TXSC: {:016x} on SA {}",
            self.sci_raw, self.encoding_sa
        )?;
        if !self.secy_stats.is_empty() {
            fmt_stats(f, "    ", SECY_STATS_NAMES, &self.secy_stats)?;
        }
        if !self.txsc_stats.is_empty() {
            fmt_stats(f, "    ", TXSC_STATS_NAMES, &self.txsc_stats)?;
        }
        for sa in &self.sa_list {
            sa.fmt_with_prefix(f, "        ")?;
        }
        for rxsc in &self.rx_sc {
            rxsc.fmt_with_prefix(f, "    ")?;
        }
        if let Some(offload) = &self.offload {
            write!(f, "    offload: {offload} ")?;
            if self.oneline {
                write!(f, "{sep}")?;
            }
        }
        Ok(())
    }
}

impl CanDisplay for CliMacsec {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliMacsec {}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn fmt_stats(
    f: &mut fmt::Formatter<'_>,
    prefix: &str,
    names: &[&str],
    stats: &Stats,
) -> fmt::Result {
    write!(f, "{prefix}stats:")?;
    for name in names {
        write!(f, " {name}")?;
    }
    write!(f, "\n{prefix}      ")?;
    for name in names {
        let width = name.len() + 1;
        match stats.get(name) {
            Some(value) => write!(f, "{value:>width$}")?,
            None => write!(f, "{:>width$}", "-")?,
        }
    }
    writeln!(f)
}

pub(crate) async fn handle_show(
    opts: &[String],
    show_stats: bool,
    oneline: bool,
) -> Result<Vec<CliMacsec>, CliError> {
    let filter = if opts.is_empty() {
        None
    } else if opts.len() == 1 {
        Some(resolve_ifindex(&opts[0])?)
    } else {
        return Err(usage_error());
    };

    let (connection, mut handle, _) = new_connection()?;
    tokio::spawn(connection);

    let configs = handle.get_all().await?;
    Ok(configs
        .into_iter()
        .filter(|config| filter.is_none_or(|ifindex| ifindex == config.ifindex))
        .map(|config| config_to_cli(config, show_stats, oneline))
        .collect())
}

fn config_to_cli(
    config: MacsecConfig,
    show_stats: bool,
    oneline: bool,
) -> CliMacsec {
    let is_xpn = config.is_xpn();
    let state = config.secy.encoding_sa != 0;
    let (secy_stats, txsc_stats) = if show_stats {
        (
            secy_stats_from(&config.secy_stats),
            txsc_stats_from(&config.tx_sc_stats),
        )
    } else {
        (Stats::default(), Stats::default())
    };

    CliMacsec {
        ifindex: config.ifindex,
        ifname: index_to_name(config.ifindex),
        protect: config.secy.protect,
        validate: validate_name(&config.secy.validate).to_string(),
        sc: state,
        sa: state,
        encrypt: config.secy.encrypt,
        send_sci: config.secy.send_sci,
        end_station: config.secy.end_station,
        scb: config.secy.scb,
        replay: config.secy.replay,
        window: config.secy.window,
        cipher_suite: cipher_name(&config.secy.cipher_suite).to_string(),
        icv_length: config.secy.icv_len,
        sci: format!("{:#x}", config.secy.sci),
        encoding_sa: config.secy.encoding_sa,
        secy_stats,
        txsc_stats,
        sa_list: config
            .tx_sa
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|sa| sa_to_cli(sa, is_xpn, true, show_stats))
            .collect(),
        rx_sc: config
            .rx_sc
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|sc| rx_sc_to_cli(sc, is_xpn, show_stats))
            .collect(),
        offload: config
            .secy
            .offload
            .map(|offload| offload_name(&offload).to_string()),
        sci_raw: config.secy.sci,
        oneline,
    }
}

fn rx_sc_to_cli(
    config: &MacsecRxScConfig,
    is_xpn: bool,
    show_stats: bool,
) -> CliMacsecRxsc {
    CliMacsecRxsc {
        sci: format!("{:#x}", config.sci),
        active: config.active.unwrap_or(false),
        stats: if show_stats {
            rxsc_stats_from(&config.stats)
        } else {
            Stats::default()
        },
        sa_list: config
            .sa_list
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|sa| sa_to_cli(sa, is_xpn, false, show_stats))
            .collect(),
        sci_raw: config.sci,
    }
}

fn sa_to_cli(
    config: &MacsecSaConfig,
    is_xpn: bool,
    tx: bool,
    show_stats: bool,
) -> CliMacsecSa {
    CliMacsecSa {
        an: config.an,
        pn: config.pn.unwrap_or_default(),
        ssci: config.ssci.map(|value| format!("{value:#x}")),
        active: config.active.unwrap_or(false),
        key: hex_string(&config.key_id),
        stats: if show_stats {
            sa_stats_from(&config.stats, tx)
        } else {
            Stats::default()
        },
        ssci_raw: config.ssci,
        is_xpn,
        tx,
    }
}

fn secy_stats_from(stats: &MacsecSecyStats) -> Stats {
    let mut result = Stats::default();
    result.push("OutPktsUntagged", stats.out_pkts_untagged);
    result.push("InPktsUntagged", stats.in_pkts_untagged);
    result.push("OutPktsTooLong", stats.out_pkts_too_long);
    result.push("InPktsNoTag", stats.in_pkts_no_tag);
    result.push("InPktsBadTag", stats.in_pkts_bad_tag);
    result.push("InPktsUnknownSCI", stats.in_pkts_unknown_sci);
    result.push("InPktsNoSCI", stats.in_pkts_no_sci);
    result.push("InPktsOverrun", stats.in_pkts_overrun);
    result
}

fn txsc_stats_from(stats: &MacsecTxScStats) -> Stats {
    let mut result = Stats::default();
    result.push("OutPktsProtected", stats.out_pkts_protected);
    result.push("OutPktsEncrypted", stats.out_pkts_encrypted);
    result.push("OutOctetsProtected", stats.out_octets_protected);
    result.push("OutOctetsEncrypted", stats.out_octets_encrypted);
    result
}

fn rxsc_stats_from(stats: &MacsecRxScStats) -> Stats {
    let mut result = Stats::default();
    result.push("InOctetsValidated", stats.in_octets_validated);
    result.push("InOctetsDecrypted", stats.in_octets_decrypted);
    result.push("InPktsUnchecked", stats.in_pkts_unchecked);
    result.push("InPktsDelayed", stats.in_pkts_delayed);
    result.push("InPktsOK", stats.in_pkts_ok);
    result.push("InPktsInvalid", stats.in_pkts_invalid);
    result.push("InPktsLate", stats.in_pkts_late);
    result.push("InPktsNotValid", stats.in_pkts_not_valid);
    result.push("InPktsNotUsingSA", stats.in_pkts_not_using_sa);
    result.push("InPktsUnusedSA", stats.in_pkts_unused_sa);
    result
}

fn sa_stats_from(stats: &MacsecSaStats, tx: bool) -> Stats {
    let mut result = Stats::default();
    if tx {
        result.push("OutPktsProtected", stats.out_pkts_protected);
        result.push("OutPktsEncrypted", stats.out_pkts_encrypted);
    } else {
        result.push("InPktsOK", stats.in_pkts_ok);
        result.push("InPktsInvalid", stats.in_pkts_invalid);
        result.push("InPktsNotValid", stats.in_pkts_not_valid);
        result.push("InPktsNotUsingSA", stats.in_pkts_not_using_sa);
        result.push("InPktsUnusedSA", stats.in_pkts_unused_sa);
    }
    result
}

fn cipher_name(cipher: &MacSecCipherId) -> &'static str {
    match cipher {
        MacSecCipherId::GcmAes128 => "GCM-AES-128",
        MacSecCipherId::GcmAes256 => "GCM-AES-256",
        MacSecCipherId::GcmAesXpn128 => "GCM-AES-XPN-128",
        MacSecCipherId::GcmAesXpn256 => "GCM-AES-XPN-256",
        _ => "(unknown)",
    }
}

fn validate_name(validate: &MacSecValidate) -> &'static str {
    match validate {
        MacSecValidate::Disabled => "disabled",
        MacSecValidate::Check => "check",
        MacSecValidate::Strict => "strict",
        _ => "(unknown)",
    }
}

fn offload_name(offload: &MacSecOffload) -> &'static str {
    match offload {
        MacSecOffload::Off => "off",
        MacSecOffload::Phy => "phy",
        MacSecOffload::Mac => "mac",
        _ => "(unknown)",
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn index_to_name(index: u32) -> String {
    let mut buf = [0i8; libc::IF_NAMESIZE];
    // SAFETY: `if_indextoname()` writes at most `IF_NAMESIZE` bytes into
    // `buf`.
    let ptr = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return format!("if{index}");
    }
    // SAFETY: `if_indextoname()` returned a pointer to the NUL terminated
    // name inside `buf`.
    let name = unsafe { CStr::from_ptr(ptr) };
    name.to_string_lossy().into_owned()
}
