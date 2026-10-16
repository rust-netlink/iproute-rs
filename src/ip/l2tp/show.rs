// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use iproute_rs::{CanDisplay, CanOutput, CliError};
use nl_l2tp::{L2tpEncapType, L2tpSession, L2tpTunnel};
use serde::Serialize;

use super::parm::{missarg, parse_options};

/// iproute2 prints the encapsulation of a tunnel as `UDP`, `IP` or `??`.
fn encap_name(encap: Option<L2tpEncapType>) -> &'static str {
    match encap {
        Some(L2tpEncapType::Udp) => "UDP",
        Some(L2tpEncapType::Ip) => "IP",
        _ => "??",
    }
}

fn cookie_string(cookie: &[u8]) -> String {
    cookie.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Serialize)]
pub(crate) struct CliL2tpTunnel {
    tunnel_id: u32,
    encap: String,
    local: String,
    peer: String,
    peer_tunnel: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_port: Option<u16>,
    /// The UDP checksum state of an IPv4 tunnel.
    #[serde(skip_serializing_if = "Option::is_none")]
    checksum: Option<bool>,
    /// The UDP checksum state on transmit of an IPv6 tunnel.
    #[serde(skip_serializing_if = "Option::is_none")]
    checksum_tx: Option<bool>,
    /// The UDP checksum state on receive of an IPv6 tunnel.
    #[serde(skip_serializing_if = "Option::is_none")]
    checksum_rx: Option<bool>,
    /// iproute2 replaces the newlines of `print_nl()` with a backslash in
    /// oneline mode.
    #[serde(skip)]
    oneline: bool,
}

impl From<L2tpTunnel> for CliL2tpTunnel {
    fn from(tunnel: L2tpTunnel) -> Self {
        let is_ipv6 = matches!(tunnel.local, Some(IpAddr::V6(_)));
        let udp = tunnel.encap == Some(L2tpEncapType::Udp);
        let (checksum, checksum_tx, checksum_rx) = if udp {
            if is_ipv6 {
                (None, Some(tunnel.udp6_csum_tx), Some(tunnel.udp6_csum_rx))
            } else {
                (Some(tunnel.udp_csum), None, None)
            }
        } else {
            (None, None, None)
        };
        Self {
            tunnel_id: tunnel.tunnel_id.unwrap_or_default(),
            encap: encap_name(tunnel.encap).to_string(),
            local: tunnel
                .local
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            peer: tunnel
                .peer
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            peer_tunnel: tunnel.peer_tunnel_id.unwrap_or_default(),
            local_port: udp.then(|| tunnel.local_udp_port.unwrap_or_default()),
            peer_port: udp.then(|| tunnel.peer_udp_port.unwrap_or_default()),
            checksum,
            checksum_tx,
            checksum_rx,
            oneline: false,
        }
    }
}

impl std::fmt::Display for CliL2tpTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // In oneline mode iproute2 replaces the newlines with a backslash,
        // a non UDP tunnel then ends with the backslash of the last
        // `print_nl()` without a trailing newline. The final newline added
        // by `print_result_and_exit()` is an accepted divergence, matching
        // the missing newline of iproute2 would need a reworked output.
        let sep = if self.oneline { "\\" } else { "\n" };
        write!(
            f,
            "Tunnel {}, encap {}{sep}  From {} to {}{sep}  Peer tunnel {}",
            self.tunnel_id, self.encap, self.local, self.peer, self.peer_tunnel
        )?;
        if let (Some(local_port), Some(peer_port)) =
            (self.local_port, self.peer_port)
        {
            write!(
                f,
                "{sep}  UDP source / dest ports: {local_port}/{peer_port}"
            )?;
            if let Some(checksum) = self.checksum {
                write!(
                    f,
                    "{sep}  UDP checksum: {}",
                    if checksum { "enabled" } else { "disabled" }
                )?;
            } else {
                let tx = self.checksum_tx.unwrap_or(true);
                let rx = self.checksum_rx.unwrap_or(true);
                write!(
                    f,
                    "{sep}  UDP checksum: {}{}{}{}",
                    if tx && rx { "enabled" } else { "" },
                    if tx && !rx { "tx" } else { "" },
                    if !tx && rx { "rx" } else { "" },
                    if !tx && !rx { "disabled" } else { "" }
                )?;
            }
        }
        Ok(())
    }
}

impl CanDisplay for CliL2tpTunnel {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliL2tpTunnel {}

#[derive(Serialize)]
pub(crate) struct CliL2tpSession {
    session_id: u32,
    tunnel_id: u32,
    peer_session_id: u32,
    peer_tunnel_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookie: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_cookie: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reorder_timeout: Option<u64>,
    /// Present as JSON `null` when sequence numbering is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    send_seq: Option<()>,
    /// Present as JSON `null` when sequence numbering is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    recv_seq: Option<()>,
    /// iproute2 replaces the newlines of `print_nl()` with a backslash in
    /// oneline mode.
    #[serde(skip)]
    oneline: bool,
}

impl From<L2tpSession> for CliL2tpSession {
    fn from(session: L2tpSession) -> Self {
        Self {
            session_id: session.session_id.unwrap_or_default(),
            tunnel_id: session.tunnel_id.unwrap_or_default(),
            peer_session_id: session.peer_session_id.unwrap_or_default(),
            peer_tunnel_id: session.peer_tunnel_id.unwrap_or_default(),
            interface: session.ifname,
            cookie: session.cookie.as_deref().map(cookie_string),
            peer_cookie: session.peer_cookie.as_deref().map(cookie_string),
            reorder_timeout: session.reorder_timeout,
            send_seq: session.send_seq.then_some(()),
            recv_seq: session.recv_seq.then_some(()),
            oneline: false,
        }
    }
}

impl std::fmt::Display for CliL2tpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sep = if self.oneline { "\\" } else { "\n" };
        write!(
            f,
            "Session {} in tunnel {}{sep}  Peer session {}, tunnel {}",
            self.session_id,
            self.tunnel_id,
            self.peer_session_id,
            self.peer_tunnel_id
        )?;
        if let Some(interface) = &self.interface {
            write!(f, "{sep}  interface name: {interface}")?;
        }
        // iproute2 ends the offsets line with a literal newline and prints
        // the optional properties without a separator.
        writeln!(f, "{sep}  offset 0, peer offset 0")?;
        if let Some(cookie) = &self.cookie {
            write!(f, "  cookie {cookie}")?;
        }
        if let Some(peer_cookie) = &self.peer_cookie {
            write!(f, "  peer cookie {peer_cookie}")?;
        }
        if let Some(timeout) = self.reorder_timeout {
            write!(f, "  reorder timeout: {timeout}")?;
        }
        if self.send_seq.is_some() || self.recv_seq.is_some() {
            write!(f, "{sep}  sequence numbering:")?;
            if self.send_seq.is_some() {
                write!(f, " send")?;
            }
            if self.recv_seq.is_some() {
                write!(f, " recv")?;
            }
        }
        Ok(())
    }
}

impl CanDisplay for CliL2tpSession {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliL2tpSession {}

/// The output of `ip l2tp show`, either a tunnel or a session. The variants
/// are serialized as the object itself, so a list becomes the JSON array of
/// iproute2.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum CliL2tp {
    Tunnel(CliL2tpTunnel),
    Session(CliL2tpSession),
}

impl std::fmt::Display for CliL2tp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tunnel(tunnel) => tunnel.fmt(f),
            Self::Session(session) => session.fmt(f),
        }
    }
}

impl CanDisplay for CliL2tp {
    fn gen_string(&self) -> String {
        self.to_string()
    }
}

impl CanOutput for CliL2tp {}

pub(crate) async fn handle_show(
    opts: &[String],
    oneline: bool,
) -> Result<Vec<CliL2tp>, CliError> {
    let parm = parse_options(opts)?;
    if !parm.tunnel && !parm.session {
        return Err(missarg("tunnel or session"));
    }

    let (connection, mut handle, _) = nl_l2tp::new_connection()?;
    tokio::spawn(connection);

    if parm.session {
        let mut filter = L2tpSession::default();
        // iproute2 only sends the filter when both IDs are set.
        if parm.tunnel_id != 0 && parm.session_id != 0 {
            filter.tunnel_id = Some(parm.tunnel_id);
            filter.session_id = Some(parm.session_id);
        }
        let sessions = handle.get_sessions(&filter).await?;
        Ok(sessions
            .into_iter()
            .map(|session| {
                let mut cli = CliL2tpSession::from(session);
                cli.oneline = oneline;
                CliL2tp::Session(cli)
            })
            .collect())
    } else {
        let mut filter = L2tpTunnel::default();
        if parm.tunnel_id != 0 {
            filter.tunnel_id = Some(parm.tunnel_id);
        }
        let tunnels = handle.get_tunnels(&filter).await?;
        Ok(tunnels
            .into_iter()
            .map(|tunnel| {
                let mut cli = CliL2tpTunnel::from(tunnel);
                cli.oneline = oneline;
                CliL2tp::Tunnel(cli)
            })
            .collect())
    }
}
