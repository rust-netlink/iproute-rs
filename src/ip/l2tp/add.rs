// SPDX-License-Identifier: MIT

use iproute_rs::CliError;
use nl_l2tp::{L2tpSession, L2tpTunnel};

use super::parm::{Parm, missarg, parse_options};

pub(crate) async fn handle_add(opts: &[String]) -> Result<(), CliError> {
    let parm = parse_options(opts)?;
    send_add(&parm).await
}

pub(crate) async fn handle_delete(opts: &[String]) -> Result<(), CliError> {
    let parm = parse_options(opts)?;
    send_delete(&parm).await
}

async fn send_add(parm: &Parm) -> Result<(), CliError> {
    // The checks and their order follow `do_add()` of iproute2.
    if !parm.tunnel && !parm.session {
        return Err(missarg("tunnel or session"));
    }
    if parm.tunnel_id == 0 {
        return Err(missarg("tunnel_id"));
    }
    if parm.session && parm.peer_session_id == 0 {
        return Err(missarg("peer_session_id"));
    }
    if parm.session && parm.session_id == 0 {
        return Err(missarg("session_id"));
    }
    if parm.tunnel && parm.peer_tunnel_id == 0 {
        return Err(missarg("peer_tunnel_id"));
    }

    let (connection, mut handle, _) = nl_l2tp::new_connection()?;
    tokio::spawn(connection);

    if parm.tunnel {
        if parm.local.is_none() {
            return Err(missarg("local"));
        }
        if parm.peer.is_none() {
            return Err(missarg("remote"));
        }
        if parm.encap == nl_l2tp::L2tpEncapType::Udp {
            if parm.local_udp_port == 0 {
                return Err(missarg("udp_sport"));
            }
            if parm.peer_udp_port == 0 {
                return Err(missarg("udp_dport"));
            }
        }

        let mut config = L2tpTunnel::new(parm.tunnel_id);
        config.peer_tunnel_id = Some(parm.peer_tunnel_id);
        config.encap = Some(parm.encap);
        config.local = parm.local;
        config.peer = parm.peer;
        config.local_udp_port =
            (parm.local_udp_port != 0).then_some(parm.local_udp_port);
        config.peer_udp_port =
            (parm.peer_udp_port != 0).then_some(parm.peer_udp_port);
        config.udp_csum = parm.udp_csum;
        config.udp6_csum_tx = parm.udp6_csum_tx;
        config.udp6_csum_rx = parm.udp6_csum_rx;
        handle.add_tunnel(&config).await?;
    }

    if parm.session {
        let mut config = L2tpSession::new(parm.tunnel_id, parm.session_id);
        config.peer_tunnel_id = Some(parm.peer_tunnel_id);
        config.peer_session_id = Some(parm.peer_session_id);
        config.ifname = parm.ifname.clone();
        config.cookie = parm.cookie.clone();
        config.peer_cookie = parm.peer_cookie.clone();
        config.recv_seq = parm.recv_seq;
        config.send_seq = parm.send_seq;
        config.l2spec_type = parm.l2spec_type;
        config.l2spec_len = parm.l2spec_len;
        handle.add_session(&config).await?;
    }

    Ok(())
}

async fn send_delete(parm: &Parm) -> Result<(), CliError> {
    // The checks and their order follow `do_del()` of iproute2.
    if !parm.tunnel && !parm.session {
        return Err(missarg("tunnel or session"));
    }
    if parm.tunnel && parm.tunnel_id == 0 {
        return Err(missarg("tunnel_id"));
    }
    if parm.session && parm.session_id == 0 {
        return Err(missarg("session_id"));
    }

    let (connection, mut handle, _) = nl_l2tp::new_connection()?;
    tokio::spawn(connection);

    if parm.session_id != 0 {
        let config = L2tpSession::new(parm.tunnel_id, parm.session_id);
        handle.delete_session(&config).await?;
    } else {
        handle
            .delete_tunnel(&L2tpTunnel::new(parm.tunnel_id))
            .await?;
    }

    Ok(())
}
