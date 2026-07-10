// SPDX-License-Identifier: MIT

use std::io::{IsTerminal, Read, Write};

use futures_util::{TryStreamExt, stream::StreamExt};
use iproute_rs::CanDisplay;
use rtnetlink::{
    packet_core::{
        NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
    },
    packet_route::{RouteNetlinkMessage, route::RouteMessage},
};

use super::show::{RouteShowFilter, parse_nl_msg_to_route};
use crate::CliError;

const ROUTE_DUMP_MAGIC: u32 = 0x45311224;

pub(crate) async fn handle_save(opts: &[String]) -> Result<(), CliError> {
    if std::io::stdout().is_terminal() {
        return Err(CliError::from("Not sending a binary stream to stdout"));
    }

    let opts_refs: Vec<&str> = opts.iter().map(String::as_str).collect();
    let (filter, _link_opts) = RouteShowFilter::parse(&opts_refs)?;
    drop(opts_refs);

    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    stdout
        .write_all(&ROUTE_DUMP_MAGIC.to_le_bytes())
        .map_err(|e| {
            CliError::from(format!("Can't write magic to dump file: {e}"))
        })?;

    // Build link index -> name map for filtering
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut link_map = std::collections::HashMap::new();
    let mut links = handle.link().get().execute();
    while let Ok(Some(link)) = links.try_next().await {
        let ifname = link
            .attributes
            .iter()
            .find_map(|attr| {
                if let rtnetlink::packet_route::link::LinkAttribute::IfName(n) =
                    attr
                {
                    Some(n.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| format!("if{}", link.header.index));
        link_map.insert(link.header.index, ifname);
    }

    let msg = RouteMessage::default();
    let mut routes = handle.route().get(msg).execute();

    while let Ok(Some(nl_msg)) = routes.try_next().await {
        let route = parse_nl_msg_to_route(nl_msg.clone(), false, &link_map);

        if !filter.matches(&route) {
            continue;
        }

        let mut nl_msg_out =
            NetlinkMessage::from(RouteNetlinkMessage::NewRoute(nl_msg));
        nl_msg_out.finalize();
        let len = nl_msg_out.buffer_len();
        let mut buf = vec![0u8; len];
        nl_msg_out.serialize(&mut buf);
        stdout.write_all(&buf).map_err(|e| {
            CliError::from(format!("Short write while saving nlmsg: {e}"))
        })?;
    }

    Ok(())
}

pub(crate) async fn handle_restore() -> Result<(), CliError> {
    if std::io::stdin().is_terminal() {
        return Err(CliError::from("Can't restore route dump from a terminal"));
    }

    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();

    let mut magic_buf = [0u8; 4];
    stdin
        .read_exact(&mut magic_buf)
        .map_err(|e| CliError::from(format!("Failed to read magic: {e}")))?;
    let magic = u32::from_le_bytes(magic_buf);
    if magic != ROUTE_DUMP_MAGIC {
        return Err(CliError::from(format!("Magic mismatch ({magic:#x})")));
    }

    let (connection, mut handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    loop {
        let mut len_buf = [0u8; 4];
        match stdin.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                return Err(CliError::from(format!(
                    "Failed to read nlmsg length: {e}"
                )));
            }
        }
        let nlmsg_len = u32::from_le_bytes(len_buf) as usize;

        let mut buf = Vec::with_capacity(nlmsg_len);
        buf.extend_from_slice(&len_buf);
        buf.resize(nlmsg_len, 0);
        stdin.read_exact(&mut buf[4..]).map_err(|e| {
            CliError::from(format!("Failed to read nlmsg: {e}"))
        })?;

        let nl_msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&buf)
            .map_err(|e| {
            CliError::from(format!("Failed to parse nlmsg: {e}"))
        })?;

        let mut msg = nl_msg;

        let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(_)) =
            msg.payload
        else {
            continue;
        };

        msg.header.flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;

        let mut response = handle
            .request(msg)
            .map_err(|e| CliError::from(format!("{e}")))?;
        while let Some(resp) = response.next().await {
            if let NetlinkPayload::Error(err) = resp.payload
                && let Some(code) = err.code
                && code.get() != -libc::EEXIST
            {
                return Err(CliError::from(format!(
                    "Received a netlink error message {err}"
                )));
            }
        }
    }

    Ok(())
}

pub(crate) async fn handle_showdump() -> Result<(), CliError> {
    if std::io::stdin().is_terminal() {
        return Err(CliError::from("Can't show route dump from a terminal"));
    }

    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();

    let mut magic_buf = [0u8; 4];
    stdin
        .read_exact(&mut magic_buf)
        .map_err(|e| CliError::from(format!("Failed to read magic: {e}")))?;
    let magic = u32::from_le_bytes(magic_buf);
    if magic != ROUTE_DUMP_MAGIC {
        return Err(CliError::from(format!("Magic mismatch ({magic:#x})")));
    }

    let link_map = std::collections::HashMap::new();

    loop {
        let mut len_buf = [0u8; 4];
        match stdin.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                return Err(CliError::from(format!(
                    "Failed to read nlmsg length: {e}"
                )));
            }
        }
        let nlmsg_len = u32::from_le_bytes(len_buf) as usize;

        let mut buf = Vec::with_capacity(nlmsg_len);
        buf.extend_from_slice(&len_buf);
        buf.resize(nlmsg_len, 0);
        stdin.read_exact(&mut buf[4..]).map_err(|e| {
            CliError::from(format!("Failed to read nlmsg: {e}"))
        })?;

        let nl_msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&buf)
            .map_err(|e| {
            CliError::from(format!("Failed to parse nlmsg: {e}"))
        })?;

        let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(msg)) =
            nl_msg.payload
        else {
            continue;
        };

        let route = parse_nl_msg_to_route(msg, false, &link_map);
        println!("{}", route.gen_string());
    }

    Ok(())
}
