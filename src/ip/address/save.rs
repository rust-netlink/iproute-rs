// SPDX-License-Identifier: MIT

use std::io::{IsTerminal, Read, Write};

use futures_util::{TryStreamExt, stream::StreamExt};
use iproute_rs::CanDisplay;
use rtnetlink::{
    packet_core::{
        NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
    },
    packet_route::RouteNetlinkMessage,
};

use super::show::parse_nl_msg_to_address;
use crate::CliError;

const IPADD_DUMP_MAGIC: u32 = 0x47361222;

pub(crate) async fn handle_save() -> Result<(), CliError> {
    if std::io::stdout().is_terminal() {
        return Err(CliError::from("Not sending a binary stream to stdout"));
    }

    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    stdout
        .write_all(&IPADD_DUMP_MAGIC.to_le_bytes())
        .map_err(|e| {
            CliError::from(format!("Can't write magic to dump file: {e}"))
        })?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut addresses = handle.address().get().execute();
    while let Some(msg) = addresses.try_next().await? {
        let mut nl_msg =
            NetlinkMessage::from(RouteNetlinkMessage::NewAddress(msg));
        nl_msg.finalize();
        let len = nl_msg.buffer_len();
        let mut buf = vec![0u8; len];
        nl_msg.serialize(&mut buf);
        stdout.write_all(&buf).map_err(|e| {
            CliError::from(format!("Short write while saving nlmsg: {e}"))
        })?;
    }

    Ok(())
}

pub(crate) async fn handle_restore() -> Result<(), CliError> {
    if std::io::stdin().is_terminal() {
        return Err(CliError::from(
            "Can't restore address dump from a terminal",
        ));
    }

    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();

    let mut magic_buf = [0u8; 4];
    stdin
        .read_exact(&mut magic_buf)
        .map_err(|e| CliError::from(format!("Failed to read magic: {e}")))?;
    let magic = u32::from_le_bytes(magic_buf);
    if magic != IPADD_DUMP_MAGIC {
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

        // Don't send NLMSG_DONE or other control messages
        if !matches!(
            msg.payload,
            rtnetlink::packet_core::NetlinkPayload::InnerMessage(
                RouteNetlinkMessage::NewAddress(_)
            )
        ) {
            continue;
        }

        msg.header.flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;

        let mut response = handle
            .request(msg)
            .map_err(|e| CliError::from(format!("{e}")))?;
        while let Some(resp) = response.next().await {
            if let rtnetlink::packet_core::NetlinkPayload::Error(err) =
                resp.payload
            {
                // EEXIST is not an error for restore
                if let Some(code) = err.code
                    && code.get() != -libc::EEXIST
                {
                    return Err(CliError::from(format!(
                        "Received a netlink error message {err}"
                    )));
                }
            }
        }
    }

    Ok(())
}

pub(crate) async fn handle_showdump() -> Result<(), CliError> {
    if std::io::stdin().is_terminal() {
        return Err(CliError::from(
            "Can't restore address dump from a terminal",
        ));
    }

    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();

    let mut magic_buf = [0u8; 4];
    stdin
        .read_exact(&mut magic_buf)
        .map_err(|e| CliError::from(format!("Failed to read magic: {e}")))?;
    let magic = u32::from_le_bytes(magic_buf);
    if magic != IPADD_DUMP_MAGIC {
        return Err(CliError::from(format!("Magic mismatch ({magic:#x})")));
    }

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

        let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(msg)) =
            nl_msg.payload
        else {
            continue;
        };

        let addr_info = parse_nl_msg_to_address(msg)?;
        println!("{}", addr_info.gen_string());
    }

    Ok(())
}

pub(crate) async fn handle_flush(opts: &[String]) -> Result<(), CliError> {
    let mut dev: Option<String> = None;
    let mut iter = opts.iter();
    while let Some(key) = iter.next() {
        match key.as_str() {
            "dev" => {
                dev = Some(
                    iter.next()
                        .ok_or_else(|| {
                            CliError::from("\"dev\" argument requires a value")
                        })?
                        .clone(),
                );
            }
            _ => {
                return Err(CliError::from(format!("unknown argument: {key}")));
            }
        }
    }

    let (connection, mut handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let max_rounds: u32 = 10;
    let mut round = 0u32;

    loop {
        if max_rounds > 0 && round >= max_rounds {
            break;
        }

        let mut addr_get = handle.address().get();
        if let Some(ref name) = dev {
            let mut links =
                handle.link().get().match_name(name.clone()).execute();
            let link = links.try_next().await?.ok_or_else(|| {
                CliError::from(format!("Device \"{name}\" does not exist"))
            })?;
            addr_get = addr_get.set_link_index_filter(link.header.index);
        }

        let mut addresses = addr_get.execute();
        let mut flushed_in_round = 0u32;
        while let Some(address) = addresses.try_next().await? {
            let mut nl_msg =
                NetlinkMessage::from(RouteNetlinkMessage::DelAddress(address));
            nl_msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

            let mut response = handle
                .request(nl_msg)
                .map_err(|e| CliError::from(format!("{e}")))?;
            let mut deleted = false;
            while let Some(resp) = response.next().await {
                if let NetlinkPayload::Error(err) = resp.payload {
                    if let Some(code) = err.code
                        && code.get() == -libc::EADDRNOTAVAIL
                    {
                        break;
                    }
                    return Err(CliError::from(format!(
                        "Received a netlink error message {err}"
                    )));
                }
                deleted = true;
            }
            if deleted {
                flushed_in_round += 1;
            }
        }

        if flushed_in_round == 0 {
            if round == 0 {
                eprintln!("Nothing to flush.");
            }
            break;
        }

        round += 1;
        eprintln!(
            "*** Round {round}, deleting {flushed_in_round} addresses ***"
        );
    }

    if round > 0 {
        eprintln!(
            "*** Flush is complete after {round} round{} ***",
            if round > 1 { "s" } else { "" }
        );
    }

    Ok(())
}
