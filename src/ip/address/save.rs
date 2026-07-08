// SPDX-License-Identifier: MIT

use std::io::{IsTerminal, Read, Write};

use futures_util::stream::StreamExt;
use futures_util::TryStreamExt;
use rtnetlink::packet_core::{
    NetlinkMessage, NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST,
};
use rtnetlink::packet_route::RouteNetlinkMessage;

use crate::CliError;

const IPADD_DUMP_MAGIC: u32 = 0x47361222;

pub(crate) async fn handle_save() -> Result<(), CliError> {
    if std::io::stdout().is_terminal() {
        return Err(CliError::from(
            "Not sending a binary stream to stdout",
        ));
    }

    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    stdout
        .write_all(&IPADD_DUMP_MAGIC.to_le_bytes())
        .map_err(|e| CliError::from(format!("Can't write magic to dump file: {e}")))?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut addresses = handle.address().get().execute();
    while let Some(msg) = addresses.try_next().await? {
        let mut nl_msg =
            NetlinkMessage::from(RouteNetlinkMessage::NewAddress(msg));
        nl_msg.header.length = nl_msg.buffer_len() as u32;
        let len = nl_msg.buffer_len();
        let mut buf = vec![0u8; len];
        nl_msg.serialize(&mut buf);
        stdout
            .write_all(&buf)
            .map_err(|e| CliError::from(format!("Short write while saving nlmsg: {e}")))?;
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
        return Err(CliError::from(format!(
            "Magic mismatch ({magic:#x})"
        )));
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
        stdin
            .read_exact(&mut buf[4..])
            .map_err(|e| CliError::from(format!("Failed to read nlmsg: {e}")))?;

        let nl_msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&buf)
            .map_err(|e| CliError::from(format!("Failed to parse nlmsg: {e}")))?;

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

        let mut response = handle.request(msg).map_err(|e| {
            CliError::from(format!("{e}"))
        })?;
        while let Some(resp) = response.next().await {
            if let rtnetlink::packet_core::NetlinkPayload::Error(err) = resp.payload
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
