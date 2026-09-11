// SPDX-License-Identifier: MIT

use rtnetlink::packet_route::AddressFamily;

use super::{
    add::{parse_route_config, resolve_route_ifindexes},
    modify::build_route_message,
};
use crate::CliError;

pub(crate) async fn handle_delete(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    let config = parse_route_config(opts, preferred_family)?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let ifindexes = resolve_route_ifindexes(&handle, &config).await?;
    let msg = build_route_message(&config, &ifindexes)?;

    handle
        .route()
        .del(msg)
        .execute()
        .await
        .map_err(|e| CliError::from(format!("{e}")))?;

    Ok(())
}
