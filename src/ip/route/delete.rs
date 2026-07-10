// SPDX-License-Identifier: MIT

use rtnetlink::packet_route::{AddressFamily, route::RouteAttribute};

use super::{
    add::{parse_route_config, resolve_ifindex},
    modify::build_route_message,
};
use crate::CliError;

pub(crate) async fn handle_delete(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    let config = parse_route_config(opts, preferred_family)?;
    let mut msg = build_route_message(&config)?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    if let Some(ref dev) = config.dev {
        let index = resolve_ifindex(&handle, dev).await?;
        msg.attributes.push(RouteAttribute::Oif(index));
    }

    handle
        .route()
        .del(msg)
        .execute()
        .await
        .map_err(|e| CliError::from(format!("{e}")))?;

    Ok(())
}
