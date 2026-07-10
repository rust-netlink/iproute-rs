// SPDX-License-Identifier: MIT

use std::{collections::HashMap, time::Instant};

use futures_util::TryStreamExt;
use rtnetlink::packet_route::{AddressFamily, route::RouteMessage};

use super::show::{RouteShowFilter, parse_nl_msg_to_route};
use crate::CliError;

pub(crate) async fn handle_flush(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
    show_stats: bool,
) -> Result<(), CliError> {
    let opts_refs: Vec<&str> = opts.iter().map(String::as_str).collect();
    let (filter, _link_opts) = RouteShowFilter::parse(&opts_refs)?;
    drop(opts_refs);

    if opts.is_empty() {
        return Err(CliError::from("\"ip route flush\" requires arguments."));
    }

    let show_all_tables = filter.tb == Some(0);
    let filter_family = if show_all_tables && preferred_family.is_none() {
        None
    } else {
        Some(preferred_family.unwrap_or(AddressFamily::Inet))
    };

    let start = Instant::now();
    let mut round = 0u32;

    loop {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        let mut link_map: HashMap<u32, String> = HashMap::new();
        let mut links = handle.link().get().execute();
        while let Ok(Some(link)) = links.try_next().await {
            let ifname = link
                .attributes
                .iter()
                .find_map(|attr| {
                    if let rtnetlink::packet_route::link::LinkAttribute::IfName(
                        name,
                    ) = attr
                    {
                        Some(name.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| format!("if{}", link.header.index));
            link_map.insert(link.header.index, ifname);
        }

        let msg = RouteMessage::default();
        let mut routes = handle.route().get(msg).execute();

        let mut to_delete: Vec<RouteMessage> = Vec::new();

        while let Ok(Some(nl_msg)) = routes.try_next().await {
            if let Some(fam) = filter_family
                && nl_msg.header.address_family != fam
            {
                continue;
            }

            let route = parse_nl_msg_to_route(nl_msg.clone(), false, &link_map);

            let is_main_table = matches!(
                route.table.as_deref(),
                None | Some("main") | Some("254") | Some("unspec") | Some("0")
            );
            if !show_all_tables && !is_main_table {
                continue;
            }

            if filter.matches(&route) {
                to_delete.push(nl_msg);
            }
        }

        if to_delete.is_empty() {
            if show_stats {
                if round == 0 {
                    eprintln!("Nothing to flush.");
                } else {
                    eprintln!(
                        "*** Flush is complete after {round} round{} ***",
                        if round > 1 { "s" } else { "" },
                    );
                }
            }
            return Ok(());
        }

        round += 1;
        let count = to_delete.len() as u64;

        for route_msg in to_delete {
            handle
                .route()
                .del(route_msg)
                .execute()
                .await
                .map_err(|e| CliError::from(format!("{e}")))?;
        }

        if start.elapsed().as_secs() > 30 {
            eprintln!(
                "*** Flush not completed after 30 seconds, {} entries remain \
                 ***",
                count,
            );
            return Err(CliError::from("Flush timeout"));
        }

        if show_stats {
            eprintln!("*** Round {round}, deleting {count} entries ***",);
        }
    }
}
