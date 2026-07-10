// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use futures_util::stream::StreamExt;
use rtnetlink::{
    packet_core::{
        NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE,
        NLM_F_REQUEST, NetlinkMessage,
    },
    packet_route::{
        AddressFamily, RouteNetlinkMessage,
        route::{
            RouteAddress, RouteAttribute, RouteMessage, RoutePreference,
            RouteProtocol, RouteScope, RouteType, RouteVia,
        },
    },
};

use super::add::{RouteAddConfig, parse_route_config, resolve_ifindex};
use crate::CliError;

enum RouteModifyOp {
    Add,
    Append,
    Change,
    Prepend,
    Replace,
}

async fn send_route_request(
    mut handle: rtnetlink::Handle,
    msg: RouteMessage,
    op: RouteModifyOp,
) -> Result<(), CliError> {
    let mut nl_msg = NetlinkMessage::from(RouteNetlinkMessage::NewRoute(msg));
    nl_msg.header.flags = match op {
        RouteModifyOp::Add => {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE
        }
        RouteModifyOp::Append => {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_APPEND | NLM_F_CREATE
        }
        RouteModifyOp::Prepend => NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        RouteModifyOp::Change => NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE,
        RouteModifyOp::Replace => {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE
        }
    };

    let mut response = handle
        .request(nl_msg)
        .map_err(|e| CliError::from(format!("{e}")))?;
    while let Some(msg) = response.next().await {
        if let rtnetlink::packet_core::NetlinkPayload::Error(err) = msg.payload
        {
            return Err(CliError::from(format!(
                "Received a netlink error message {err}"
            )));
        }
    }
    Ok(())
}

async fn handle_modify(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
    op: RouteModifyOp,
) -> Result<(), CliError> {
    let config = parse_route_config(opts, preferred_family)?;
    let mut msg = build_route_message(&config)?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    if let Some(ref dev) = config.dev {
        let index = resolve_ifindex(&handle, dev).await?;
        msg.attributes.push(RouteAttribute::Oif(index));
    }

    let need_onlink = config.onlink
        || (msg.header.scope == RouteScope::Link && config.via.is_some());
    if need_onlink {
        msg.header.flags |= rtnetlink::packet_route::route::RouteFlags::Onlink;
    }

    send_route_request(handle, msg, op).await
}

pub(crate) fn build_route_message(
    config: &RouteAddConfig,
) -> Result<RouteMessage, CliError> {
    let mut msg = RouteMessage::default();

    let family = config.family.unwrap_or(AddressFamily::Inet);
    msg.header.address_family = family;

    msg.header.protocol = RouteProtocol::Boot;
    msg.header.scope = RouteScope::Universe;
    msg.header.kind = RouteType::Unicast;
    msg.header.table = 254;

    if let Some(proto) = config.protocol {
        msg.header.protocol = proto;
    }
    if let Some(scope) = config.scope {
        msg.header.scope = scope;
    }
    if let Some(kind) = config.kind {
        msg.header.kind = kind;
    }
    if let Some(table) = config.table {
        if table > 255 {
            msg.attributes.push(RouteAttribute::Table(table));
        } else {
            msg.header.table = table as u8;
        }
    }

    if let Some(ref addr) = config.dst {
        msg.header.destination_prefix_length = config.dst_len;
        let rta = match addr {
            IpAddr::V4(a) => {
                RouteAttribute::Destination(RouteAddress::Inet(*a))
            }
            IpAddr::V6(a) => {
                RouteAttribute::Destination(RouteAddress::Inet6(*a))
            }
        };
        msg.attributes.push(rta);
    }

    if let Some(ref addr) = config.src {
        msg.header.source_prefix_length = config.src_len;
        let rta = match addr {
            IpAddr::V4(a) => RouteAttribute::Source(RouteAddress::Inet(*a)),
            IpAddr::V6(a) => RouteAttribute::Source(RouteAddress::Inet6(*a)),
        };
        msg.attributes.push(rta);
    }

    if let Some(ref addr) = config.via {
        let use_via = matches!(
            (family, addr),
            (AddressFamily::Inet, IpAddr::V6(_))
                | (AddressFamily::Inet6, IpAddr::V4(_))
        );
        let rta = if use_via {
            match addr {
                IpAddr::V4(a) => RouteAttribute::Via(RouteVia::Inet(*a)),
                IpAddr::V6(a) => RouteAttribute::Via(RouteVia::Inet6(*a)),
            }
        } else {
            match addr {
                IpAddr::V4(a) => {
                    RouteAttribute::Gateway(RouteAddress::Inet(*a))
                }
                IpAddr::V6(a) => {
                    RouteAttribute::Gateway(RouteAddress::Inet6(*a))
                }
            }
        };
        msg.attributes.push(rta);
    }

    if let Some(ref addr) = config.prefsrc {
        let rta = match addr {
            IpAddr::V4(a) => RouteAttribute::PrefSource(RouteAddress::Inet(*a)),
            IpAddr::V6(a) => {
                RouteAttribute::PrefSource(RouteAddress::Inet6(*a))
            }
        };
        msg.attributes.push(rta);
    }

    if let Some(m) = config.metric {
        msg.attributes.push(RouteAttribute::Priority(m));
    }

    if let Some(e) = config.expires {
        msg.attributes.push(RouteAttribute::Expires(e));
    }

    #[cfg(not(target_os = "android"))]
    if let Some(m) = config.mark {
        msg.attributes.push(RouteAttribute::Mark(m));
    }

    if let Some(u) = config.uid {
        msg.attributes.push(RouteAttribute::Uid(u));
    }

    if let Some(p) = config.preference {
        msg.attributes
            .push(RouteAttribute::Preference(RoutePreference::from(p)));
    }

    let kind = msg.header.kind;
    let scope_set = config.scope.is_some();
    if (kind == RouteType::Local || kind == RouteType::Nat) && !scope_set {
        msg.header.scope = RouteScope::Host;
    } else if (kind == RouteType::Broadcast
        || kind == RouteType::Multicast
        || kind == RouteType::Anycast
        || (kind == RouteType::Unicast || kind == RouteType::Unspec)
            && config.via.is_none()
            && config.dev.is_none()
            && config.preference.is_none())
        && !scope_set
    {
        msg.header.scope = RouteScope::Link;
    }

    if (kind == RouteType::Local
        || kind == RouteType::Broadcast
        || kind == RouteType::Nat
        || kind == RouteType::Anycast)
        && config.table.is_none()
    {
        msg.header.table = 255;
    }

    Ok(msg)
}

pub(crate) async fn handle_modify_add(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Add).await
}

pub(crate) async fn handle_modify_append(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Append).await
}

pub(crate) async fn handle_modify_change(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Change).await
}

pub(crate) async fn handle_modify_prepend(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Prepend).await
}

pub(crate) async fn handle_modify_replace(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    handle_modify(opts, preferred_family, RouteModifyOp::Replace).await
}
