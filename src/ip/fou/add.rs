// SPDX-License-Identifier: MIT

use std::{
    ffi::{CStr, CString},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use iproute_rs::CliError;
use nl_fou::{FouAddressFamily, FouConfig, FouEncap};
use rtnetlink::packet_route::AddressFamily;

pub(crate) async fn handle_add(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    let config = parse_fou_opts(opts, preferred_family, true)?;
    send(&config, true).await
}

pub(crate) async fn handle_delete(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
) -> Result<(), CliError> {
    let config = parse_fou_opts(opts, preferred_family, false)?;
    send(&config, false).await
}

async fn send(config: &FouConfig, adding: bool) -> Result<(), CliError> {
    let (connection, mut handle, _) = nl_fou::new_connection()?;
    tokio::spawn(connection);
    if adding {
        handle.add(config).await?;
    } else {
        handle.delete(config).await?;
    }
    Ok(())
}

fn parse_fou_opts(
    opts: &[String],
    preferred_family: Option<AddressFamily>,
    adding: bool,
) -> Result<FouConfig, CliError> {
    let mut family = fou_family(preferred_family);
    let mut port: Option<u16> = None;
    let mut ipproto: Option<u8> = None;
    let mut gue_set = false;
    let mut local: Option<&str> = None;
    let mut peer: Option<&str> = None;
    let mut peer_port: Option<u16> = None;
    let mut ifindex: Option<i32> = None;

    let mut iter = opts.iter();
    while let Some(arg) = iter.next() {
        let arg = arg.as_str();
        if matches(arg, "port") {
            let val = next_value(&mut iter)?;
            port = Some(
                parse_u16_base0(val)
                    .filter(|port| *port != 0)
                    .ok_or_else(|| invarg(val, "invalid port"))?,
            );
        } else if matches(arg, "ipproto") {
            let val = next_value(&mut iter)?;
            ipproto = Some(
                parse_ipproto(val)
                    .ok_or_else(|| invarg(val, "invalid ipproto"))?,
            );
        } else if matches(arg, "gue") {
            gue_set = true;
        } else if matches(arg, "-6") {
            family = FouAddressFamily::Ipv6;
        } else if matches(arg, "local") {
            local = Some(next_value(&mut iter)?);
        } else if matches(arg, "peer") {
            peer = Some(next_value(&mut iter)?);
        } else if matches(arg, "peer_port") {
            let val = next_value(&mut iter)?;
            peer_port = Some(
                parse_u16_base0(val)
                    .filter(|port| *port != 0)
                    .ok_or_else(|| invarg(val, "invalid peer port"))?,
            );
        } else if matches(arg, "dev") {
            let val = next_value(&mut iter)?;
            ifindex = Some(resolve_ifindex(val)?);
        } else {
            return Err(CliError {
                code: 255,
                msg: format!(
                    "fou: unknown command \"{arg}\"?\n{}",
                    super::cli::USAGE
                ),
            });
        }
    }

    // iproute2 warns about the following problems but sends the request
    // anyway, the kernel then rejects it with `EINVAL` and the command
    // exits with the kernel error code 2.
    let Some(port) = port else {
        return Err(semantic_error("fou: missing port"));
    };
    if ipproto.is_none() && !gue_set && adding {
        return Err(semantic_error("fou: must set ipproto or gue"));
    }
    if ipproto.is_some() && gue_set {
        return Err(semantic_error("fou: cannot set ipproto and gue"));
    }
    if peer_port.is_some() != peer.is_some() {
        return Err(semantic_error("fou: both peer and peer port must be set"));
    }

    // iproute2 parses the addresses after the option loop, therefore an
    // inline `-6` written behind them still selects the address family.
    let local = local.map(|s| parse_addr(s, family)).transpose()?;
    let peer = peer.map(|s| parse_addr(s, family)).transpose()?;

    let mut config = FouConfig::new(port);
    config.family = Some(family);
    config.encap = Some(if gue_set {
        FouEncap::Gue
    } else {
        FouEncap::Direct
    });
    config.ipproto = ipproto;
    config.local = local;
    config.peer = peer;
    config.peer_port = peer_port;
    config.ifindex = ifindex;
    Ok(config)
}

/// iproute2 `matches()`: the argument must be a non-empty prefix of the
/// keyword.
fn matches(arg: &str, keyword: &str) -> bool {
    !arg.is_empty() && keyword.starts_with(arg)
}

fn next_value<'a>(
    iter: &mut std::slice::Iter<'a, String>,
) -> Result<&'a str, CliError> {
    iter.next().map(|s| s.as_str()).ok_or_else(|| CliError {
        code: 255,
        msg: "Command line is not complete. Try option \"help\"".to_string(),
    })
}

/// iproute2 `invarg()` exits with the code 255.
fn invarg(value: &str, msg: &str) -> CliError {
    CliError {
        code: 255,
        msg: format!("Error: argument \"{value}\" is wrong: {msg}"),
    }
}

fn semantic_error(msg: &str) -> CliError {
    CliError {
        code: 2,
        msg: msg.to_string(),
    }
}

/// iproute2 uses the preferred family for FOU, IPv4 by default.
fn fou_family(preferred_family: Option<AddressFamily>) -> FouAddressFamily {
    match preferred_family {
        None | Some(AddressFamily::Unspec) => FouAddressFamily::Ipv4,
        Some(AddressFamily::Inet) => FouAddressFamily::Ipv4,
        Some(AddressFamily::Inet6) => FouAddressFamily::Ipv6,
        Some(family) => FouAddressFamily::Other(u8::from(family)),
    }
}

/// iproute2 `get_u16(&val, arg, 0)` and `get_addr_ipv4()` parse numbers
/// with `strtoul(..., 0)`: `0x` hexadecimal and leading `0` octal numbers
/// are accepted.
fn parse_u64_base0(s: &str) -> Option<u64> {
    let (radix, digits) = if let Some(hex) =
        s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
    {
        (16, hex)
    } else if s.len() > 1 && s.starts_with('0') {
        (8, &s[1..])
    } else {
        (10, s)
    };
    u64::from_str_radix(digits, radix).ok()
}

fn parse_u16_base0(s: &str) -> Option<u16> {
    parse_u64_base0(s).and_then(|value| u16::try_from(value).ok())
}

/// iproute2 resolves the protocol name with `getprotobyname()` first and
/// falls back to `get_u8()`, zero is rejected either way.
fn parse_ipproto(s: &str) -> Option<u8> {
    if let Some(ipproto) = protocol_by_name(s) {
        return Some(ipproto);
    }
    parse_u16_base0(s)
        .filter(|ipproto| *ipproto != 0 && *ipproto <= u8::MAX as u16)
        .map(|ipproto| ipproto as u8)
}

fn protocol_by_name(name: &str) -> Option<u8> {
    let name = CString::new(name).ok()?;
    // SAFETY: `getprotobyname()` returns NULL or a valid `protoent` which
    // stays valid until the next call.
    let protoent = unsafe { libc::getprotobyname(name.as_ptr()) };
    if protoent.is_null() {
        return None;
    }
    let ipproto = unsafe { (*protoent).p_proto };
    (0..=u8::MAX as i32)
        .contains(&ipproto)
        .then_some(ipproto as u8)
}

/// iproute2 `get_addr()`: `default` is the unspecified address, the
/// keywords `all` and `any` become an empty attribute which the kernel
/// rejects, and IPv4 addresses use the legacy notation of
/// `get_addr_ipv4()`, not `inet_pton()`.
fn parse_addr(s: &str, family: FouAddressFamily) -> Result<IpAddr, CliError> {
    if s == "all" || s == "any" {
        return Err(policy_validation_error());
    }
    match family {
        FouAddressFamily::Ipv4 => {
            if s == "default" {
                Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            } else {
                parse_ipv4_addr(s)
                    .map(IpAddr::V4)
                    .ok_or_else(|| addr_error(family, s))
            }
        }
        FouAddressFamily::Ipv6 => {
            if s == "default" {
                Ok(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
            } else {
                s.parse::<Ipv6Addr>()
                    .map(IpAddr::V6)
                    .map_err(|_| addr_error(family, s))
            }
        }
        _ => Err(if s == "default" {
            policy_validation_error()
        } else {
            addr_error(family, s)
        }),
    }
}

/// iproute2 `get_addr_ipv4()`: up to four dot separated parts, each of
/// them parsed with `strtoul(..., 0)`, the missing parts stay zero. It is
/// not `inet_pton()`: `127.1` becomes `127.1.0.0` and `0x7f.1` becomes
/// `127.1.0.0`.
fn parse_ipv4_addr(s: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    for (count, part) in s.split('.').enumerate() {
        if count == 4 {
            return None;
        }
        octets[count] = u8::try_from(parse_u64_base0(part)?).ok()?;
    }
    Some(Ipv4Addr::from(octets))
}

/// iproute2 sends the empty address attribute of `all` and `any`, the
/// kernel rejects it with this message and the command exits with the
/// kernel error code 2.
fn policy_validation_error() -> CliError {
    CliError {
        code: 2,
        msg: "Error: Attribute failed policy validation.".to_string(),
    }
}

/// iproute2 `get_addr()` exits with the code 1 for an unparsable
/// address.
fn addr_error(family: FouAddressFamily, arg: &str) -> CliError {
    CliError {
        code: 1,
        msg: format!(
            "Error: {} address is expected rather than \"{arg}\".",
            family_name_verbose(family)
        ),
    }
}

/// iproute2 `family_name()` for the families the global options accept.
fn family_name_verbose(family: FouAddressFamily) -> &'static str {
    match family {
        FouAddressFamily::Ipv4 => "inet",
        FouAddressFamily::Ipv6 => "inet6",
        FouAddressFamily::Other(family) if family == libc::AF_BRIDGE as u8 => {
            "bridge"
        }
        FouAddressFamily::Other(family) if family == libc::AF_PACKET as u8 => {
            "link"
        }
        FouAddressFamily::Other(family) if family == libc::AF_MPLS as u8 => {
            "mpls"
        }
        _ => "???",
    }
}

/// iproute2 `ll_name_to_index()` exits when the device does not exist.
fn resolve_ifindex(dev: &str) -> Result<i32, CliError> {
    let name = CString::new(dev)
        .map_err(|_| CliError::from("fou: invalid device name"))?;
    // SAFETY: `if_nametoindex()` only reads the provided C string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(CliError::from("fou: unknown device name"));
    }
    Ok(index as i32)
}

/// iproute2 `ll_index_to_name()` falls back to `if%u` when the interface
/// index is unknown, e.g. the device was removed after the listener was
/// added.
pub(crate) fn index_to_name(index: i32) -> Option<String> {
    if index <= 0 {
        return None;
    }
    let index = index as u32;
    let mut buf = [0i8; libc::IF_NAMESIZE];
    // SAFETY: `if_indextoname()` writes at most `IF_NAMESIZE` bytes into
    // `buf`.
    let ptr = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return Some(format!("if{index}"));
    }
    // SAFETY: `if_indextoname()` returned a pointer to the NUL terminated
    // name inside `buf`.
    let name = unsafe { CStr::from_ptr(ptr) };
    Some(name.to_string_lossy().into_owned())
}
