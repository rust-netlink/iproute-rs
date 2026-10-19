// SPDX-License-Identifier: MIT

const DEFAULT_ERROR_CODE: i32 = 1;

#[derive(Debug, Default)]
pub struct CliError {
    pub code: i32,
    pub msg: String,
}

impl From<String> for CliError {
    fn from(msg: String) -> Self {
        Self {
            code: DEFAULT_ERROR_CODE,
            msg,
        }
    }
}

impl From<&str> for CliError {
    fn from(msg: &str) -> Self {
        Self {
            code: DEFAULT_ERROR_CODE,
            msg: msg.into(),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError {
            code: DEFAULT_ERROR_CODE,
            msg: format!("std::io::Error: {e}"),
        }
    }
}

impl From<rtnetlink::Error> for CliError {
    fn from(e: rtnetlink::Error) -> Self {
        // iproute2 exits with code 2 for kernel/netlink errors
        CliError {
            code: 2,
            msg: format!("rtnetlink::Error: {e}"),
        }
    }
}

impl From<nl_l2tp::L2tpError> for CliError {
    fn from(e: nl_l2tp::L2tpError) -> Self {
        // iproute2 exits with code 2 for the kernel error of a request and
        // with code 1 for invalid arguments rejected before the request is
        // sent or for a failed generic netlink family resolution.
        let code = match e.kind {
            nl_l2tp::ErrorKind::InvalidInput => 1,
            nl_l2tp::ErrorKind::NetlinkError
                if e.msg.starts_with("Netlink request failed") =>
            {
                1
            }
            _ => 2,
        };
        CliError {
            code,
            msg: format!("nl_l2tp::Error: {e}"),
        }
    }
}

impl From<nl_fou::FouError> for CliError {
    fn from(e: nl_fou::FouError) -> Self {
        // iproute2 exits with code 2 for the kernel error of a request and
        // with code 1 for invalid arguments rejected before the request is
        // sent or for a failed `genl_init_handle()`.
        //
        // `nl-fou` wraps a failed generic netlink family resolution, e.g.
        // the `fou` module is not loaded, as a netlink request failure,
        // while the kernel replies to an actual request use the
        // `Netlink error:` prefix.
        let code = match e.kind {
            nl_fou::ErrorKind::InvalidInput => 1,
            nl_fou::ErrorKind::NetlinkError
                if e.msg.starts_with("Netlink request failed") =>
            {
                1
            }
            _ => 2,
        };
        CliError {
            code,
            msg: format!("nl_fou::Error: {e}"),
        }
    }
}

impl From<nl_macsec::MacsecError> for CliError {
    fn from(e: nl_macsec::MacsecError) -> Self {
        // iproute2 exits with code 2 for a kernel error and with code 1 for
        // invalid arguments rejected before the request is sent or for a
        // failed generic netlink family resolution.
        let code = match e.kind {
            nl_macsec::ErrorKind::InvalidInput => 1,
            nl_macsec::ErrorKind::NetlinkError
                if e.msg.starts_with("Netlink request failed") =>
            {
                1
            }
            _ => 2,
        };
        CliError {
            code,
            msg: format!("nl_macsec::Error: {e}"),
        }
    }
}
