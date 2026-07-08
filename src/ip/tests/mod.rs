// SPDX-License-Identifier: MIT

mod netns;

pub(crate) use self::netns::{CmdOutput, NetnsGuard, with_netns};
