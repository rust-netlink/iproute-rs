// SPDX-License-Identifier: MIT

mod netns;

pub(crate) use self::netns::{NetnsGuard, with_netns};
