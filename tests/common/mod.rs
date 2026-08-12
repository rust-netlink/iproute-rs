// SPDX-License-Identifier: MIT

#[allow(dead_code)]
mod dummy;
#[allow(dead_code)]
mod netns;

#[allow(unused_imports)]
pub(crate) use self::dummy::{
    DUMMY_NAME, with_dummy_iface_empty, with_dummy_iface_static_ip,
};
#[allow(unused_imports)]
pub(crate) use self::netns::{NetnsGuard, with_netns};
