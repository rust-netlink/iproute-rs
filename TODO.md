# TODO

## `ip address`

- show: `-j -br` only serializes `link`/`link_index`, `ifname`,
  `operstate` and the brief address entries without family, scope, flags
  and lifetimes - `src/ip/address/show.rs`

## Build

- clippy: fix the warnings of the current nightly toolchain:
  `unnecessary_as_slice` in `src/ip/link/add.rs`,
  `src/ip/link/ifaces/vlan.rs` and `src/ip/link/show.rs`, and
  `needless_borrows_for_generic_args` in `src/ip/link/ifaces/vti.rs`

