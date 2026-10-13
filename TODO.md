# TODO

## `ip address`

- show: with a `label` filter, omit the link line and its JSON fields like
  iproute2 `print_linkinfo()`, which returns early, and match addresses
  without an `IFA_LABEL` attribute against the interface name -
  `src/ip/address/show.rs`, `src/ip/link/show.rs`
- show: `-j -br` only serializes `link`/`link_index`, `ifname`,
  `operstate` and the brief address entries without family, scope, flags
  and lifetimes - `src/ip/address/show.rs`

