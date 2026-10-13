# TODO

## `ip address`

- show: with a `label` filter, omit the link line and its JSON fields like
  iproute2 `print_linkinfo()`, which returns early, and match addresses
  without an `IFA_LABEL` attribute against the interface name -
  `src/ip/address/show.rs`, `src/ip/link/show.rs`
- show: `-j -br` only serializes `link`/`link_index`, `ifname`,
  `operstate` and the brief address entries without family, scope, flags
  and lifetimes - `src/ip/address/show.rs`
- show: omit the empty `addr_info` array from `-j -0` output -
  `src/ip/address/show.rs`
- show: reject protocol names for the `proto` filter like iproute2 which
  only accepts numbers - `src/ip/address/show.rs`
