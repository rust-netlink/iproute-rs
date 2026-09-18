# TODO

## `ip link`

- show: implement `-br`/`--brief` output and the matching `-j` JSON shape
  - `src/ip/link/show.rs`, `src/ip/link/cli.rs`

## `ip address`

- show: print the `@NONE`/`@ifN` suffix of the interface name in `-br`
  output - `src/ip/link/show.rs`
- show: omit the `link/...` line of `-4`/`-6` output unless `-d` is used,
  and follow the reduced `-6` link attributes (no qdisc/group/qlen) -
  `src/ip/address/show.rs`
- show: emit an empty JSON object for each address rejected by the
  `scope`, `label`, `to`, flag and `proto` filters -
  `src/ip/address/show.rs`
- show: place the `metric` JSON key right after `prefixlen` -
  `src/ip/address/show.rs`
- show: omit the empty `addr_info` array from `-j -0` output -
  `src/ip/address/show.rs`
- show: reject protocol names for the `proto` filter like iproute2 which
  only accepts numbers - `src/ip/address/show.rs`
