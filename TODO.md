# TODO

## `ip address`

- show: emit an empty JSON object for each address rejected by the
  `scope`, `label`, `to`, flag and `proto` filters -
  `src/ip/address/show.rs`
- show: place the `metric` JSON key right after `prefixlen` -
  `src/ip/address/show.rs`
- show: omit the empty `addr_info` array from `-j -0` output -
  `src/ip/address/show.rs`
- show: reject protocol names for the `proto` filter like iproute2 which
  only accepts numbers - `src/ip/address/show.rs`
