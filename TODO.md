# TODO

## `ip address`

- show: implement `-o`/`--oneline` output — `src/ip/address/show.rs`
- show: implement `-s`/`--stats` RX/TX statistics output —
  `src/ip/address/show.rs`
- show: accept the `-br` short flag (brief output works via `--brief`, but
  `-br` is rejected by clap) — `src/ip/main.rs`
- show: format unknown numeric address protocols like iproute2 (`proto 0x63`,
  not `proto 99`) — `src/ip/address/show.rs`
