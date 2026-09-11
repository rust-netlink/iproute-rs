# TODO

## `ip route`

- add/del/change/replace/append/prepend: support `encap`
  (`mpls | ip | ip6 | seg6 | seg6local | rpl | ioam6 | xfrm`)
  — `src/ip/route/add.rs`, `src/ip/route/modify.rs`
- `netlink-packet-route`: support `LWTUNNEL_ENCAP_SEG6_LOCAL`,
  `LWTUNNEL_ENCAP_RPL` and `LWTUNNEL_ENCAP_IOAM6` encapsulation
- `rtnetlink`: build a connection with `NETLINK_GET_STRICT_CHK` enabled so
  that unsupported attributes of `ip route get as ADDRESS` are rejected
  like iproute2 — `src/ip/route/get.rs`
- add/del/change/replace/prepend: parse and emit MPLS routes —
  `src/ip/route/add.rs`, `src/ip/route/modify.rs`

## `ip link`

- show: implement `-o`/`--oneline` output — `src/ip/link/show.rs` (also
  applies to address/neighbour/route show)
- show: implement `-s`/`--stats` RX/TX statistics output —
  `src/ip/link/show.rs`
- add/set: audit per-type options against `ip link add type <TYPE> help`
  (candidates: vxlan, bond, bridge)

## `ip address`

- show: implement `-o`/`--oneline` output — `src/ip/address/show.rs`
- show: implement `-s`/`--stats` RX/TX statistics output —
  `src/ip/address/show.rs`
- show: accept the `-br` short flag (brief output works via `--brief`, but
  `-br` is rejected by clap) — `src/ip/main.rs`
- show: format unknown numeric address protocols like iproute2 (`proto 0x63`,
  not `proto 99`) — `src/ip/address/show.rs`
