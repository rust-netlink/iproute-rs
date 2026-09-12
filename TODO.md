# TODO

## `ip route`

- add/del/change/replace/append/prepend: support `encap ip geneve_opts`,
  `encap ip vxlan_opts`, `encap ip erspan_opts`, `encap ip6 geneve_opts`,
  `encap ip6 vxlan_opts`, `encap ip6 erspan_opts`, `encap seg6 tunsrc`,
  `encap seg6 hmac` and `encap seg6 lookup` — `src/ip/route/add.rs`
- `netlink-packet-route`: support the `geneve_opts`, `vxlan_opts` and
  `erspan_opts` attributes of `LWTUNNEL_IP_OPTS`, and the `tunsrc`, `hmac`
  and `lookup` attributes of `LWTUNNEL_ENCAP_SEG6`

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
