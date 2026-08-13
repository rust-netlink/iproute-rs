# TODO

## `ip route`

- add/del/change/replace/append/prepend: support metric options (`mtu`,
  `advmss`, `rtt`, `rttvar`, `reordering`, `window`, `cwnd`, `initcwnd`,
  `initrwnd`, `ssthresh`, `hoplimit`, `rto_min`, `features`, `quickack`,
  `congctl`, `fastopen_no_cookie`, `realms`, `as`) — `src/ip/route/add.rs`
- add/del/change/replace/append/prepend: support multipath (`nexthop ...`,
  `weight`), `nhid ID`, and the `pervasive` next-hop flag —
  `src/ip/route/add.rs`, `src/ip/route/modify.rs`
- add/del/change/replace/append/prepend: support `tos TOS` and
  `ttl-propagate` in NODE_SPEC
- add/del/change/replace/append/prepend: support `encap`
  (`mpls | ip | ip6 | seg6 | seg6local | rpl | ioam6 | xfrm`)
- add/del/change/replace/append/prepend: accept TIME values with `s`/`ms`
  suffix (e.g. `expires 300s`)
- get: support `vrf NAME` and `as ADDRESS` — `src/ip/route/get.rs`
- show/flush selectors: support `root PREFIX`, `match PREFIX`,
  `exact PREFIX`, and `vrf NAME` — `src/ip/route/show.rs`
  (`RouteShowFilter::parse`)
- show: display metrics, `expires`, `nhid`, `encap`, `realms`,
  `ipproto`/`sport`/`dport`/`flowlabel`; populate `ttl_propagate` from the
  dump — `src/ip/route/show.rs` (`parse_nl_msg_to_route`)
- tests: add coverage for the above (`tests/ip_route*.rs`)

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
