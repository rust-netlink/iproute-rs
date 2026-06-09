# iproute-rs

Rust drop-in replacement for Linux `iproute2`'s `ip` command. Uses
`rtnetlink` for Netlink kernel communication. **WIP** — implements
`ip link show/add` and `ip address show`.

## Build & check

```sh
cargo build                         # debug binary → target/debug/ip
cargo build --release
make check                          # cargo build + sudo cargo test
```

## Test

Tests **require root** (`sudo`) — `.cargo/config.toml` sets
`runner = 'sudo'` on Linux.  They create/modify/delete real kernel
interfaces, so run with care on a dev machine.

The `cargo build` should always be invoked before `cargo test`.

Single test: `cargo test <name>` (runs under sudo automatically).

Integration tests live in `src/ip/{link,address}/tests/`. Pattern:
run the same command against both system `ip` and compiled `ip-rs`,
then compare output via `pretty_assertions`.  All test interface
names use unique prefixes (`tdmy`, `test-br`, `tvlan`, etc.) for
parallel safety.  Bridge timer values are normalized to avoid
kernel-timing flakiness.

## Lint & format

Uses **Rust nightly** for formatting.  CI runs these after
`rustup override set nightly`:

```sh
cargo fmt --all -- --check          # nightly required
cargo clippy -- -D warnings
cargo clippy --tests -- -D warnings
```

## Project structure

Single crate, not a workspace.

| Crate             | Path              | Description                     |
|-------------------|-------------------|---------------------------------|
| `iproute_rs` (lib) | `src/lib.rs`     | Shared: color, error, MAC, ... |
| `ip` (bin)         | `src/ip/main.rs` | CLI entrypoint (clap + tokio)  |

## Key conventions

- **Edition 2024** with 80-column width, `reorder_imports`,
  `group_imports = "StdExternalCrate"`,
  `imports_granularity = "Crate"` (see `.rustfmt.toml`).
- All source files carry `// SPDX-License-Identifier: MIT`.
- `rtnetlink` and `netlink-packet-route` pulled from git via
  `[patch.crates-io]` (not crates.io).
- Async: `#[tokio::main(flavor = "current_thread")]` —
  single-threaded.
- CLI with `clap`; command aliases mirror `iproute2`
  (e.g. `link` → `lin`, `li`, `l`).
- `Cargo.lock` is **not** committed (gitignored).

## Netlink connection pattern

```rust
let (connection, handle, _) = rtnetlink::new_connection()?;
tokio::spawn(connection);
// use handle to send Netlink messages
```

### Notes from developer

 * Netlink attribute parsing and emitting code should be done by other
   rust-netlink crates which are also locally maintained, change code in
   local folder and use local folder temporally before upstream merge.
