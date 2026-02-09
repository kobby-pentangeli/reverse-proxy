# reverse-proxy

An HTTP reverse proxy built on [hyper](https://hyper.rs/) and [tokio](https://tokio.rs/). Accepts client connections, applies policy (header/parameter blocking, sensitive data masking), forwards requests to upstream backends, and streams responses back.

## Quick Start

- Requires [Rust](https://www.rust-lang.org/tools/install) 1.85 or later (with `rustup`)
- Cargo (comes with Rust)

1. Clone the repo:

```bash
git clone https://github.com/kobby-pentangeli/reverse-proxy.git
cd reverse-proxy
```

2. Configure `Config.yml` at the project root:

```yaml
upstream: "http://localhost:3000"
blocked_headers:
  - User-Agent
  - X-Forwarded-For
blocked_params:
  - access_token
  - secret_key
masked_params:
  - password
  - ssn
  - credit_card
```

3. Run the proxy:

```bash
cargo run --release
```

4. Send a request:

```bash
curl -i http://127.0.0.1:8100/
```

The proxy listens on `127.0.0.1:8100` and forwards to the configured `upstream`.

## Development

```bash
cargo build                                                # debug build
cargo test --all-features                                  # run all tests
cargo +nightly fmt                                         # format
cargo clippy --all-features --all-targets -- -D warnings   # lint
cargo build --release --all-features --all-targets         # release build
```

## Contributing

All contributions large and small are actively accepted.

- Read the [contribution guidelines](https://github.com/kobby-pentangeli/reverse-proxy/blob/master/CONTRIBUTING.md).
- Browse [Good First Issues](https://github.com/kobby-pentangeli/reverse-proxy/labels/good%20first%20issue).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this codebase by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
