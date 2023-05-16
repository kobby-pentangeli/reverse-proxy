# ReverseProxy

An implementation of a simple HTTP server acting as a reverse proxy.

## Setup & Run

1. Clone the repo && cd:

```bash
git clone https://github.com/kobby-pentangeli/reverse-proxy.git
cd reverse-proxy
```

2. Define and/or edit the `Config.yml` file at the root of the project:

```yml
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

3. Run the server:

```bash
cargo run
```

4. In a new terminal, send a request:

```bash
curl -i http://127.0.0.1:8100/
```

## Background

A startup needs a reverse proxy to help in data governance. We need to create a simple HTTP server that will act as a reverse proxy. The proxy should be able to handle incoming requests, inspect the request headers, and then forward the requests to the intended destination. In addition, the proxy should be able to log all incoming requests, including the headers and body, and the response headers and body. The proxy should also be able to block certain requests based on a set of predefined rules.

## Requirements

1. The reverse proxy should be able to forward any kind of request but inspect only `GET` requests.
2. The proxy should inspect the response body for any sensitive information and mask it before forwarding the response.
3. The proxy should log all incoming requests, including headers and body, and response headers and body.
4. The proxy should be able to block requests based on a set of predefined rules. For example, block requests that contain specific headers or parameters.
5. Provide a configuration file that allows the startup to define the rules for blocking requests.
6. Write unittests to ensure that the proxy is functioning correctly.
7. Provide documentation on how to install and run the reverse proxy.

## Contributing

Thank you for considering to contribute to this project!

All contributions large and small are actively accepted.

- To get started, please read the [contribution guidelines](https://github.com/kobby-pentangeli/reverse-proxy/blob/master/CONTRIBUTING.md).

- Browse [Good First Issues](https://github.com/kobby-pentangeli/reverse-proxy/labels/good%20first%20issue).

## License

Licensed under either of <a href="LICENSE-APACHE">Apache License, Version 2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this codebase by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
