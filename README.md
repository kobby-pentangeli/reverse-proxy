# ReverseProxy

An implementation of a simple HTTP server acting as a reverse proxy.

## Background

A startup needs a reverse proxy to help in data governance. We need to create a simple HTTP server that will act as a reverse proxy. The proxy should be able to handle incoming requests, inspect the request headers, and then
forward the requests to the intended destination. In addition, the proxy should be able to log all
incoming requests, including the headers and body, and the response headers and body. The
proxy should also be able to block certain requests based on a set of predefined rules.

## Requirements

1. The reverse proxy should be able to forward any kind of request but inspect only `GET`
requests.
2. The proxy should inspect the response body for any sensitive information and mask it
before forwarding the response.
3. The proxy should log all incoming requests, including headers and body, and response
headers and body.
4. The proxy should be able to block requests based on a set of predefined rules. For
example, block requests that contain specific headers or parameters.
5. Provide a configuration file that allows the startup to define the rules for
blocking requests.
6. Write unittests to ensure that the proxy is functioning correctly.
7. Provide documentation on how to install and run the reverse proxy.
