# go-tlsdriver

go-tlsdriver is a simple wrapper around Go [crypto/tls] library to be
able to test interoperability against other TLS libraries, as in the
[TLS interoperability][tls-interop] project.

## Installation

```console
go install github.com/ueno/go-tlsdriver/cmd/server@latest
go install github.com/ueno/go-tlsdriver/cmd/client@latest
```

## Usage

### Running server

```console
server --http --certfile cert-ecc.pem --keyfile key-ecc.pem --address localhost:5556
```

### Running client

```console
client --server-name localhost --address localhost:5556 --cafile ca.pem
```

### Configuration

Both of those commands take configuration options from the command
line.  Run with `--help` to see what options are available.

## License

MIT

[crypto/tls]: https://pkg.go.dev/crypto/tls
[tls-interop]: https://gitlab.com/redhat-crypto/tests/interop/
