# Derp418

A small, opinionated [DERP](https://tailscale.com/kb/1232/derp-servers) relay
for a single tailnet.

DERP servers relay encrypted traffic between Tailscale clients that cannot reach
each other directly. Derp418 is built on Tailscale's
[`derpserver`](https://pkg.go.dev/tailscale.com/derp/derpserver) package and
trims everything that is not needed to run one private relay: no mesh, no rate
limiting, no debug or metrics endpoints, no certificate modes (it always uses
Let's Encrypt). In return it adds a few behaviours of its own:

- **Tailnet only.** Every client is checked against the local `tailscaled`;
  anyone who is not a peer of your tailnet is refused.
- **Wildcard host.** It answers on each listed domain other than the apex and
  its direct subdomains
  with a Let's Encrypt certificate for each, and redirects everything that is
  not DERP to a single apex domain. More deeply nested names are refused.
- **Modern TLS only.** TLS 1.3, ECDSA certificates, post-quantum hybrid key
  exchange preferred, no HTTP/2. No RSA, ever.
- **State in one directory.** The node key and the certificates live in a
  data directory you can back up.

## How it works

| Port | Protocol | What it does |
|---|---|---|
| 443 | TCP, TLS 1.3 | DERP (`/derp`, plain or WebSocket), latency probes (`/derp/probe`, `/derp/latency-check`), `/generate_204`, `/bootstrap-dns`, and a redirect to the apex for any other path |
| 80 | TCP | ACME challenges, `/generate_204`, and a `301` to the same URL over HTTPS |
| 3478 | UDP | STUN |

All three addresses can be changed with flags.

### Which hosts are served

Give it `--domains example.org,example.net --apex example.com`:

| Host | Served? |
|---|---|
| `anything.example.org`, `a.b.example.org` | yes |
| `example.org`, `www.example.org` | yes |
| `anything.example.net`, `example.net` | yes |
| `anything.example.com` | only if `example.com` is also listed in `--domains` |
| `example.com` (the apex) | **never**: it is where requests are redirected to, and is hosted elsewhere |
| any other name, an IP address, or no SNI | no |

Requests for a served host that are not DERP are answered with a
`301 Moved Permanently` to the same path and query on the apex, over HTTPS. A
request over TLS whose `Host` header is the apex or an unknown host (possible
when it differs from the SNI) gets a `404`. On port 80 there is no such check:
every host is sent to the same URL over HTTPS, where the handshake decides.

For a handshake with a host that is not served, the TLS connection is simply
refused, and it is kept out of the log, since scanners produce plenty of them.

### Certificates

Certificates come from Let's Encrypt through ACME, using the TLS-ALPN-01 or
HTTP-01 challenge, so ports 443 and 80 must be reachable from the Internet.

- One certificate per host, **obtained on the first connection** to it and
  renewed automatically.
- At startup, `www.<domain>` and `<domain>` are obtained in advance for every
  wildcard domain other than the apex.
- Certificates are ECDSA (P-256) only. A client that cannot verify ECDSA is
  refused, never served RSA.
- They are kept in `<datadir>/certs`, together with the ACME account key.

> **Rate limits.** Because certificates are issued on demand, anyone who can
> reach the server can ask for names under your domains and spend your Let's
> Encrypt [rate limits](https://letsencrypt.org/docs/rate-limits/), which can
> block the renewal of the certificate you actually use. Keep that in mind when
> choosing the domains you list.

### Who can connect

The server asks the local `tailscaled` whether the client's node key belongs to
one of its peers. This means:

- the machine running Derp418 must be a node of your tailnet, with
  `tailscaled` running;
- your ACLs decide which nodes the server can see, and therefore which clients
  are admitted;
- if `tailscaled` cannot be queried, clients are refused rather than admitted.

### Bootstrap DNS

`GET /bootstrap-dns` returns the addresses of a fixed list of names as JSON
(`{"name": ["ip", ...]}`), resolved through the system resolver on every request
and in parallel. Tailscale clients whose own DNS is broken use it to reach the
control plane. Names that do not resolve are left out, and the answer is a `503`
if none does. Nothing is cached in the process: rely on a local DNS cache.

### Other behaviours

- `CONNECT` requests are answered with `418`.
- Every response carries the headers of an old Apache/PHP box (`Server`,
  `Set-Cookie: PHPSESSID`, a 1981 `Expires`...). It is an easter egg, not a
  security measure. DERP connections themselves are not affected.

## Requirements

- Go 1.27 or later to build.
- A tailnet, and `tailscaled` running on the server, connected to it.
- DNS records for the domains you list, pointing at the server: a wildcard
  (`*.example.org`) and, if you want them served, the bare names.
- Ports 80 and 443 (TCP) and 3478 (UDP) open. On Linux, binding to ports below
  1024 needs root or `CAP_NET_BIND_SERVICE`.
- A persistent data directory.

Derp418 is tested in CI on Linux, FreeBSD and OpenBSD.

## Build

```sh
go build -o derp418 .
```

## Run

```sh
./derp418 \
  --domains example.org,example.net \
  --apex example.com \
  --acme-email you@example.com
```

On first run it creates `derper.key` in the data directory. That key is the
identity of the node: keep it, or you will have to update your DERP map.

### Flags

| Flag | Default | Description |
|---|---|---|
| `--domains` | none, **required** | Comma-separated wildcard domains. |
| `--apex` | none, **required** | Domain everything that is not DERP is redirected to. It is not served by this server. |
| `--datadir` | `<user config dir>/derp418` | Where the node key and the certificates are kept. Must persist across restarts. |
| `--acme-email` | none | Contact address for the ACME account (expiry notices). |
| `--socket` | OS default | Path of the local `tailscaled` socket, used to verify clients. |
| `--https-addr` | `:443` | HTTPS listen address. |
| `--http-addr` | `:80` | HTTP listen address. |
| `--stun-addr` | `:3478` | STUN (UDP) listen address. |
| `--bootstrap-dns-names` | the five names the official DERP servers publish | Names served at `/bootstrap-dns`. |
| `--version` | | Print the version and exit. |

### Data directory

```
<datadir>/
├── derper.key        node private key, mode 0600
└── certs/            ACME account key and certificates (autocert cache)
```

## Telling Tailscale about the server

Add the node to the DERP map in your tailnet policy file. Use a host that this
server serves as `HostName`; setting `IPv4` and `IPv6` as well is recommended, so
clients can connect even when DNS is unavailable:

```json
{
  "derpMap": {
    "Regions": {
      "900": {
        "RegionID": 900,
        "RegionCode": "mine",
        "RegionName": "My DERP",
        "Nodes": [
          {
            "Name": "900a",
            "RegionID": 900,
            "HostName": "derp.example.org",
            "IPv4": "203.0.113.10",
            "IPv6": "2001:db8::10"
          }
        ]
      }
    }
  }
}
```

The `HostName` must be a name for which the server can obtain a certificate:
one of your `--domains` (other than the apex), or a direct subdomain exactly one
label below one of them.

## Development

```sh
go test -race ./...
golangci-lint run
```

The linter configuration in `.golangci.yml` is strict, and the project passes it
without exceptions beyond the ones it declares. Tests run in parallel wherever
they can; the few that share process-wide state say so.

| File | Contents |
|---|---|
| `main.go` | Flags and the entry point |
| `derper.go` | Wiring: node key, servers, listeners, shutdown |
| `domains.go` | Which hosts are served, and the redirect to the apex |
| `cert.go` | Certificate manager and TLS configuration |
| `bootstrap_dns.go` | The `/bootstrap-dns` endpoint |
| `redstar.go` | The response-header easter egg |

## License

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
