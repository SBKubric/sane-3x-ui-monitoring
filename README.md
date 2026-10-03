# mon-server

Monitoring for [3AX-UI](https://github.com/SBKubric/3ax-ui-proxy) panel inbounds: **mon-server** runs on its own box and is the single source of truth for monitoring; **mon-client** boxes in each target region probe every inbound through the proxy front — each hop of the proxy chain, when the panel has one — and directly, once a minute; the panel only displays what mon-server tells it and sends Telegram on mon-server's behalf. Terms below follow [CONTEXT.md](CONTEXT.md). See [docs/spec/mon-server.md](docs/spec/mon-server.md) for the full spec this README summarizes, [docs/spec/mon-client.md](docs/spec/mon-client.md) for the mon-client side, [mon-protocol.md](docs/spec/mon-protocol.md) for the mon-server↔mon-client wire protocol, [the panel's monitoring contract](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/spec/monitoring-contract.md) for what mon-server calls on the panel, and [ADR 0003](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/adr/0003-mon-server-single-source-panel-passive.md) for why the panel is a passive receiver.

## Requirements

- A Linux box with a **public IP** it can be reached on. mon-server terminates its own TLS and needs no reverse proxy in front of it.
- **Port 443 open to the whole internet** — both Let's Encrypt's `tls-alpn-01` validators (default TLS mode, see below) and every mon-client need to reach it. No other inbound port is used.
- **NTP running.** Let's Encrypt's certificate validation and mon-server's own state machine (timestamps, timeouts, the 24h/7d retention windows) all depend on the clock being correct.
- No domain name is required: the default TLS mode gets a certificate for the box's bare IP address.

Packaging (a container image or an installer) is intentionally out of scope here — that is tracked separately in [SBKubric/3ax-ui-proxy#38](https://github.com/SBKubric/3ax-ui-proxy/issues/38). What follows is how to build and run the binary by hand or under systemd.

## Quick start

### 1. Build

```sh
make build          # -> ./mon-server, version stamped from `git describe`
```

or build a container image with the project's `Dockerfile` if you prefer that (see that file for details — it is not covered here).

Or download a release: every `v*` tag publishes `mon-server-linux-amd64.tar.gz` and `mon-client-linux-amd64.tar.gz` (each with a `.sha256`) on the [Releases](https://github.com/SBKubric/3ax-ui-monitoring/releases) page, built by `.github/workflows/release.yml`. Both binaries are static, so they run on any supported distribution (Debian 12/13, Ubuntu 22.04/24.04) regardless of its glibc. Tags with a suffix (`v0.1.0-stand.1`) are pre-releases.

```sh
TAG=v0.1.0-stand.1
curl -LO https://github.com/SBKubric/3ax-ui-monitoring/releases/download/$TAG/mon-server-linux-amd64.tar.gz
curl -LO https://github.com/SBKubric/3ax-ui-monitoring/releases/download/$TAG/mon-server-linux-amd64.tar.gz.sha256
sha256sum -c mon-server-linux-amd64.tar.gz.sha256 && tar -xzf mon-server-linux-amd64.tar.gz
```

### 2. Bootstrap config

mon-server needs a minimal bootstrap config *before* it has a database to keep settings in — everything else (panel URL, Telegram, thresholds) is configured later, at runtime, through the admin UI (see the spec's §9.4, [docs/spec/mon-server.md](docs/spec/mon-server.md)). Write `/etc/mon-server/config.json`:

```json
{
  "listen": ":443",
  "publicIp": "203.0.113.10",
  "dataDir": "/var/lib/mon-server",
  "tls": { "mode": "acme-ip" }
}
```

| key | ENV | default | meaning |
|---|---|---|---|
| `listen` | `MON_LISTEN` | `:443` | address the single HTTPS listener binds — serves `/v1/*` (mon-clients), `/admin/*` (admin UI) and `/healthz` on the same port |
| `publicIp` | `MON_PUBLIC_IP` | — | this box's public IP, required in **both** TLS modes and always an IP literal: mon-clients send tunnel probes to `https://<publicIp>:<port>/v1/probe`, and in `acme-ip` mode it is what Let's Encrypt certifies |
| `dataDir` | `MON_DATA_DIR` | `/var/lib/mon-server` | where the SQLite file and, in `acme-ip` mode, certmagic's certificate cache live; kept at `0700` (database `0600`) on every start |
| `tls.mode` | `MON_TLS_MODE` | `acme-ip` | `acme-ip` (built-in Let's Encrypt cert for `publicIp`, no domain needed) or `files` (bring your own cert/key — a test environment that must not touch the ACME network, or your own CA) |
| `tls.acmeCa` | `MON_TLS_ACME_CA` | `production` | `acme-ip` only: `production` (Let's Encrypt), `staging` (Let's Encrypt staging — for stands rebuilt often enough to hit production's per-IP rate limits; mon-clients then need the staging roots, see [mon-client](#mon-client)), or an ACME directory URL (e.g. Pebble in CI) |
| `tls.cert` | `MON_TLS_CERT` | — | certificate path, required when `tls.mode=files`; the certificate must carry `publicIp` as an **IP SAN** (mon-clients connect by IP), otherwise start-up fails with `cert has no IP SAN for publicIp` |
| `tls.key` | `MON_TLS_KEY` | — | key path, required when `tls.mode=files` |

ENV always wins over the file, so a systemd unit or container can override a single field without templating the whole JSON. An unknown key in the file is a hard error (almost always a typo, or a setting that belongs in the admin UI instead).

### 3. Set the admin login

```sh
mon-server admin set -config /etc/mon-server/config.json alice
```

Flags go before the username (`-config` after it is taken as a second positional argument and refused). Prompts for the password twice on a terminal (bcrypt hash only, never stored in the clear); running it again changes the login and/or password. For scripted provisioning, set `MON_ADMIN_PASSWORD` to skip the prompt.

### 4. Run

```sh
mon-server run -config /etc/mon-server/config.json
```

Then open `https://<publicIp>/admin/`, log in, and fill in **Settings → Real server**: `panelUrl` (the panel's base URL) and `monToken` (from the panel's Monitoring tab). Use **Check** to verify those two values reach the panel before saving. mon-server needs a panel that speaks exactly monitoring contract 3 (an AWG probe peer per mon-client × path, decision [#80](https://github.com/SBKubric/3ax-ui-monitoring/issues/80); the proxy chain in `GET /state` for per-hop paths, decision [#61](https://github.com/SBKubric/3ax-ui-monitoring/issues/61)); update the panel and mon-server together. Any other version is refused with `panel speaks monitoring contract N, mon-server needs 3 — update the panel` (or `— update mon-server` for a newer panel), on Check, on the Settings status line and in the log, and no targets are built until the versions match. If the panel runs on a self-signed or private-CA certificate, Check reports `x509: unknown authority`: paste the panel's certificate (or its CA chain) as PEM into **Panel CA** (`panelCa`) — mon-server then trusts exactly that chain for panel requests instead of the system CAs; leave it empty for a panel with a public certificate. The value can be fetched from the panel box, e.g. `openssl s_client -connect <panel-ip>:<port> </dev/null | openssl x509`. While you're there, the **Telegram** tab (`tgToken`, `tgChatId`) lets mon-server send its own alerts (panel unreachable, config errors) — optional, but recommended.

### What happens next

Once the panel is reachable, mon-server polls it once a minute for inbound state and probe configs, builds each mon-client's per-target config, and starts accepting heartbeats and tunnel probes. New mon-client boxes show up under **Requests** with a pairing code to approve against the box's own boot log; approved ones then appear under **mon-clients** with their live state.

### Version

```sh
mon-server version
```

Prints the build's version string (the release tag, `make build`'s `git describe`, or `dev` for an unstamped local build).

## Running under systemd

```ini
[Unit]
Description=mon-server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/mon-server run
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
StateDirectory=mon-server
StateDirectoryMode=0700
UMask=0077
User=mon-server

[Install]
WantedBy=multi-user.target
```

`AmbientCapabilities=CAP_NET_BIND_SERVICE` lets the process bind `:443` without running as root; `StateDirectory=mon-server` gives it `/var/lib/mon-server` (matching `dataDir`'s default) owned by the service user. Adjust `dataDir`/`MON_DATA_DIR` if you point `StateDirectory` elsewhere.

The database holds the panel's `monToken` and the Telegram bot token, so `dataDir` is private: `StateDirectoryMode=0700` and `UMask=0077` keep systemd and every file the process creates owner-only, and mon-server itself also sets `dataDir` to `0700` and `mon-server.db` to `0600` on every start (so an older install with `0755`/`0644` is repaired by a restart). Run `admin set` as the service user (`sudo -u mon-server mon-server admin set …`) so the database is not created owned by root.

## mon-client

**mon-client** is the box each target region runs: one Go process in one container, with no
capabilities, that mon-server assigns a set of targets to. For every xray-target it runs a child
`xray` process (binary from the official image, config written to a file, stderr read over a
pipe); for every AWG-target it uses an in-process `amneziawg-go`/`netstack` device — no
`/dev/net/tun`, no routes, no privileges. Once a minute it sends mon-server a tunnel probe through
each target's tunnel and one heartbeat past them. See
[docs/spec/mon-client.md](docs/spec/mon-client.md) for the full spec.

Packaging (a container image meant for production, or an installer) is out of scope here too —
tracked in [SBKubric/3ax-ui-proxy#39](https://github.com/SBKubric/3ax-ui-proxy/issues/39).
`Dockerfile.mon-client` is a stand sketch: enough to build and run one container by hand for
manual verification against a real mon-server and panel.

```sh
make docker-client   # docker build -f Dockerfile.mon-client -t mon-client:dev .

docker run -d --name mon-client \
  -v mon-client-state:/var/lib/mon-client \
  -e MON_SERVER_URL=https://<mon-server-ip>:443 \
  mon-client:dev
```

The single required parameter is `MON_SERVER_URL` (or `--server`), mon-server's own base URL —
mon-client dials it with a pairing code, prints that code to `docker logs`, and waits for an
administrator to approve the resulting request under mon-server's admin UI **Requests** page.
Everything else it needs (targets, probe accounts, config revisions) comes from mon-server itself.

mon-client verifies mon-server's certificate against the system CAs and has no CA flag. A mon-server
on `tls.acmeCa=staging` presents a chain from Let's Encrypt's staging roots, which no trust store
carries, so on such a stand point Go's `SSL_CERT_FILE` at a file with the four staging roots
(`(STAGING) Pretend Pear X1`, `Bogus Broccoli X2`, `Yearning Yucca YE`, `Yonder Yam YR`, from
[letsencrypt.org/docs/staging-environment](https://letsencrypt.org/docs/staging-environment/)):

```sh
docker run -d --name mon-client \
  -v mon-client-state:/var/lib/mon-client \
  -v /etc/mon-client/le-staging-roots.pem:/etc/mon-client/le-staging-roots.pem:ro \
  -e SSL_CERT_FILE=/etc/mon-client/le-staging-roots.pem \
  -e MON_SERVER_URL=https://<mon-server-ip>:443 \
  mon-client:dev
```

Go still reads the system directory `/etc/ssl/certs` alongside that file, so public CAs keep working.
A production mon-server (`tls.acmeCa=production`) needs none of this.

During a diagnostic sweep (all edge paths of an inbound kind down) mon-client also checks the
chain's hops and the real server with ICMP echoes. It needs no capability for that — it opens an
unprivileged ICMP datagram socket — but the kernel only allows one to the groups in
`net.ipv4.ping_group_range`. Docker 20.10 and later set that for every container; elsewhere set it
(`--sysctl net.ipv4.ping_group_range="0 2147483647"`), or the sweep reports `icmp_unavailable`
for every host instead of a loss figure.

State — `state.json` (registration), `cycles.json` (unverified heartbeat buffer) and `xray.json`
(generated xray config) — lives under `/var/lib/mon-client`, which the image declares as a
`VOLUME` so it survives a container restart.

For the full manual stand checklist (registration, `UP` on every path, `DOWN` on a stopped
inbound, `reality_real_cert`, `awg_no_handshake`, buffering through a mon-server outage, `401`
after Revoke), see [docs/runbooks/mon-client-stand.md](docs/runbooks/mon-client-stand.md).

## Development

```sh
make check     # fmt + vet + staticcheck + test, the full gate CI runs
make test      # go test -race -count=1 ./...
```

An end-to-end harness (`make e2e`, driving a real panel stub end to end) is being added on this branch stack by another change; once it lands, see `e2e/` for how to run it.

There is no `go` toolchain assumption beyond what `go.mod` names — `make build`/`make test` work with a plain local Go install.
