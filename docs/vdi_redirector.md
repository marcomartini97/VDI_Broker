# VDI Redirection Server

The VDI redirection server is a standalone FreeRDP-based broker that reuses the
existing `vdi_broker` configuration, logging, and Podman integration to forward
incoming RDP clients directly to per-user containers via server redirection.

## Building

The server is built alongside the rest of the FreeRDP targets. A typical build
configuration is:

```bash
cmake -S . -B build -DWITH_PROXY=ON -DWITH_SHADOW=OFF
cmake --build build --target vdi-redirector vdi-proxy -j"$(nproc)"
```

The target depends on libcurl, PAM, and jsoncpp in the same way as the proxy
module, so make sure those development packages are installed.

## Running

```
vdi-proxy &
vdi-redirector \
  --certificate /etc/vdi/server.crt \
  --private-key /etc/vdi/server.key \
  --config /etc/vdi/vdi_broker.yaml \
  [--bind 0.0.0.0] \
  [--port 3389]
```

* `vdi-proxy` listens on `127.0.0.1:3390` for the redirected RDP sessions and
  pipes them to the per-user container.
* `--certificate` / `--private-key` – PEM encoded TLS certificate and key
  presented to the client during the initial handshake.
* `--config` – optional path to the VDI broker configuration file. When omitted,
  the defaults from `vdi_broker_config` are used.
* `--bind` / `--port` – redirector listening endpoint (defaults to
  `0.0.0.0:3389`).

On each connection the server:

1. Captures the credentials provided by the client (including `user#suffix`
   routing).
2. Authenticates the user against the configured PAM service (network level
   authentication is disabled; standard username/password logon is used).
3. Displays a temporary blue screen so the user receives immediate feedback.
4. Starts or resumes the matching container using the existing Podman manager
   and registers it with the TCP proxy.
5. Issues an RDP server redirection PDU pointing the client at the proxy on
   `127.0.0.1:3390` with the broker-managed credentials; the proxy forwards the
   session to the per-user container.

Logs are written through the shared `vdi_logging` helpers under
`/var/log/vdi-broker`.
