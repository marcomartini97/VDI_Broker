# VDI Broker Proxy Plugin

The VDI broker plugin embeds the container orchestration logic directly inside
the FreeRDP proxy. It authenticates incoming RDP connections, ensures the
matching container is running, and rewrites the target settings so the proxy
relays traffic to the user’s desktop session.

Much like the standalone redirector, the plugin reuses the shared Podman manager
and configuration helpers located under `server/vdi-common`.

## Building

Enable the proxy targets when configuring CMake:

```bash
cmake -S . -B build -DWITH_PROXY=ON -DWITH_SHADOW=OFF
cmake --build build --target proxy-vdi-broker-plugin -j"$(nproc)"
```

The build pulls in libcurl, PAM, and jsoncpp support, so the corresponding
development packages must be available on the host.

## Runtime Flow

When the proxy receives a connection the plugin:

1. Splits usernames of the form `user#suffix` and authenticates the account via
   the configured PAM service (`vdi_broker.yaml`, `pam_service`).
2. Invokes `vdi::ManageContainer(user, prefix)` to handle Podman lifecycle
   (network creation, container build/start) and retrieve connection details.
3. Applies the resolved target host, port, and credentials to the session before
   the proxy completes the upstream handshake.

### Container Connection Details

`ManageContainer` now calls `/usr/bin/setup_grd.sh` inside the user container
through a Podman exec request. The script must print a JSON document containing:

```json
{"ip":"10.0.0.5","username":"grd-user","password":"secret"}
```

- `ip` (required): Address the proxy should forward traffic to.
- `username` / `password` (optional): Credentials for the GNOME Remote Desktop
  session. When omitted the plugin falls back to the static
  `rdp_username` / `rdp_password` pair defined in `vdi_broker.yaml`.

The plugin logs a warning whenever it has to resort to the fallback so the
container image can be updated to provide explicit credentials.

### Network Configuration

Podman networking is controlled through the `network` block in
`vdi_broker.yaml`:

```yaml
network:
  name: vortice-network
  interface_name: vortice0
  type: macvlan        # bridge (managed default), bridge-unmanaged, macvlan, or none
  parent: br0          # required for macvlan; ignored otherwise
```

- **Bridge (default, managed)** – omitting `type` or setting it to any value other than
  `macvlan`/`none`/`bridge-unmanaged` enables Podman’s user-defined bridge network. The helper
  ensures the network exists (creating it if necessary) and assigns the container-facing
  interface name (`interface_name`) inside each session. Optionally provide `parent` to point at the
  existing Linux bridge (for example `br0`).
- **Bridge (unmanaged)** – set `type: bridge-unmanaged` to reuse an existing network bridge. The
  broker verifies that the network already exists and skips auto-creation. Supplying `parent`
  documents the expected uplink but does not trigger creation. Podman keeps NAT and port forwarding
  disabled when a bridge operates in unmanaged mode.
- **Macvlan** – set `type: macvlan` and provide a physical uplink via
  `parent`/`master`. The broker validates the presence of the parent interface;
  if it is missing the configuration gracefully falls back to bridge mode to
  keep containers reachable. Macvlan isolates containers from the host, so
  host-to-container traffic (for example, RDP clients running locally) is not
  possible.
- **None/disabled** – set `type: none` (or `network: false`) to skip Podman
  network management entirely. Use this when the container image attaches to an
  externally-defined network namespace.

All modes share the same `name` and optional `interface_name` fields; leaving
`interface_name` blank lets Podman pick a default (for example `eth0`).

### Handling Failures

If the JSON payload is invalid, missing fields, or the Podman exec fails, the
plugin aborts the connection and surfaces the error via the shared broker logs.
Look under `/var/log/vdi-broker` for details. Run the container manually and
execute `/usr/bin/setup_grd.sh` to verify it returns valid JSON.

## Related Components

- `docs/vdi_redirector.md` – overview of the standalone redirector that uses the
  same container manager.
- `server/vdi-common/vdi_container_manager.cpp` – Podman networking, container
  lifecycle helpers, and the exec-based JSON retrieval.
- `server/vdi-common/vdi_broker_config.{h,cpp}` – configuration schema for
  broker targets and fallback credentials.
