# PRIMEVPN

[![Build](https://github.com/vpn-panel-dev/vpn-management-panel/actions/workflows/docker.yml/badge.svg)](https://github.com/vpn-panel-dev/vpn-management-panel/actions/workflows/docker.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Self-hosted PRIMEVPN control plane for multi-node WireGuard/AmneziaWG and OpenVPN deployments.

## Architecture

```
                    ┌──────────────────────────┐
                    │     PRIMEVPN Control Plane    │
                    │                          │
  Browser ───────── │  Nginx (admin + user UI) │
                    │  FastAPI (panel API)     │
                    │  Panel worker            │
                    │  RabbitMQ (queue)        │
                    │  PostgreSQL (db)         │
                    └──────────┬───────────────┘
                               │ HTTP / agent API
                    ┌──────────▼───────────────┐
                    │        PRIMEVPN VPN Node          │
                    │                          │
  Clients ──UDP──── │  WireGuard/AmneziaWG (:51820/udp) + OpenVPN (:1194/udp)  │
                    │  Node Agent (:8000)      │
                    └──────────────────────────┘
```

| Server | What runs on it | Exposed ports |
|---|---|---|
| VPN node | AmneziaWG + node agent + MTProxy runtime | `51820/udp`, `8000` (restrict to panel IP), `443/tcp` or `${MTPROXY_PORT}` when Telegram proxy is enabled |
| Management panel | Admin frontend + user frontend + panel backend + worker + RabbitMQ + PostgreSQL | `80` |

The node agent (`8000`) must **not** be exposed to the public internet — restrict it to the management server IP via firewall.
The Telegram MTProxy port is public only on the VPN node that runs the proxy. The management panel does not need to expose it.

## Docker images

Pre-built images are published to GitHub Container Registry on every push to `main`:

| Image | Description |
|---|---|
| `ghcr.io/hadish0123/primevpn-node` | AmneziaWG userspace tunnel + FastAPI agent + Telegram MTProxy runtime |
| `ghcr.io/hadish0123/primevpn-panel` | FastAPI management backend |
| `ghcr.io/hadish0123/primevpn-panel-worker` | Background worker for panel jobs |
| `ghcr.io/hadish0123/primevpn-panel-frontend` | Vue 3 admin SPA served by Nginx |
| `ghcr.io/hadish0123/primevpn-user-frontend` | Vue 3 user self-service page (served at `/u/<token>`) |

---

## Deploy: PRIMEVPN VPN Node

Run on each **VPN node server**. Repeat for every node.

### Requirements

- Linux x86_64 or arm64
- Docker + Docker Compose
- Kernel with `tun` support (virtually all VPS providers)
- UDP port `51820` open in firewall
- TCP port `443` open in firewall if you enable Telegram MTProxy, or whatever value you set in `MTPROXY_PORT`

### 1. Create working directory

```bash
mkdir -p /opt/primevpn-node/config && cd /opt/primevpn-node
```

### 2. Create `docker-compose.yml`

```bash
cat > docker-compose.yml << 'EOF'
services:
  node:
    image: ghcr.io/hadish0123/primevpn-node:latest
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.forwarding=1
    volumes:
      - ./config:/etc/amnezia/amneziawg
    ports:
      - "51820:51820/udp"
      - "8000:8000"
      - "${MTPROXY_PORT:-443}:${MTPROXY_PORT:-443}/tcp"
    environment:
      - WG_INTERFACE=awg0
      - AGENT_TOKEN=${AGENT_TOKEN}
      - SERVER_ENDPOINT=${SERVER_ENDPOINT}
      - WG_CONFIG=/etc/amnezia/amneziawg/awg0.conf
      - MTPROXY_PORT=${MTPROXY_PORT:-443}
EOF
```

### 3. Generate `.env`

This command writes a fresh random token and auto-detects the public IP:

```bash
cat > .env << EOF
AGENT_TOKEN=$(openssl rand -hex 32)
SERVER_ENDPOINT=$(curl -4 -s ifconfig.me):51820
EOF
```

### 4. Start

```bash
docker compose pull && docker compose up -d && docker compose logs --tail=30
```

The node will start and wait for the panel to send its configuration.

### 5. Restrict port 8000 to the management server

Replace `x.x.x.x` with the panel server IP:

```bash
PANEL_IP=x.x.x.x
ufw allow from $PANEL_IP to any port 8000
ufw deny 8000
ufw allow 51820/udp
ufw --force enable
```

### 6. Telegram MTProxy

The node image already includes the MTProxy runtime. Its runtime config is stored under the existing node config mount at `/etc/amnezia/amneziawg/mtproxy`.

- The public TCP port defaults to `443`. Override `MTPROXY_PORT` in the node compose file if you want a different public port, and open that same port in the node firewall.
- The shared secret is node-wide. Reusing the same secret keeps the public proxy URL stable, while rotation changes the URL and invalidates any old shared links.
- The selected primary node is the public Telegram endpoint. Move the primary node in the panel if you want Telegram proxy traffic to come from a different server.
- Telegram users do not need separate Telegram accounts or per-user server logins. They use the public MTProxy URL generated for the node.
- Keep `8000` private to the panel IP. Only the MTProxy TCP port is public.

---

## Deploy: Management Panel

Run on the **management server**.

### Requirements

- Linux x86_64 or arm64
- Docker + Docker Compose
- TCP port `80` open in firewall

### 1. Create working directory

```bash
mkdir -p /opt/primevpn-panel && cd /opt/primevpn-panel
```

### 2. Create `docker-compose.yml`

```bash
cat > docker-compose.yml << 'EOF'
services:
  frontend:
    image: ghcr.io/hadish0123/primevpn-panel-frontend:latest
    restart: unless-stopped
    ports:
      - "80:80"
    depends_on:
      - panel
      - user-frontend

  user-frontend:
    image: ghcr.io/hadish0123/primevpn-user-frontend:latest
    restart: unless-stopped
    depends_on:
      - panel

  rabbitmq:
    image: rabbitmq:4-alpine
    restart: unless-stopped
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "-q", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10

  panel:
    image: ghcr.io/hadish0123/primevpn-panel:latest
    restart: unless-stopped
    environment:
      - DATABASE_URL=postgresql+asyncpg://amnezia:${DB_PASSWORD}@db:5432/amnezia
      - RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672/
      - WORKER_TOKEN=${WORKER_TOKEN}
      - SYNC_INTERVAL_SEC=300
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - SECRET_KEY=${SECRET_KEY}
      - REMNAWAVE_SECRET_KEY=${REMNAWAVE_SECRET_KEY}
    depends_on:
      db:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8080/openapi.json')\""]
      interval: 5s
      timeout: 3s
      retries: 10

  panel-worker:
    image: ghcr.io/hadish0123/primevpn-panel-worker:latest
    restart: unless-stopped
    environment:
      - RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672/
      - BACKEND_INTERNAL_URL=http://panel:8080
      - WORKER_TOKEN=${WORKER_TOKEN}
      - SYNC_INTERVAL_SEC=300
      - NODE_HEARTBEAT_INTERVAL_SEC=5
      - WORKER_CONCURRENCY=4
      - PROVISION_RECOVERY_INTERVAL_SEC=60
      - PROVISION_PENDING_RETRY_SEC=60
      - PROVISION_FAILED_RETRY_SEC=300
    depends_on:
      panel:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy

  db:
    image: postgres:18-alpine
    restart: unless-stopped
    volumes:
      - postgres_data:/var/lib/postgresql
    environment:
      - POSTGRES_USER=amnezia
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_DB=amnezia
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U amnezia"]
      interval: 5s
      timeout: 3s
      retries: 10

volumes:
  postgres_data:
  rabbitmq_data:
EOF
```

### 3. Generate `.env`

```bash
cat > .env << EOF
DB_PASSWORD=$(openssl rand -hex 32)
ADMIN_PASSWORD=$(openssl rand -hex 16)
SECRET_KEY=$(openssl rand -hex 32)
WORKER_TOKEN=$(openssl rand -hex 32)
REMNAWAVE_SECRET_KEY=$(openssl rand -hex 32)
EOF
```

### 4. Start

```bash
docker compose pull && docker compose up -d && docker compose logs --tail=30
```

The panel is now accessible at `http://<panel-server-ip>`.

### 5. View credentials

```bash
cat /opt/primevpn-panel/.env
```

Login: `admin` / value of `ADMIN_PASSWORD`.

---

## Connect nodes to the panel

1. Open the panel in your browser.
2. Go to **Nodes → Add node**.
3. On each node server, read its config:
   ```bash
   cat /opt/primevpn-node/.env
   ```
4. Fill in:
   - **Name** — friendly label for this node
   - **Agent URL** — `http://<node-ip>:8000`
   - **Agent token** — `AGENT_TOKEN` from the node's `.env`
   - **Endpoint** — `SERVER_ENDPOINT` from the node's `.env`
   - **Listen port** — `51820`
5. Save. The panel generates a key pair for the node and pushes the full interface config to the agent. The WireGuard interface comes up automatically.

---

## Remnawave integration

Amnezia can sync users from [Remnawave](https://remnawave.com) via API polling or webhooks.

### Setup

1. Go to **Settings → Remnawave** in the admin panel.
2. Enter your Remnawave base URL, API token, and webhook secret.
3. Set `REMNAWAVE_SECRET_KEY` in the panel environment (at least 32 characters). This key encrypts the Remnawave API token and webhook secret stored in the database.
4. Enable polling or configure Remnawave to send webhooks to `https://<panel>/api/remnawave/webhook`.

### Important notes

- Remnawave is the source of truth. Changes flow one-way from Remnawave to Amnezia.
- Remnawave-managed users are not automatically linked to existing local users.
- Imported Remnawave usage is the traffic value read from Remnawave during sync. Local WireGuard/AmneziaWG usage is measured from node peer counters (`rx + tx`) and stored reset-safely by Amnezia.
- For local Amnezia display and enforcement, Remnawave-managed users use combined usage: imported Remnawave traffic used plus local AmneziaWG lifetime usage.
- Local and combined WireGuard/AmneziaWG usage are not pushed back to Remnawave traffic counters.
- If combined usage reaches the Remnawave-imported traffic limit, Amnezia blocks the user's local peers, queues node sync, and asks Remnawave to disable the user through its lifecycle API when the integration is enabled. This does not mutate Remnawave traffic counters.
- Remnawave polling can be enabled in settings. The backend stores `polling_interval_seconds` with a default of 300 seconds; the worker checks whether polling is due once per minute.
- Without the same `REMNAWAVE_SECRET_KEY`, stored Remnawave secrets and subscription URLs cannot be decrypted after a backup restore.

## Operational semantics

- Node `online`/`offline` status reflects the latest worker heartbeat to the node-agent `/health` endpoint. Sync/provision results are tracked separately as last sync and provision status.
- The worker automatically republishes stale `queued` operations and marks stale `running` operations as `failed_by_timeout` after `RUNNING_TIMEOUT_SEC` so operators can resolve them from the admin operations list.
- The worker automatically creates and publishes provisioning retries for nodes stuck in
  `provision_status=pending` or `provision_status=failed`. By default pending nodes are retried after
  60 seconds, failed nodes after 300 seconds, and the recovery scan runs every 60 seconds. The admin
  Provision button is a force/retry action, not a required manual deployment step.
- The admin operations panel is a current-state recovery view, not a historical log: it shows only the
  latest actionable operation per operation kind and target. Older failures disappear after a newer retry
  or successful run supersedes them.
- Worker jobs are split by execution semantics. Node-mutating commands (`sync_all`, `sync_node`,
  `provision_node`) share one sequential RabbitMQ queue with one active consumer. Heartbeat,
  cleanup, and Remnawave commands use parallel queues controlled by `WORKER_CONCURRENCY`.
- Worker-scheduled heartbeat, cleanup, and polling jobs are internal maintenance commands. They execute
  without creating backend `async_operations` rows, so they do not spam `/internal/worker/operations/*`
  with missing-operation lifecycle calls.
- Rolling upgrade order for the queue split: update `panel-worker` first so it drains both legacy
  `amnezia.sync`/`amnezia.provision` queues and new operation queues, then update `panel` so new
  jobs are published directly to operation queues. Keep legacy queues until they are empty.

---

## Multi-device accounts

An PRIMEVPN account (the "user") owns its lifecycle, limits and traffic aggregates; each **device**
owns its own keypair, VPN IP and peers. One account may hold several devices on the same node, so a
peer is identified by its `(device, node)` pair - never by the owner or the node alone.

- **Existing accounts** keep working: migration `0019` gives every account that existed one device
  named `Default` that inherits its key material, VPN IP, peer rows (ids and pre-shared keys) and
  traffic history. Nothing is regenerated and no peer row is deleted.
- **New accounts** (created locally or imported from Remnawave) start with **no** devices, keys or
  peers, so they have nothing to download until a device is added.
- **Per-user device limit** is local and `0` means unlimited. A Remnawave-imported account is judged
  by its imported `hwid_device_limit` instead, where a null (or `0`) value also means unlimited and
  the local column stays inert. Lowering a limit never removes an existing device - it only blocks
  further additions once the count is reached.
- **Deleting a device** frees its limit slot immediately, but the actual revocation on the node is
  asynchronous: the device is tombstoned, its peers are marked `pending_delete`, and the node drops
  them on the next sync. The device row, its peers and its traffic history are retained for
  accounting. Deletion stays available to the owner of a blocked or expired account, unlike
  downloads.
- **Unblocking an account** restores the peers the block removed *and* provisions the peers a node
  that was added while the account was blocked never got, then queues those nodes like any other
  change. Deleting a device stays durable: no lifecycle transition resurrects a tombstoned device,
  and an account without devices still owns nothing after a lifecycle pass.

### Address recycling and the size of the pool

The client address space is **finite**: a `/24` (`VPN_SUBNET`, `10.8.0.0/24` by default) yields
roughly 250 client addresses, so a deployment has a real ceiling on how many devices can exist at
once. PRIMEVPN does not offer unlimited client capacity, and a larger deployment needs a wider subnet.

- Only `devices.vpn_ip` reserves an address. The pre-migration per-user `users.vpn_ip` column is
  frozen and reserves nothing: migration `0019` copied each of those addresses onto the account's
  `Default` device, so honouring it twice would keep an address busy forever.
- When a device is deleted, its address returns to the pool **only after every peer of that device
  is confirmed `deleted`**. Until then it stays reserved: a node that has not answered may still hold
  that peer, and handing the address to a new device would put two tunnels on one address.
- The hand-back is recorded (`released_vpn_ip`, `ip_released_at`) instead of erasing the address, and
  it never regenerates a key, deletes a peer row or touches traffic history. A new device that
  reuses the address gets fresh key material and its own peer row; node results are matched by public
  key, so the released device's old peer can never be applied to the new device.
- A **live** device never releases its address, not even a blocked or expired one - blocking is not
  deletion.
- A device that never reached any node (no peers) releases immediately when deleted. A device deleted
  before migration `0020` keeps its address until its removal is confirmed again: deleting it once
  more, or deleting the node that held it, runs the release.
- If every address is held (live devices plus removals no node has confirmed yet), adding a device
  answers **`503`** with the reason instead of an unexplained `500`. The pool recovers as soon as the
  unreachable node reports, or the removed peers are confirmed.

### Config download readiness

- A configuration, QR or AmneziaWG QR download requires that device's peer on that node to be
  `active`; a peer that is still pending answers `503` instead of serving a config built from the
  device credentials alone.
- A later sync failure of a node is reported as an `error` diagnostic and does **not** remove a
  working config: a peer the node already acknowledged stays usable while a newer sync of the same
  node fails.

### Live updates (SSE)

- Each public account page may open one `text/event-stream` at `/pub/u/{id}/events`. The frames are
  `connected` (`{user_id, notifications}`), `changed` (`{reason}`), `unauthorized` (`{reason}`) and
  `: keepalive` comments. A frame never carries keys, configuration bodies or profile data - the
  client re-reads `/pub/u/{token}/info`, so the stream only ever says "re-read".
- Notifications are transactional: they are issued inside the transaction that writes the change
  through PostgreSQL `LISTEN`/`NOTIFY`, so a client is never told to re-read state that was never
  committed. **All backend processes must share the same PostgreSQL database**, because each process
  runs its own `LISTEN` connection and a change committed by the process that handled a worker
  result reaches a stream held by any other process.
- Behind a reverse proxy, disable response buffering for the stream (the backend already sends
  `X-Accel-Buffering: no` for nginx); a buffering proxy would hold events until its buffer fills up
  and the page would look frozen.
- The stream heartbeats (`: keepalive`) so intermediaries do not idle the connection out, and the
  client keeps a periodic poll as its fallback. If the listener is unavailable, the `connected`
  frame reports `notifications: false` and the poll is the transport.
- Node agents stay private: live updates need **no** public access to them. The worker reports node
  results and heartbeats to the backend, which commits the change and notifies.

### Safe rollout of migrations 0019 and 0020

Running old and new writers against the same database is **not** safe: the old backend does not set
`peers.device_id` and there is no lazy backfill at runtime. Upgrade in this order:

1. **Back up the database** and verify the backup can be restored.
2. **Pause** the old backend writers and the worker's result ingestion, so nothing writes while the
   schema changes.
3. **Apply migration `0019`** with the backend stopped, then `0020` (address-release metadata; purely
   additive, so it runs in the same stopped window and backfills nothing).
4. **Deploy the new backend**, then the compatible worker, then the frontends.
5. **Resume** the queues and confirm operations drain.

Installed VPN nodes keep their existing tunnels and configurations throughout - this change is on
the management side only, so **do not rebuild or recreate the nodes**.

### Downgrade and restore

- Downgrading to `0018` is refused once any device has been deleted or any non-migration device
  exists, because the legacy per-user schema cannot express device deletion and would resurrect
  deleted credentials.
- Downgrading to `0019` drops only the two release-metadata columns. Live credentials, IPs and peer
  rows are untouched, but the record of which addresses were already handed back is lost; a device
  that released its address stays tombstoned, so a later downgrade to `0018` is still refused.
- Restoring an older backup is lossy and manual: it silently discards every device, deletion and
  device-scoped change made after the backup. Do it only with an explicit understanding of that loss
  and a reconciliation plan. There is no automatic lossy rollback.

---

## Security

See [SECURITY.md](SECURITY.md) for supported versions and how to report vulnerabilities responsibly.

---

## Updating

Pull the latest images and recreate containers:

```bash
cd /opt/primevpn-node  && docker compose pull && docker compose up -d
cd /opt/primevpn-panel && docker compose pull && docker compose up -d
```

For Telegram MTProxy changes, update the panel worker first, then the panel, then the node. That keeps config writes and the node runtime in sync when you rotate the shared secret or change the public port.

---

## Development

```
panel/
├── backend/          # FastAPI management API, Alembic migrations, RabbitMQ publisher
├── worker/           # Async worker for sync, provisioning, heartbeats, cleanup, integrations
├── admin-frontend/   # Vue 3 + PrimeVue admin SPA
├── user-frontend/    # Vue 3 user self-service page
└── docker-compose.yml # Local panel stack: frontends, backend, worker, RabbitMQ, PostgreSQL
node/
├── agent/            # FastAPI node agent (Python)
├── mtproxy.sh        # Telegram MTProxy runtime wrapper
├── tunnel.sh         # AmneziaWG userspace tunnel wrapper
└── docker-compose.yml # Local node stack: AmneziaWG + agent + MTProxy port
```

Clone the repo and use the `build:`-based compose files in each subdirectory:

```bash
# Node
cd node && docker compose up --build

# Panel
cd panel && docker compose up --build
```

For service-specific development, install dependencies and run checks in the changed module:

```bash
# Python services
uv run --directory panel/backend pytest -q
uv run --directory panel/worker pytest -q
uv run --directory node/agent pytest -q

# Frontends
cd panel/admin-frontend && npm run lint && npm run build
cd panel/user-frontend && npm run lint && npm run build
```

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and how to submit changes.

## License

This project is licensed under the [MIT License](LICENSE).
