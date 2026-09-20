# PRIMEVPN v100 Architecture
Control Plane: Web, API, Worker, Scheduler and cache on Railway.
Data Plane: VPS Node with Node Agent, WireGuard, AmneziaWG, OpenVPN, firewall/NAT and enforcement.
VPN traffic is Client <-> VPS Node and never traverses Railway.
Every tenant-scoped resource carries tenant_id and every resource query is authorization-scoped.
Node Agent exposes only allowlisted inspection, validation, apply, health and counters operations.
