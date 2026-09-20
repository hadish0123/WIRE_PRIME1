# PRIMEVPN Node Agent v100.0.0

Restricted data-plane agent for PRIMEVPN. The control plane sends desired state; the agent validates and atomically applies protocol configuration, reports capabilities/health and exposes traffic counters. No arbitrary shell endpoint exists.

Lifecycle: DISCOVERED -> AUTHENTICATING -> INSTALLING -> CONFIGURING -> HEALTH_CHECK -> SYNCING -> READY.

A node keeps its last valid configuration when the control plane is unavailable.