/**
 * Device-scoped public URLs and the composite cache keys built from them.
 *
 * Every configuration, QR code and chunk list belongs to one device *and* one node, so the URL
 * always carries both. Nothing here ever builds a URL from a node id alone: a legacy
 * node-only path would let the page serve whatever device the backend aliases to it, which is
 * exactly the cross-device QR leak this module exists to prevent.
 *
 * Kept dependency-free so it can be exercised directly by the Node test runner
 * (see `tests/userPage.test.ts`).
 */

export type AppKind = 'awg' | 'vpn'

function encode(value: string): string {
  return encodeURIComponent(value)
}

/** `/pub/u/{token}/devices/{deviceId}` - the owner- and device-scoped prefix. */
export function deviceBasePath(token: string, deviceId: string): string {
  return `/pub/u/${encode(token)}/devices/${encode(deviceId)}`
}

/** Downloadable config for one device on one node (`awg` = `.conf`, `vpn` = `.vpn`). */
export function deviceConfigUrl(
  token: string,
  deviceId: string,
  app: AppKind,
  nodeId: string,
): string {
  return `${deviceBasePath(token, deviceId)}/config/${app}/${encode(nodeId)}`
}

/** QR image for one device on one node. */
export function deviceQrUrl(token: string, deviceId: string, app: AppKind, nodeId: string): string {
  return `${deviceBasePath(token, deviceId)}/qr/${app}/${encode(nodeId)}`
}

/** Multi-part AmneziaVPN QR chunks; the legacy chunk endpoint has no `awg` variant. */
export function deviceQrChunksUrl(token: string, deviceId: string, nodeId: string): string {
  return `${deviceBasePath(token, deviceId)}/qr-chunks/vpn/${encode(nodeId)}`
}

/**
 * Cache key for one device's configuration on one node.
 *
 * The device id is part of the key, so two devices on the same node can never share a cached QR
 * code or URI - the separators make `('a:b', 'c')` and `('a', 'b:c')` distinct keys too.
 */
export function nodeCacheKey(deviceId: string, nodeId: string): string {
  return `${deviceId}\u0000${nodeId}`
}

export function parseNodeCacheKey(key: string): { deviceId: string; nodeId: string } | null {
  const separator = key.indexOf('\u0000')
  if (separator < 0) return null
  return { deviceId: key.slice(0, separator), nodeId: key.slice(separator + 1) }
}

/** Unique `v-for` key for a device's server card. */
export function deviceNodeCardKey(deviceId: string, nodeId: string): string {
  return `${deviceId}:${nodeId}`
}

/**
 * Key identifying one open QR code: the app tab plus the device/node it belongs to.
 *
 * Two devices never share a key, so opening a code on one card cannot reveal another device's code,
 * and a delete can tell whether the open code belonged to the device that just went away.
 */
export function deviceCardQrKey(tab: AppKind, deviceId: string, nodeId: string): string {
  return `${tab}:${deviceNodeCardKey(deviceId, nodeId)}`
}

export function parseDeviceCardQrKey(
  key: string,
): { tab: string; deviceId: string; nodeId: string } | null {
  const parts = key.split(':')
  if (parts.length !== 3 || parts.some((part) => !part)) return null
  const [tab, deviceId, nodeId] = parts
  return { tab, deviceId, nodeId }
}
