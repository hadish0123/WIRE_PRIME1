/**
 * Canonical paths of the authenticated, device-scoped admin configuration routes.
 *
 * Every configuration, QR code and archive the admin UI requests names its device explicitly. The
 * backend's implicit (pre-device) routes resolve *only* the migration ``Default`` device and answer
 * ``409`` otherwise, so they must never be used to guess which device an account means - a new
 * account owns no devices and therefore has nothing to download at all.
 *
 * The module is deliberately pure (no DOM, no fetch, no Vue): it is the single place the routes are
 * spelled out, and plain Node can unit-test it without a bundler or a test runner dependency.
 */

export interface DeviceRoute {
  userId: string
  deviceId: string
}

export interface DeviceNodeRoute extends DeviceRoute {
  nodeId: string
}

const segment = (value: string): string => encodeURIComponent(value)

/** The owner's device budget plus its live devices (``AdminUserDevices``). */
export function userDevicesPath(userId: string): string {
  return `/users/${segment(userId)}/devices`
}

/** The local per-user device limit write (``0`` means unlimited). */
export function userDeviceLimitPath(userId: string): string {
  return `/users/${segment(userId)}/device-limit`
}

/** Per-node config texts of one device; unready nodes are reported instead of omitted. */
export function deviceConfigsPath({ userId, deviceId }: DeviceRoute): string {
  return `/users/${segment(userId)}/devices/${segment(deviceId)}/configs`
}

/** One device's ``.conf`` for one node. */
export function deviceConfigPath({ userId, deviceId, nodeId }: DeviceNodeRoute): string {
  return `${deviceConfigsPath({ userId, deviceId })}/${segment(nodeId)}`
}

/** One device's AmneziaWG QR code for one node. */
export function deviceQrPath({ userId, deviceId, nodeId }: DeviceNodeRoute): string {
  return `/users/${segment(userId)}/devices/${segment(deviceId)}/qr/${segment(nodeId)}`
}

/** One device's AmneziaVPN QR code for one node. */
export function deviceQrAmneziaPath({ userId, deviceId, nodeId }: DeviceNodeRoute): string {
  return `/users/${segment(userId)}/devices/${segment(deviceId)}/qr-amnezia/${segment(nodeId)}`
}

/**
 * The *user-wide* archive, which needs no device id because it covers every live device and lays
 * them out in one uniquely named folder per device.
 */
export function userConfigsZipPath(userId: string): string {
  return `/users/${segment(userId)}/configs/zip`
}

/**
 * Row key of a peer in tables: the device/node pair.
 *
 * Keying on the owner (or on the node alone) collides as soon as one owner holds two devices on one
 * node, which is exactly the case device ownership introduces.
 */
export function peerRowKey(deviceId: string | null, nodeId: string): string {
  return `${deviceId ?? 'legacy'}:${nodeId}`
}
