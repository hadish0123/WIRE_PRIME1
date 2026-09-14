/**
 * Per-device, per-node QR chunk state for the public page.
 *
 * Every entry is keyed by device *and* node through {@link DeviceQrCache}, so a QR code can never
 * surface under another device, and a device that disappears (deleted here, revoked elsewhere) takes
 * its cached configuration with it. Requests for a device/node that is already loading are not
 * repeated, and an answer that arrives after the device was forgotten or the route token changed is
 * refused instead of re-adding state for a page that no longer shows it.
 */

import { computed, onUnmounted, ref } from 'vue'

import {
  EMPTY_QR_ITEM,
  fetchVpnChunks,
  type QrMapItem,
  type UserDevice,
  type UserNode,
} from '../api/userPage'
import { DeviceQrCache, type QrLoadState } from '../utils/deviceQrCache'
import { deviceNodeCardKey, nodeCacheKey, parseNodeCacheKey } from '../utils/deviceUrls'
import { svgToDataUri } from '../utils/format'

const ROTATION_INTERVAL_MS = 1500

export function useVpnQrChunks(getUserId: () => string) {
  const cache = new DeviceQrCache()
  /** Bumped after every cache change; the computed below reads it to stay reactive. */
  const version = ref(0)
  const knownDevices = new Set<string>()
  const controllers = new Map<string, AbortController>()
  let rotationTimer: ReturnType<typeof setInterval> | null = null

  const qrMap = computed<Record<string, QrMapItem>>(() => {
    void version.value
    const map: Record<string, QrMapItem> = {}
    for (const key of cache.keys()) {
      const parsed = parseNodeCacheKey(key)
      if (!parsed) continue
      const entry = cache.get(parsed.deviceId, parsed.nodeId)
      if (!entry) continue
      const cardKey = deviceNodeCardKey(parsed.deviceId, parsed.nodeId)
      if (entry.state.kind === 'chunks') {
        map[cardKey] = {
          hasChunks: true,
          hasError: false,
          chunks: entry.state.chunks,
          idx: entry.state.idx,
          chunkCount: entry.state.chunks.length,
        }
      } else if (entry.state.kind === 'error') {
        map[cardKey] = { ...EMPTY_QR_ITEM, hasError: true }
      }
    }
    return map
  })

  function touch(): void {
    version.value += 1
  }

  function abortDevice(deviceId: string): void {
    const prefix = nodeCacheKey(deviceId, '')
    for (const [key, controller] of [...controllers.entries()]) {
      if (key.startsWith(prefix)) {
        controller.abort()
        controllers.delete(key)
      }
    }
  }

  function abortAll(): void {
    for (const controller of controllers.values()) controller.abort()
    controllers.clear()
  }

  function stopRotation(): void {
    if (rotationTimer !== null) {
      clearInterval(rotationTimer)
      rotationTimer = null
    }
  }

  function startRotation(): void {
    if (rotationTimer !== null) return
    rotationTimer = setInterval(() => {
      cache.rotate()
      touch()
    }, ROTATION_INTERVAL_MS)
  }

  /** Tell the cache which devices the page currently lists; deleted ones are dropped. */
  function syncDevices(devices: UserDevice[]): void {
    const live = new Set(devices.map((device) => device.id))
    for (const deviceId of [...knownDevices]) {
      if (!live.has(deviceId)) forgetDevice(deviceId)
    }
    for (const deviceId of live) {
      if (!knownDevices.has(deviceId)) {
        knownDevices.add(deviceId)
        cache.trackDevice(deviceId)
      }
    }
  }

  async function loadChunks(deviceId: string, node: UserNode): Promise<void> {
    if (!node.ready || !node.vpn_uri) return
    if (cache.has(deviceId, node.id) || cache.isLoading(deviceId, node.id)) return
    const generation = cache.currentGeneration
    const key = nodeCacheKey(deviceId, node.id)
    const controller = new AbortController()
    controllers.set(key, controller)
    cache.set(deviceId, node.id, { kind: 'loading' }, generation)
    touch()
    try {
      const data = await fetchVpnChunks(
        getUserId(),
        deviceId,
        node.id,
        svgToDataUri,
        controller.signal,
      )
      if (data === null) return
      const state: QrLoadState =
        'chunks' in data
          ? { kind: 'chunks', chunks: data.chunks, idx: data.idx }
          : { kind: 'error' }
      if (cache.setIfLive(deviceId, node.id, state, generation)) touch()
    } finally {
      if (controllers.get(key) === controller) controllers.delete(key)
    }
  }

  /** Fetch every missing QR chunk list; existing entries are kept (no refetch on each refresh). */
  function fetchAllVpnChunks(devices: UserDevice[]): void {
    syncDevices(devices)
    for (const device of devices) {
      for (const node of device.nodes) void loadChunks(device.id, node)
    }
    startRotation()
  }

  /** Drop one device: abort its fetches and remove its cached configuration. */
  function forgetDevice(deviceId: string): void {
    abortDevice(deviceId)
    knownDevices.delete(deviceId)
    cache.forgetDevice(deviceId)
    touch()
  }

  /** Route token change: nothing cached from the previous page may survive. */
  function reset(): void {
    abortAll()
    knownDevices.clear()
    cache.clear()
    stopRotation()
    touch()
  }

  onUnmounted(() => {
    abortAll()
    stopRotation()
  })

  return { qrMap, syncDevices, fetchAllVpnChunks, forgetDevice, reset, version }
}
