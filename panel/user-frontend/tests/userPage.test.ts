/**
 * Focused unit tests for the device-scoped URL, cache and refresh policy modules.
 *
 * Run with the Node test runner (`npm run test`): the user frontend has no frontend test runner and
 * these are pure modules, so no dependency was added. The cases that matter are here: a
 * configuration URL must belong to one device, a cached QR code must never surface under another
 * device, and a stale `/info` response must not overwrite a newer mutation or route change.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  deviceBasePath,
  deviceCardQrKey,
  deviceConfigUrl,
  deviceNodeCardKey,
  deviceQrChunksUrl,
  deviceQrUrl,
  nodeCacheKey,
  parseDeviceCardQrKey,
  parseNodeCacheKey,
} from '../src/utils/deviceUrls.ts'
import { DeviceQrCache } from '../src/utils/deviceQrCache.ts'
import { deviceSectionState } from '../src/utils/deviceListState.ts'
import { MAX_DEVICE_NAME_LENGTH, normalizeDeviceName } from '../src/utils/deviceNames.ts'
import {
  PENDING_POLL_MS,
  IDLE_POLL_MS,
  createStaleGuard,
  hasPendingWork,
  initialRefreshState,
  nextPollDelayMs,
  resolveRefresh,
  type PollableInfo,
} from '../src/utils/refreshPolicy.ts'

const TOKEN = 'tok-123'
const DEVICE_A = 'dev-a'
const DEVICE_B = 'dev-b'
const NODE_1 = 'node-1'

describe('device-scoped URLs', () => {
  it('builds every configuration URL from the device and the node', () => {
    assert.equal(deviceBasePath(TOKEN, DEVICE_A), '/pub/u/tok-123/devices/dev-a')
    assert.equal(
      deviceConfigUrl(TOKEN, DEVICE_A, 'awg', NODE_1),
      '/pub/u/tok-123/devices/dev-a/config/awg/node-1',
    )
    assert.equal(
      deviceConfigUrl(TOKEN, DEVICE_A, 'vpn', NODE_1),
      '/pub/u/tok-123/devices/dev-a/config/vpn/node-1',
    )
    assert.equal(
      deviceQrUrl(TOKEN, DEVICE_A, 'awg', NODE_1),
      '/pub/u/tok-123/devices/dev-a/qr/awg/node-1',
    )
    assert.equal(
      deviceQrUrl(TOKEN, DEVICE_A, 'vpn', NODE_1),
      '/pub/u/tok-123/devices/dev-a/qr/vpn/node-1',
    )
    assert.equal(
      deviceQrChunksUrl(TOKEN, DEVICE_A, NODE_1),
      '/pub/u/tok-123/devices/dev-a/qr-chunks/vpn/node-1',
    )
  })

  it('never produces the same URL for two devices on the same node', () => {
    const forDevice = (deviceId: string) => [
      deviceConfigUrl(TOKEN, deviceId, 'awg', NODE_1),
      deviceConfigUrl(TOKEN, deviceId, 'vpn', NODE_1),
      deviceQrUrl(TOKEN, deviceId, 'awg', NODE_1),
      deviceQrUrl(TOKEN, deviceId, 'vpn', NODE_1),
      deviceQrChunksUrl(TOKEN, deviceId, NODE_1),
    ]

    const urlsA = forDevice(DEVICE_A)
    const urlsB = forDevice(DEVICE_B)

    assert.equal(new Set(urlsA).size, urlsA.length)
    for (const url of urlsA) {
      assert.ok(url.includes(`/devices/${DEVICE_A}/`), url)
      assert.ok(!url.includes(`/devices/${DEVICE_B}/`), url)
    }
    assert.deepEqual(
      urlsA.filter((url) => urlsB.includes(url)),
      [],
    )
  })

  it('escapes the token and node id instead of pasting them raw', () => {
    assert.equal(
      deviceQrUrl('a/b c', DEVICE_A, 'vpn', 'node/1'),
      '/pub/u/a%2Fb%20c/devices/dev-a/qr/vpn/node%2F1',
    )
  })

  it('keys a cache entry by device and node together', () => {
    assert.notEqual(nodeCacheKey(DEVICE_A, NODE_1), nodeCacheKey(DEVICE_B, NODE_1))
    assert.notEqual(nodeCacheKey(DEVICE_A, NODE_1), nodeCacheKey(DEVICE_A, 'node-2'))
    assert.notEqual(nodeCacheKey('a:b', 'c'), nodeCacheKey('a', 'b:c'))
    assert.deepEqual(parseNodeCacheKey(nodeCacheKey(DEVICE_A, NODE_1)), {
      deviceId: DEVICE_A,
      nodeId: NODE_1,
    })
    assert.equal(parseNodeCacheKey('no-separator'), null)
    assert.notEqual(deviceNodeCardKey(DEVICE_A, NODE_1), deviceNodeCardKey(DEVICE_B, NODE_1))
  })

  it('identifies an open QR code by app, device and node', () => {
    const vpnA = deviceCardQrKey('vpn', DEVICE_A, NODE_1)

    assert.deepEqual(parseDeviceCardQrKey(vpnA), {
      tab: 'vpn',
      deviceId: DEVICE_A,
      nodeId: NODE_1,
    })
    assert.notEqual(vpnA, deviceCardQrKey('vpn', DEVICE_B, NODE_1))
    assert.notEqual(vpnA, deviceCardQrKey('awg', DEVICE_A, NODE_1))
    assert.notEqual(vpnA, deviceCardQrKey('vpn', DEVICE_A, 'node-2'))
    assert.equal(parseDeviceCardQrKey('garbage'), null)
  })
})

describe('device QR cache', () => {
  function seeded(): DeviceQrCache {
    const cache = new DeviceQrCache()
    cache.trackDevice(DEVICE_A)
    cache.trackDevice(DEVICE_B)
    cache.set(DEVICE_A, NODE_1, { kind: 'chunks', chunks: ['a1', 'a2'], idx: 0 })
    cache.set(DEVICE_B, NODE_1, { kind: 'chunks', chunks: ['b1'], idx: 0 })
    return cache
  }

  it('returns each device its own configuration on a shared node', () => {
    const cache = seeded()

    assert.deepEqual(cache.chunks(DEVICE_A, NODE_1)?.chunks, ['a1', 'a2'])
    assert.deepEqual(cache.chunks(DEVICE_B, NODE_1)?.chunks, ['b1'])
    assert.equal(cache.chunks(DEVICE_A, 'node-2'), undefined)
  })

  it('rotates only multi-part QR codes', () => {
    const cache = seeded()

    cache.rotate()

    assert.equal(cache.chunks(DEVICE_A, NODE_1)?.idx, 1)
    assert.equal(cache.chunks(DEVICE_B, NODE_1)?.idx, 0)
  })

  it('drops exactly one device on delete', () => {
    const cache = seeded()

    assert.equal(cache.forgetDevice(DEVICE_A), 1)

    assert.equal(cache.chunks(DEVICE_A, NODE_1), undefined)
    assert.equal(cache.has(DEVICE_A, NODE_1), false)
    assert.deepEqual(cache.chunks(DEVICE_B, NODE_1)?.chunks, ['b1'])
    assert.deepEqual(cache.keys(), [nodeCacheKey(DEVICE_B, NODE_1)])
  })

  it('refuses a configuration for a device the page no longer lists', () => {
    const cache = seeded()
    const generation = cache.currentGeneration
    cache.forgetDevice(DEVICE_A)

    assert.equal(
      cache.setIfLive(DEVICE_A, NODE_1, { kind: 'chunks', chunks: ['late'], idx: 0 }, generation),
      false,
    )
    assert.equal(cache.chunks(DEVICE_A, NODE_1), undefined)
  })

  it('refuses a response that was requested before a deletion or route change', () => {
    const cache = seeded()
    const inFlight = cache.currentGeneration

    cache.bumpGeneration()
    assert.equal(
      cache.setIfLive(DEVICE_B, NODE_1, { kind: 'chunks', chunks: ['stale'], idx: 0 }, inFlight),
      false,
    )
    assert.deepEqual(cache.chunks(DEVICE_B, NODE_1)?.chunks, ['b1'])

    const current = cache.currentGeneration
    assert.equal(
      cache.setIfLive(DEVICE_B, NODE_1, { kind: 'chunks', chunks: ['fresh'], idx: 0 }, current),
      true,
    )
    assert.deepEqual(cache.chunks(DEVICE_B, NODE_1)?.chunks, ['fresh'])
  })

  it('clears every device and invalidates in-flight work on a route token change', () => {
    const cache = seeded()
    const inFlight = cache.currentGeneration

    cache.clear()

    assert.deepEqual(cache.keys(), [])
    assert.equal(cache.accepts(DEVICE_A, inFlight), false)
    assert.equal(cache.setIfLive(DEVICE_A, NODE_1, { kind: 'error' }, inFlight), false)
  })

  it('tracks loading state so a fetch is not started twice', () => {
    const cache = new DeviceQrCache()
    cache.trackDevice(DEVICE_A)
    cache.set(DEVICE_A, NODE_1, { kind: 'loading' })

    assert.equal(cache.isLoading(DEVICE_A, NODE_1), true)
    assert.equal(cache.chunks(DEVICE_A, NODE_1), undefined)

    cache.set(DEVICE_A, NODE_1, { kind: 'error' })

    assert.equal(cache.isLoading(DEVICE_A, NODE_1), false)
    assert.equal(cache.get(DEVICE_A, NODE_1)?.state.kind, 'error')
  })
})

describe('stale refresh guard', () => {
  it('accepts only the newest outstanding request', () => {
    const guard = createStaleGuard()
    const first = guard.begin()
    const second = guard.begin()

    assert.equal(guard.isCurrent(first), false)
    assert.equal(guard.isCurrent(second), true)
  })

  it('drops an in-flight response once a mutation or route change happens', () => {
    const guard = createStaleGuard()
    const refresh = guard.begin()
    let rendered = 'device list before add'

    // add/delete accepted by the server, or the route token changed: newer state exists now
    guard.invalidate()
    const mutationResult = guard.begin()
    if (guard.isCurrent(mutationResult)) rendered = 'device list after add'

    // the slow /info that started before the mutation now resolves and must be ignored
    if (guard.isCurrent(refresh)) rendered = 'stale device list'

    assert.equal(rendered, 'device list after add')
  })

  it('still applies a response that is the newest one', () => {
    const guard = createStaleGuard()
    const ticket = guard.begin()

    assert.equal(guard.isCurrent(ticket), true)
    guard.begin()
    assert.equal(guard.isCurrent(ticket), false)
  })
})

describe('polling policy', () => {
  function info(overrides: Partial<PollableInfo> = {}): PollableInfo {
    return {
      blocked: false,
      status: { code: 'active' },
      devices: [
        { status: 'ready', nodes: [{ status: 'ready', ready: true }] },
        { status: 'pending', nodes: [{ status: 'pending', ready: false }] },
      ],
      ...overrides,
    }
  }

  it('polls quickly while a device is still being provisioned', () => {
    assert.equal(hasPendingWork(info()), true)
    assert.equal(nextPollDelayMs(info()), PENDING_POLL_MS)
    assert.equal(nextPollDelayMs(info(), { pendingForMs: 5_000 }), PENDING_POLL_MS)
  })

  it('slows down once nothing is pending, and after the fast window closes', () => {
    const settled = info({
      devices: [{ status: 'ready', nodes: [{ status: 'ready', ready: true }] }],
    })

    assert.equal(hasPendingWork(settled), false)
    assert.equal(nextPollDelayMs(settled), IDLE_POLL_MS)
    assert.equal(nextPollDelayMs(info(), { pendingForMs: 600_000 }), IDLE_POLL_MS)
  })

  it('does not treat a blocked, expired or limited account as pending work', () => {
    for (const variant of [
      info({ blocked: true }),
      info({ status: { code: 'expired' } }),
      info({ status: { code: 'limited' } }),
      info({ status: { code: 'blocked' } }),
    ]) {
      assert.equal(hasPendingWork(variant), false)
      assert.equal(nextPollDelayMs(variant), IDLE_POLL_MS)
    }
  })

  it('stops polling while the tab is hidden so the listener can revalidate instead', () => {
    assert.equal(nextPollDelayMs(info(), { hidden: true }), null)
    assert.equal(nextPollDelayMs(info({ blocked: true }), { hidden: true }), null)
  })

  it('treats an unusable configuration on a failed node as pending', () => {
    const diagnosticError = info({
      devices: [{ status: 'error', nodes: [{ status: 'error', ready: false }] }],
    })
    assert.equal(hasPendingWork(diagnosticError), true)

    // the backend may report `error` while still serving an acknowledged peer: that is not pending
    const usableAfterFailedSync = info({
      devices: [{ status: 'ready', nodes: [{ status: 'error', ready: true }] }],
    })
    assert.equal(hasPendingWork(usableAfterFailedSync), false)
  })
})

describe('device names', () => {
  it('normalises Unicode and trims the name the backend will store', () => {
    // the backend trims and NFC-normalises identically; it never rewrites the inner spelling
    assert.deepEqual(normalizeDeviceName('  MacBook Pro  '), { ok: true, name: 'MacBook Pro' })
    assert.deepEqual(normalizeDeviceName('MacBook   Pro'), { ok: true, name: 'MacBook   Pro' })
    // decomposed and precomposed spellings must end up identical
    assert.deepEqual(normalizeDeviceName('Te\u0301le\u0301phone'), { ok: true, name: 'Téléphone' })
    assert.deepEqual(normalizeDeviceName('Телефон'), { ok: true, name: 'Телефон' })
    assert.deepEqual(normalizeDeviceName('手机'), { ok: true, name: '手机' })
  })

  it('refuses a blank, over-long or control-character name before sending it', () => {
    assert.deepEqual(normalizeDeviceName('   '), { ok: false, error: 'blank' })
    assert.deepEqual(normalizeDeviceName('x'.repeat(MAX_DEVICE_NAME_LENGTH + 1)), {
      ok: false,
      error: 'too_long',
    })
    assert.deepEqual(normalizeDeviceName('a\u0000b'), { ok: false, error: 'control_chars' })
    assert.deepEqual(normalizeDeviceName('a\u202Eb'), { ok: false, error: 'control_chars' })
    assert.deepEqual(normalizeDeviceName('x'.repeat(MAX_DEVICE_NAME_LENGTH)), {
      ok: true,
      name: 'x'.repeat(MAX_DEVICE_NAME_LENGTH),
    })
    // a name of 64 astral characters is 128 UTF-16 units but still 64 characters
    assert.deepEqual(normalizeDeviceName('😀'.repeat(64)), { ok: true, name: '😀'.repeat(64) })
    assert.deepEqual(normalizeDeviceName('😀'.repeat(65)), { ok: false, error: 'too_long' })
  })
})

describe('device section state', () => {
  it('shows the owned devices of an inactive owner instead of an empty state', () => {
    // blocked, expired and traffic-limited owners keep their device cards, so they can revoke them
    assert.equal(deviceSectionState({ hasDevices: true, inactive: true }), 'list')
    assert.equal(deviceSectionState({ hasDevices: true, inactive: false }), 'list')
  })

  it('invites a device only while the account may still add one', () => {
    assert.equal(deviceSectionState({ hasDevices: false, inactive: false }), 'invite')
  })

  it('explains an inactive account with no devices rather than a hidden list', () => {
    assert.equal(deviceSectionState({ hasDevices: false, inactive: true }), 'inactive')
  })

  it('never renders an empty state for an account that still owns devices', () => {
    for (const inactive of [true, false]) {
      assert.notEqual(deviceSectionState({ hasDevices: true, inactive }), 'invite')
      assert.notEqual(deviceSectionState({ hasDevices: true, inactive }), 'inactive')
    }
  })
})

describe('refresh outcome folding', () => {
  it('keeps the last good data and reports a retry when a refresh fails', () => {
    const loaded = resolveRefresh(initialRefreshState<string, string>(), {
      ok: true,
      data: 'device list',
    })

    const failed = resolveRefresh(loaded, { ok: false, error: 'network' })

    assert.deepEqual(failed, { data: 'device list', error: 'network', retrying: true })
  })

  it('shows the first-load error as an error, not as a retry', () => {
    const state = resolveRefresh(initialRefreshState<string, string>(), {
      ok: false,
      error: '404',
    })

    assert.deepEqual(state, { data: null, error: '404', retrying: false })
  })

  it('clears the error on the next success', () => {
    const recovered = resolveRefresh(
      { data: 'device list', error: 'network', retrying: true },
      { ok: true, data: 'device list with new device' },
    )

    assert.deepEqual(recovered, {
      data: 'device list with new device',
      error: null,
      retrying: false,
    })
  })
})
