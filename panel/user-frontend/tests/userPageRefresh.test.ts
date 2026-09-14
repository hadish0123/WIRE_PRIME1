/**
 * Behavioural tests for the page's refresh loop and its change stream.
 *
 * `useUserPageRefresh` takes every side effect it needs - the authoritative read, the `EventSource`,
 * the visibility source, the clock and the timers - as an injectable environment, so these tests run
 * the *real* composable under the Node test runner against a deferred fetch and a scripted
 * `EventSource`. They cover what a pure guard test cannot: an old response settling after a newer
 * request started, a refresh queued during a flight, a stop in the middle of one, a stream that
 * reconnects or is refused, a hidden tab, and a revoked link.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { PublicApiError, type UserInfo } from '../src/api/userPage.ts'
import { useUserPageRefresh } from '../src/composables/useUserPageRefresh.ts'
import { IDLE_POLL_MS } from '../src/utils/refreshPolicy.ts'
import {
  STREAM_RETRY_DELAYS_MS,
  type EventSourceLike,
  type ServerEvent,
} from '../src/utils/userEventStream.ts'

function userInfo(name: string): UserInfo {
  return {
    user_name: name,
    blocked: false,
    device_limit: 0,
    device_count: 0,
    can_add_device: true,
    nodes: [],
    devices: [],
    status: { code: 'active', reason: null },
    subscription: { managed: true, expire_at: null, last_synced_at: null },
    traffic: {
      used_bytes: 0,
      limit_bytes: null,
      local_used_bytes: 0,
      remote_used_bytes: 0,
      updated_at: null,
    },
    telegram_proxy: null,
    updated_at: null,
  }
}

/** Resolves once every already-queued microtask and one macrotask turn have run. */
function flush(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve))
}

interface PendingRead {
  token: string
  signal?: AbortSignal
  aborted: boolean
  resolve: (data: UserInfo) => void
  reject: (error: unknown) => void
}

function deferredReads(abortRejects: boolean) {
  const reads: PendingRead[] = []
  const fetchInfo = (token: string, signal?: AbortSignal): Promise<UserInfo> => {
    return new Promise<UserInfo>((resolve, reject) => {
      const read: PendingRead = { token, signal, aborted: false, resolve, reject }
      reads.push(read)
      signal?.addEventListener('abort', () => {
        read.aborted = true
        // A real fetch rejects with an AbortError; `abortRejects: false` models a response that was
        // already on its way, which still has to be dropped by the composable itself.
        if (abortRejects) reject(new DOMException('aborted', 'AbortError'))
      })
    })
  }
  return { reads, fetchInfo }
}

interface ArmedTimer {
  id: number
  delayMs: number
  listener: () => void
}

function fakeTimers() {
  let nextId = 1
  const timers = new Map<number, ArmedTimer>()
  return {
    setTimer: (listener: () => void, delayMs: number): ReturnType<typeof setTimeout> => {
      const id = (nextId += 1)
      timers.set(id, { id, delayMs, listener })
      return id as unknown as ReturnType<typeof setTimeout>
    },
    clearTimer: (handle: ReturnType<typeof setTimeout>): void => {
      timers.delete(Number(handle))
    },
    delays: (): number[] => [...timers.values()].map((entry) => entry.delayMs),
    /** Fire the single armed timer with this delay; fails loudly when there is none. */
    run(delayMs: number): void {
      const found = [...timers.values()].find((entry) => entry.delayMs === delayMs)
      assert.ok(
        found,
        `no timer armed with delay ${delayMs}; armed: ${JSON.stringify(timers.size)}`,
      )
      timers.delete(found.id)
      found.listener()
    },
  }
}

class StubEventSource implements EventSourceLike {
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSED = 2
  readonly CONNECTING = 0
  readonly OPEN = 1
  readonly CLOSED = 2
  readyState = 0
  closed = false
  url: string
  private readonly listeners = new Map<string, ((event: ServerEvent) => void)[]>()

  constructor(url: string) {
    this.url = url
  }

  addEventListener(type: string, listener: (event: ServerEvent) => void): void {
    const listeners = this.listeners.get(type) ?? []
    listeners.push(listener)
    this.listeners.set(type, listeners)
  }

  close(): void {
    this.closed = true
    this.readyState = this.CLOSED
  }

  emit(type: string, data?: string): void {
    for (const listener of [...(this.listeners.get(type) ?? [])]) listener({ data })
  }

  /** The connection opened: the server sends `connected` once per connection. */
  connect(notifications = true): void {
    this.readyState = this.OPEN
    this.emit('open')
    this.emit('connected', JSON.stringify({ user_id: 'user-1', notifications }))
  }

  /** The server refused the connection (404/503): the browser never retries this one. */
  failFatal(): void {
    this.readyState = this.CLOSED
    this.emit('error')
  }

  /** The connection dropped: the browser reconnects it on its own. */
  failTransient(): void {
    this.readyState = this.CONNECTING
    this.emit('error')
  }
}

function fakeVisibility(initialHidden = false) {
  let hidden = initialHidden
  const listeners = new Set<() => void>()
  return {
    source: {
      isHidden: () => hidden,
      listen: (listener: () => void): (() => void) => {
        listeners.add(listener)
        return () => {
          listeners.delete(listener)
        }
      },
    },
    setHidden(next: boolean): void {
      hidden = next
      for (const listener of [...listeners]) listener()
    },
    listenerCount: (): number => listeners.size,
  }
}

function createPage(options: { token?: string; hidden?: boolean; abortRejects?: boolean } = {}) {
  const reads = deferredReads(options.abortRejects ?? true)
  const timers = fakeTimers()
  const visibility = fakeVisibility(options.hidden ?? false)
  const sources: StubEventSource[] = []
  let token = options.token ?? 'tok-1'
  let unauthorizedCalls = 0
  let clock = 1_000

  const page = useUserPageRefresh(() => token, {
    fetchInfo: reads.fetchInfo,
    createEventSource: (url) => {
      const source = new StubEventSource(url)
      sources.push(source)
      return source
    },
    visibility: visibility.source,
    now: () => (clock += 1),
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
    onUnauthorized: () => {
      unauthorizedCalls += 1
    },
  })

  return {
    page,
    reads: reads.reads,
    timers,
    visibility,
    sources,
    setToken: (next: string) => {
      token = next
    },
    unauthorizedCalls: () => unauthorizedCalls,
  }
}

describe('page refresh loop', () => {
  it('starts, keeps polling as the fallback and opens one stream for the token', async () => {
    const h = createPage()

    h.page.start()
    await flush()
    assert.equal(h.reads.length, 1)
    assert.equal(h.reads[0].token, 'tok-1')
    assert.equal(h.sources.length, 1)
    assert.equal(h.sources[0].url, '/pub/u/tok-1/events')
    assert.equal(h.page.loading.value, true)

    h.reads[0].resolve(userInfo('first'))
    await flush()

    assert.equal(h.page.info.value?.user_name, 'first')
    assert.equal(h.page.loading.value, false)
    // Polling stays armed even though the stream is healthy: the stream is an accelerator only.
    assert.deepEqual(h.timers.delays(), [IDLE_POLL_MS])
    h.timers.run(IDLE_POLL_MS)
    await flush()
    assert.equal(h.reads.length, 2)
  })

  it('coalesces every refresh asked for during a flight into one follow-up', async () => {
    const h = createPage()

    h.page.start()
    await flush()
    assert.equal(h.reads.length, 1)

    void h.page.refresh()
    void h.page.refresh()
    await flush()
    assert.equal(h.reads.length, 1, 'no overlapping request')

    h.reads[0].resolve(userInfo('first'))
    await flush()
    assert.equal(h.reads.length, 2, 'exactly one follow-up ran')

    h.reads[1].resolve(userInfo('second'))
    await flush()
    assert.equal(h.page.info.value?.user_name, 'second')
    assert.deepEqual(h.timers.delays(), [IDLE_POLL_MS])
  })

  it('drops a superseded answer even when the fetch ignores the abort', async () => {
    const h = createPage({ abortRejects: false })

    h.page.start()
    await flush()
    h.setToken('tok-2')
    void h.page.reset()
    await flush()
    assert.equal(h.reads.length, 2)
    assert.equal(h.reads[1].token, 'tok-2')

    // The old account's read settles last, after the new request is already in flight.
    h.reads[0].resolve(userInfo('previous account'))
    await flush()

    assert.equal(h.page.info.value, null, 'the old answer must not land')
    assert.deepEqual(
      h.timers.delays(),
      [],
      'its finalizer must not arm a poll for the old response',
    )
    assert.equal(h.page.loading.value, true, 'nor clear the new request loading state')

    h.reads[1].resolve(userInfo('new account'))
    await flush()
    assert.equal(h.page.info.value?.user_name, 'new account')
    assert.equal(h.page.loading.value, false)
  })

  it('keeps the newer request controller: a stop aborts it, not the superseded one', async () => {
    const h = createPage()

    h.page.start()
    await flush()
    h.setToken('tok-2')
    void h.page.reset()
    await flush()

    assert.equal(h.reads[0].aborted, true, 'reset aborted the old request')
    assert.equal(h.reads[1].aborted, false)
    // The old finalizer ran by now; a clobbered controller would leave nothing to abort here.
    h.page.stop()
    assert.equal(h.reads[1].aborted, true, 'stop aborted the request that owned the state')
  })

  it('stop cancels queued work, timers and any late answer', async () => {
    const h = createPage({ abortRejects: false })

    h.page.start()
    await flush()
    void h.page.refresh()
    h.page.stop()

    h.reads[0].resolve(userInfo('late'))
    await flush()

    assert.equal(h.page.info.value, null)
    assert.deepEqual(h.timers.delays(), [])
    assert.equal(h.reads.length, 1, 'the queued refresh must not run after exit')
    assert.equal(h.visibility.listenerCount(), 0)

    await h.page.refresh()
    await flush()
    assert.equal(h.reads.length, 1, 'no request may start after exit')
  })

  it('retries a failed first read on the idle cadence instead of leaving the page dead', async () => {
    const h = createPage()

    h.page.start()
    await flush()
    h.reads[0].reject(new PublicApiError('network'))
    await flush()

    assert.equal(h.page.error.value?.kind, 'network')
    assert.equal(h.page.loading.value, false)
    assert.deepEqual(h.timers.delays(), [IDLE_POLL_MS])

    h.timers.run(IDLE_POLL_MS)
    await flush()
    assert.equal(h.reads.length, 2)

    h.reads[1].resolve(userInfo('first'))
    await flush()
    assert.equal(h.page.info.value?.user_name, 'first')
    assert.equal(h.page.error.value, null)
  })

  it('keeps the last good payload when a later refresh fails', async () => {
    const h = createPage()

    h.page.start()
    await flush()
    h.reads[0].resolve(userInfo('first'))
    await flush()
    h.timers.run(IDLE_POLL_MS)
    await flush()
    h.reads[1].reject(new PublicApiError('network'))
    await flush()

    assert.equal(h.page.info.value?.user_name, 'first')
    assert.equal(h.page.retrying.value, true)
    assert.equal(h.page.error.value?.kind, 'network')
  })

  it('accepts a mutation snapshot and refuses the read that was in flight before it', async () => {
    const h = createPage()

    h.page.start()
    await flush()
    h.page.invalidate()
    h.page.acceptInfo(userInfo('mutation snapshot'))
    assert.equal(h.reads.length, 1)

    h.reads[0].resolve(userInfo('pre-write'))
    await flush()

    assert.equal(h.page.info.value?.user_name, 'mutation snapshot')
    assert.equal(h.page.loading.value, false)
  })
})

describe('page change stream', () => {
  it('re-reads the authoritative state on connected and on changed, never from the frame', async () => {
    const h = createPage()

    h.page.start()
    await flush()
    h.reads[0].resolve(userInfo('first'))
    await flush()

    const source = h.sources[0]
    source.connect()
    await flush()
    assert.equal(h.reads.length, 2, 'connected re-reads')
    assert.equal(h.page.notificationsAvailable.value, true)

    h.reads[1].resolve(userInfo('first'))
    await flush()
    source.emit(
      'changed',
      JSON.stringify({ reason: 'device.created', user_name: 'injected', devices: [{ id: 'x' }] }),
    )
    await flush()
    assert.equal(h.page.info.value?.user_name, 'first', 'the frame is not applied as state')
    assert.equal(h.page.info.value?.devices.length, 0)
    assert.equal(h.reads.length, 3, 'changed re-reads')

    h.reads[2].resolve(userInfo('second'))
    await flush()
    assert.equal(h.page.info.value?.user_name, 'second')
  })

  it('keeps polling when the stream reports notifications unavailable', async () => {
    const h = createPage()

    h.page.start()
    await flush()
    h.reads[0].resolve(userInfo('first'))
    await flush()

    h.sources[0].connect(false)
    await flush()
    assert.equal(h.page.notificationsAvailable.value, false)
    assert.equal(h.reads.length, 2, 'a reconnect re-reads even when push is degraded')
    h.reads[1].resolve(userInfo('first'))
    await flush()

    assert.deepEqual(h.timers.delays(), [IDLE_POLL_MS], 'polling remains the transport')
    h.timers.run(IDLE_POLL_MS)
    await flush()
    assert.equal(h.reads.length, 3)
  })

  it('closes the stream while hidden and reopens plus revalidates on return', async () => {
    const h = createPage()

    h.page.start()
    await flush()
    h.reads[0].resolve(userInfo('first'))
    await flush()
    assert.equal(h.sources.length, 1)

    h.visibility.setHidden(true)
    await flush()
    assert.equal(h.sources[0].closed, true)
    assert.deepEqual(h.timers.delays(), [], 'a hidden tab is not polled')

    h.visibility.setHidden(false)
    await flush()
    assert.equal(h.sources.length, 2, 'a fresh stream for the same token')
    assert.equal(h.reads.length, 2, 'and an immediate revalidation')
    h.reads[1].resolve(userInfo('first'))
    await flush()
    assert.deepEqual(h.timers.delays(), [IDLE_POLL_MS])
  })

  it('reconnects a refused stream with a bounded backoff and leaves a dropped one to the browser', async () => {
    const h = createPage()

    h.page.start()
    await flush()
    h.reads[0].resolve(userInfo('first'))
    await flush()

    h.sources[0].failTransient()
    await flush()
    assert.equal(h.sources.length, 1, 'the browser reconnects a dropped stream itself')
    assert.deepEqual(h.timers.delays(), [IDLE_POLL_MS], 'and the page schedules no retry for it')

    h.sources[0].failFatal()
    await flush()
    assert.equal(h.sources.length, 1, 'not reconnected immediately')
    assert.ok(h.timers.delays().includes(STREAM_RETRY_DELAYS_MS[0]))

    h.timers.run(STREAM_RETRY_DELAYS_MS[0])
    await flush()
    assert.equal(h.sources.length, 2, 'the controlled retry opened a fresh stream')
    assert.equal(h.sources[1].url, '/pub/u/tok-1/events')
  })

  it('closes a revoked token, drops rendered state and re-reads to surface the invalid link', async () => {
    const h = createPage()

    h.page.start()
    await flush()
    h.reads[0].resolve(userInfo('first'))
    await flush()

    h.sources[0].emit('unauthorized', JSON.stringify({ reason: 'token' }))
    await flush()

    assert.equal(h.sources[0].closed, true)
    assert.equal(h.page.info.value, null, 'nothing rendered may survive a revoked link')
    assert.equal(h.page.loading.value, true)
    assert.equal(h.unauthorizedCalls(), 1, 'the page drops its cached configurations')
    assert.equal(h.reads.length, 2, 'the state is re-read')

    h.reads[1].reject(new PublicApiError('not_found', 404))
    await flush()
    assert.equal(h.page.error.value?.kind, 'not_found')
    assert.equal(h.page.retrying.value, false)
    assert.equal(h.page.loading.value, false)

    // A revoked token is not reconnected by visibility alone; only a token change reopens it.
    h.visibility.setHidden(true)
    h.visibility.setHidden(false)
    await flush()
    assert.equal(h.sources.length, 1)
    assert.equal(h.reads.length, 3, 'becoming visible still revalidates the page')
  })

  it("closes the old account's stream and opens a new one on a token change", async () => {
    const h = createPage()

    h.page.start()
    await flush()
    h.reads[0].resolve(userInfo('first'))
    await flush()

    h.setToken('tok-2')
    void h.page.reset()
    await flush()

    assert.equal(h.sources[0].closed, true)
    assert.equal(h.sources.length, 2)
    assert.equal(h.sources[1].url, '/pub/u/tok-2/events')

    // A late frame from the closed stream must not touch the new account.
    h.sources[0].emit('changed', JSON.stringify({ reason: 'device.created' }))
    await flush()
    assert.equal(h.reads.length, 2, 'the old stream cannot trigger a read')

    h.reads[1].resolve(userInfo('new account'))
    await flush()
    assert.equal(h.page.info.value?.user_name, 'new account')
  })
})
