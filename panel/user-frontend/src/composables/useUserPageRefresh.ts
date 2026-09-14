/**
 * Authoritative-state refresh loop with polling as the fallback transport and the public change
 * stream as an accelerator.
 *
 * This is the single place the page re-reads `/info`. The stream (`GET /pub/u/{token}/events`) is a
 * hint, never a source of state: `connected` (including every browser reconnect) and `changed` only
 * trigger a re-read of the authoritative `/info` payload and anything a frame carries is discarded.
 * Polling is only ever *added to*, so a missed event, a degraded stream (`notifications: false`) or
 * a refused one cannot leave the page stale.
 *
 * Invariants:
 * - one request at a time; a refresh asked for while one is in flight is queued and runs immediately
 *   after it, never dropped (a delete must reconcile at once, not at the next poll);
 * - every request owns a generation: a reset, a stop or a newer request turns the older one's answer
 *   *and its finalizer* into no-ops, so a slow earlier response can neither overwrite newer state
 *   nor clear the newer request's controller, run a queued refresh or arm a timer;
 * - `acceptInfo` invalidates outstanding answers before applying a mutation snapshot, so the
 *   snapshot wins over the read that was in flight before the write;
 * - a failed refresh keeps the last good payload and reports a retry; a failed *first* read is
 *   retried on the idle cadence instead of leaving the page blank and dead;
 * - the stream exists only while the page is started and visible: hiding closes it, becoming visible
 *   reopens it and revalidates, and a token change closes the old account's stream before a new one
 *   is opened, so a late event of the old one can never revive it;
 * - `unauthorized` closes the stream for that token, drops everything rendered (it can hold a
 *   configuration secret) and re-reads, which is what surfaces an invalid link;
 * - timers, the visibility listener, the stream and the in-flight request are released on unmount.
 */

import { getCurrentInstance, onUnmounted, ref, type Ref } from 'vue'

import { PublicApiError, fetchUserInfo, type UserInfo } from '../api/userPage.ts'
import {
  IDLE_POLL_MS,
  createStaleGuard,
  hasPendingWork,
  nextPollDelayMs,
  resolveRefresh,
} from '../utils/refreshPolicy.ts'
import {
  createUserEventStream,
  type EventSourceLike,
  type TimerHandle,
} from '../utils/userEventStream.ts'

export interface RefreshOptions {
  /** A background re-read: never shows the first-load skeleton. */
  silent?: boolean
}

/** Where the page's visibility comes from; injectable so the composable runs outside a browser. */
export interface RefreshVisibilitySource {
  isHidden: () => boolean
  /** Returns the unsubscribe function. */
  listen: (listener: () => void) => () => void
}

/**
 * Everything this composable touches outside its own state. Production uses the defaults; the tests
 * pass a deferred read and a scripted `EventSource` to drive the real lifecycle without a browser.
 */
export interface UserPageRefreshEnvironment {
  fetchInfo?: (token: string, signal?: AbortSignal) => Promise<UserInfo>
  createEventSource?: (url: string) => EventSourceLike
  visibility?: RefreshVisibilitySource
  now?: () => number
  setTimer?: (listener: () => void, delayMs: number) => TimerHandle
  clearTimer?: (handle: TimerHandle) => void
  /** The link stopped being authorized: the page drops cached configuration secrets. */
  onUnauthorized?: () => void
}

export interface UseUserPageRefresh {
  info: Ref<UserInfo | null>
  error: Ref<PublicApiError | null>
  retrying: Ref<boolean>
  loading: Ref<boolean>
  refreshing: Ref<boolean>
  lastLoadedAt: Ref<number | null>
  /** Whether the last `connected` frame said the backend can push notifications. */
  notificationsAvailable: Ref<boolean>
  refresh: (options?: RefreshOptions) => Promise<UserInfo | null>
  /** Accept payload the client already has (mutation response, later the event stream). */
  acceptInfo: (data: UserInfo) => void
  /** Mark newer state as existing: in-flight answers are dropped from now on. */
  invalidate: () => void
  /** Route token changed: drop everything and load the new page. */
  reset: () => Promise<UserInfo | null>
  start: () => void
  stop: () => void
}

const documentVisibility: RefreshVisibilitySource = {
  isHidden: () => typeof document !== 'undefined' && document.visibilityState === 'hidden',
  listen: (listener) => {
    if (typeof document === 'undefined') return () => {}
    document.addEventListener('visibilitychange', listener)
    return () => document.removeEventListener('visibilitychange', listener)
  },
}

/**
 * @param getToken Current public token. Read on every request rather than captured, so the same
 *   composable instance follows a route change instead of re-reading the previous account.
 * @param environment Side effects to use instead of the browser's (tests).
 */
export function useUserPageRefresh(
  getToken: () => string,
  environment: UserPageRefreshEnvironment = {},
): UseUserPageRefresh {
  const fetchInfo = environment.fetchInfo ?? fetchUserInfo
  // The native `EventSource` is an adapter away from the small interface the stream uses: every
  // member it reads (readyState and the three state constants, addEventListener, close) exists on
  // the real object with the same meaning.
  const createEventSource =
    environment.createEventSource ??
    ((url: string) => new EventSource(url) as unknown as EventSourceLike)
  const visibility = environment.visibility ?? documentVisibility
  const now = environment.now ?? Date.now
  const setTimer =
    environment.setTimer ??
    ((listener: () => void, delayMs: number) => setTimeout(listener, delayMs))
  const clearTimer = environment.clearTimer ?? ((handle: TimerHandle) => clearTimeout(handle))

  const guard = createStaleGuard()
  const info = ref<UserInfo | null>(null)
  const error = ref<PublicApiError | null>(null)
  const retrying = ref(false)
  const loading = ref(true)
  const refreshing = ref(false)
  const lastLoadedAt = ref<number | null>(null)
  const notificationsAvailable = ref(false)

  let timer: TimerHandle | null = null
  let controller: AbortController | null = null
  /** The generation of the request that currently owns the shared state. */
  let run = 0
  let inFlight = false
  let queued = false
  let started = false
  let pendingSince: number | null = null
  let unlistenVisibility: (() => void) | null = null

  const stream = createUserEventStream({
    getToken,
    createEventSource,
    setTimer,
    clearTimer,
    handlers: {
      onConnected: (event) => {
        notificationsAvailable.value = event.notifications
        // Re-read on every connect, the reconnect itself included: that covers anything announced
        // while the stream was down. What the frame says is never applied as state.
        void refresh({ silent: true })
      },
      onChanged: () => {
        // The reason names what moved; the page still reads the whole authoritative state.
        void refresh({ silent: true })
      },
      onUnauthorized: () => {
        notificationsAvailable.value = false
        dropRevokedState()
        environment.onUnauthorized?.()
        void refresh({ silent: true })
      },
    },
  })

  function clearPollTimer(): void {
    if (timer !== null) {
      clearTimer(timer)
      timer = null
    }
  }

  function pendingForMs(): number {
    if (!hasPendingWork(info.value)) {
      pendingSince = null
      return 0
    }
    if (pendingSince === null) pendingSince = now()
    return now() - pendingSince
  }

  function isHidden(): boolean {
    return visibility.isHidden()
  }

  /** (Re)arm the fallback poll for the state that is on screen right now. */
  function schedule(): void {
    clearPollTimer()
    if (!started || (!info.value && !error.value)) return
    let delay: number | null
    if (info.value) {
      delay = nextPollDelayMs(info.value, { hidden: isHidden(), pendingForMs: pendingForMs() })
    } else {
      // Nothing was ever loaded: retry the first read slowly instead of leaving a dead page, and
      // let a manual retry or the return to a visible tab revalidate at once.
      delay = isHidden() ? null : IDLE_POLL_MS
    }
    if (delay === null) return
    timer = setTimer(() => {
      timer = null
      void refresh({ silent: true })
    }, delay)
  }

  function apply(
    result: { ok: true; data: UserInfo } | { ok: false; error: PublicApiError },
  ): void {
    const current = { data: info.value, error: error.value, retrying: retrying.value }
    const next = resolveRefresh(current, result)
    info.value = next.data
    error.value = next.error
    retrying.value = next.retrying
  }

  /** Everything rendered goes: it can hold a configuration secret for a link that is now dead. */
  function dropRevokedState(): void {
    guard.invalidate()
    info.value = null
    error.value = null
    retrying.value = false
    lastLoadedAt.value = null
    pendingSince = null
    loading.value = true
  }

  /**
   * Take the shared state away from whatever request is in flight. Its answer and its finalizer both
   * become no-ops, which is what keeps a superseded request from clobbering its successor.
   */
  function seize(): void {
    run += 1
    inFlight = false
    queued = false
  }

  function isLive(requestRun: number): boolean {
    return requestRun === run
  }

  async function refresh(options: RefreshOptions = {}): Promise<UserInfo | null> {
    // After a stop nothing may start work again, neither a queued refresh nor a late event handler.
    if (!started) return info.value
    if (inFlight) {
      // Never overlap, but never drop the request either: it runs as soon as this one settles.
      queued = true
      return info.value
    }
    inFlight = true
    const requestRun = ++run
    if (!options.silent) refreshing.value = true
    const ticket = guard.begin()
    const requestedToken = getToken()
    const own = new AbortController()
    controller = own
    try {
      const data = await fetchInfo(requestedToken, own.signal)
      if (isLive(requestRun) && guard.isCurrent(ticket) && getToken() === requestedToken) {
        apply({ ok: true, data })
        lastLoadedAt.value = now()
      }
    } catch (caught) {
      const aborted = caught instanceof DOMException && caught.name === 'AbortError'
      if (
        !aborted &&
        isLive(requestRun) &&
        guard.isCurrent(ticket) &&
        getToken() === requestedToken
      ) {
        apply({
          ok: false,
          error: caught instanceof PublicApiError ? caught : new PublicApiError('unknown'),
        })
      }
    } finally {
      // A reset, a stop or a newer request owns the state now: this finalizer must change nothing,
      // must not run the queued refresh and must not arm the next poll.
      if (isLive(requestRun)) {
        inFlight = false
        controller = null
        refreshing.value = false
        loading.value = false
        if (!started) {
          queued = false
        } else if (queued) {
          queued = false
          void refresh({ silent: true })
        } else {
          schedule()
        }
      }
    }
    return info.value
  }

  function acceptInfo(data: UserInfo): void {
    // A newer snapshot exists now: anything already in flight is older than it and must not land.
    guard.invalidate()
    apply({ ok: true, data })
    lastLoadedAt.value = now()
    loading.value = false
    schedule()
  }

  function invalidate(): void {
    guard.invalidate()
  }

  /** The stream exists only while the page is started and visible; hidden closes it outright. */
  function syncStream(): void {
    if (started && !isHidden()) {
      stream.open()
    } else {
      stream.close()
      notificationsAvailable.value = false
    }
  }

  async function reset(): Promise<UserInfo | null> {
    guard.invalidate()
    seize()
    controller?.abort()
    controller = null
    clearPollTimer()
    pendingSince = null
    info.value = null
    error.value = null
    retrying.value = false
    lastLoadedAt.value = null
    loading.value = true
    // The token changed: the previous account's stream is closed before a new one is opened, so a
    // late event of the old page can neither refresh nor revive it.
    syncStream()
    return refresh()
  }

  function onVisibilityChange(): void {
    if (isHidden()) {
      clearPollTimer()
      stream.close()
      notificationsAvailable.value = false
      return
    }
    // Back on screen: reconnect the stream and revalidate at once.
    syncStream()
    void refresh({ silent: true })
  }

  function start(): void {
    if (started) return
    started = true
    unlistenVisibility = visibility.listen(onVisibilityChange)
    syncStream()
    void refresh()
  }

  function stop(): void {
    started = false
    guard.invalidate()
    seize()
    controller?.abort()
    controller = null
    clearPollTimer()
    pendingSince = null
    unlistenVisibility?.()
    unlistenVisibility = null
    stream.close()
    notificationsAvailable.value = false
  }

  // Registered only inside a component: the tests run this composable directly.
  if (getCurrentInstance()) onUnmounted(stop)

  return {
    info,
    error,
    retrying,
    loading,
    refreshing,
    lastLoadedAt,
    notificationsAvailable,
    refresh,
    acceptInfo,
    invalidate,
    reset,
    start,
    stop,
  }
}
