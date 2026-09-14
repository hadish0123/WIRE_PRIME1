/**
 * The public page's change stream: one native `EventSource` per account token.
 *
 * The stream is a *hint*, never a source of state. It carries no keys and no configuration bodies -
 * `connected` says the channel is up and `changed` carries a descriptive reason - and the page's
 * only reaction to either is to re-read `/pub/u/{token}/info` through `useUserPageRefresh`. Nothing
 * this module parses is ever applied to the page; a malformed frame is not guessed at.
 *
 * Transport rules kept here so the page does not have to know them:
 *
 * - a `connected` frame (sent once per connection, so also on every browser reconnect) reports
 *   whether the backend's notification listener is available; the client keeps its polling
 *   regardless, so `notifications: false` means "do not lean on this", not "stop reading";
 * - a dropped connection is reconnected by the browser itself (`readyState` back to `CONNECTING`,
 *   with its own backoff) and needs nothing from here;
 * - a connection the server *refused* (404 for a token that no longer resolves, 503 while the hub is
 *   at capacity or shutting down) ends up `CLOSED`, which the browser never retries: that case is
 *   retried here with a bounded backoff, so a dead endpoint cannot become a hot loop;
 * - `unauthorized` means the token stopped resolving: the stream closes, is latched for that token
 *   (nothing reconnects a revoked link until the token changes) and the caller drops what it
 *   rendered and re-reads, which is what surfaces the invalid link.
 */

/** The part of a `MessageEvent` these frames carry. */
export interface ServerEvent {
  readonly data?: string
}

/**
 * The slice of the native `EventSource` this module uses, so a test can drive the stream without a
 * browser. Kept minimal on purpose: the real `EventSource` is one adapter away (see the default
 * factory in `useUserPageRefresh`).
 */
export interface EventSourceLike {
  readonly readyState: number
  readonly CONNECTING: number
  readonly OPEN: number
  readonly CLOSED: number
  addEventListener: (type: string, listener: (event: ServerEvent) => void) => void
  close: () => void
}

export type TimerHandle = ReturnType<typeof setTimeout>

export interface ConnectedEvent {
  /** Informational only: the stream is already scoped to one token. */
  userId: string | null
  /** Whether the backend's notification listener was available when this connection opened. */
  notifications: boolean
}

export interface UserEventStreamHandlers {
  onConnected: (event: ConnectedEvent) => void
  onChanged: (reason: string) => void
  onUnauthorized: () => void
}

export interface UserEventStreamOptions {
  getToken: () => string
  createEventSource: (url: string) => EventSourceLike
  setTimer: (listener: () => void, delayMs: number) => TimerHandle
  clearTimer: (handle: TimerHandle) => void
  handlers: UserEventStreamHandlers
  /** Backoff for a refused connection; the last entry repeats. */
  retryDelaysMs?: number[]
}

/** Bounded retry for a connection the server refused; the last delay repeats. */
export const STREAM_RETRY_DELAYS_MS = [1_000, 2_000, 5_000, 15_000, 30_000]

export function userEventsUrl(token: string): string {
  return `/pub/u/${encodeURIComponent(token)}/events`
}

function parseJsonObject(data: string | undefined): Record<string, unknown> | null {
  if (typeof data !== 'string' || !data) return null
  try {
    const parsed: unknown = JSON.parse(data)
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null
    return parsed as Record<string, unknown>
  } catch {
    return null
  }
}

/** `connected` payload, or `null` when the frame is not the small document the backend sends. */
export function parseConnectedEvent(data: string | undefined): ConnectedEvent | null {
  const payload = parseJsonObject(data)
  if (!payload) return null
  return {
    userId: typeof payload.user_id === 'string' ? payload.user_id : null,
    notifications: payload.notifications === true,
  }
}

/** `changed` payload. The reason only names what moved; the page still re-reads the whole state. */
export function parseChangedEvent(data: string | undefined): { reason: string } | null {
  const payload = parseJsonObject(data)
  if (!payload) return null
  return { reason: typeof payload.reason === 'string' ? payload.reason : '' }
}

export interface UserEventStream {
  /** Connect for the current token; a changed token drops the old stream and opens a new one. */
  open: () => void
  /** Disconnect, cancel retries and stay closed until the next {@link UserEventStream.open}. */
  close: () => void
}

export function createUserEventStream(options: UserEventStreamOptions): UserEventStream {
  const retryDelays = options.retryDelaysMs ?? STREAM_RETRY_DELAYS_MS

  let source: EventSourceLike | null = null
  let connectedToken: string | null = null
  /** Bumped whenever a stream is dropped: a late callback of an old one must change nothing. */
  let generation = 0
  let attempts = 0
  let retry: TimerHandle | null = null
  let disabled = false
  /** A token the server already refused; it is not reconnected until the token itself changes. */
  let rejectedToken: string | null = null

  function cancelRetry(): void {
    if (retry !== null) {
      options.clearTimer(retry)
      retry = null
    }
  }

  function detach(): void {
    generation += 1
    const previous = source
    source = null
    connectedToken = null
    if (previous) previous.close()
  }

  function scheduleRetry(): void {
    if (disabled) return
    cancelRetry()
    const delay = retryDelays[Math.min(attempts, retryDelays.length - 1)]
    attempts += 1
    retry = options.setTimer(() => {
      retry = null
      connect()
    }, delay)
  }

  function connect(): void {
    const token = options.getToken()
    if (!token) return
    cancelRetry()
    const gen = ++generation
    connectedToken = token
    source = options.createEventSource(userEventsUrl(token))
    const mine = source

    mine.addEventListener('connected', (event) => {
      if (gen !== generation) return
      // A malformed frame is not a reason to skip the re-read: the frame itself says the channel is
      // up, and a reconnect must always re-read the authoritative state.
      const parsed = parseConnectedEvent(event.data)
      attempts = 0
      options.handlers.onConnected(parsed ?? { userId: null, notifications: false })
    })

    mine.addEventListener('changed', (event) => {
      if (gen !== generation) return
      options.handlers.onChanged(parseChangedEvent(event.data)?.reason ?? '')
    })

    mine.addEventListener('unauthorized', () => {
      if (gen !== generation) return
      rejectedToken = connectedToken
      disabled = true
      detach()
      options.handlers.onUnauthorized()
    })

    mine.addEventListener('error', () => {
      if (gen !== generation) return
      // Still CONNECTING: the browser is already reconnecting it with its own backoff. Only a
      // connection the server refused (CLOSED, which the browser never retries) is retried here.
      if (mine.readyState !== mine.CLOSED) return
      detach()
      scheduleRetry()
    })

    mine.addEventListener('open', () => {
      if (gen !== generation) return
      attempts = 0
    })
  }

  function open(): void {
    disabled = false
    const token = options.getToken()
    if (!token) {
      cancelRetry()
      detach()
      return
    }
    if (source !== null && connectedToken === token) return
    if (source === null && rejectedToken === token) return
    detach()
    connect()
  }

  function close(): void {
    disabled = true
    cancelRetry()
    detach()
  }

  return { open, close }
}
