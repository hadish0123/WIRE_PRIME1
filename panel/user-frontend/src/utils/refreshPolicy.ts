/**
 * Refresh policy for the public user page: what to poll, when to poll it and which answers are
 * still allowed to count.
 *
 * The page is authoritative-state-read only: the backend never pushes configuration bodies, so the
 * browser re-reads `/info` and lets the *server* decide when a device became ready. Polling is the
 * fallback transport until the event stream lands, so it has to be honest about the cases that
 * break naive implementations:
 *
 * - a still-pending device is re-read quickly (~1s) so a user sees readiness immediately, but the
 *   fast interval is bounded: a node that cannot become ready because its metadata is missing must
 *   not turn the page into a 1s hammer;
 * - a hidden tab is not polled at all - the visibility handler revalidates on return instead;
 * - a failed refresh keeps the last good data and reports it as retrying, so a network blip never
 *   blanks a page (or a working configuration) that was already on screen;
 * - an answer that was requested before a mutation (add/delete) or a route change is *stale* and is
 *   dropped instead of overwriting the newer state.
 *
 * Dependency-free so the Node test runner can exercise it (`tests/userPage.test.ts`).
 */

/** Re-read interval while provisioning work is outstanding. */
export const PENDING_POLL_MS = 1000
/** How long the fast interval may stay in effect before falling back to the idle interval. */
export const PENDING_POLL_WINDOW_MS = 120_000
/** Re-read interval when nothing looks like it is still being provisioned. */
export const IDLE_POLL_MS = 15_000

export interface PollableNode {
  status: string
  ready: boolean
}

export interface PollableDevice {
  status: string
  nodes: PollableNode[]
}

export interface PollableInfo {
  blocked: boolean
  status: { code: string }
  devices: PollableDevice[]
}

export interface PollContext {
  /** The tab is hidden: polling pauses and the visibility handler revalidates instead. */
  hidden?: boolean
  /** How long work has been seen pending; the fast interval is only used inside the window. */
  pendingForMs?: number
}

/**
 * Whether the backend still has something to finish for this account.
 *
 * Only an *active* account is polled fast: when the account is blocked, expired or limited the
 * nodes stay `ready: false` for authorization reasons and will never become ready, so treating that
 * as pending work would poll at full speed forever.
 */
export function hasPendingWork(info: PollableInfo | null): boolean {
  if (!info || info.blocked || info.status.code !== 'active') return false
  return info.devices.some(
    (device) => device.status === 'pending' || device.nodes.some((node) => !node.ready),
  )
}

/**
 * Delay before the next `/info` re-read, or `null` when no timer should run at all.
 *
 * A hidden document is not polled; a `visibilitychange` back to visible refreshes immediately, so
 * nothing is missed by the pause.
 */
export function nextPollDelayMs(
  info: PollableInfo | null,
  context: PollContext = {},
): number | null {
  if (context.hidden) return null
  if (!hasPendingWork(info)) return IDLE_POLL_MS
  const pendingForMs = context.pendingForMs ?? 0
  return pendingForMs < PENDING_POLL_WINDOW_MS ? PENDING_POLL_MS : IDLE_POLL_MS
}

/**
 * Monotonic ticket source that decides which async answer may still be applied.
 *
 * Every request takes a ticket when it starts. A mutation, a route change or a manual refresh
 * advances the counter, so a slower earlier response that arrives afterwards is no longer
 * `isCurrent` and must be discarded rather than overwrite the newer state.
 */
export interface StaleGuard {
  /** Reserve a ticket for a new request. */
  begin(): number
  /** True while no newer request, mutation or reset has happened since the ticket was taken. */
  isCurrent(ticket: number): boolean
  /** Drop every outstanding ticket; the next `begin()` starts a new era. */
  invalidate(): number
}

export function createStaleGuard(): StaleGuard {
  let current = 0
  return {
    begin(): number {
      current += 1
      return current
    },
    isCurrent(ticket: number): boolean {
      return ticket === current
    },
    invalidate(): number {
      current += 1
      return current
    },
  }
}

export type RefreshResult<T, E> = { ok: true; data: T } | { ok: false; error: E }

export interface RefreshState<T, E> {
  /** The last successfully loaded payload; kept across failures. */
  data: T | null
  /** Error of the most recent failed attempt, cleared by the next success. */
  error: E | null
  /** A failed attempt while earlier data is still on screen: show a retry notice, not a blank page. */
  retrying: boolean
}

export function initialRefreshState<T, E>(): RefreshState<T, E> {
  return { data: null, error: null, retrying: false }
}

/**
 * Fold a refresh outcome into the page state.
 *
 * Success replaces the payload; failure keeps whatever was last shown and only reports the error,
 * because losing a working configuration to a transient network error is worse than showing
 * slightly stale data with a retry notice.
 */
export function resolveRefresh<T, E>(
  state: RefreshState<T, E>,
  result: RefreshResult<T, E>,
): RefreshState<T, E> {
  if (result.ok) {
    return { data: result.data, error: null, retrying: false }
  }
  return { data: state.data, error: result.error, retrying: state.data !== null }
}
