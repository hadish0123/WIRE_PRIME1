/**
 * Which device's configuration belongs to which node, and when a fetched QR state may be stored.
 *
 * A cache entry is keyed by device *and* node (`nodeCacheKey`) and never by node alone: the same
 * node serves a different configuration for every device of the account, so a node-only cache would
 * hand one device's QR code to another. Deleting a device drops exactly its entries, and a response
 * that arrives after that deletion - or after the route token changed - is refused instead of
 * re-adding the dead device.
 *
 * Dependency-free on purpose so the Node test runner can drive this module directly
 * (`tests/userPage.test.ts`); the explicit `.ts` specifier below is what lets Node load it, while
 * Vite and `vue-tsc` resolve it through `allowImportingTsExtensions`.
 */

import { nodeCacheKey } from './deviceUrls.ts'

export type QrLoadState =
  { kind: 'loading' } | { kind: 'chunks'; chunks: string[]; idx: number } | { kind: 'error' }

export interface DeviceQrCacheEntry {
  state: QrLoadState
  /** Generation of the page state that asked for it; older generations are discarded. */
  generation: number
}

export class DeviceQrCache {
  private entries = new Map<string, DeviceQrCacheEntry>()
  /** Device ids the page currently lists; nothing may be cached for any other device. */
  private known = new Set<string>()
  private generation = 0

  /** Current generation; a delete or a route change advances it. */
  get currentGeneration(): number {
    return this.generation
  }

  /** Invalidate every in-flight response: they describe state that no longer exists. */
  bumpGeneration(): number {
    this.generation += 1
    return this.generation
  }

  /** True when a response produced for `generation` still belongs to the live page. */
  accepts(deviceId: string, generation: number): boolean {
    return generation === this.generation && this.known.has(deviceId)
  }

  /** A device enters the cache when the page lists it. */
  trackDevice(deviceId: string): void {
    this.known.add(deviceId)
  }

  /** A device leaves the page (deleted): its cached configuration goes with it. */
  forgetDevice(deviceId: string): number {
    this.known.delete(deviceId)
    return this.deleteByDevice(deviceId)
  }

  /** Drop every cached node entry of one device; returns how many were removed. */
  deleteByDevice(deviceId: string): number {
    const prefix = nodeCacheKey(deviceId, '')
    let removed = 0
    for (const key of [...this.entries.keys()]) {
      if (key.startsWith(prefix)) {
        this.entries.delete(key)
        removed += 1
      }
    }
    return removed
  }

  /** Forget everything: used when the route token changes. */
  clear(): void {
    this.entries.clear()
    this.known.clear()
    this.bumpGeneration()
  }

  has(deviceId: string, nodeId: string): boolean {
    return this.entries.has(nodeCacheKey(deviceId, nodeId))
  }

  get(deviceId: string, nodeId: string): DeviceQrCacheEntry | undefined {
    return this.entries.get(nodeCacheKey(deviceId, nodeId))
  }

  /** The stored chunks for this device+node, or `undefined` when absent, failed or still loading. */
  chunks(deviceId: string, nodeId: string): { chunks: string[]; idx: number } | undefined {
    const entry = this.get(deviceId, nodeId)
    return entry && entry.state.kind === 'chunks' ? entry.state : undefined
  }

  /** True while a fetch for this device+node is outstanding. */
  isLoading(deviceId: string, nodeId: string): boolean {
    return this.get(deviceId, nodeId)?.state.kind === 'loading'
  }

  /** Advance the rotating multi-part QR of every entry; single-part entries are left alone. */
  rotate(): void {
    for (const entry of this.entries.values()) {
      if (entry.state.kind === 'chunks' && entry.state.chunks.length > 1) {
        entry.state.idx = (entry.state.idx + 1) % entry.state.chunks.length
      }
    }
  }

  set(deviceId: string, nodeId: string, state: QrLoadState, generation?: number): void {
    if (!this.known.has(deviceId)) return
    this.entries.set(nodeCacheKey(deviceId, nodeId), {
      state,
      generation: generation ?? this.generation,
    })
  }

  /** Store a fetched result only when it still belongs to the live page state. */
  setIfLive(deviceId: string, nodeId: string, state: QrLoadState, generation: number): boolean {
    if (!this.accepts(deviceId, generation)) return false
    this.set(deviceId, nodeId, state, generation)
    return true
  }

  /** Keys currently held, for tests and diagnostics. */
  keys(): string[] {
    return [...this.entries.keys()]
  }
}
