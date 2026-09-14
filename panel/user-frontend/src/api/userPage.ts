/**
 * The public user API: one place that knows the device-scoped URLs, the response shapes and how a
 * failure is reported to the UI.
 *
 * Every failure becomes a {@link PublicApiError} carrying only a small, translatable `kind`. Server
 * text - FastAPI `detail`, validation messages, stack traces - is deliberately dropped: the page
 * renders a translated sentence, never a backend string, so an internal error cannot leak through
 * the UI.
 */

// Explicit `.ts` so the Node test runner can also import this module (see tests/userPageRefresh.test.ts).
import { deviceQrChunksUrl } from '../utils/deviceUrls.ts'

export type NodeStatus = 'ready' | 'pending' | 'error' | 'deleting'

export interface UserNode {
  id: string
  name: string
  status: NodeStatus
  ready: boolean
  vpn_uri?: string | null
  copied?: boolean
}

export interface UserDevice {
  id: string
  name: string
  created_at: string
  status: string
  nodes: UserNode[]
}

export interface PublicStatus {
  code: 'active' | 'blocked' | 'limited' | 'expired'
  reason: string | null
}

export interface PublicSubscription {
  managed: boolean
  expire_at: string | null
  last_synced_at: string | null
}

export interface PublicTraffic {
  used_bytes: number
  limit_bytes: number | null
  local_used_bytes: number
  remote_used_bytes: number
  updated_at: string | null
}

export interface TelegramProxyInfo {
  enabled: boolean
  primary_node_name: string
  tg_url: string
  https_url: string
  status: string
}

export interface UserInfo {
  user_name: string
  blocked: boolean
  /** Effective limit; `0` means unlimited. */
  device_limit: number
  device_count: number
  /** The backend's own answer to "may another device be added right now". */
  can_add_device: boolean
  /** Legacy field: nodes of the migration `Default` device only. */
  nodes: UserNode[]
  devices: UserDevice[]
  status: PublicStatus
  subscription: PublicSubscription
  traffic: PublicTraffic
  telegram_proxy: TelegramProxyInfo | null
  updated_at: string | null
}

export interface DeviceDeleteResult {
  id: string
  name: string
  status: string
  deleted_at: string | null
  device_count: number
}

export interface VpnQrState {
  chunks: string[]
  idx: number
}

export interface VpnQrError {
  error: true
}

export type VpnQrData = VpnQrState | VpnQrError | null

export interface QrMapItem {
  hasChunks: boolean
  hasError: boolean
  chunks: string[]
  idx: number
  chunkCount: number
}

export const EMPTY_QR_ITEM: QrMapItem = {
  hasChunks: false,
  hasError: false,
  chunks: [],
  idx: 0,
  chunkCount: 0,
}

export type PublicApiErrorKind =
  | 'not_found'
  | 'blocked'
  | 'conflict'
  | 'validation'
  | 'network'
  | 'server'
  | 'unknown'

/** i18n key describing a failure; the raw server text is never part of it. */
export function apiErrorKey(kind: PublicApiErrorKind): string {
  return `apiErrors.${kind}`
}

export class PublicApiError extends Error {
  readonly kind: PublicApiErrorKind
  readonly status: number | null

  constructor(kind: PublicApiErrorKind, status: number | null = null) {
    super(kind)
    this.name = 'PublicApiError'
    this.kind = kind
    this.status = status
  }
}

function errorForStatus(status: number): PublicApiError {
  if (status === 404) return new PublicApiError('not_found', status)
  if (status === 403) return new PublicApiError('blocked', status)
  if (status === 409) return new PublicApiError('conflict', status)
  if (status === 422) return new PublicApiError('validation', status)
  if (status >= 500) return new PublicApiError('server', status)
  return new PublicApiError('unknown', status)
}

async function request<T>(url: string, init: RequestInit = {}): Promise<T> {
  let res: Response
  try {
    res = await fetch(url, init)
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new PublicApiError('network')
  }
  if (!res.ok) throw errorForStatus(res.status)
  return (await res.json()) as T
}

function decorateNode(node: UserNode): UserNode {
  return { ...node, copied: false }
}

/** Add the client-only `copied` flag and never assume an array the backend omitted. */
function decorateInfo(data: UserInfo): UserInfo {
  const devices = (data.devices ?? []).map((device) => ({
    ...device,
    nodes: (device.nodes ?? []).map(decorateNode),
  }))
  return { ...data, devices, nodes: (data.nodes ?? []).map(decorateNode) }
}

export async function fetchUserInfo(userId: string, signal?: AbortSignal): Promise<UserInfo> {
  const data = await request<UserInfo>(`/pub/u/${encodeURIComponent(userId)}/info`, { signal })
  return decorateInfo(data)
}

export async function createDevice(
  userId: string,
  name: string,
  signal?: AbortSignal,
): Promise<UserDevice> {
  const device = await request<UserDevice>(`/pub/u/${encodeURIComponent(userId)}/devices`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
    signal,
  })
  return { ...device, nodes: (device.nodes ?? []).map(decorateNode) }
}

export async function deleteDevice(
  userId: string,
  deviceId: string,
  signal?: AbortSignal,
): Promise<DeviceDeleteResult> {
  return request<DeviceDeleteResult>(
    `/pub/u/${encodeURIComponent(userId)}/devices/${encodeURIComponent(deviceId)}`,
    { method: 'DELETE', signal },
  )
}

/** Multi-part AmneziaVPN QR chunks for one device on one node. */
export async function fetchVpnChunks(
  userId: string,
  deviceId: string,
  nodeId: string,
  svgToDataUri: (svg: string) => string,
  signal?: AbortSignal,
): Promise<VpnQrData> {
  try {
    const res = await fetch(deviceQrChunksUrl(userId, deviceId, nodeId), { signal })
    if (!res.ok) return { error: true }
    const data = (await res.json()) as { chunks: string[] }
    const chunks = data.chunks ?? []
    if (!chunks.length) return { error: true }
    return { chunks: chunks.map(svgToDataUri), idx: 0 }
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return null
    return { error: true }
  }
}
