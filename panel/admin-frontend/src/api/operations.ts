import { req, reqBlob } from './client'
import type {
  AsyncOperation,
  LocalAmneziawgNodeUsageTotals,
  LocalAmneziawgUsageDailyTotals,
  LocalAmneziawgUsageNodeDailyTotals,
  LocalAmneziawgUsageNodeTotals,
  LocalAmneziawgUsageTotals,
  TrafficPoint,
} from './types'
import {
  deviceConfigPath,
  deviceQrAmneziaPath,
  deviceQrPath,
  userConfigsZipPath,
} from '../utils/deviceConfigUrls'

export const operationsApi = {
  sync: () => req<null>('POST', '/sync'),
  getOperations: (status?: string, limit = 50) => {
    const params = new URLSearchParams({ limit: String(limit) })
    if (status) params.set('status', status)
    return req<AsyncOperation[]>('GET', `/operations?${params.toString()}`)
  },
  retryOperation: (operationId: string) =>
    req<{ operation_id: string; status_url: string }>('POST', `/operations/${operationId}/retry`),
  getUserTraffic: (uid: string, days = 30) =>
    req<TrafficPoint[]>('GET', `/users/${uid}/traffic?days=${days}`),
  getUserLocalTraffic: (uid: string) =>
    req<LocalAmneziawgUsageTotals>('GET', `/users/${uid}/local-traffic`),
  getUserLocalTrafficDaily: (uid: string, days = 30) =>
    req<LocalAmneziawgUsageDailyTotals[]>('GET', `/users/${uid}/local-traffic/daily?days=${days}`),
  getUserLocalTrafficNodes: (uid: string) =>
    req<LocalAmneziawgUsageNodeTotals[]>('GET', `/users/${uid}/local-traffic/nodes`),
  getUserLocalTrafficNodesDaily: (uid: string, days = 30) =>
    req<LocalAmneziawgUsageNodeDailyTotals[]>(
      'GET',
      `/users/${uid}/local-traffic/nodes/daily?days=${days}`,
    ),
  getNodeLocalTraffic: (nodeId: string) =>
    req<LocalAmneziawgNodeUsageTotals>('GET', `/nodes/${nodeId}/local-traffic`),
  // Configuration downloads are always device-scoped: which device a config belongs to is named in
  // the request, never inferred. Only the user-wide archive is device-free, because it covers every
  // live device in one folder per device.
  fetchDeviceConfig: (userId: string, deviceId: string, nodeId: string) =>
    reqBlob(deviceConfigPath({ userId, deviceId, nodeId })),
  fetchDeviceQr: (userId: string, deviceId: string, nodeId: string) =>
    reqBlob(deviceQrPath({ userId, deviceId, nodeId })),
  fetchDeviceQrAmnezia: (userId: string, deviceId: string, nodeId: string) =>
    reqBlob(deviceQrAmneziaPath({ userId, deviceId, nodeId })),
  fetchConfigZip: (uid: string) => reqBlob(userConfigsZipPath(uid)),
}
