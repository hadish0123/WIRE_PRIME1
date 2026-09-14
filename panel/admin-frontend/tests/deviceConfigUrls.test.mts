import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  deviceConfigPath,
  deviceQrAmneziaPath,
  deviceQrPath,
  peerRowKey,
  userConfigsZipPath,
  userDeviceLimitPath,
  userDevicesPath,
} from '../src/utils/deviceConfigUrls.ts'

const route = { userId: 'user-1', deviceId: 'device-1', nodeId: 'node-1' }

describe('device-scoped admin config routes', () => {
  it('names the device in every download route', () => {
    assert.equal(
      deviceConfigPath(route),
      '/users/user-1/devices/device-1/configs/node-1',
    )
    assert.equal(deviceQrPath(route), '/users/user-1/devices/device-1/qr/node-1')
    assert.equal(deviceQrAmneziaPath(route), '/users/user-1/devices/device-1/qr-amnezia/node-1')
  })

  it('never falls back to the implicit pre-device routes', () => {
    const paths = [
      deviceConfigPath(route),
      deviceQrPath(route),
      deviceQrAmneziaPath(route),
    ]

    for (const path of paths) {
      assert.ok(path.includes('/devices/device-1/'), path)
      assert.ok(!path.includes('/configs/node-1') || path.includes('/devices/'), path)
    }
    assert.ok(!paths.includes('/users/user-1/configs/node-1'))
    assert.ok(!paths.includes('/users/user-1/qr/node-1'))
    assert.ok(!paths.includes('/users/user-1/qr-amnezia/node-1'))
  })

  it('keeps the user-wide archive free of a device id', () => {
    assert.equal(userConfigsZipPath('user-1'), '/users/user-1/configs/zip')
  })

  it('exposes the device list and the local limit write', () => {
    assert.equal(userDevicesPath('user-1'), '/users/user-1/devices')
    assert.equal(userDeviceLimitPath('user-1'), '/users/user-1/device-limit')
  })

  it('keeps two devices of one owner apart for the same node', () => {
    const first = deviceConfigPath({ userId: 'user-1', deviceId: 'device-1', nodeId: 'node-1' })
    const second = deviceConfigPath({ userId: 'user-1', deviceId: 'device-2', nodeId: 'node-1' })

    assert.notEqual(first, second)
  })

  it('keys peer rows by device and node, never by the owner', () => {
    assert.equal(peerRowKey('device-1', 'node-1'), 'device-1:node-1')
    assert.notEqual(peerRowKey('device-1', 'node-1'), peerRowKey('device-2', 'node-1'))
    assert.equal(peerRowKey(null, 'node-1'), 'legacy:node-1')
  })

  it('escapes ids so a path cannot gain extra segments', () => {
    assert.equal(
      deviceConfigPath({ userId: 'user/1', deviceId: 'device 1', nodeId: 'node#1' }),
      '/users/user%2F1/devices/device%201/configs/node%231',
    )
  })
})
