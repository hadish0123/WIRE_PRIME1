import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { selectedDeviceId } from '../src/utils/deviceSelection.ts'

describe('selected device', () => {
  it('keeps the selected device while it remains in the response', () => {
    assert.equal(
      selectedDeviceId(
        [
          { id: 'laptop', name: 'Laptop' },
          { id: 'phone', name: 'Phone' },
        ],
        'phone',
      ),
      'phone',
    )
  })

  it('selects the first device when no selection exists or it was removed', () => {
    const devices = [
      { id: 'laptop', name: 'Laptop' },
      { id: 'phone', name: 'Phone' },
    ]

    assert.equal(selectedDeviceId(devices, null), 'laptop')
    assert.equal(selectedDeviceId(devices, 'removed-device'), 'laptop')
  })

  it('has no selection when the account owns no devices', () => {
    assert.equal(selectedDeviceId([], 'laptop'), null)
  })
})
