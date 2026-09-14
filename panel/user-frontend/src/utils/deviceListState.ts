/**
 * Which body the device section renders.
 *
 * The device list belongs to its owner and is shown whenever the account owns devices - including a
 * blocked, expired or traffic-limited account, where the backend keeps every readiness flag off and
 * never ships a configuration. The section must therefore never claim that the owner's own device
 * list is hidden: with no devices the honest answers are the invite form (the account may add one)
 * or the inactive empty state (it may not).
 */

export type DeviceSectionState = 'list' | 'invite' | 'inactive'

export function deviceSectionState(input: {
  /** The `/info` payload already lists at least one device of this account. */
  hasDevices: boolean
  /** The account is blocked or its lifecycle state is not `active`. */
  inactive: boolean
}): DeviceSectionState {
  if (input.hasDevices) return 'list'
  return input.inactive ? 'inactive' : 'invite'
}
