export interface SelectableDevice {
  id: string
}

/** Keep the current device selected while it exists; otherwise use the first available device. */
export function selectedDeviceId(
  devices: readonly SelectableDevice[],
  currentId: string | null,
): string | null {
  if (currentId && devices.some((device) => device.id === currentId)) return currentId
  return devices[0]?.id ?? null
}
