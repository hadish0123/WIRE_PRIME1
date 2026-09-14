/**
 * Device naming rules, mirrored from the backend so the form can refuse a name before it is sent.
 *
 * The backend stays authoritative (it answers `422` on the same rules): this only keeps an obvious
 * mistake - blank, too long, control characters - from becoming a round trip. Names are Unicode and
 * are NFC-normalised, so two spellings of the same name compare and render identically.
 *
 * Dependency-free so the Node test runner can exercise it (`tests/userPage.test.ts`).
 */

export const MAX_DEVICE_NAME_LENGTH = 64

export type DeviceNameError = 'blank' | 'too_long' | 'control_chars'

export type DeviceNameCheck = { ok: true; name: string } | { ok: false; error: DeviceNameError }

/** Control, format and surrogate code points: they break filenames, logs and headers. */
const CONTROL_CHARACTERS = /[\p{Cc}\p{Cf}\p{Cs}]/u

export function normalizeDeviceName(raw: string): DeviceNameCheck {
  const name = raw.normalize('NFC').trim()
  if (!name) return { ok: false, error: 'blank' }
  if (CONTROL_CHARACTERS.test(name)) return { ok: false, error: 'control_chars' }
  if ([...name].length > MAX_DEVICE_NAME_LENGTH) return { ok: false, error: 'too_long' }
  return { ok: true, name }
}
