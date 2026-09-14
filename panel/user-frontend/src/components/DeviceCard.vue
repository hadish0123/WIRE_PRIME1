<template>
  <section class="device-card" :class="`device-${device.status}`">
    <header class="device-head">
      <div class="device-identity">
        <span :class="['device-dot', dotClass]" />
        <div class="device-text">
          <!-- Plain interpolation: a device name is user input and is never rendered as markup. -->
          <h3 class="device-name" :title="device.name">{{ device.name }}</h3>
          <span class="device-meta">{{ createdText }}</span>
        </div>
      </div>
      <span :class="['device-status', statusKey]">{{ $t(`devices.status.${statusKey}`) }}</span>
      <button
        type="button"
        class="remove-btn"
        :disabled="deleting"
        @click="$emit('request-delete', device.id)"
      >
        <TrashIcon />
        <span>{{ $t('devices.remove') }}</span>
      </button>
    </header>

    <p v-if="inactive" class="device-note note-warn">
      {{ $t('devices.inactiveNote') }}
    </p>
    <p v-else-if="device.status === 'pending'" class="device-note">
      {{ $t('devices.pendingNote') }}
    </p>
    <p v-else-if="failedNodes" class="device-note note-warn">
      {{ $t('devices.syncWarning', { count: failedNodes }) }}
    </p>

    <div v-if="confirming" class="confirm">
      <strong>{{ $t('devices.deleteConfirmTitle', { name: device.name }) }}</strong>
      <p>{{ $t('devices.deleteConfirmText') }}</p>
      <div class="confirm-actions">
        <button
          type="button"
          class="ghost-btn"
          :disabled="deleting"
          @click="$emit('cancel-delete')"
        >
          {{ $t('common.cancel') }}
        </button>
        <button
          type="button"
          class="confirm-btn"
          :disabled="deleting"
          @click="$emit('confirm-delete', device.id)"
        >
          {{ deleting ? $t('devices.deleting') : $t('devices.deleteConfirmAction') }}
        </button>
      </div>
    </div>

    <div v-else class="device-nodes">
      <ConfigCard
        v-for="node in device.nodes"
        :key="deviceNodeCardKey(device.id, node.id)"
        :tab="tab"
        :token="token"
        :device-id="device.id"
        :node="node"
        :active-qr-key="activeQrKey"
        :qr-item="qrItems[deviceNodeCardKey(device.id, node.id)] || EMPTY_QR_ITEM"
        :inactive="inactive"
        @toggle-qr="$emit('toggleQr', $event)"
        @copy="$emit('copy', $event)"
      />
      <p v-if="!device.nodes.length" class="device-note">{{ $t('devices.noServers') }}</p>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

import { EMPTY_QR_ITEM, type QrMapItem, type UserDevice, type UserNode } from '../api/userPage'
import { deviceNodeCardKey } from '../utils/deviceUrls'
import { fmtDateTime } from '../utils/format'
import { TrashIcon } from '../icons'
import ConfigCard from './ConfigCard.vue'

const { t, locale } = useI18n()

const props = defineProps<{
  token: string
  device: UserDevice
  tab: 'awg' | 'vpn'
  activeQrKey: string | null
  /** QR state per `device:node` card key; a device only ever reads its own entries. */
  qrItems: Record<string, QrMapItem>
  /** The account cannot download or add right now, but may still remove this device. */
  inactive: boolean
  deleting: boolean
  confirming: boolean
}>()

defineEmits<{
  toggleQr: [key: string]
  copy: [node: UserNode]
  'request-delete': [deviceId: string]
  'cancel-delete': []
  'confirm-delete': [deviceId: string]
}>()

const statusKey = computed(() =>
  ['ready', 'pending', 'error', 'deleting'].includes(props.device.status)
    ? props.device.status
    : 'pending',
)

const dotClass = computed(() => (props.device.status === 'ready' ? 'online' : 'offline'))

const failedNodes = computed(
  () => props.device.nodes.filter((node) => node.status === 'error').length,
)

const createdText = computed(() =>
  t('devices.createdAt', { value: fmtDateTime(props.device.created_at, locale.value) }),
)
</script>

<style scoped>
.device-card {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 18px;
  border: 1px solid var(--border);
  border-radius: calc(var(--radius) + 4px);
  background: color-mix(in srgb, var(--card) 92%, transparent);
  box-shadow: var(--shadow);
}
.device-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}
.device-identity {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
  flex: 1 1 200px;
}
.device-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  flex-shrink: 0;
}
.device-dot.online {
  background: var(--success);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--success) 18%, transparent);
}
.device-dot.offline {
  background: #f59e0b;
  box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.18);
}
.device-text {
  min-width: 0;
  display: flex;
  flex-direction: column;
}
.device-name {
  font-size: 17px;
  letter-spacing: -0.02em;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.device-meta {
  color: var(--muted);
  font-size: 12px;
}
.device-status {
  flex-shrink: 0;
  border-radius: 999px;
  padding: 4px 10px;
  font-size: 11px;
  font-weight: 800;
  color: var(--muted);
  background: var(--bg-soft);
}
.device-status.ready {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 12%, transparent);
}
.device-status.pending,
.device-status.error,
.device-status.deleting {
  color: #b45309;
  background: #fef3c7;
}
@media (prefers-color-scheme: dark) {
  .device-status.pending,
  .device-status.error,
  .device-status.deleting {
    color: #fbbf24;
    background: rgba(251, 191, 36, 0.14);
  }
}
.remove-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
  min-height: 34px;
  padding: 0 12px;
  border: 1.5px solid var(--border);
  border-radius: 999px;
  background: var(--card);
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.15s;
}
.remove-btn svg {
  width: 13px;
  height: 13px;
}
.remove-btn:hover:not(:disabled) {
  border-color: var(--danger);
  color: var(--danger);
  background: var(--danger-bg);
}
.remove-btn:disabled {
  opacity: 0.6;
  cursor: default;
}
.device-note {
  color: var(--muted);
  font-size: 13px;
  line-height: 1.5;
}
.note-warn {
  padding: 9px 11px;
  border-radius: 9px;
  background: #fef3c7;
  color: #92400e;
  font-weight: 600;
}
@media (prefers-color-scheme: dark) {
  .note-warn {
    background: rgba(251, 191, 36, 0.14);
    color: #fbbf24;
  }
}
.device-nodes {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
  align-items: start;
}
.confirm {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 14px 16px;
  border: 1.5px solid color-mix(in srgb, var(--danger) 45%, var(--border));
  border-radius: calc(var(--radius) - 2px);
  background: var(--danger-bg);
}
.confirm strong {
  font-size: 15px;
  overflow-wrap: anywhere;
}
.confirm p {
  color: var(--muted);
  font-size: 13px;
  line-height: 1.5;
}
.confirm-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 4px;
}
.ghost-btn,
.confirm-btn {
  min-height: 38px;
  padding: 0 16px;
  border-radius: 999px;
  font-size: 13px;
  font-weight: 700;
  cursor: pointer;
}
.ghost-btn {
  border: 1.5px solid var(--border);
  background: var(--card);
  color: var(--text);
}
.confirm-btn {
  border: none;
  background: var(--danger);
  color: #fff;
}
.confirm-btn:disabled,
.ghost-btn:disabled {
  opacity: 0.6;
  cursor: default;
}
</style>
