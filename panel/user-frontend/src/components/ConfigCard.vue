<template>
  <div class="card">
    <div class="card-head">
      <div :class="['dot', !statusReady && 'offline']" />
      <div class="card-name">{{ node.name }}</div>
      <span :class="['node-status', statusReady ? 'ready' : 'pending']">
        {{ statusReady ? $t('configCard.ready') : $t('configCard.pending') }}
      </span>
    </div>
    <div class="card-body">
      <!-- A failed node sync is diagnostic: an already acknowledged peer keeps working. -->
      <p v-if="syncWarning" class="sync-warning">
        <WarningIcon />
        <span>{{ $t('configCard.syncWarning') }}</span>
      </p>

      <!-- AWG card -->
      <template v-if="tab === 'awg'">
        <div
          class="qr-box"
          :class="{
            blurred: node.ready && activeQrKey !== qrKey,
            'qr-clickable': node.ready,
          }"
          @click="node.ready && $emit('toggleQr', qrKey)"
        >
          <img v-if="node.ready" :src="awgQrUrl" :alt="`QR ${node.name}`" class="qr-img" />
          <div v-if="node.ready" class="qr-overlay">
            <EyeIcon />
            <span>{{ $t('configCard.showQr') }}</span>
          </div>
          <div v-if="!node.ready" class="qr-placeholder">
            <QrIcon />
            <span>{{ unavailableTitle }}</span>
            <small>{{ unavailableHint }}</small>
          </div>
        </div>
        <p v-if="node.ready" class="hint">{{ $t('configCard.scanHint') }}</p>
      </template>

      <!-- VPN card -->
      <template v-else>
        <div
          class="qr-box"
          :class="{
            blurred: qrItem.hasChunks && activeQrKey !== qrKey,
            'qr-clickable': qrItem.hasChunks,
          }"
          @click="qrItem.hasChunks && $emit('toggleQr', qrKey)"
        >
          <div
            v-if="node.ready && node.vpn_uri && !qrItem.hasChunks && !qrItem.hasError"
            class="qr-placeholder"
          >
            <div class="spinner" style="width: 28px; height: 28px; border-width: 2.5px" />
          </div>
          <div v-else-if="qrItem.hasError" class="qr-placeholder">
            <QrIcon />
            <span>{{ $t('configCard.qrUnavailable') }}</span>
            <small>{{ $t('configCard.qrUnavailableHint') }}</small>
          </div>
          <img
            v-else-if="qrItem.hasChunks"
            :src="qrItem.chunks[qrItem.idx]"
            :alt="`QR ${node.name}`"
            class="qr-img"
          />
          <div v-else class="qr-placeholder">
            <QrIcon />
            <span>{{ unavailableTitle }}</span>
            <small>{{ unavailableHint }}</small>
          </div>
          <div v-if="qrItem.hasChunks" class="qr-overlay">
            <EyeIcon />
            <span>{{ $t('configCard.showQr') }}</span>
          </div>
        </div>
        <div
          v-if="qrItem.hasChunks && qrItem.chunkCount > 1 && activeQrKey === qrKey"
          class="chunk-dots"
        >
          <span
            v-for="i in qrItem.chunkCount"
            :key="i"
            :class="['chunk-dot', i - 1 === qrItem.idx && 'active']"
          />
        </div>
        <p v-if="qrItem.hasChunks && activeQrKey === qrKey" class="hint">
          {{ $t('configCard.scanHintVpn') }}
          <template v-if="qrItem.chunkCount > 1">
            &nbsp;·&nbsp;{{ $t('configCard.part') }} {{ qrItem.idx + 1 }}/{{ qrItem.chunkCount }}
          </template>
        </p>
        <div v-if="node.vpn_uri" class="uri-row">
          <span class="uri-code">{{ node.vpn_uri }}</span>
          <button :class="['copy-btn', node.copied && 'copied']" @click="$emit('copy', node)">
            <CheckIcon v-if="node.copied" />
            <CopyIcon v-else />
            {{ node.copied ? $t('configCard.copied') : $t('configCard.copy') }}
          </button>
        </div>
      </template>
    </div>
    <div v-if="hasActions" class="card-actions">
      <a :href="downloadHref" download class="dl-btn"> <DownloadIcon /> {{ downloadLabel }} </a>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { DownloadIcon, CopyIcon, CheckIcon, QrIcon, EyeIcon, WarningIcon } from '../icons'
import type { QrMapItem, UserNode } from '../api/userPage'
import { deviceCardQrKey, deviceConfigUrl, deviceQrUrl } from '../utils/deviceUrls'

const { t } = useI18n()

const props = defineProps<{
  tab: 'awg' | 'vpn'
  /** Owner token and device id: the configuration belongs to this device, never to a node alone. */
  token: string
  deviceId: string
  node: UserNode
  activeQrKey: string | null
  qrItem: QrMapItem
  /** The account is not active: configurations stay hidden, deletions remain possible. */
  inactive: boolean
}>()

defineEmits<{
  toggleQr: [key: string]
  copy: [node: UserNode]
}>()

/** Unique to this device *and* node, so two devices never share an open-QR state. */
const qrKey = computed(() => deviceCardQrKey(props.tab, props.deviceId, props.node.id))

const statusReady = computed(() =>
  props.tab === 'awg' ? props.node.ready : props.node.ready && !!props.node.vpn_uri,
)

/** A later failed sync of an already acknowledged node: worth saying, not worth blocking. */
const syncWarning = computed(() => props.node.status === 'error' && props.node.ready)

const hasActions = computed(
  () => !props.inactive && (props.tab === 'awg' ? props.node.ready : !!props.node.vpn_uri),
)

const downloadHref = computed(() =>
  deviceConfigUrl(props.token, props.deviceId, props.tab, props.node.id),
)

const awgQrUrl = computed(() => deviceQrUrl(props.token, props.deviceId, 'awg', props.node.id))

const downloadLabel = computed(() =>
  props.tab === 'awg' ? t('configCard.downloadConf') : t('configCard.downloadVpn'),
)

const unavailableTitle = computed(() =>
  props.inactive ? t('configCard.inactive') : t('configCard.configPreparing'),
)

const unavailableHint = computed(() =>
  props.inactive ? t('configCard.inactiveHint') : t('configCard.configPreparingHint'),
)
</script>

<style scoped>
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  overflow: hidden;
  display: flex;
  flex-direction: column;
  transition:
    box-shadow 0.2s,
    transform 0.2s;
}
.card:hover {
  box-shadow: 0 8px 30px rgba(0, 0, 0, 0.1);
  transform: translateY(-2px);
}
.card-head {
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 10px;
  background: rgba(128, 128, 128, 0.03);
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
  background: #10b981;
  box-shadow: 0 0 0 2px rgba(16, 185, 129, 0.2);
}
.dot.offline {
  background: #f59e0b;
  box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.18);
}
.card-name {
  min-width: 0;
  flex: 1;
  font-size: 14px;
  font-weight: 700;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.node-status {
  flex-shrink: 0;
  border-radius: 999px;
  padding: 3px 8px;
  font-size: 11px;
  font-weight: 700;
}
.node-status.ready {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 12%, transparent);
}
.node-status.pending {
  color: #b45309;
  background: #fef3c7;
}
@media (prefers-color-scheme: dark) {
  .node-status.pending {
    color: #fbbf24;
    background: rgba(251, 191, 36, 0.14);
  }
}
.card-body {
  padding: 20px 18px 12px;
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 14px;
}
.sync-warning {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 9px 11px;
  border-radius: 9px;
  background: #fef3c7;
  color: #92400e;
  font-size: 12px;
  font-weight: 600;
  line-height: 1.4;
}
.sync-warning svg {
  width: 15px;
  height: 15px;
  flex-shrink: 0;
  margin-top: 1px;
}
@media (prefers-color-scheme: dark) {
  .sync-warning {
    background: rgba(251, 191, 36, 0.14);
    color: #fbbf24;
  }
}
.qr-box {
  width: 260px;
  height: 260px;
  max-width: 100%;
  align-self: center;
  border: 1.5px solid var(--border);
  border-radius: 10px;
  background: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  padding: 6px;
  position: relative;
}
.qr-clickable {
  cursor: pointer;
}
.qr-img {
  width: 100%;
  height: 100%;
  object-fit: contain;
  display: block;
  transition: filter 0.25s;
}
.qr-box.blurred .qr-img {
  filter: blur(18px) saturate(0.7);
  opacity: 0.72;
}
.qr-overlay {
  position: absolute;
  inset: 0;
  display: none;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: #0f172a;
  font-size: 13px;
  font-weight: 600;
  padding: 1rem;
  text-align: center;
  background: rgba(255, 255, 255, 0.72);
  backdrop-filter: blur(2px);
}
.qr-overlay svg {
  width: 28px;
  height: 28px;
}
.qr-box.blurred .qr-overlay {
  display: flex;
}
.qr-placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
  max-width: 13rem;
  gap: 8px;
  color: var(--muted);
  text-align: center;
  font-size: 13px;
  font-weight: 650;
  line-height: 1.35;
}
.qr-placeholder small {
  max-width: 12rem;
  color: var(--muted);
  font-size: 11px;
  font-weight: 500;
  line-height: 1.35;
}
.qr-placeholder svg {
  width: 44px;
  height: 44px;
  opacity: 0.4;
}
.hint {
  font-size: 12px;
  color: var(--muted);
  text-align: center;
}
.chunk-dots {
  display: flex;
  justify-content: center;
  gap: 6px;
}
.chunk-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--border);
  border: 1.5px solid var(--muted);
  transition:
    background 0.2s,
    transform 0.2s;
}
.chunk-dot.active {
  background: var(--primary);
  border-color: var(--primary);
  transform: scale(1.2);
}
.uri-row {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 7px 8px 7px 12px;
}
.uri-code {
  font-family: ui-monospace, 'SFMono-Regular', Menlo, monospace;
  font-size: 11px;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  min-width: 0;
}
.copy-btn {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 5px 10px;
  background: var(--primary);
  color: #fff;
  border: none;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition:
    background 0.15s,
    transform 0.1s;
  white-space: nowrap;
}
.copy-btn svg {
  width: 12px;
  height: 12px;
}
.copy-btn:hover {
  background: var(--primary-hover);
}
.copy-btn:active {
  transform: scale(0.95);
}
.copy-btn.copied {
  background: var(--success);
}
.card-actions {
  padding: 0 18px 18px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.dl-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  padding: 10px 16px;
  border-radius: 8px;
  border: 1.5px solid var(--border);
  background: var(--card);
  color: var(--text);
  font-size: 13px;
  font-weight: 600;
  text-decoration: none;
  transition: all 0.15s;
}
.dl-btn svg {
  width: 15px;
  height: 15px;
  flex-shrink: 0;
}
.dl-btn:hover {
  background: var(--primary-light);
  border-color: var(--primary);
  color: var(--primary);
}
.spinner {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  border: 3px solid var(--border);
  border-top-color: var(--primary);
  animation: spin 0.7s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
@media (max-width: 600px) {
  .qr-box {
    width: min(260px, 100%);
    height: min(260px, calc(100vw - 96px));
  }
}
</style>
