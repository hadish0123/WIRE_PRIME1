<template>
  <aside v-if="user" class="user-detail-drawer" data-testid="user-detail">
    <div class="drawer-head">
      <div>
        <span class="page-kicker"><i class="pi pi-id-card" /> {{ $t('userDetail.kicker') }}</span>
        <h3>{{ primaryIdentity(user) }}</h3>
        <p>
          {{ user.remnawave ? $t('userDetail.identityRemnawave') : $t('userDetail.identityLocal') }}
        </p>
        <p v-if="user.remnawave" class="drawer-identity-meta">
          <span>{{ remnawaveContext(user) }}</span>
          <a
            v-if="telegramLinkLabel(user)"
            :href="user.remnawave.telegram_url || undefined"
            v-bind="telegramLinkAttrs(user)"
          >
            {{ telegramLinkLabel(user) }}
          </a>
        </p>
      </div>
      <Button
        icon="pi pi-times"
        text
        rounded
        severity="secondary"
        :aria-label="$t('userDetail.close')"
        @click="$emit('close')"
      />
    </div>

    <div class="drawer-status-row">
      <Tag
        :severity="user.is_blocked ? 'danger' : 'success'"
        :value="user.is_blocked ? $t('userTable.statusBlocked') : $t('userTable.statusActive')"
      />
      <Tag
        :severity="user.online ? 'success' : 'secondary'"
        :value="user.online ? $t('userTable.statusOnline') : $t('userTable.statusOffline')"
      />
      <Tag v-if="user.remnawave" severity="info" :value="$t('userTable.readonlyExternal')" />
      <Tag
        v-if="user.remnawave"
        :severity="syncSeverity(user.remnawave.sync_status, user.remnawave.sync_error)"
        :value="user.remnawave.sync_error ? $t('userTable.syncError') : user.remnawave.sync_status"
      />
    </div>

    <section class="detail-section detail-section--accent">
      <div class="section-header compact-section-header">
        <h4>{{ $t('userDetail.nextActions') }}</h4>
        <p>{{ $t('userDetail.nextActionsHint') }}</p>
      </div>
      <div class="drawer-action-grid">
        <Button
          :label="$t('userDetail.copyLink')"
          icon="pi pi-link"
          severity="secondary"
          outlined
          @click="$emit('copyUserLink', user)"
        />
        <Button
          :label="$t('userDetail.traffic')"
          icon="pi pi-chart-bar"
          severity="secondary"
          outlined
          @click="$emit('showTraffic', user)"
        />
        <Button
          v-if="!user.remnawave"
          :label="$t('userDetail.rotateLink')"
          icon="pi pi-refresh"
          severity="secondary"
          outlined
          @click="$emit('regenerateLink', user)"
        />
        <Button
          v-if="user.remnawave"
          :label="$t('userDetail.resyncUser')"
          icon="pi pi-refresh"
          severity="secondary"
          outlined
          :loading="syncingUser"
          @click="$emit('syncRemnawaveUser', user)"
        />
        <template v-else>
          <Button
            v-if="user.is_blocked"
            :label="$t('userDetail.unblock')"
            icon="pi pi-lock-open"
            severity="success"
            outlined
            @click="$emit('unblock', user)"
          />
          <Button
            v-else
            :label="$t('userDetail.block')"
            icon="pi pi-ban"
            severity="warn"
            outlined
            @click="$emit('block', user)"
          />
        </template>
      </div>
    </section>

    <section v-if="!user.remnawave" class="detail-section detail-section--accent">
      <div class="section-header compact-section-header">
        <h4>{{ $t('userDetail.lifecycle') }}</h4>
        <p>{{ $t('userDetail.lifecycleHint') }}</p>
      </div>
      <div class="lifecycle-form-grid">
        <label>
          <span>{{ $t('userDetail.labelExpires') }}</span>
          <input
            :value="dateInput(user)"
            type="datetime-local"
            @change="onExpireChange(user, $event)"
          />
        </label>
        <label>
          <span>{{ $t('userDetail.labelTrafficLimit') }}</span>
          <input
            :value="limitGb(user)"
            type="number"
            min="0"
            step="1"
            @change="onLimitChange(user, $event)"
          />
        </label>
        <label>
          <span>{{ $t('userDetail.labelResetPolicy') }}</span>
          <select
            :value="user.lifecycle?.traffic_reset_policy ?? user.traffic_reset_policy"
            @change="onPolicyChange(user, $event)"
          >
            <option value="manual">{{ $t('userDetail.resetManual') }}</option>
            <option value="no_reset">{{ $t('userDetail.resetDisabled') }}</option>
          </select>
        </label>
      </div>
      <div class="drawer-action-grid">
        <Button
          :label="$t('userDetail.resetTraffic')"
          icon="pi pi-history"
          severity="secondary"
          outlined
          :disabled="
            (user.lifecycle?.traffic_reset_policy ?? user.traffic_reset_policy) !== 'manual'
          "
          @click="$emit('resetTraffic', user)"
        />
      </div>
    </section>

    <section class="detail-section detail-section--accent" data-testid="user-devices">
      <div class="section-header compact-section-header">
        <h4>{{ $t('userDetail.devices') }}</h4>
        <p>{{ $t('userDetail.devicesHint') }}</p>
      </div>

      <div class="detail-grid">
        <div>
          <span>{{ $t('userDetail.deviceCount') }}</span
          ><b>{{ user.device_count }}</b>
        </div>
        <div>
          <span>{{ $t('userDetail.labelDeviceLimit') }}</span
          ><b>{{ deviceLimitLabel(user) }}</b>
        </div>
      </div>

      <div v-if="user.remnawave" class="device-limit-note">
        <Tag severity="info" :value="$t('userDetail.deviceLimitRemnawave')" />
        <span>{{ $t('userDetail.deviceLimitRemnawaveHint') }}</span>
      </div>

      <div v-else class="device-limit-form" data-testid="device-limit-form">
        <label>
          <span>{{ $t('userDetail.labelDeviceLimit') }}</span>
          <input
            v-model.number="deviceLimitDraft"
            type="number"
            min="0"
            step="1"
            :disabled="savingDeviceLimit"
            @keyup.enter="submitDeviceLimit(user)"
          />
        </label>
        <div class="device-limit-actions">
          <Button
            :label="$t('userDetail.saveDeviceLimit')"
            icon="pi pi-save"
            size="small"
            :loading="savingDeviceLimit"
            :disabled="savingDeviceLimit"
            @click="submitDeviceLimit(user)"
          />
          <small class="device-limit-hint">{{ $t('userDetail.deviceLimitHint') }}</small>
        </div>
        <Message v-if="deviceLimitError" severity="error" :closable="false">
          {{ deviceLimitError }}
        </Message>
      </div>

      <div v-if="user.devices.length" class="device-list">
        <article v-for="device in user.devices" :key="device.id" class="device-card">
          <div class="device-head">
            <div>
              <strong>{{ device.name }}</strong>
              <code>{{ device.vpn_ip || '—' }}</code>
            </div>
            <div class="device-tags">
              <Tag
                :severity="deviceStatusSeverity(device.status)"
                :value="deviceStatusLabel(device.status)"
              />
              <Tag
                v-if="device.is_legacy_default"
                severity="secondary"
                :value="$t('userDetail.deviceLegacy')"
              />
            </div>
          </div>
          <div v-if="device.nodes.length" class="device-node-list">
            <div v-for="node in device.nodes" :key="node.node_id" class="device-node-row">
              <div class="device-node-identity">
                <strong>{{ node.node_name }}</strong>
                <Tag
                  :severity="deviceStatusSeverity(node.status)"
                  :value="deviceStatusLabel(node.status)"
                />
              </div>
              <div class="config-node-actions">
                <Button
                  icon="pi pi-download"
                  :label="$t('userDetail.config')"
                  size="small"
                  text
                  severity="secondary"
                  :disabled="!node.ready"
                  @click="$emit('downloadConfig', user, device, node)"
                />
                <Button
                  icon="pi pi-qrcode"
                  :label="$t('userDetail.qr')"
                  size="small"
                  text
                  severity="secondary"
                  :disabled="!node.ready"
                  @click="$emit('showQr', user, device, node)"
                />
              </div>
            </div>
          </div>
          <div v-else class="drawer-empty">{{ $t('userDetail.deviceNoNodes') }}</div>
        </article>
        <Button
          v-if="user.devices.length > 1"
          :label="$t('userDetail.downloadZip')"
          icon="pi pi-file-export"
          severity="secondary"
          outlined
          @click="$emit('downloadConfigZip', user)"
        />
      </div>
      <div v-else class="drawer-empty device-empty">
        <span>{{ $t('userDetail.noDevices') }}</span>
        <span>{{ $t('userDetail.noDevicesHint') }}</span>
        <Button
          :label="$t('userDetail.inviteDevice')"
          icon="pi pi-link"
          size="small"
          severity="secondary"
          outlined
          @click="$emit('copyUserLink', user)"
        />
      </div>
    </section>

    <section class="detail-section">
      <div class="section-header compact-section-header">
        <h4>{{ $t('userDetail.overview') }}</h4>
      </div>
      <div class="detail-grid">
        <div>
          <span>{{ $t('userDetail.labelId') }}</span
          ><code>{{ user.id }}</code>
        </div>
        <div>
          <span>{{ $t('userDetail.labelDeviceIps') }}</span
          ><b>{{ deviceIpsLabel(user) }}</b>
        </div>
        <div>
          <span>{{ $t('userDetail.labelPublicKey') }}</span
          ><code>{{ user.public_key || '—' }}</code>
        </div>
        <div>
          <span>{{ $t('userDetail.labelCreated') }}</span
          ><b>{{ formatDateTimeOrDash(user.created_at) }}</b>
        </div>
        <div>
          <span>{{ $t('userDetail.labelTraffic') }}</span
          ><b>{{ trafficValue(user) }}</b>
        </div>
      </div>
    </section>

    <section class="detail-section">
      <div class="section-header compact-section-header">
        <h4>{{ $t('userDetail.nodes') }}</h4>
      </div>
      <div v-if="user.peers.length" class="peer-detail-list">
        <article
          v-for="peer in sortedPeers"
          :key="peerKey(peer.device_id, peer.node_id)"
          class="peer-detail-card"
        >
          <div class="peer-head">
            <strong>{{ peerDeviceLabel(peer) }}</strong>
            <Tag
              :severity="peerSeverity(peer.status, user.is_blocked)"
              :value="peerLabel(peer.status, user.is_blocked)"
            />
          </div>
          <div class="detail-grid detail-grid--single">
            <div>
              <span>{{ $t('userDetail.labelDeviceIp') }}</span
              ><b>{{ peer.vpn_ip || '—' }}</b>
            </div>
            <div>
              <span>{{ $t('userDetail.labelServer') }}</span
              ><b>{{ peer.node_name }}</b>
            </div>
            <div>
              <span>{{ $t('userDetail.labelOnline') }}</span
              ><b>{{
                peer.online ? $t('userTable.statusOnline') : $t('userTable.statusOffline')
              }}</b>
            </div>
            <div>
              <span>{{ $t('userDetail.labelLastHandshake') }}</span
              ><b>{{ fmtHandshake(peer.last_handshake) }}</b>
            </div>
            <div>
              <span>{{ $t('userDetail.labelEndpoint') }}</span
              ><code>{{ peer.endpoint || '—' }}</code>
            </div>
          </div>
        </article>
      </div>
      <div v-else class="drawer-empty">{{ $t('userDetail.noPeers') }}</div>
    </section>

    <section
      v-if="user.remnawave"
      class="detail-section detail-section--rw"
      data-testid="remnawave-metadata"
    >
      <div class="section-header compact-section-header">
        <h4>{{ $t('userDetail.remnawaveData') }}</h4>
        <p>{{ $t('userDetail.remnawaveDataHint') }}</p>
      </div>
      <div class="detail-grid">
        <div>
          <span>{{ $t('userDetail.labelUuid') }}</span
          ><code>{{ user.remnawave.uuid }}</code>
        </div>
        <div>
          <span>Display name</span><b>{{ user.remnawave.display_name || '—' }}</b>
        </div>
        <div>
          <span>{{ $t('userDetail.labelUsername') }}</span
          ><b>{{ user.remnawave.username }}</b>
        </div>
        <div v-if="user.remnawave.telegram_url">
          <span>Telegram</span
          ><a :href="user.remnawave.telegram_url" v-bind="telegramLinkAttrs(user)">
            {{ telegramLinkLabel(user) }}
          </a>
        </div>
        <div>
          <span>{{ $t('userDetail.labelEmail') }}</span
          ><b>{{ user.remnawave.email || '—' }}</b>
        </div>
        <div>
          <span>{{ $t('userDetail.labelStatus') }}</span
          ><b>{{ user.remnawave.status }}</b>
        </div>
        <div>
          <span>{{ $t('userDetail.labelExpires') }}</span
          ><b>{{ fmtDate(user.remnawave.expire_at) }}</b>
        </div>
        <div>
          <span>{{ $t('userDetail.labelTrafficLimit') }}</span
          ><b>{{ trafficLimit(user.remnawave.traffic_limit_bytes) }}</b>
        </div>
        <div>
          <span>{{ $t('userDetail.labelCombinedUsed') }}</span
          ><b>{{ fmtBytes(user.remnawave.combined_traffic_used_bytes) }}</b>
        </div>
        <div>
          <span>{{ $t('userDetail.labelBlockedReason') }}</span
          ><b>{{ user.remnawave.blocked_reason || '—' }}</b>
        </div>
        <div>
          <span>{{ $t('userDetail.labelLastSync') }}</span
          ><b>{{ formatDateTimeOrDash(user.remnawave.last_synced_at) }}</b>
        </div>
        <div>
          <span>{{ $t('userDetail.labelSyncReason') }}</span
          ><b>{{ user.remnawave.sync_reason || '—' }}</b>
        </div>
        <div class="detail-wide">
          <span>{{ $t('userDetail.labelSyncError') }}</span
          ><code>{{ user.remnawave.sync_error || '—' }}</code>
        </div>
      </div>
    </section>

    <section v-if="!user.remnawave" class="detail-section detail-section--danger">
      <div class="section-header compact-section-header">
        <h4>{{ $t('userDetail.dangerZone') }}</h4>
        <p>{{ $t('userDetail.dangerZoneHint') }}</p>
      </div>
      <Button
        :label="$t('userDetail.deleteUser')"
        icon="pi pi-trash"
        severity="danger"
        outlined
        @click="$emit('confirmDelete', $event, user)"
      />
    </section>
  </aside>

  <aside v-else class="user-detail-placeholder" data-testid="user-detail-placeholder">
    <i class="pi pi-arrow-left" />
    <strong>{{ $t('userDetail.placeholderTitle') }}</strong>
    <span>{{ $t('userDetail.placeholderText') }}</span>
  </aside>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import Button from 'primevue/button'
import Message from 'primevue/message'
import Tag from 'primevue/tag'
import { fmtBytes, fmtDate, fmtHandshake, formatDateTime } from '../../utils/format'
import { peerLabel, peerSeverity } from '../../utils/status'
import { peerRowKey } from '../../utils/deviceConfigUrls'
import type { AdminDevice, DeviceNodeAvailability, Peer, User } from '../../api'

const { t } = useI18n()

const props = defineProps<{
  user: User | null
  syncingUser: boolean
  savingDeviceLimit: boolean
  deviceLimitError: string | null
}>()

const emit = defineEmits<{
  close: []
  block: [user: User]
  unblock: [user: User]
  confirmDelete: [event: Event, user: User]
  showTraffic: [user: User]
  copyUserLink: [user: User]
  regenerateLink: [user: User]
  updateLifecycle: [
    user: User,
    payload: {
      expire_at: string | null
      traffic_limit_bytes: number
      traffic_reset_policy: 'manual' | 'no_reset'
    },
  ]
  resetTraffic: [user: User]
  downloadConfig: [user: User, device: AdminDevice, node: DeviceNodeAvailability]
  downloadConfigZip: [user: User]
  showQr: [user: User, device: AdminDevice, node: DeviceNodeAvailability]
  saveDeviceLimit: [user: User, deviceLimit: number]
  syncRemnawaveUser: [user: User]
}>()

// Device status strings come from the shared readiness rule in the backend; the label falls back to
// the raw value so an unknown status is still readable instead of rendering a missing-key string.
const DEVICE_STATUS_KEYS: Record<string, string> = {
  ready: 'deviceStatus.ready',
  pending: 'deviceStatus.pending',
  error: 'deviceStatus.error',
  deleting: 'deviceStatus.deleting',
}

// The local device-limit draft is seeded from the *local* column: that is the field the PUT writes
// and the one an operator edits. The effective limit (which for a Remnawave owner is the imported
// one) is what gets displayed next to it.
const deviceLimitDraft = ref(0)

watch(
  () => [props.user?.id, props.user?.device_limit] as const,
  () => {
    deviceLimitDraft.value = props.user?.device_limit ?? 0
  },
  { immediate: true },
)

function submitDeviceLimit(user: User) {
  const parsed = Number(deviceLimitDraft.value)
  const limit = Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 0
  deviceLimitDraft.value = limit
  emit('saveDeviceLimit', user, limit)
}

/** ``0`` means unlimited on both sides; a Remnawave owner is judged by its imported limit only. */
function deviceLimitLabel(user: User): string {
  const limit = user.remnawave ? user.remnawave.hwid_device_limit ?? 0 : user.effective_device_limit
  return limit > 0 ? String(limit) : t('userDetail.noLimit')
}

function deviceIpsLabel(user: User): string {
  const ips = user.devices.map((device) => device.vpn_ip).filter((ip): ip is string => !!ip)
  return ips.length ? ips.join(', ') : '—'
}

function deviceStatusLabel(status: string): string {
  const key = DEVICE_STATUS_KEYS[status]
  return key ? t(key) : status
}

function deviceStatusSeverity(status: string): string {
  if (status === 'ready') return 'success'
  if (status === 'error' || status === 'deleting') return 'danger'
  return 'warn'
}

function peerKey(deviceId: string | null, nodeId: string): string {
  return peerRowKey(deviceId, nodeId)
}

function peerDeviceLabel(peer: Peer): string {
  return peer.device_name ? `${peer.device_name} · ${peer.node_name}` : peer.node_name
}

function formatDateTimeOrDash(iso?: string | null): string {
  return iso ? formatDateTime(iso) : '—'
}

function primaryIdentity(user: User): string {
  return user.remnawave?.display_name ?? user.name
}

function normalizeTelegramUsername(username: string | null | undefined): string | null {
  const value = username?.trim().replace(/^@/, '')
  return value ? value : null
}

function remnawaveContext(user: User): string | null {
  if (!user.remnawave) return null

  const username = normalizeTelegramUsername(user.remnawave.username)
  if (!username) return user.name

  return `${user.name} · @${username}`
}

function telegramLinkLabel(user: User): string | null {
  const remnawave = user.remnawave
  if (!remnawave?.telegram_url) return null

  if (remnawave.telegram_url.startsWith('https://t.me/')) {
    const username = normalizeTelegramUsername(remnawave.telegram_username)
    return username ? `@${username}` : 'Telegram username'
  }

  if (remnawave.telegram_url.startsWith('tg://user?id=')) {
    return remnawave.telegram_id !== null
      ? `Telegram ID ${remnawave.telegram_id}`
      : 'Telegram contact'
  }

  return 'Telegram contact'
}

function telegramLinkAttrs(user: User): {
  readonly rel?: 'noreferrer'
  readonly target?: '_blank'
} {
  if (user.remnawave?.telegram_url?.startsWith('http')) {
    return { rel: 'noreferrer', target: '_blank' }
  }

  return {}
}

function trafficValue(user: User): string {
  if (user.remnawave) return fmtBytes(user.remnawave.combined_traffic_used_bytes)
  return user.local_traffic ? fmtBytes(user.local_traffic.total_bytes) : '—'
}

function trafficLimit(value: number): string {
  return value > 0 ? fmtBytes(value) : t('userDetail.noLimit')
}

function dateInput(user: User): string {
  const value = user.lifecycle?.expire_at ?? user.expire_at
  return value ? value.slice(0, 16) : ''
}

function limitGb(user: User): number {
  const value = user.lifecycle?.traffic_limit_bytes ?? user.traffic_limit_bytes
  return Math.round(value / 1024 ** 3)
}

function onExpireChange(user: User, event: Event) {
  const target = event.target as { value?: unknown } | null
  if (!target || target.value === undefined) return
  emitLifecycle(user, {
    expire_at: String(target.value || '') || null,
    traffic_limit_bytes: user.lifecycle?.traffic_limit_bytes ?? user.traffic_limit_bytes,
    traffic_reset_policy: user.lifecycle?.traffic_reset_policy ?? user.traffic_reset_policy,
  })
}

function onLimitChange(user: User, event: Event) {
  const target = event.target as { value?: unknown } | null
  if (!target || target.value === undefined) return
  emitLifecycle(user, {
    expire_at: user.lifecycle?.expire_at ?? user.expire_at,
    traffic_limit_bytes: Number(target.value || 0) * 1024 ** 3,
    traffic_reset_policy: user.lifecycle?.traffic_reset_policy ?? user.traffic_reset_policy,
  })
}

function onPolicyChange(user: User, event: Event) {
  const target = event.target as { value?: unknown } | null
  if (!target || target.value === undefined) return
  emitLifecycle(user, {
    expire_at: user.lifecycle?.expire_at ?? user.expire_at,
    traffic_limit_bytes: user.lifecycle?.traffic_limit_bytes ?? user.traffic_limit_bytes,
    traffic_reset_policy: String(target.value) === 'no_reset' ? 'no_reset' : 'manual',
  })
}

function emitLifecycle(
  user: User,
  payload: {
    expire_at: string | null
    traffic_limit_bytes: number
    traffic_reset_policy: 'manual' | 'no_reset'
  },
) {
  emit('updateLifecycle', user, payload)
}

function syncSeverity(status: string, error: string | null): string {
  if (error || status === 'failed' || status === 'error') return 'danger'
  if (status === 'synced') return 'success'
  return 'warn'
}

function compareText(left: string | null | undefined, right: string | null | undefined): number {
  return (left ?? '').localeCompare(right ?? '', 'ru', { sensitivity: 'base' })
}

const sortedPeers = computed(() => {
  if (!props.user) return []

  // Ordered by device first: one owner holds several peers on one node, so the device is what makes
  // a peer row unique and keeps an owner's devices grouped instead of interleaved.
  return [...props.user.peers].sort((left, right) => {
    const deviceDiff = compareText(left.device_name, right.device_name)
    if (deviceDiff !== 0) return deviceDiff

    const nameDiff = compareText(left.node_name, right.node_name)
    if (nameDiff !== 0) return nameDiff

    return compareText(left.node_id, right.node_id)
  })
})
</script>

<style scoped>
.user-detail-drawer,
.user-detail-placeholder {
  min-width: 0;
  align-self: start;
  max-height: calc(100vh - 3rem);
  overflow: auto;
  border: 1px solid var(--app-border-strong);
  border-radius: var(--app-radius-lg);
  background: linear-gradient(
    180deg,
    var(--app-shell-solid),
    color-mix(in srgb, var(--app-shell-solid) 90%, var(--app-bg-accent))
  );
  box-shadow: var(--app-shadow);
}

.user-detail-placeholder {
  display: grid;
  gap: 0.5rem;
  place-items: center;
  min-height: 18rem;
  padding: var(--app-space-5);
  color: var(--app-text-muted);
  text-align: center;
}

.drawer-head {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  padding: var(--app-space-5);
  border-bottom: 1px solid var(--app-border);
}

.drawer-head h3 {
  margin: 0;
  color: var(--app-text);
  font-size: 1.35rem;
  font-weight: 950;
  overflow-wrap: anywhere;
}

.drawer-head p {
  margin: 0.3rem 0 0;
  color: var(--app-text-muted);
}

.drawer-identity-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem;
  margin: 0.45rem 0 0;
  color: var(--app-text-muted);
  font-size: 0.82rem;
}

.drawer-identity-meta a {
  color: var(--app-accent);
  font-weight: 750;
  text-decoration: none;
}

.drawer-identity-meta a:hover {
  text-decoration: underline;
}

.drawer-status-row,
.drawer-action-grid,
.config-node-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem;
}

.drawer-status-row {
  padding: 0 var(--app-space-5) var(--app-space-4);
}

.detail-section {
  display: grid;
  gap: 0.85rem;
  margin: 0 var(--app-space-5) var(--app-space-4);
  padding: var(--app-space-4);
  border: 1px solid var(--app-border);
  border-radius: var(--app-radius-md);
  background: color-mix(in srgb, var(--app-surface-raised) 76%, transparent);
}

.detail-section--accent {
  border-color: color-mix(in srgb, var(--app-accent) 40%, var(--app-border));
}

.detail-section--rw {
  border-color: color-mix(in srgb, var(--app-cyan) 42%, var(--app-border));
}

.detail-section--danger {
  border-color: color-mix(in srgb, var(--app-red) 36%, var(--app-border));
}

.lifecycle-form-grid {
  display: grid;
  gap: 0.75rem;
}

.lifecycle-form-grid label {
  display: grid;
  gap: 0.35rem;
}

.lifecycle-form-grid input,
.lifecycle-form-grid select {
  width: 100%;
  min-height: 2.5rem;
  padding: 0.55rem 0.7rem;
  border: 1px solid var(--app-border-strong);
  border-radius: 0.8rem;
  background: var(--app-shell-solid);
  color: var(--app-text);
}

.compact-section-header {
  margin-bottom: 0;
}

.compact-section-header h4 {
  margin: 0;
  color: var(--app-text);
  font-size: 0.86rem;
  font-weight: 950;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.device-limit-form {
  display: grid;
  gap: 0.75rem;
}

.device-limit-form label {
  display: grid;
  gap: 0.35rem;
}

.device-limit-form input {
  width: 100%;
  min-height: 2.5rem;
  padding: 0.55rem 0.7rem;
  border: 1px solid var(--app-border-strong);
  border-radius: 0.8rem;
  background: var(--app-shell-solid);
  color: var(--app-text);
}

.device-limit-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.6rem;
}

.device-limit-hint,
.device-limit-note span {
  color: var(--app-text-muted);
  font-size: 0.78rem;
}

.device-limit-note {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.device-list,
.device-node-list,
.peer-detail-list {
  display: grid;
  gap: 0.6rem;
}

.device-card,
.peer-detail-card {
  display: grid;
  gap: 0.6rem;
  padding: 0.75rem;
  border: 1px solid var(--app-border);
  border-radius: var(--app-radius-sm);
  background: color-mix(in srgb, var(--app-shell-solid) 80%, transparent);
}

.device-head,
.device-node-identity {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.device-tags {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.35rem;
}

.device-node-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 0.6rem;
}

.device-empty {
  display: grid;
  gap: 0.5rem;
}

.device-card strong,
.peer-detail-card strong {
  display: block;
  margin-bottom: 0.25rem;
  color: var(--app-text);
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.75rem;
}

.detail-grid--single {
  grid-template-columns: 1fr;
}

.detail-grid > div {
  display: grid;
  gap: 0.25rem;
  min-width: 0;
}

.detail-grid span {
  color: var(--app-text-soft);
  font-size: 0.68rem;
  font-weight: 900;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.detail-grid b {
  color: var(--app-text);
  overflow-wrap: anywhere;
}

.detail-grid code {
  overflow-wrap: anywhere;
  white-space: normal;
}

.detail-wide {
  grid-column: 1 / -1;
}

.peer-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
}

.drawer-empty {
  color: var(--app-text-muted);
  padding: 0.9rem;
  border: 1px dashed var(--app-border);
  border-radius: var(--app-radius-sm);
}

@media (max-width: 980px) {
  .user-detail-drawer,
  .user-detail-placeholder {
    max-height: none;
  }
}

@media (max-width: 640px) {
  .detail-grid,
  .device-node-row {
    grid-template-columns: 1fr;
  }
}
</style>
