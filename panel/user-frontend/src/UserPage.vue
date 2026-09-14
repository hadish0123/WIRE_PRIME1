<template>
  <div class="shell">
    <UserHeader :user-name="info?.user_name || null" />

    <main>
      <UserStateCard v-if="loading" state="loading" />
      <UserStateCard
        v-else-if="!info"
        state="error"
        :is-404="error?.kind === 'not_found'"
        :text="errorText"
      />

      <template v-else>
        <section class="hero" :class="`hero-${info.status.code}`">
          <div>
            <p class="eyebrow">{{ $t('dashboard.eyebrow') }}</p>
            <h1>{{ $t('dashboard.title', { name: info.user_name }) }}</h1>
            <p class="hero-subtitle">{{ statusText }}</p>
          </div>
          <div class="hero-status">
            <span :class="['status-pill', info.status.code]">
              {{ $t(`statuses.${info.status.code}.label`) }}
            </span>
            <span class="status-note">
              <span v-if="refreshing" class="inline-spinner" />
              {{ updatedText }}
            </span>
            <button type="button" class="hero-refresh" :disabled="refreshing" @click="refreshNow">
              <RefreshIcon />
              <span>{{ $t('common.refresh') }}</span>
            </button>
          </div>
        </section>

        <!-- A failed background refresh keeps the whole page on screen and says so. -->
        <section v-if="retrying" class="notice-card retry-card">
          <strong>{{ $t('refresh.retryTitle') }}</strong>
          <p>{{ $t('refresh.retryNotice') }}</p>
          <span>{{ errorText }}</span>
          <button type="button" class="ghost-btn" :disabled="refreshing" @click="refreshNow">
            {{ $t('refresh.now') }}
          </button>
        </section>

        <TelegramProxyCard v-if="telegramProxy" :proxy="telegramProxy" />

        <UserStateCard v-if="info.blocked" state="blocked" :title="stateTitle" :text="stateBody" />
        <section v-else-if="!isActive" class="notice-card">
          <strong>{{ $t(`statuses.${info.status.code}.label`) }}</strong>
          <p>{{ $t(`statuses.${info.status.code}.text`) }}</p>
          <span>{{ $t('support.placeholder') }}</span>
        </section>

        <section class="summary-grid" :aria-label="$t('dashboard.summary')">
          <article class="summary-card primary-card">
            <span class="card-kicker">{{ $t('traffic.title') }}</span>
            <strong>{{ trafficUsed }}</strong>
            <span>{{ trafficLimitText }}</span>
            <div class="meter" :aria-label="trafficLimitText">
              <span :style="{ width: `${trafficPercent}%` }" />
            </div>
          </article>

          <article class="summary-card">
            <span class="card-kicker">{{ $t('subscription.title') }}</span>
            <strong>{{ subscriptionDate }}</strong>
            <span>{{ subscriptionText }}</span>
          </article>

          <article class="summary-card">
            <span class="card-kicker">{{ $t('connection.title') }}</span>
            <strong>{{ nodeSummary.ready }}/{{ nodeSummary.total }}</strong>
            <span>{{ connectionHint }}</span>
          </article>
        </section>

        <section v-if="warningText" class="notice-card">
          <strong>{{ $t('warnings.title') }}</strong>
          <p>{{ warningText }}</p>
          <span>{{ $t('support.placeholder') }}</span>
        </section>

        <section class="devices-section" :aria-label="$t('devices.title')">
          <div class="section-head">
            <div>
              <p class="eyebrow">{{ $t('devices.eyebrow') }}</p>
              <h2>{{ $t('devices.title') }}</h2>
              <p class="section-sub">{{ $t('devices.subtitle') }}</p>
            </div>
            <div class="devices-actions">
              <span class="device-count">{{ deviceCountText }}</span>
              <button
                v-if="devices.length && !showAddForm"
                type="button"
                class="add-open"
                :disabled="!canAdd"
                @click="showAddForm = true"
              >
                <PlusIcon />
                <span>{{ $t('devices.add') }}</span>
              </button>
            </div>
          </div>

          <div v-if="devices.length > 1" class="device-tabs" role="tablist">
            <button
              v-for="device in devices"
              :key="device.id"
              type="button"
              role="tab"
              :aria-selected="selectedDevice?.id === device.id"
              :class="['device-tab', selectedDevice?.id === device.id && 'active']"
              @click="activeDeviceId = device.id"
            >
              {{ device.name }}
            </button>
          </div>

          <!-- An inactive owner sees the devices the account actually holds, with the inactive note
               and an enabled Delete button; the empty state below only ever means "no devices". -->
          <div v-if="deviceSection === 'inactive'" class="notice-card empty-devices">
            <LaptopIcon />
            <strong>{{ $t('devices.inactiveEmptyTitle') }}</strong>
            <p>{{ $t('devices.inactiveEmptyText') }}</p>
            <span>{{ $t('support.placeholder') }}</span>
          </div>

          <!-- A brand new account: invite a named device instead of the old "no servers" placeholder. -->
          <div v-else-if="deviceSection === 'invite'" class="empty-devices">
            <LaptopIcon />
            <h3>{{ $t('devices.emptyTitle') }}</h3>
            <p>{{ $t('devices.emptyText') }}</p>
            <AddDeviceForm
              :busy="adding"
              :disabled="!canAdd"
              :error-key="addErrorKey"
              :reset-token="formResetToken"
              @submit="submitAdd"
            />
          </div>

          <template v-else>
            <div v-if="showAddForm" class="add-panel">
              <AddDeviceForm
                :busy="adding"
                :disabled="!canAdd"
                :error-key="addErrorKey"
                :reset-token="formResetToken"
                @submit="submitAdd"
              />
              <button type="button" class="ghost-btn" @click="closeAddForm">
                {{ $t('common.cancel') }}
              </button>
            </div>

            <p v-if="limitNote" class="limit-note">{{ limitNote }}</p>
            <p v-if="deleteErrorKey" class="limit-note danger">{{ $t(deleteErrorKey) }}</p>

            <div class="device-list">
              <DeviceCard
                v-if="selectedDevice"
                :key="selectedDevice.id"
                :token="userId"
                :device="selectedDevice"
                :tab="activeTab"
                :active-qr-key="effectiveActiveQrKey"
                :qr-items="qrMap"
                :inactive="!isActive"
                :deleting="deletingId === selectedDevice.id"
                :confirming="confirmingDeleteId === selectedDevice.id"
                @toggle-qr="toggleQr"
                @copy="copy"
                @request-delete="requestDelete"
                @cancel-delete="cancelDelete"
                @confirm-delete="confirmDelete"
              />
            </div>
          </template>
        </section>

        <section class="guide-grid">
          <article class="guide-card platform-card">
            <div class="section-head compact-head">
              <div>
                <h2>{{ $t('platforms.title') }}</h2>
                <p>{{ $t('platforms.subtitle') }}</p>
              </div>
            </div>

            <div class="platform-tabs" role="tablist" :aria-label="$t('platforms.choose')">
              <button
                v-for="platform in platforms"
                :key="platform.id"
                type="button"
                role="tab"
                :aria-selected="selectedPlatformId === platform.id"
                :class="['platform-tab', selectedPlatformId === platform.id && 'active']"
                @click="selectedPlatformId = platform.id"
              >
                {{ $t(`platforms.items.${platform.id}.name`) }}
              </button>
            </div>

            <div class="platform-tabs" role="tablist" :aria-label="$t('platforms.chooseApp')">
              <button
                v-for="app in apps"
                :key="app"
                type="button"
                role="tab"
                :aria-selected="activeTab === app"
                :class="['platform-tab', activeTab === app && 'active']"
                @click="activeTab = app"
              >
                {{ $t(`platforms.apps.${app}.name`) }}
              </button>
            </div>

            <div class="platform-details">
              <div class="download-panel">
                <div>
                  <span class="card-kicker">{{ $t('platforms.downloadApp') }}</span>
                  <h3>
                    {{ $t(`platforms.apps.${activeTab}.name`) }} ·
                    {{ $t(`platforms.items.${activePlatform.id}.name`) }}
                  </h3>
                  <p>{{ $t(`platforms.apps.${activeTab}.downloadHint`) }}</p>
                </div>
                <a class="download-link" :href="activeDownloadUrl" target="_blank" rel="noreferrer">
                  <DownloadIcon />
                  {{ $t('platforms.openDownload') }}
                </a>
              </div>

              <div class="app-qr-card">
                <img
                  :src="downloadQrUrl"
                  :alt="
                    $t('platforms.qrAlt', {
                      app: $t(`platforms.apps.${activeTab}.name`),
                      platform: $t(`platforms.items.${activePlatform.id}.name`),
                    })
                  "
                  width="168"
                  height="168"
                />
                <span>{{ $t('platforms.scanToDownload') }}</span>
              </div>

              <div class="instruction-panel">
                <span class="card-kicker">{{ $t('platforms.addConfig') }}</span>
                <ol class="platform-list">
                  <li>{{ $t('platforms.configStep1') }}</li>
                  <li>{{ $t(`platforms.apps.${activeTab}.configStep`) }}</li>
                  <li>{{ $t(`platforms.items.${activePlatform.id}.configStep`) }}</li>
                </ol>
              </div>
            </div>
          </article>

          <article class="guide-card">
            <h2>{{ $t('help.title') }}</h2>
            <p>{{ $t('help.text') }}</p>
          </article>
        </section>
      </template>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'

import {
  PublicApiError,
  apiErrorKey,
  createDevice,
  deleteDevice,
  type TelegramProxyInfo,
  type UserDevice,
  type UserNode,
} from './api/userPage'
import AddDeviceForm from './components/AddDeviceForm.vue'
import DeviceCard from './components/DeviceCard.vue'
import TelegramProxyCard from './components/TelegramProxyCard.vue'
import UserHeader from './components/UserHeader.vue'
import UserStateCard from './components/UserStateCard.vue'
import { useUserPageRefresh } from './composables/useUserPageRefresh'
import { useVpnQrChunks } from './composables/useVpnQrChunks'
import { DownloadIcon, PlusIcon, RefreshIcon } from './icons'
import { parseDeviceCardQrKey } from './utils/deviceUrls'
import { deviceSectionState } from './utils/deviceListState'
import { selectedDeviceId as resolveSelectedDeviceId } from './utils/deviceSelection'
import { copyToClipboard, fmtBytes, fmtDate, fmtDateTime } from './utils/format'

type PlatformId = 'ios' | 'android' | 'macos' | 'windows' | 'linux'
type AppId = 'vpn' | 'awg'

interface PlatformOption {
  id: PlatformId
  urls: Record<AppId, string>
}

const { t, locale } = useI18n()
const route = useRoute()
const userId = computed(() => String(route.params.userId ?? ''))

const activeTab = ref<AppId>('vpn')
const activeQrKey = ref<string | null>(null)
const selectedPlatformId = ref<PlatformId>('ios')
const apps: AppId[] = ['vpn', 'awg']

const showAddForm = ref(false)
const adding = ref(false)
const addErrorKey = ref<string | null>(null)
const formResetToken = ref(0)
const confirmingDeleteId = ref<string | null>(null)
const deletingId = ref<string | null>(null)
const deleteErrorKey = ref<string | null>(null)

const platforms: PlatformOption[] = [
  {
    id: 'ios',
    urls: {
      vpn: 'https://apps.apple.com/us/app/amneziavpn/id1600529900',
      awg: 'https://apps.apple.com/us/app/amneziawg/id6478942365',
    },
  },
  {
    id: 'android',
    urls: {
      vpn: 'https://play.google.com/store/apps/details?id=org.amnezia.vpn',
      awg: 'https://play.google.com/store/apps/details?id=org.amnezia.awg',
    },
  },
  {
    id: 'macos',
    urls: {
      vpn: 'https://amnezia.org/downloads',
      awg: 'https://apps.apple.com/us/app/amneziawg/id6478942365',
    },
  },
  {
    id: 'windows',
    urls: {
      vpn: 'https://amnezia.org/downloads',
      awg: 'https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest',
    },
  },
  {
    id: 'linux',
    urls: {
      vpn: 'https://amnezia.org/downloads',
      awg: 'https://github.com/amnezia-vpn/amneziawg-go',
    },
  },
]

const {
  qrMap,
  syncDevices,
  fetchAllVpnChunks,
  forgetDevice,
  reset: resetQr,
} = useVpnQrChunks(() => userId.value)

const {
  info,
  error,
  retrying,
  loading,
  refreshing,
  refresh,
  acceptInfo,
  invalidate,
  reset,
  start,
} = useUserPageRefresh(() => userId.value, {
  // A revoked link must not leave a cached configuration on screen: the page drops its QR caches
  // here, and the authoritative re-read that follows surfaces the invalid link.
  onUnauthorized: () => {
    resetQr()
    activeQrKey.value = null
  },
})

const devices = computed<UserDevice[]>(() => info.value?.devices ?? [])
const activeDeviceId = ref<string | null>(null)
const selectedDevice = computed(
  () => devices.value.find((device) => device.id === activeDeviceId.value) ?? null,
)

/** An account may only add and download while it is active and not blocked. */
const isActive = computed(
  () => !!info.value && info.value.status.code === 'active' && !info.value.blocked,
)

/** The backend decides: its effective limit, block and lifecycle state are already folded in. */
const canAdd = computed(() => !!info.value?.can_add_device && isActive.value)

/**
 * The device section is never told that a list of the owner's own devices is hidden: an inactive
 * account still sees its devices (with the inactive note and Delete), and the empty state is only
 * used when the account truly owns none.
 */
const deviceSection = computed(() =>
  deviceSectionState({ hasDevices: devices.value.length > 0, inactive: !isActive.value }),
)

const deviceCount = computed(() => info.value?.device_count ?? devices.value.length)
const deviceLimit = computed(() => info.value?.device_limit ?? 0)

const deviceCountText = computed(() =>
  deviceLimit.value > 0
    ? t('devices.countOf', { count: deviceCount.value, limit: deviceLimit.value })
    : t('devices.countUnlimited', { count: deviceCount.value }),
)

const limitNote = computed(() => {
  if (!info.value) return ''
  if (!isActive.value) return t('devices.inactiveNote')
  if (deviceLimit.value > 0 && deviceCount.value >= deviceLimit.value) {
    return t('devices.limitNote', { limit: deviceLimit.value })
  }
  return ''
})

const telegramProxy = computed<TelegramProxyInfo | null>(() => {
  const proxy = info.value?.telegram_proxy
  return proxy && proxy.enabled ? proxy : null
})

/** Nodes the account can use, counted once even when several devices share a node. */
const nodeSummary = computed(() => {
  const seen = new Map<string, boolean>()
  for (const device of devices.value) {
    for (const node of device.nodes) seen.set(node.id, Boolean(seen.get(node.id)) || node.ready)
  }
  if (!seen.size) {
    for (const node of info.value?.nodes ?? []) seen.set(node.id, node.ready)
  }
  return {
    total: seen.size,
    ready: [...seen.values()].filter(Boolean).length,
  }
})

const trafficUsed = computed(() => fmtBytes(info.value?.traffic.used_bytes || 0))
const trafficPercent = computed(() => {
  const traffic = info.value?.traffic
  if (!traffic?.limit_bytes) return 100
  return Math.min(100, Math.round((traffic.used_bytes / traffic.limit_bytes) * 100))
})
const trafficLimitText = computed(() => {
  const traffic = info.value?.traffic
  if (!traffic?.limit_bytes) return t('traffic.noLimit')
  return t('traffic.ofLimit', {
    limit: fmtBytes(traffic.limit_bytes),
    percent: trafficPercent.value,
  })
})
const subscriptionDate = computed(() =>
  fmtDate(info.value?.subscription.expire_at || null, locale.value),
)
const subscriptionText = computed(() =>
  info.value?.subscription.expire_at
    ? t('subscription.expires')
    : info.value && !info.value.subscription.managed
      ? t('subscription.local')
      : t('subscription.noExpiry'),
)
const updatedText = computed(() =>
  info.value?.updated_at
    ? t('dashboard.updatedAt', { value: fmtDateTime(info.value.updated_at, locale.value) })
    : t('dashboard.updatedAt', { value: t('common.notAvailable') }),
)
const statusText = computed(() => {
  const code = info.value?.status.code || 'active'
  return t(`statuses.${code}.text`)
})
const stateTitle = computed(() => t(`statuses.${info.value?.status.code || 'blocked'}.label`))
const stateBody = computed(
  () => `${t(`statuses.${info.value?.status.code || 'blocked'}.text`)} ${t('support.placeholder')}`,
)
const connectionHint = computed(() =>
  nodeSummary.value.ready > 0 ? t('connection.readyHint') : t('connection.pendingHint'),
)
const activePlatform = computed(
  () => platforms.find((platform) => platform.id === selectedPlatformId.value) || platforms[0],
)
const activeDownloadUrl = computed(() => activePlatform.value.urls[activeTab.value])
const downloadQrUrl = computed(
  () =>
    `https://api.qrserver.com/v1/create-qr-code/?size=168x168&margin=8&data=${encodeURIComponent(
      activeDownloadUrl.value,
    )}`,
)

/** Translated description of the last failure; the raw server text is never rendered. */
const errorText = computed(() =>
  error.value ? t(apiErrorKey(error.value.kind)) : t('errors.generic'),
)

/** An open QR is dropped as soon as its device/node leaves the page. */
const effectiveActiveQrKey = computed(() => {
  const key = activeQrKey.value
  if (!key) return null
  const parsed = parseDeviceCardQrKey(key)
  if (!parsed) return null
  const device = devices.value.find((entry) => entry.id === parsed.deviceId)
  return device?.nodes.some((node) => node.id === parsed.nodeId) ? key : null
})

const warningText = computed(() => {
  if (!info.value || info.value.status.code !== 'active') return ''
  const expireAt = info.value.subscription.expire_at
  if (expireAt) {
    const ms = new Date(expireAt).getTime() - Date.now()
    if (Number.isFinite(ms) && ms > 0 && ms <= 7 * 24 * 60 * 60 * 1000) {
      return t('warnings.expiring')
    }
  }
  if (info.value.traffic.limit_bytes && trafficPercent.value >= 80) {
    return t('warnings.traffic')
  }
  return ''
})

function detectPlatform(): PlatformId {
  const nav = navigator as typeof navigator & { userAgentData?: { platform?: string } }
  const platform = nav.userAgentData?.platform || nav.platform || nav.userAgent
  const value = platform.toLowerCase()
  if (value.includes('iphone') || value.includes('ipad') || value.includes('ios')) return 'ios'
  if (value.includes('android')) return 'android'
  if (value.includes('mac')) return 'macos'
  if (value.includes('win')) return 'windows'
  if (value.includes('linux')) return 'linux'
  return 'ios'
}

function toggleQr(key: string): void {
  activeQrKey.value = activeQrKey.value === key ? null : key
}

function closeAddForm(): void {
  showAddForm.value = false
  addErrorKey.value = null
}

function errorKeyFor(failure: unknown): string {
  const kind = failure instanceof PublicApiError ? failure.kind : 'unknown'
  // A full device limit is the one conflict worth naming: the other answers have their own text.
  return kind === 'conflict' ? 'devices.errors.limit' : apiErrorKey(kind)
}

function canAddFromCount(count: number): boolean {
  if (!isActive.value) return false
  return deviceLimit.value === 0 || count < deviceLimit.value
}

async function submitAdd(name: string): Promise<void> {
  if (adding.value || !canAdd.value) return
  adding.value = true
  addErrorKey.value = null
  // Whatever was requested before this write must not overwrite its result.
  invalidate()
  try {
    const device = await createDevice(userId.value, name)
    const current = info.value
    if (current) {
      const nextCount = current.device_count + 1
      acceptInfo({
        ...current,
        devices: [...current.devices, device],
        device_count: nextCount,
        can_add_device: canAddFromCount(nextCount),
      })
    }
    formResetToken.value += 1
    showAddForm.value = false
    await refresh({ silent: true })
  } catch (failure) {
    addErrorKey.value = errorKeyFor(failure)
  } finally {
    adding.value = false
  }
}

function requestDelete(deviceId: string): void {
  confirmingDeleteId.value = deviceId
  deleteErrorKey.value = null
}

function cancelDelete(): void {
  if (deletingId.value) return
  confirmingDeleteId.value = null
}

async function confirmDelete(deviceId: string): Promise<void> {
  if (deletingId.value) return
  deletingId.value = deviceId
  deleteErrorKey.value = null
  invalidate()
  try {
    const result = await deleteDevice(userId.value, deviceId)
    const current = info.value
    if (current) {
      // The slot is free as soon as the server accepted: show that before the reconcile lands.
      acceptInfo({
        ...current,
        devices: current.devices.filter((device) => device.id !== deviceId),
        device_count: result.device_count,
        can_add_device: canAddFromCount(result.device_count),
      })
    }
    // Close this device's configuration: cached QR codes and any open code go with it.
    forgetDevice(deviceId)
    const parsed = activeQrKey.value ? parseDeviceCardQrKey(activeQrKey.value) : null
    if (parsed?.deviceId === deviceId) activeQrKey.value = null
    confirmingDeleteId.value = null
    await refresh({ silent: true })
  } catch (failure) {
    deleteErrorKey.value = errorKeyFor(failure)
  } finally {
    deletingId.value = null
  }
}

async function copy(node: UserNode): Promise<void> {
  const text = node.vpn_uri || ''
  if (!text) return
  await copyToClipboard(text)
  node.copied = true
  const target = node
  setTimeout(() => {
    target.copied = false
  }, 2200)
}

function refreshNow(): void {
  void refresh()
}

watch(activeTab, (tab) => {
  activeQrKey.value = null
  if (tab === 'vpn' && isActive.value) fetchAllVpnChunks(devices.value)
})

watch(
  () => info.value?.devices,
  (next) => {
    if (!next) return
    activeDeviceId.value = resolveSelectedDeviceId(next, activeDeviceId.value)
    syncDevices(next)
    if (isActive.value && activeTab.value === 'vpn') fetchAllVpnChunks(next)
  },
)

// The router reuses this component when only the token changes: nothing from the old page may stay.
watch(userId, async (next, previous) => {
  if (!next || next === previous) return
  resetQr()
  activeQrKey.value = null
  confirmingDeleteId.value = null
  deleteErrorKey.value = null
  showAddForm.value = false
  await reset()
})

onMounted(() => {
  selectedPlatformId.value = detectPlatform()
  start()
})
</script>

<style>
@import './styles/tokens.css';

*,
*::before,
*::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html {
  overflow-y: scroll;
  overflow-x: hidden;
}

body {
  font-family:
    ui-sans-serif,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    'Segoe UI',
    sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  overflow-x: hidden;
}

.shell {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  overflow-x: hidden;
}

.notice-card {
  margin-bottom: 1.5rem;
  padding: 1rem 1.2rem;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--card);
  display: grid;
  gap: 0.35rem;
}

.retry-card {
  border-color: color-mix(in srgb, var(--danger) 40%, var(--border));
  background: var(--danger-bg);
}

.retry-card p {
  color: var(--muted);
  font-size: 14px;
  line-height: 1.5;
}

.retry-card span {
  color: var(--muted);
  font-size: 13px;
}

.retry-card button {
  justify-self: start;
  margin-top: 4px;
}

main {
  display: flex;
  flex-direction: column;
  max-width: 1180px;
  margin: 0 auto;
  padding: 28px 16px 72px;
  flex: 1;
  min-width: 0;
  width: 100%;
}

.hero {
  display: grid;
  gap: 24px;
  padding: 28px;
  margin-bottom: 20px;
  border: 1px solid var(--border);
  border-radius: calc(var(--radius) + 8px);
  background: radial-gradient(
      circle at top right,
      color-mix(in srgb, var(--primary) 22%, transparent),
      transparent 42%
    ),
    var(--card);
  box-shadow: var(--shadow);
}

.hero h1 {
  max-width: 760px;
  margin-top: 6px;
  font-size: clamp(28px, 7vw, 54px);
  line-height: 0.98;
  letter-spacing: -0.055em;
}

.hero-subtitle {
  max-width: 640px;
  margin-top: 14px;
  color: var(--muted);
  font-size: 16px;
  line-height: 1.55;
}

.eyebrow,
.card-kicker {
  color: var(--muted);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.hero-status {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}

.status-pill {
  display: inline-flex;
  align-items: center;
  min-height: 36px;
  padding: 0 14px;
  border-radius: 999px;
  font-weight: 800;
}

.status-pill.active {
  color: var(--success);
  background: color-mix(in srgb, var(--success) 12%, transparent);
}

.status-pill.blocked,
.status-pill.expired,
.status-pill.limited {
  color: var(--danger);
  background: var(--danger-bg);
}

.status-note {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  color: var(--muted);
  font-size: 13px;
}

.hero-refresh {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-height: 34px;
  padding: 0 13px;
  border: 1.5px solid var(--border);
  border-radius: 999px;
  background: var(--card);
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
}

.hero-refresh svg {
  width: 13px;
  height: 13px;
}

.hero-refresh:hover:not(:disabled) {
  border-color: var(--primary);
  color: var(--primary);
}

.hero-refresh:disabled {
  opacity: 0.6;
  cursor: default;
}

.inline-spinner {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  border: 2px solid var(--border);
  border-top-color: var(--primary);
  animation: spin 0.7s linear infinite;
}

.summary-grid,
.guide-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 14px;
  margin-bottom: 20px;
}

.guide-grid {
  order: 1;
}

.summary-card,
.guide-card {
  display: flex;
  flex-direction: column;
  gap: 8px;
  min-width: 0;
  padding: 20px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--card);
  box-shadow: var(--shadow);
}

.summary-card strong {
  font-size: 30px;
  letter-spacing: -0.04em;
}

.summary-card span:not(.card-kicker),
.guide-card p {
  color: var(--muted);
  font-size: 14px;
  line-height: 1.5;
}

.meter {
  width: 100%;
  height: 9px;
  margin-top: 8px;
  overflow: hidden;
  border-radius: 999px;
  background: var(--bg-soft);
}

.meter span {
  display: block;
  height: 100%;
  border-radius: inherit;
  background: linear-gradient(90deg, var(--primary), var(--success));
}

.guide-card h2,
.section-head h2 {
  font-size: 20px;
  letter-spacing: -0.03em;
}

.compact-head {
  margin-bottom: 12px;
}

.platform-card {
  gap: 14px;
}

.platform-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.platform-tab {
  min-height: 38px;
  padding: 8px 13px;
  border: 1.5px solid var(--border);
  border-radius: 999px;
  background: var(--bg);
  color: var(--muted);
  font-size: 13px;
  font-weight: 800;
  cursor: pointer;
}

.platform-tab.active {
  border-color: var(--primary);
  background: var(--primary-light);
  color: var(--primary);
}

.platform-details {
  display: grid;
  gap: 14px;
  align-items: stretch;
}

.download-panel,
.instruction-panel,
.app-qr-card {
  border: 1px solid var(--border);
  border-radius: calc(var(--radius) - 2px);
  background: var(--bg);
}

.download-panel,
.instruction-panel {
  padding: 16px;
}

.download-panel {
  display: grid;
  gap: 12px;
}

.download-panel h3 {
  margin: 6px 0;
  font-size: 22px;
  letter-spacing: -0.03em;
}

.download-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  min-height: 42px;
  border-radius: 999px;
  background: var(--primary);
  color: #fff;
  padding: 0 16px;
  font-size: 14px;
  font-weight: 800;
  text-decoration: none;
}

.download-link svg {
  width: 16px;
  height: 16px;
}

.app-qr-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 16px;
  text-align: center;
  color: var(--muted);
  font-size: 13px;
  font-weight: 700;
}

.app-qr-card img {
  width: 168px;
  height: 168px;
  border-radius: 12px;
  background: #fff;
  padding: 8px;
}

.platform-list {
  display: grid;
  gap: 10px;
  margin-top: 8px;
  padding-left: 20px;
  color: var(--muted);
  font-size: 14px;
  line-height: 1.5;
}

.platform-list li::marker {
  color: var(--primary);
  font-weight: 800;
}

.devices-section {
  order: 2;
  margin-bottom: 20px;
  padding: 20px;
  border: 1px solid var(--border);
  border-radius: calc(var(--radius) + 6px);
  background: color-mix(in srgb, var(--card) 84%, transparent);
}

.section-head {
  display: grid;
  gap: 16px;
  margin-bottom: 18px;
}

.section-sub {
  margin-top: 6px;
  color: var(--muted);
  font-size: 14px;
  line-height: 1.5;
}

.devices-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}

.device-count {
  display: inline-flex;
  align-items: center;
  min-height: 38px;
  padding: 0 14px;
  border-radius: 999px;
  background: var(--bg-soft);
  color: var(--text);
  font-size: 13px;
  font-weight: 800;
}

.add-open {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  min-height: 38px;
  padding: 0 16px;
  border: none;
  border-radius: 999px;
  background: var(--primary);
  color: #fff;
  font-size: 13px;
  font-weight: 800;
  cursor: pointer;
}

.add-open svg {
  width: 14px;
  height: 14px;
}

.add-open:disabled {
  opacity: 0.55;
  cursor: default;
}

.empty-devices {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 26px 22px;
  border: 1px dashed var(--border);
  border-radius: var(--radius);
  background: var(--card);
  text-align: left;
}

.empty-devices svg {
  width: 34px;
  height: 34px;
  color: var(--primary);
}

.empty-devices h3 {
  font-size: 19px;
  letter-spacing: -0.02em;
}

.empty-devices p,
.empty-devices span {
  color: var(--muted);
  font-size: 14px;
  line-height: 1.55;
}

.empty-devices .add-form {
  margin-top: 6px;
  max-width: 620px;
}

.add-panel {
  display: grid;
  gap: 10px;
  margin-bottom: 16px;
  padding: 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--card);
}

.add-panel .add-form {
  max-width: 620px;
}

.limit-note {
  margin-bottom: 12px;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.5;
}

.limit-note.danger {
  color: var(--danger);
  font-weight: 600;
}

.device-list {
  display: grid;
  gap: 16px;
}

.device-tabs {
  display: flex;
  gap: 8px;
  margin: 0 0 18px;
  overflow-x: auto;
  padding-bottom: 2px;
}

.device-tab {
  flex: 0 0 auto;
  min-height: 38px;
  max-width: 15rem;
  overflow: hidden;
  padding: 0 14px;
  border: 1.5px solid var(--border);
  border-radius: 999px;
  background: var(--card);
  color: var(--muted);
  cursor: pointer;
  font-size: 13px;
  font-weight: 700;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.device-tab:hover,
.device-tab.active {
  border-color: var(--primary);
  color: var(--primary);
}

.device-tab.active {
  background: var(--primary-light);
}

.ghost-btn {
  justify-self: start;
  min-height: 38px;
  padding: 0 16px;
  border: 1.5px solid var(--border);
  border-radius: 999px;
  background: var(--card);
  color: var(--text);
  font-size: 13px;
  font-weight: 700;
  cursor: pointer;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@media (min-width: 720px) {
  main {
    padding: 40px 24px 80px;
  }

  .hero {
    grid-template-columns: 1fr auto;
    align-items: end;
    padding: 40px;
  }

  .hero-status {
    justify-content: flex-end;
  }

  .summary-grid {
    grid-template-columns: 1.3fr 1fr 1fr;
  }

  .guide-grid {
    grid-template-columns: 1.2fr 0.8fr;
  }

  .platform-details {
    grid-template-columns: minmax(0, 1fr) 210px;
  }

  .instruction-panel {
    grid-column: 1 / -1;
  }

  .section-head {
    grid-template-columns: 1fr auto;
    align-items: end;
  }
}

@media (max-width: 520px) {
  .hero,
  .devices-section {
    padding: 18px;
  }
}
</style>
