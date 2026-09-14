<template>
  <form class="add-form" @submit.prevent="submit">
    <label class="add-label" :for="inputId">{{ $t('devices.nameLabel') }}</label>
    <div class="add-row">
      <input
        :id="inputId"
        v-model="name"
        class="add-input"
        type="text"
        :maxlength="MAX_DEVICE_NAME_LENGTH"
        :placeholder="$t('devices.namePlaceholder')"
        :disabled="disabled || busy"
        autocomplete="off"
        @input="localError = null"
      />
      <button type="submit" class="add-submit" :disabled="disabled || busy">
        <PlusIcon />
        <span>{{ busy ? $t('devices.adding') : $t('devices.add') }}</span>
      </button>
    </div>
    <p v-if="message" class="add-error">{{ message }}</p>
    <p v-else class="add-hint">{{ $t('devices.nameHint') }}</p>
  </form>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

import { MAX_DEVICE_NAME_LENGTH, normalizeDeviceName } from '../utils/deviceNames'
import { PlusIcon } from '../icons'

const { t } = useI18n()

const props = defineProps<{
  /** A create request is in flight: the button is disabled, so a double click cannot add twice. */
  busy: boolean
  /** Adding is not allowed at all (limit reached, or the account is not active). */
  disabled: boolean
  /** Translated failure of the last attempt, decided by the page. */
  errorKey: string | null
  /** Bumped by the page after a successful add, so the field is cleared for the next device. */
  resetToken: number
}>()

const emit = defineEmits<{ submit: [name: string] }>()

const inputId = 'device-name-input'
const name = ref('')
const localError = ref<string | null>(null)

const message = computed(() => localError.value ?? (props.errorKey ? t(props.errorKey) : null))

watch(
  () => props.resetToken,
  () => {
    name.value = ''
    localError.value = null
  },
)

function submit(): void {
  if (props.busy || props.disabled) return
  const checked = normalizeDeviceName(name.value)
  if (!checked.ok) {
    localError.value = t(`devices.nameErrors.${checked.error}`)
    return
  }
  localError.value = null
  emit('submit', checked.name)
}
</script>

<style scoped>
.add-form {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.add-label {
  color: var(--muted);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
.add-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.add-input {
  flex: 1 1 200px;
  min-width: 0;
  min-height: 44px;
  padding: 0 14px;
  border: 1.5px solid var(--border);
  border-radius: 10px;
  background: var(--bg);
  color: var(--text);
  font-size: 15px;
  font-family: inherit;
}
.add-input:focus {
  outline: none;
  border-color: var(--primary);
  background: var(--card);
}
.add-input:disabled {
  opacity: 0.6;
}
.add-submit {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  flex-shrink: 0;
  min-height: 44px;
  padding: 0 20px;
  border: none;
  border-radius: 10px;
  background: var(--primary);
  color: #fff;
  font-size: 14px;
  font-weight: 800;
  cursor: pointer;
  transition: background 0.15s;
}
.add-submit svg {
  width: 15px;
  height: 15px;
}
.add-submit:hover:not(:disabled) {
  background: var(--primary-hover);
}
.add-submit:disabled {
  opacity: 0.55;
  cursor: default;
}
.add-error {
  color: var(--danger);
  font-size: 13px;
  font-weight: 600;
}
.add-hint {
  color: var(--muted);
  font-size: 12px;
  line-height: 1.45;
}
</style>
