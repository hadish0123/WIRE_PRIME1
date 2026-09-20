<template>
  <section>
    <div class="page-header">
      <div>
        <span class="page-kicker"><i class="pi pi-shield" /> {{ $t('admins.kicker') }}</span>
        <h2>{{ $t('admins.title') }}</h2>
        <p class="page-description">{{ $t('admins.description') }}</p>
      </div>
      <Button :label="$t('admins.create')" icon="pi pi-plus" @click="showCreate = true" />
    </div>

    <section class="settings-card">
      <div v-if="loading" class="muted-card">{{ $t('common.loading') }}</div>
      <div v-else-if="error" class="error-card">{{ error }}</div>
      <div v-else class="admin-list">
        <article v-for="admin in admins" :key="admin.id" class="admin-card">
          <div class="admin-main">
            <div>
              <strong>{{ admin.username }}</strong>
              <div class="muted">{{ admin.role }} · {{ admin.is_active ? $t('status.active') : $t('status.disabled') }}</div>
            </div>
            <Tag :value="admin.role" :severity="admin.role === 'super_admin' ? 'success' : 'info'" />
          </div>
          <div class="admin-meta">
            <span>{{ $t('admins.permissions') }}: {{ admin.permissions.length ? admin.permissions.join(', ') : $t('admins.roleDefaults') }}</span>
            <span>{{ $t('admins.nodes') }}: {{ admin.node_ids.length ? admin.node_ids.join(', ') : $t('admins.allNodes') }}</span>
          </div>
          <div class="admin-actions">
            <Button :label="$t('admins.toggle')" size="small" severity="secondary" outlined @click="toggle(admin)" />
            <Button v-if="admin.role !== 'super_admin'" :label="$t('common.delete')" size="small" severity="danger" outlined @click="remove(admin)" />
          </div>
        </article>
      </div>
    </section>

    <Dialog v-model:visible="showCreate" modal :header="$t('admins.createTitle')" :style="{ width: 'min(34rem, 94vw)' }">
      <div class="form">
        <label>{{ $t('login.username') }}<input v-model="form.username" /></label>
        <label>{{ $t('login.password') }}<input v-model="form.password" type="password" /></label>
        <label>{{ $t('admins.role') }}<select v-model="form.role"><option value="sub_admin">{{ $t('admins.subAdmin') }}</option><option value="admin">{{ $t('admins.admin') }}</option><option value="super_admin">{{ $t('admins.superAdmin') }}</option></select></label>
        <label>{{ $t('admins.permissionsInput') }}<input v-model="permissionsText"  :placeholder="$t('admins.permissionsPlaceholder')" /></label>
        <label>{{ $t('admins.nodeIds') }}<input v-model="nodesText" /></label>
        <label class="check"><input v-model="form.is_active" type="checkbox" /> {{ $t('status.active') }}</label>
      </div>
      <template #footer>
        <Button :label="$t('common.cancel')" severity="secondary" text @click="showCreate = false" />
        <Button :label="$t('admins.create')" :loading="saving" @click="create" />
      </template>
    </Dialog>
  </section>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import Tag from 'primevue/tag'
import { useI18n } from 'vue-i18n'
import { adminsApi, type Admin } from '../api/admins'

const { t } = useI18n()
const admins = ref<Admin[]>([])
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const showCreate = ref(false)
const permissionsText = ref('')
const nodesText = ref('')
const form = reactive({ username: '', password: '', role: 'sub_admin' as Admin['role'], is_active: true })

async function load() {
  loading.value = true
  error.value = ''
  try { admins.value = (await adminsApi.list()) || [] } catch (e) { error.value = e instanceof Error ? e.message : t('admins.loadError') } finally { loading.value = false }
}
async function create() {
  saving.value = true
  try {
    await adminsApi.create({ ...form, permissions: permissionsText.value.split(',').map(x => x.trim()).filter(Boolean), node_ids: nodesText.value.split(',').map(x => x.trim()).filter(Boolean) })
    form.username = ''; form.password = ''; permissionsText.value = ''; nodesText.value = ''; showCreate.value = false
    await load()
  } catch (e) { error.value = e instanceof Error ? e.message : t('admins.createError') } finally { saving.value = false }
}
async function toggle(admin: Admin) {
  await adminsApi.update(admin.id, { is_active: !admin.is_active }); await load()
}
async function remove(admin: Admin) {
  if (!confirm(t('admins.deleteConfirm'))) return
  await adminsApi.remove(admin.id); await load()
}
onMounted(load)
</script>

<style scoped>
.settings-card { display:grid; gap:1rem; padding:1rem; border:1px solid var(--app-border-strong); border-radius:var(--app-radius-lg); background:var(--app-shell-solid); }
.admin-list { display:grid; gap:.8rem; }
.admin-card { display:grid; gap:.7rem; padding:1rem; border:1px solid var(--app-border); border-radius:16px; }
.admin-main,.admin-meta,.admin-actions { display:flex; align-items:center; justify-content:space-between; gap:.75rem; flex-wrap:wrap; }
.admin-meta { color:var(--app-text-muted); font-size:.82rem; }
.muted { color:var(--app-text-soft); font-size:.8rem; margin-top:.25rem; }
.error-card { color:var(--app-red); padding:1rem; }
.form { display:grid; gap:.8rem; }
.form label { display:grid; gap:.3rem; color:var(--app-text-muted); font-size:.8rem; font-weight:800; }
.form input,.form select { width:100%; padding:.65rem; border:1px solid var(--app-border-strong); border-radius:10px; background:var(--app-surface-raised); color:var(--app-text); }
.form .check { display:flex; align-items:center; grid-template-columns:auto 1fr; }
.form .check input { width:auto; }
</style>
