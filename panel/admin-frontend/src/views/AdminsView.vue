<template>
  <section>
    <div class="page-header">
      <div>
        <span class="page-kicker"><i class="pi pi-shield" /> ADMINISTRATION</span>
        <h2>Admins & Permissions</h2>
        <p class="page-description">Manage PRIMEVPN administrators, roles, activation state and node scopes.</p>
      </div>
      <Button label="Create admin" icon="pi pi-plus" @click="showCreate = true" />
    </div>

    <section class="settings-card">
      <div v-if="loading" class="muted-card">Loading…</div>
      <div v-else-if="error" class="error-card">{{ error }}</div>
      <div v-else class="admin-list">
        <article v-for="admin in admins" :key="admin.id" class="admin-card">
          <div class="admin-main">
            <div>
              <strong>{{ admin.username }}</strong>
              <div class="muted">{{ admin.role }} · {{ admin.is_active ? 'active' : 'inactive' }}</div>
            </div>
            <Tag :value="admin.role" :severity="admin.role === 'super_admin' ? 'success' : 'info'" />
          </div>
          <div class="admin-meta">
            <span>Permissions: {{ admin.permissions.length ? admin.permissions.join(', ') : 'role defaults' }}</span>
            <span>Nodes: {{ admin.node_ids.length ? admin.node_ids.join(', ') : 'all nodes' }}</span>
          </div>
          <div class="admin-actions">
            <Button label="Toggle active" size="small" severity="secondary" outlined @click="toggle(admin)" />
            <Button v-if="admin.role !== 'super_admin'" label="Delete" size="small" severity="danger" outlined @click="remove(admin)" />
          </div>
        </article>
      </div>
    </section>

    <Dialog v-model:visible="showCreate" modal header="Create administrator" :style="{ width: 'min(34rem, 94vw)' }">
      <div class="form">
        <label>Username<input v-model="form.username" /></label>
        <label>Password<input v-model="form.password" type="password" /></label>
        <label>Role<select v-model="form.role"><option value="sub_admin">Sub Admin</option><option value="admin">Admin</option><option value="super_admin">Super Admin</option></select></label>
        <label>Permissions (comma separated)<input v-model="permissionsText" placeholder="nodes.view,users.view" /></label>
        <label>Node IDs (comma separated; empty = all)<input v-model="nodesText" /></label>
        <label class="check"><input v-model="form.is_active" type="checkbox" /> Active</label>
      </div>
      <template #footer>
        <Button label="Cancel" severity="secondary" text @click="showCreate = false" />
        <Button label="Create" :loading="saving" @click="create" />
      </template>
    </Dialog>
  </section>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import Tag from 'primevue/tag'
import { adminsApi, type Admin } from '../api/admins'

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
  try { admins.value = (await adminsApi.list()) || [] } catch (e) { error.value = e instanceof Error ? e.message : 'Failed to load admins' } finally { loading.value = false }
}
async function create() {
  saving.value = true
  try {
    await adminsApi.create({ ...form, permissions: permissionsText.value.split(',').map(x => x.trim()).filter(Boolean), node_ids: nodesText.value.split(',').map(x => x.trim()).filter(Boolean) })
    form.username = ''; form.password = ''; permissionsText.value = ''; nodesText.value = ''; showCreate.value = false
    await load()
  } catch (e) { error.value = e instanceof Error ? e.message : 'Failed to create admin' } finally { saving.value = false }
}
async function toggle(admin: Admin) {
  await adminsApi.update(admin.id, { is_active: !admin.is_active }); await load()
}
async function remove(admin: Admin) {
  if (!confirm('Delete this administrator?')) return
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
