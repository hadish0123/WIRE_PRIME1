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
              <div class="muted">{{ roleLabel(admin.role) }} · {{ admin.is_active ? $t('status.active') : $t('status.disabled') }}</div>
            </div>
            <Tag :value="roleLabel(admin.role)" :severity="admin.role === 'super_admin' ? 'success' : 'info'" />
          </div>
          <div class="permission-summary">
            <span v-for="permission in admin.permissions" :key="permission" class="permission-chip">{{ permissionLabel(permission) }}</span>
            <span v-if="!admin.permissions.length" class="muted">{{ $t('admins.roleDefaults') }}</span>
          </div>
          <div class="admin-actions">
            <Button :label="$t('admins.toggle')" size="small" severity="secondary" outlined @click="toggle(admin)" />
            <Button v-if="admin.role !== 'super_admin'" :label="$t('common.delete')" size="small" severity="danger" outlined @click="remove(admin)" />
          </div>
        </article>
      </div>
    </section>

    <Dialog v-model:visible="showCreate" modal :header="$t('admins.createTitle')" :style="{ width: 'min(48rem, 96vw)' }">
      <form class="form" @submit.prevent="create">
        <div class="form-grid">
          <label>{{ $t('login.username') }}<InputText v-model="form.username" autocomplete="off" required /></label>
          <label>{{ $t('login.password') }}<Password v-model="form.password" :feedback="true" toggleMask required /></label>
          <label>{{ $t('admins.role') }}
            <Select v-model="form.role" :options="roles" optionLabel="label" optionValue="value" />
          </label>
        </div>

        <div class="section-box">
          <div class="section-title">دسترسی‌های مدیر</div>
          <div class="permissions-grid">
            <label v-for="p in permissions" :key="p.key" class="permission-item">
              <Checkbox v-model="selectedPermissions" :value="p.key" />
              <span>{{ p.label }}</span>
            </label>
          </div>
        </div>

        <div class="section-box">
          <div class="section-title">نودهای مجاز</div>
          <div class="node-permissions">
            <label class="permission-item">
              <Checkbox v-model="allNodes" binary />
              <span>همه نودها</span>
            </label>
            <label v-for="node in nodes" :key="node.id" class="permission-item">
              <Checkbox v-model="selectedNodes" :value="node.id" />
              <span>{{ node.name }}</span>
            </label>
          </div>
        </div>

        <label class="check"><Checkbox v-model="form.is_active" binary /> {{ $t('status.active') }}</label>

        <div class="dialog-footer">
          <Button type="button" :label="$t('common.cancel')" severity="secondary" text @click="showCreate = false" />
          <Button type="submit" :label="$t('admins.create')" :loading="saving" icon="pi pi-check" />
        </div>
      </form>
    </Dialog>
  </section>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref, watch } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import Tag from 'primevue/tag'
import InputText from 'primevue/inputtext'
import Password from 'primevue/password'
import Select from 'primevue/select'
import Checkbox from 'primevue/checkbox'
import { useI18n } from 'vue-i18n'
import { adminsApi, type Admin } from '../api/admins'
import { req } from '../api/client'

const { t } = useI18n()
const admins = ref<Admin[]>([])
const nodes = ref<Array<{id:string;name:string}>>([])
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const showCreate = ref(false)
const selectedPermissions = ref<string[]>([])
const selectedNodes = ref<string[]>([])
const allNodes = ref(true)

const form = reactive({ username: '', password: '', role: 'sub_admin' as Admin['role'], is_active: true })
const roles = [
  { value:'sub_admin', label:'مدیر محدود' },
  { value:'admin', label:'مدیر' },
  { value:'super_admin', label:'مدیر کل' },
]
const permissions = [
  {key:'nodes.view',label:'مشاهده نودها'},{key:'nodes.create',label:'ساخت نود'},{key:'nodes.edit',label:'ویرایش نود'},{key:'nodes.delete',label:'حذف نود'},
  {key:'users.view',label:'مشاهده کلاینت‌ها'},{key:'users.create',label:'ساخت کلاینت'},{key:'users.edit',label:'ویرایش کلاینت'},{key:'users.delete',label:'حذف کلاینت'},{key:'users.disable',label:'غیرفعال‌سازی کلاینت'},
  {key:'wireguard.manage',label:'مدیریت WireGuard'},{key:'openvpn.manage',label:'مدیریت OpenVPN'},
  {key:'configs.view',label:'مشاهده کانفیگ'},{key:'configs.download',label:'دانلود کانفیگ'},{key:'traffic.view',label:'مشاهده ترافیک'},
  {key:'admins.view',label:'مشاهده مدیران'},{key:'admins.create',label:'ساخت مدیر'},{key:'admins.edit',label:'ویرایش مدیر'},{key:'admins.delete',label:'حذف مدیر'},
  {key:'settings.view',label:'مشاهده تنظیمات'},{key:'settings.edit',label:'ویرایش تنظیمات'},
]

function roleLabel(role:string){ return roles.find(r=>r.value===role)?.label || role }
function permissionLabel(key:string){ return permissions.find(p=>p.key===key)?.label || key }

watch(allNodes,(v)=>{ if(v) selectedNodes.value=[] })

async function load() {
  loading.value = true; error.value = ''
  try {
    admins.value = (await adminsApi.list()) || []
    nodes.value = ((await req<any[]>('GET','/nodes')) || []).map(n=>({id:n.id,name:n.name}))
  } catch (e) { error.value = e instanceof Error ? e.message : t('admins.loadError') }
  finally { loading.value = false }
}
function resetForm(){
  form.username=''; form.password=''; form.role='sub_admin'; form.is_active=true
  selectedPermissions.value=[]; selectedNodes.value=[]; allNodes.value=true
}
async function create(){
  saving.value=true
  try{
    await adminsApi.create({...form, permissions:selectedPermissions.value, node_ids:allNodes.value?[]:selectedNodes.value})
    showCreate.value=false; resetForm(); await load()
  }catch(e){ error.value=e instanceof Error?e.message:t('admins.createError') }
  finally{ saving.value=false }
}
async function toggle(admin:Admin){ await adminsApi.update(admin.id,{is_active:!admin.is_active}); await load() }
async function remove(admin:Admin){ if(!confirm(t('admins.deleteConfirm')))return; await adminsApi.remove(admin.id); await load() }
onMounted(load)
</script>

<style scoped>
.settings-card{display:grid;gap:1rem;padding:1.15rem;border:1px solid var(--app-border-strong);border-radius:var(--app-radius-lg);background:var(--app-shell-solid)}
.admin-list{display:grid;gap:.8rem}.admin-card{display:grid;gap:.8rem;padding:1rem;border:1px solid var(--app-border);border-radius:16px;background:color-mix(in srgb,var(--app-surface-raised) 55%,transparent)}
.admin-main,.admin-actions{display:flex;align-items:center;justify-content:space-between;gap:.75rem;flex-wrap:wrap}
.permission-summary{display:flex;gap:.4rem;flex-wrap:wrap}.permission-chip{padding:.35rem .55rem;border:1px solid var(--app-border);border-radius:999px;background:var(--app-surface-raised);font-size:.72rem;color:var(--app-text-muted)}
.muted{color:var(--app-text-soft);font-size:.8rem;margin-top:.25rem}.error-card{color:var(--app-red);padding:1rem}
.form{display:grid;gap:1rem}.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.8rem}.form label{display:grid;gap:.4rem;color:var(--app-text-muted);font-size:.8rem;font-weight:800}.form input{width:100%}
.section-box{padding:1rem;border:1px solid var(--app-border);border-radius:14px;background:color-mix(in srgb,var(--app-surface-raised) 65%,transparent)}.section-title{margin-bottom:.75rem;color:var(--app-text);font-weight:900}
.permissions-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.55rem}.permission-item{display:flex!important;grid-template-columns:none!important;align-items:center;gap:.55rem;padding:.55rem .65rem;border:1px solid var(--app-border);border-radius:10px;background:var(--app-shell-solid);cursor:pointer}.node-permissions{display:grid;gap:.5rem}.check{display:flex!important;align-items:center;gap:.55rem}
.dialog-footer{display:flex;justify-content:flex-end;gap:.5rem;padding-top:.4rem;border-top:1px solid var(--app-border)}
@media(max-width:650px){.form-grid,.permissions-grid{grid-template-columns:1fr}}
</style>