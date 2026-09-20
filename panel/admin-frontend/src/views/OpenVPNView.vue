<template>
  <section>
    <div class="page-header">
      <div><span class="page-kicker"><i class="pi pi-lock" /> {{ $t('openvpn.kicker') }}</span><h2>{{ $t('openvpn.title') }}</h2><p class="page-description">{{ $t('openvpn.description') }}</p></div>
    </div>
    <section class="settings-card">
      <h3>{{ $t('openvpn.server') }}</h3>
      <div class="form-grid">
        <label>{{ $t('openvpn.node') }}<select v-model="server.node_id"><option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }}</option></select></label>
        <label>{{ $t('openvpn.endpoint') }}<input v-model="server.endpoint" placeholder="vpn.example.com:1194" /></label>
        <label>{{ $t('openvpn.protocol') }}<select v-model="server.protocol"><option value="udp">UDP</option><option value="tcp-server">TCP</option></select></label>
        <label>{{ $t('openvpn.network') }}<input v-model="server.network" /></label>
        <label>{{ $t('openvpn.port') }}<input v-model.number="server.port" type="number" /></label>
      </div>
      <Button :label="$t('openvpn.applyServer')" icon="pi pi-check" :loading="saving" @click="configure" />
    </section>
    <section class="settings-card">
      <h3>{{ $t('openvpn.createClient') }}</h3>
      <div class="form-grid">
        <label>{{ $t('openvpn.user') }}<select v-model="client.user_id"><option v-for="u in users" :key="u.id" :value="u.id">{{ u.name }}</option></select></label>
        <label>Node<select v-model="client.node_id"><option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }}</option></select></label>
        <label>{{ $t('openvpn.clientName') }}<input v-model="client.name" placeholder="phone-01" /></label>
      </div>
      <Button :label="$t('openvpn.createOvpn')" icon="pi pi-plus" :loading="saving" @click="createClient" />
    </section>
    <section class="settings-card">
      <h3>{{ $t('openvpn.clients') }}</h3>
      <div v-for="c in clients" :key="c.id" class="row">
        <span><strong>{{ c.name }}</strong><small>{{ c.user_id }} · {{ c.node_id }}</small></span>
        <span class="actions"><Button :label="$t('common.download')" size="small" @click="download(c)" /><Button :label="$t('openvpn.revoke')" size="small" severity="danger" outlined @click="revoke(c)" /></span>
      </div>
    </section>
  </section>
</template>
<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import Button from 'primevue/button'\nimport { useI18n } from 'vue-i18n'
import { openvpnApi, type OpenVPNClient } from '../api/openvpn'
import { req } from '../api/client'
type Item={id:string;name:string}
const { t } = useI18n()\nconst nodes=ref<Item[]>([]), users=ref<Item[]>([]), clients=ref<OpenVPNClient[]>([]), saving=ref(false)
const server=reactive({node_id:'',endpoint:'',port:1194,protocol:'udp' as 'udp'|'tcp-server',network:'10.9.0.0/24'})
const client=reactive({user_id:'',node_id:'',name:''})
async function load(){nodes.value=(await req<Item[]>('GET','/nodes'))||[]; users.value=((await req<any[]>('GET','/users'))||[]).map(u=>({id:u.id,name:u.name})); clients.value=(await openvpnApi.list())||[]; if(!server.node_id&&nodes.value[0]) server.node_id=nodes.value[0].id; if(!client.node_id&&nodes.value[0]) client.node_id=nodes.value[0].id; if(!client.user_id&&users.value[0]) client.user_id=users.value[0].id}
async function configure(){saving.value=true; try{await openvpnApi.configure(server)}finally{saving.value=false}}
async function createClient(){saving.value=true; try{await openvpnApi.create(client); client.name=''; await load()}finally{saving.value=false}}
async function download(c:OpenVPNClient){const blob=await openvpnApi.download(c.id); if(!blob)return; const url=URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download=c.name+'.ovpn'; a.click(); URL.revokeObjectURL(url)}
async function revoke(c:OpenVPNClient){if(!confirm(t('openvpn.revokeConfirm')))return; await openvpnApi.revoke(c.id); await load()}
onMounted(load)
</script>
<style scoped>
.settings-card{display:grid;gap:1rem;margin-bottom:1rem;padding:1rem;border:1px solid var(--app-border-strong);border-radius:var(--app-radius-lg);background:var(--app-shell-solid)}.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:.8rem}.form-grid label{display:grid;gap:.3rem;font-size:.8rem;color:var(--app-text-muted);font-weight:800}.form-grid input,.form-grid select{padding:.65rem;border:1px solid var(--app-border-strong);border-radius:10px;background:var(--app-surface-raised);color:var(--app-text)}.row{display:flex;justify-content:space-between;gap:1rem;align-items:center;padding:.8rem;border-bottom:1px solid var(--app-border)}small{display:block;color:var(--app-text-soft)}.actions{display:flex;gap:.5rem}
</style>
