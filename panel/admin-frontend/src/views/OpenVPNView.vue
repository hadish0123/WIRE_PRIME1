<template>
  <section>
    <div class="page-header">
      <div>
        <span class="page-kicker"><i class="pi pi-share-alt" /> PRIMEVPN</span>
        <h2>اینباندها</h2>
        <p class="page-description">اینباند هر نود را جدا مدیریت کنید و برای آن کلاینت بسازید.</p>
      </div>
    </div>

    <section class="settings-card">
      <div class="card-head">
        <div><h3>اینباند جدید</h3><p>نود و نوع سرویس را انتخاب کنید.</p></div>
        <Tag value="VPN INBOUND" severity="info" />
      </div>
      <div class="form-grid">
        <label>نود<select v-model="server.node_id"><option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }}</option></select></label>
        <label>نوع<input value="WireGuard / OpenVPN" disabled /></label>
        <label>Endpoint عمومی<input v-model="server.endpoint" placeholder="IP یا دامنه نود" /></label>
        <label>پورت<input v-model.number="server.port" type="number" /></label>
        <label>پروتکل<select v-model="server.protocol"><option value="udp">UDP</option><option value="tcp-server">TCP</option></select></label>
        <label>شبکه<input v-model="server.network" /></label>
      </div>
      <div class="protocol-actions">
        <Button label="اعمال OpenVPN" icon="pi pi-check" :loading="saving" @click="configure" />
        <Button label="WireGuard" icon="pi pi-bolt" severity="secondary" outlined @click="showWireGuardInfo=true" />
      </div>
    </section>

    <section class="settings-card">
      <div class="card-head"><div><h3>ساخت کلاینت</h3><p>اینباند، نام، حجم و مدت اعتبار را تعیین کنید.</p></div></div>
      <div class="form-grid">
        <label>اینباند<select v-model="client.node_id"><option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }} · OpenVPN</option></select></label>
        <label>کاربر موجود (اختیاری)<select v-model="client.user_id"><option value="">ساخت کاربر جدید</option><option v-for="u in users" :key="u.id" :value="u.id">{{ u.name }}</option></select></label>
        <label>نام کلاینت<input v-model="client.name" placeholder="iphone-01" /></label>
        <label>حجم (GB)<input v-model.number="client.traffic_gb" type="number" min="0" placeholder="0 = نامحدود" /></label>
        <label>مدت (روز)<input v-model.number="client.days" type="number" min="0" placeholder="0 = بدون انقضا" /></label>
      </div>
      <Button label="ساخت کلاینت" icon="pi pi-plus" :loading="saving" @click="createClient" />
    </section>

    <section class="settings-card">
      <div class="card-head"><div><h3>کلاینت‌ها</h3><p>دانلود یا کپی کانفیگ.</p></div></div>
      <div v-if="!clients.length" class="empty">هنوز کلاینتی ساخته نشده است.</div>
      <div v-for="c in clients" :key="c.id" class="client-row">
        <div><strong>{{ c.name }}</strong><small>{{ nodeName(c.node_id) }} · {{ c.status }}</small></div>
        <div class="actions">
          <Button label="کپی" icon="pi pi-copy" size="small" severity="secondary" outlined @click="copy(c)" />
          <Button label="دانلود" icon="pi pi-download" size="small" @click="download(c)" />
          <Button label="لغو" icon="pi pi-times" size="small" severity="danger" outlined @click="revoke(c)" />
        </div>
      </div>
    </section>

    <Dialog v-model:visible="showWireGuardInfo" modal header="WireGuard" :style="{width:'min(32rem,94vw)'}">
      <div class="info-box">WireGuard فعلی PRIMEVPN روی رابط Amnezia/WireGuard نود مدیریت می‌شود. برای چند اینباند مستقل WireGuard باید رابط‌های مستقل روی Agent ایجاد شوند؛ این بخش را در مرحله بعد به Agent متصل می‌کنیم و از مسیر ترافیک VPN عبور نمی‌دهیم.</div>
    </Dialog>
  </section>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import Tag from 'primevue/tag'
import { useToast } from 'primevue/usetoast'
import { openvpnApi, type OpenVPNClient } from '../api/openvpn'
import { req } from '../api/client'

type Item={id:string;name:string}
const toast=useToast()
type NodeItem=Item&{server_endpoint?:string|null;url?:string}
const nodes=ref<NodeItem[]>([]), users=ref<Item[]>([]), clients=ref<OpenVPNClient[]>([]), saving=ref(false), showWireGuardInfo=ref(false)
const server=reactive({node_id:'',endpoint:'',port:1194,protocol:'udp' as 'udp'|'tcp-server',network:'10.9.0.0/24'})
const client=reactive({user_id:'',node_id:'',name:'',traffic_gb:0,days:0})
const nodeName=(id:string)=>nodes.value.find(n=>n.id===id)?.name||id

async function load(){
  nodes.value=(await req<NodeItem[]>('GET','/nodes'))||[]
  users.value=((await req<any[]>('GET','/users'))||[]).map(u=>({id:u.id,name:u.name}))
  clients.value=(await openvpnApi.list())||[]
  if(!server.node_id&&nodes.value[0]) server.node_id=nodes.value[0].id
  if(!client.node_id&&nodes.value[0]) client.node_id=nodes.value[0].id
  if(!server.endpoint&&nodes.value[0]) server.endpoint=nodes.value[0].server_endpoint||nodes.value[0].url?.replace(/^https?:\/\//,'').split(':')[0]||''
}
async function configure(){saving.value=true;try{await openvpnApi.configure(server);toast.add({severity:'success',summary:'اینباند ذخیره شد',life:2500})}finally{saving.value=false}}
async function createClient(){
  saving.value=true
  try{
    await openvpnApi.create({user_id:client.user_id,node_id:client.node_id,name:client.name,traffic_gb:client.traffic_gb,days:client.days} as any)
    toast.add({severity:'success',summary:'کلاینت ساخته شد',life:2500})
    client.name=''; client.traffic_gb=0; client.days=0; await load()
  }finally{saving.value=false}
}
async function download(c:OpenVPNClient){const blob=await openvpnApi.download(c.id);if(!blob)return;const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=c.name+'.ovpn';a.click();URL.revokeObjectURL(url)}
async function copy(c:OpenVPNClient){const blob=await openvpnApi.download(c.id);if(!blob)return;const text=await blob.text();await navigator.clipboard.writeText(text);toast.add({severity:'success',summary:'کانفیگ کپی شد',life:2000})}
async function revoke(c:OpenVPNClient){if(!confirm('این کلاینت لغو شود؟'))return;await openvpnApi.revoke(c.id);await load()}
onMounted(load)
</script>

<style scoped>
.settings-card{display:grid;gap:1rem;margin-bottom:1rem;padding:1.2rem;border:1px solid var(--app-border-strong);border-radius:var(--app-radius-lg);background:var(--app-shell-solid);box-shadow:var(--app-shadow)}
.card-head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem}.card-head h3{margin:0 0 .25rem}.card-head p{margin:0;color:var(--app-text-soft);font-size:.82rem}
.form-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.85rem}.form-grid label{display:grid;gap:.4rem;font-size:.78rem;color:var(--app-text-muted);font-weight:800}.form-grid input,.form-grid select{width:100%;padding:.68rem;border:1px solid var(--app-border-strong);border-radius:10px;background:var(--app-surface-raised);color:var(--app-text)}
.protocol-actions,.actions{display:flex;gap:.55rem;flex-wrap:wrap}.client-row{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.85rem;border:1px solid var(--app-border);border-radius:12px}.client-row small{display:block;color:var(--app-text-soft);margin-top:.2rem}.empty,.info-box{padding:1rem;border:1px dashed var(--app-border);border-radius:12px;color:var(--app-text-muted)}
@media(max-width:850px){.form-grid{grid-template-columns:1fr 1fr}}@media(max-width:600px){.form-grid{grid-template-columns:1fr}.client-row{align-items:stretch;flex-direction:column}.actions>*{flex:1}}
</style>