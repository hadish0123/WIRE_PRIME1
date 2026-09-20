const base=(import.meta.env.VITE_API_BASE||"/api/v1").replace(/\/$/,"");
export async function api<T>(path:string,init:RequestInit={}):Promise<T>{
 const token=localStorage.getItem("primevpn_access");const headers=new Headers(init.headers);
 if(init.body)headers.set("Content-Type","application/json");if(token)headers.set("Authorization","Bearer "+token);
 const r=await fetch(base+path,{...init,headers});
 if(r.status===401){localStorage.removeItem("primevpn_access")}
 if(!r.ok){const e=await r.json().catch(()=>({detail:r.statusText}));throw new Error(e.detail||e.message||r.statusText)}
 return r.status===204?undefined as T:await r.json()
}
export const auth={
 login:(email:string,password:string)=>api<any>("/auth/login",{method:"POST",body:JSON.stringify({email,password})}),
 mfaVerify:(token:string,code:string)=>api<any>("/auth/mfa/verify?token="+encodeURIComponent(token)+"&code="+encodeURIComponent(code),{method:"POST"}),
 me:()=>api<any>("/auth/me")
};
export const nodes={
 list:()=>api<any[]>("/nodes"),
 create:(body:unknown)=>api<any>("/nodes",{method:"POST",body:JSON.stringify(body)}),
 autoProvision:(body:unknown)=>api<any>("/nodes/auto-provision",{method:"POST",body:JSON.stringify(body)}),
 provision:(id:string)=>api<any>("/nodes/"+id+"/provision",{method:"POST",headers:{"Idempotency-Key":crypto.randomUUID()}}),
 health:(id:string)=>api<any>("/nodes/"+id+"/health")
};
export const inbounds={
 list:()=>api<any[]>("/inbounds"),
 create:(body:unknown)=>api<any>("/inbounds",{method:"POST",body:JSON.stringify(body)}),
 update:(id:string,body:unknown)=>api<any>("/inbounds/"+id,{method:"PATCH",body:JSON.stringify(body)}),sync:(id:string)=>api<any>("/inbounds/"+id+"/sync",{method:"POST"}),remove:(id:string)=>api<any>("/inbounds/"+id,{method:"DELETE"})
};
export const clients={
 list:()=>api<any[]>("/clients"),
 create:(body:unknown)=>api<any>("/clients",{method:"POST",body:JSON.stringify(body)}),
 update:(id:string,body:unknown)=>api<any>("/clients/"+id,{method:"PATCH",body:JSON.stringify(body)}),
 devices:(id:string)=>api<any[]>("/clients/"+id+"/devices"),
 revoke:(id:string)=>api<any>("/clients/"+id+"/revoke",{method:"POST"}),
 credential:(id:string)=>api<any>("/credentials/"+id+"/credentials",{method:"POST"})
};
export const configs={download:(id:string)=>api<any>("/configs/"+id)};
export const traffic={summary:(days=7)=>api<any>("/traffic/summary?days="+days),breakdown:(days=7,params="")=>api<any>("/traffic/breakdown?days="+days+(params?"&"+params:"")),timeseries:(days=7)=>api<any[]>("/traffic/timeseries?days="+days),collect:()=>api<any>("/traffic/collect",{method:"POST"})};
export const quotas={
 state:(id:string)=>api<any>("/quotas/"+id+"/state"),
 get:(id:string)=>api<any>("/quotas/"+id),
 set:(body:unknown)=>api<any>("/quotas",{method:"POST",body:JSON.stringify(body)}),overview:()=>api<any[]>("/quotas/overview/all")
};
export const audit={list:()=>api<any[]>("/audit")};
export const admins={
 list:()=>api<any[]>("/admins"),
 permissions:()=>api<any>("/admins/permissions"),
 inbounds:()=>api<any[]>("/admins/inbounds"),myInbounds:()=>api<any[]>("/admins/my-inbounds"),
 create:(body:unknown)=>api<any>("/admins",{method:"POST",body:JSON.stringify(body)}),
 update:(id:string,body:unknown)=>api<any>("/admins/"+id,{method:"PATCH",body:JSON.stringify(body)}),
 disable:(id:string)=>api<any>("/admins/"+id,{method:"DELETE"})
};
