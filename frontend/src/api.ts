const base=(import.meta.env.VITE_API_BASE||"/api/v1").replace(/\/$/,"");
export async function api<T>(path:string,init:RequestInit={}):Promise<T>{const token=localStorage.getItem("primevpn_access");const headers=new Headers(init.headers);if(init.body)headers.set("Content-Type","application/json");if(token)headers.set("Authorization","Bearer "+token);const r=await fetch(base+path,{...init,headers});if(r.status===401){localStorage.removeItem("primevpn_access");window.location.reload()}if(!r.ok){const e=await r.json().catch(()=>({detail:r.statusText}));throw new Error(e.detail||e.message||r.statusText)}return r.status===204?undefined as T:await r.json()}
export const auth={login:(email:string,password:string)=>api<{access_token:string,expires_in:number}>("/auth/login",{method:"POST",body:JSON.stringify({email,password})}),me:()=>api<{id:string,email:string,tenant_id:string|null,role:string}>("/auth/me")};
export const nodes={list:()=>api<any[]>("/nodes"),create:(body:unknown)=>api("/nodes",{method:"POST",body:JSON.stringify(body)}),provision:(id:string)=>api("/nodes/"+id+"/provision",{method:"POST",headers:{"Idempotency-Key":crypto.randomUUID()}})};
export const inbounds={list:()=>api<any[]>("/inbounds"),create:(body:unknown)=>api("/inbounds",{method:"POST",body:JSON.stringify(body)})};
export const clients={list:()=>api<any[]>("/clients"),create:(body:unknown)=>api("/clients",{method:"POST",body:JSON.stringify(body)})};
export const traffic={summary:()=>api<any>("/traffic/summary")};
export const quotas={state:(id:string)=>api<any>("/quotas/"+id+"/state")};
export const audit={list:()=>api<any[]>("/audit")};
