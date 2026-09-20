const base="/api/v1";
export async function api<T>(path:string,init:RequestInit={}):Promise<T>{const token=localStorage.getItem("primevpn_access");const headers=new Headers(init.headers);headers.set("Content-Type","application/json");if(token)headers.set("Authorization","Bearer "+token);const r=await fetch(base+path,{...init,headers});if(!r.ok)throw new Error((await r.json().catch(()=>({message:r.statusText}))).message);return r.json() as Promise<T>}
export const auth={login:(email:string,password:string)=>api<{access_token:string}>("/auth/login",{method:"POST",body:JSON.stringify({email,password})}),me:()=>api("/auth/me")};
export const nodes={list:()=>api("/nodes"),create:(body:unknown)=>api("/nodes",{method:"POST",body:JSON.stringify(body)})};
export const inbounds={list:()=>api("/inbounds"),create:(body:unknown)=>api("/inbounds",{method:"POST",body:JSON.stringify(body)})};
export const clients={list:()=>api("/clients"),create:(body:unknown)=>api("/clients",{method:"POST",body:JSON.stringify(body)})};
export const traffic={summary:()=>api("/traffic/summary")};