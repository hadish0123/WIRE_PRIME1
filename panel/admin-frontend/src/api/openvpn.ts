import { req, reqBlob } from './client'
export type OpenVPNClient = { id:string; user_id:string; node_id:string; name:string; status:string; created_at:string }
export const openvpnApi = {
  status: (nodeId:string) => req<{status:string;configured:boolean}>('GET', '/openvpn/nodes/'+nodeId+'/status'),
  configure: (body:{node_id:string;endpoint:string;port:number;protocol:'udp'|'tcp-server';network:string}) => req('PUT','/openvpn/server',body),
  create: (body:{user_id:string;node_id:string;name:string}) => req('POST','/openvpn/clients',body),
  list: () => req<OpenVPNClient[]>('GET','/openvpn/clients'),
  download: (id:string) => reqBlob('/openvpn/clients/'+id+'/config'),
  revoke: (id:string) => req<null>('DELETE','/openvpn/clients/'+id),
}
