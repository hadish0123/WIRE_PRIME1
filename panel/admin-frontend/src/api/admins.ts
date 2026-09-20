import { req } from './client'

export type Admin = {
  id: string
  username: string
  role: 'super_admin' | 'admin' | 'sub_admin'
  permissions: string[]
  node_ids: string[]
  is_active: boolean
  created_at: string
  last_login_at: string | null
}

export const adminsApi = {
  list: () => req<Admin[]>('GET', '/admins'),
  create: (body: { username: string; password: string; role: Admin['role']; permissions: string[]; node_ids: string[]; is_active: boolean }) =>
    req<Admin>('POST', '/admins', body),
  update: (id: string, body: Partial<{ password: string; role: Admin['role']; permissions: string[]; node_ids: string[]; is_active: boolean }>) =>
    req<Admin>('PATCH', '/admins/' + id, body),
  remove: (id: string) => req<null>('DELETE', '/admins/' + id),
}
