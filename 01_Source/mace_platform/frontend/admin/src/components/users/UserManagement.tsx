import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { adminApi } from '@/lib/api'
import { Modal, FormField, Spinner, Table, Tr, Td, Badge, SectionHeader } from '@/components/ui'
import { roleColor, fmtAgo } from '@/lib/utils'
import type { User } from '@/types'

const ROLES = ['tenant_admin','soc_analyst','read_only','api_user']

export function UserManagement() {
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [editUser, setEditUser] = useState<User|null>(null)
  const [form, setForm] = useState({ email:'', full_name:'', role:'soc_analyst', password:'' })
  const [editForm, setEditForm] = useState({ role:'', is_active:true })

  const { data, isLoading } = useQuery<{users:User[]}>({
    queryKey: ['users'],
    queryFn: () => adminApi.users().then(r => r.data)
  })

  const create = useMutation({
    mutationFn: () => adminApi.createUser(form as Record<string,unknown>),
    onSuccess: () => { qc.invalidateQueries({queryKey:['users']}); setCreating(false); setForm({email:'',full_name:'',role:'soc_analyst',password:''}) }
  })

  const update = useMutation({
    mutationFn: (id: string) => adminApi.updateUser(id, editForm as Record<string,unknown>),
    onSuccess: () => { qc.invalidateQueries({queryKey:['users']}); setEditUser(null) }
  })

  const openEdit = (u: User) => { setEditUser(u); setEditForm({ role: u.role, is_active: u.is_active }) }

  return (
    <div className="animate-fade-in">
      <SectionHeader title={`Users (${data?.users.length || 0})`} action={
        <button className="adm-btn-primary" onClick={() => setCreating(true)}>+ Add User</button>
      }/>

      {isLoading ? <div className="flex justify-center py-12"><Spinner /></div> : (
        <Table headers={['User','Role','Status','MFA','Last Login','']}>
          {data?.users.map(u => (
            <Tr key={u.id} onClick={() => openEdit(u)}>
              <Td>
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
                    {(u.full_name || u.email)[0].toUpperCase()}
                  </div>
                  <div>
                    <div className="text-sm text-white font-medium">{u.full_name || '—'}</div>
                    <div className="text-xs text-adm-muted">{u.email}</div>
                  </div>
                </div>
              </Td>
              <Td><Badge className={roleColor(u.role)}>{u.role.replace('_',' ')}</Badge></Td>
              <Td>
                <span className={`text-xs px-2 py-0.5 rounded border font-mono ${u.is_active ? 'text-green-400 bg-green-500/10 border-green-500/25' : 'text-red-400 bg-red-500/10 border-red-500/25'}`}>
                  {u.is_active ? 'Active' : 'Disabled'}
                </span>
              </Td>
              <Td><span className={`text-xs ${u.mfa_enabled ? 'text-green-400' : 'text-adm-muted'}`}>{u.mfa_enabled ? '✓ On' : 'Off'}</span></Td>
              <Td><span className="text-xs text-adm-muted">{fmtAgo(u.last_login_at)}</span></Td>
              <Td><span className="text-xs text-indigo-400 hover:text-indigo-300">Edit →</span></Td>
            </Tr>
          ))}
        </Table>
      )}

      {/* Create user modal */}
      {creating && (
        <Modal title="Add User" onClose={() => setCreating(false)}>
          <div className="space-y-4">
            <FormField label="Full Name">
              <input className="adm-input" value={form.full_name} onChange={e => setForm({...form,full_name:e.target.value})} placeholder="Jane Smith" />
            </FormField>
            <FormField label="Email">
              <input type="email" className="adm-input" value={form.email} onChange={e => setForm({...form,email:e.target.value})} placeholder="jane@company.com" />
            </FormField>
            <FormField label="Password">
              <input type="password" className="adm-input" value={form.password} onChange={e => setForm({...form,password:e.target.value})} placeholder="Temporary password" />
            </FormField>
            <FormField label="Role">
              <select className="adm-input" value={form.role} onChange={e => setForm({...form,role:e.target.value})}>
                {ROLES.map(r => <option key={r} value={r}>{r.replace('_',' ')}</option>)}
              </select>
            </FormField>
            <div className="flex justify-end gap-3 pt-2">
              <button className="adm-btn-ghost" onClick={() => setCreating(false)}>Cancel</button>
              <button className="adm-btn-primary" onClick={() => create.mutate()} disabled={!form.email || !form.password || create.isPending}>
                {create.isPending ? <Spinner size={14} /> : 'Create User'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Edit user modal */}
      {editUser && (
        <Modal title={`Edit: ${editUser.email}`} onClose={() => setEditUser(null)}>
          <div className="space-y-4">
            <FormField label="Role">
              <select className="adm-input" value={editForm.role} onChange={e => setEditForm({...editForm,role:e.target.value})}>
                {ROLES.map(r => <option key={r} value={r}>{r.replace('_',' ')}</option>)}
              </select>
            </FormField>
            <FormField label="Account Status">
              <select className="adm-input" value={editForm.is_active ? 'active' : 'disabled'} onChange={e => setEditForm({...editForm,is_active:e.target.value==='active'})}>
                <option value="active">Active</option>
                <option value="disabled">Disabled</option>
              </select>
            </FormField>
            <div className="flex justify-end gap-3 pt-2">
              <button className="adm-btn-ghost" onClick={() => setEditUser(null)}>Cancel</button>
              <button className="adm-btn-primary" onClick={() => update.mutate(editUser.id)} disabled={update.isPending}>
                {update.isPending ? <Spinner size={14} /> : 'Save'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
