const UsersPage = {
  async load() {
    await this.fetchUsers();
  },

  async fetchUsers() {
    const list = await api.get('/users/');
    const tbody = document.getElementById('users-table-body');
    if (!tbody) return;

    tbody.innerHTML = list.map(u => `
      <tr class="border-b border-slate-800/60 hover:bg-slate-800/40 transition">
        <td class="py-3 px-3 font-mono text-cyan-400 font-bold">${u.id}</td>
        <td class="py-3 px-3">
          <div class="font-medium text-slate-200">${u.full_name}</div>
          <div class="text-xs text-slate-400">${u.email}</div>
        </td>
        <td class="py-3 px-3">
          <select class="text-xs bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200 focus:outline-none" onchange="UsersPage.updateRole(${u.id}, this.value)">
            <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option>
            <option value="analyst" ${u.role === 'analyst' ? 'selected' : ''}>Analyst</option>
            <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>Viewer</option>
          </select>
        </td>
        <td class="py-3 px-3">
          <span class="px-2 py-0.5 text-xs font-semibold rounded ${
            u.is_active ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/40' : 'bg-slate-800 text-slate-400'
          }">${u.is_active ? 'Active' : 'Deactivated'}</span>
        </td>
        <td class="py-3 px-3">
          ${u.is_locked ? `
            <span class="px-2 py-0.5 text-xs font-bold rounded bg-rose-950 text-rose-300 border border-rose-800">
              LOCKED 🔒
            </span>
          ` : `
            <span class="text-xs text-slate-400 font-mono">Normal</span>
          `}
        </td>
        <td class="py-3 px-3 text-right space-x-2">
          ${u.is_locked ? `
            <button class="px-2.5 py-1 text-xs bg-amber-600 hover:bg-amber-500 text-white rounded font-medium" onclick="UsersPage.unlockUser(${u.id})">
              Unlock
            </button>
          ` : ''}
          <button class="px-2.5 py-1 text-xs ${
            u.is_active ? 'bg-rose-900/40 hover:bg-rose-800/60 text-rose-300 border border-rose-700/50' : 'bg-emerald-900/40 hover:bg-emerald-800/60 text-emerald-300 border border-emerald-700/50'
          } rounded" onclick="UsersPage.toggleActive(${u.id}, ${!u.is_active})">
            ${u.is_active ? 'Deactivate' : 'Activate'}
          </button>
        </td>
      </tr>
    `).join('');
  },

  async updateRole(userId, newRole) {
    try {
      await api.patch(`/users/${userId}/role`, { role: newRole });
      showToast('User role updated.', 'success');
      await this.fetchUsers();
    } catch (err) {
      showToast(err.message, 'error');
    }
  },

  async toggleActive(userId, newActive) {
    try {
      await api.patch(`/users/${userId}/status`, { is_active: newActive });
      showToast(`User status toggled to ${newActive ? 'active' : 'deactivated'}.`, 'success');
      await this.fetchUsers();
    } catch (err) {
      showToast(err.message, 'error');
    }
  },

  async unlockUser(userId) {
    try {
      await api.post(`/users/${userId}/unlock`, {});
      showToast('User account unlocked.', 'success');
      await this.fetchUsers();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }
};

window.UsersPage = UsersPage;
