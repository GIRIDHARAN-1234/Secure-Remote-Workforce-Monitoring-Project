const AuditPage = {
  currentSkip: 0,
  limit: 30,

  async load() {
    this.bindEvents();
    await this.fetchLogs();
  },

  bindEvents() {
    const searchInput = document.getElementById('audit-search');
    if (searchInput) {
      searchInput.oninput = this.debounce(() => {
        this.currentSkip = 0;
        this.fetchLogs();
      }, 300);
    }

    const actionSelect = document.getElementById('audit-filter-action');
    if (actionSelect) {
      actionSelect.onchange = () => {
        this.currentSkip = 0;
        this.fetchLogs();
      };
    }

    const prevBtn = document.getElementById('audit-prev');
    const nextBtn = document.getElementById('audit-next');
    if (prevBtn) {
      prevBtn.onclick = () => {
        if (this.currentSkip >= this.limit) {
          this.currentSkip -= this.limit;
          this.fetchLogs();
        }
      };
    }
    if (nextBtn) {
      nextBtn.onclick = () => {
        this.currentSkip += this.limit;
        this.fetchLogs();
      };
    }
  },

  debounce(func, wait) {
    let timeout;
    return (...args) => {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  },

  async fetchLogs() {
    const search = document.getElementById('audit-search')?.value.trim() || '';
    const action = document.getElementById('audit-filter-action')?.value || '';

    const params = new URLSearchParams({
      skip: this.currentSkip,
      limit: this.limit
    });
    if (search) params.append('search', search);
    if (action) params.append('action', action);

    const res = await api.get(`/audit/?${params.toString()}`);
    this.renderLogs(res);
  },

  renderLogs(data) {
    const tbody = document.getElementById('audit-table-body');
    if (!tbody) return;

    document.getElementById('audit-pagination-info').textContent =
      `Showing ${data.skip + 1}–${Math.min(data.skip + data.limit, data.total)} of ${data.total} audit events`;

    document.getElementById('audit-prev').disabled = data.skip === 0;
    document.getElementById('audit-next').disabled = data.skip + data.limit >= data.total;

    if (data.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-center py-8 text-slate-400">No matching audit logs found.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.items.map(l => `
      <tr class="border-b border-slate-800/60 hover:bg-slate-800/40 transition text-xs">
        <td class="py-3 px-3 font-mono text-slate-400 whitespace-nowrap">
          ${new Date(l.timestamp).toLocaleString()}
        </td>
        <td class="py-3 px-3">
          <span class="px-2 py-0.5 font-mono font-bold rounded ${
            l.action.includes('FAILED') ? 'bg-rose-950/80 text-rose-300 border border-rose-800/50' :
            l.action.includes('REMEDIATION') ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/50' :
            l.action.includes('LOGIN') ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/50' :
            'bg-slate-800 text-slate-300'
          }">${l.action}</span>
        </td>
        <td class="py-3 px-3 font-medium text-slate-200">${l.user_email}</td>
        <td class="py-3 px-3 font-mono text-slate-400">${l.ip_address}</td>
        <td class="py-3 px-3 text-slate-300 max-w-md break-words">${l.details}</td>
      </tr>
    `).join('');
  }
};

window.AuditPage = AuditPage;
