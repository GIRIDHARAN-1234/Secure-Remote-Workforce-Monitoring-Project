const AlertsPage = {
  currentSkip: 0,
  limit: 25,
  selectedAlertIds: new Set(),

  async load() {
    this.bindEvents();
    await this.fetchAlerts();
  },

  bindEvents() {
    const searchInput = document.getElementById('alerts-search');
    if (searchInput) {
      searchInput.oninput = this.debounce(() => {
        this.currentSkip = 0;
        this.fetchAlerts();
      }, 300);
    }

    ['alert-filter-status', 'alert-filter-severity', 'alert-filter-category'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.onchange = () => {
          this.currentSkip = 0;
          this.fetchAlerts();
        };
      }
    });

    const prevBtn = document.getElementById('alerts-prev');
    const nextBtn = document.getElementById('alerts-next');
    if (prevBtn) {
      prevBtn.onclick = () => {
        if (this.currentSkip >= this.limit) {
          this.currentSkip -= this.limit;
          this.fetchAlerts();
        }
      };
    }
    if (nextBtn) {
      nextBtn.onclick = () => {
        this.currentSkip += this.limit;
        this.fetchAlerts();
      };
    }

    // Select all checkbox
    const selectAll = document.getElementById('alerts-select-all');
    if (selectAll) {
      selectAll.onchange = (e) => {
        const checked = e.target.checked;
        document.querySelectorAll('.alert-row-checkbox').forEach(cb => {
          cb.checked = checked;
          const id = cb.getAttribute('data-id');
          if (checked) this.selectedAlertIds.add(id);
          else this.selectedAlertIds.delete(id);
        });
        this.updateBulkButtonState();
      };
    }

    // Bulk update button
    const bulkBtn = document.getElementById('btn-alerts-bulk-update');
    if (bulkBtn) {
      bulkBtn.onclick = async () => {
        const targetStatus = document.getElementById('alerts-bulk-status-select').value;
        if (this.selectedAlertIds.size === 0) {
          showToast('No alerts selected.', 'warning');
          return;
        }

        try {
          const res = await api.post('/alerts/bulk-update', {
            alert_ids: Array.from(this.selectedAlertIds),
            status: targetStatus
          });
          showToast(res.message, 'success');
          this.selectedAlertIds.clear();
          await this.fetchAlerts();
        } catch (err) {
          showToast(err.message, 'error');
        }
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

  updateBulkButtonState() {
    const btn = document.getElementById('btn-alerts-bulk-update');
    const countDisplay = document.getElementById('alerts-selected-count');
    if (countDisplay) countDisplay.textContent = this.selectedAlertIds.size;
    if (btn) btn.disabled = this.selectedAlertIds.size === 0;
  },

  async fetchAlerts() {
    const search = document.getElementById('alerts-search')?.value.trim() || '';
    const status = document.getElementById('alert-filter-status')?.value || '';
    const severity = document.getElementById('alert-filter-severity')?.value || '';
    const category = document.getElementById('alert-filter-category')?.value || '';

    const params = new URLSearchParams({
      skip: this.currentSkip,
      limit: this.limit
    });

    if (search) params.append('search', search);
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);
    if (category) params.append('category', category);

    const res = await api.get(`/alerts/?${params.toString()}`);
    this.renderAlerts(res);
  },

  renderAlerts(data) {
    const tbody = document.getElementById('alerts-table-body');
    if (!tbody) return;

    document.getElementById('alerts-pagination-info').textContent =
      `Showing ${data.skip + 1}–${Math.min(data.skip + data.limit, data.total)} of ${data.total} alerts`;

    document.getElementById('alerts-prev').disabled = data.skip === 0;
    document.getElementById('alerts-next').disabled = data.skip + data.limit >= data.total;

    if (data.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center py-8 text-slate-400">No security alerts matching criteria.</td></tr>`;
      return;
    }

    const canEdit = state.isAnalystOrAdmin();

    tbody.innerHTML = data.items.map(a => `
      <tr class="border-b border-slate-800/60 hover:bg-slate-800/40 transition">
        <td class="py-3 px-3">
          <input type="checkbox" class="alert-row-checkbox rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0" data-id="${a.id}" ${this.selectedAlertIds.has(a.id) ? 'checked' : ''} onchange="AlertsPage.toggleRowCheck('${a.id}', this.checked)">
        </td>
        <td class="py-3 px-3 font-mono font-semibold text-cyan-400 text-xs">${a.id}</td>
        <td class="py-3 px-3">
          <span class="px-2 py-0.5 text-xs font-bold rounded ${
            a.severity === 'critical' ? 'badge-critical' :
            a.severity === 'high' ? 'badge-high' :
            a.severity === 'medium' ? 'badge-medium' : 'badge-low'
          }">${a.severity.toUpperCase()}</span>
        </td>
        <td class="py-3 px-3">
          <div class="font-medium text-slate-200">${a.title}</div>
          <div class="text-xs text-slate-400 mt-0.5">${a.description}</div>
          ${a.mitre_technique ? `
            <span class="inline-block mt-1 px-2 py-0.5 text-[10px] font-mono bg-purple-950/60 text-purple-300 border border-purple-800/40 rounded">
              MITRE: ${a.mitre_technique}
            </span>
          ` : ''}
        </td>
        <td class="py-3 px-3 font-mono text-xs">
          <a href="#" class="text-cyan-400 hover:underline" onclick="event.preventDefault(); DevicesPage.openDrawer('${a.device_id}')">
            ${a.device_id || 'N/A'}
          </a>
        </td>
        <td class="py-3 px-3">
          <span class="px-2 py-0.5 text-xs font-semibold rounded ${
            a.status === 'Open' ? 'bg-rose-950/60 text-rose-300 border border-rose-800/40' :
            a.status === 'Investigating' ? 'bg-amber-950/60 text-amber-300 border border-amber-800/40' :
            a.status === 'Acknowledged' ? 'bg-blue-950/60 text-blue-300 border border-blue-800/40' :
            'bg-emerald-950/60 text-emerald-300 border border-emerald-800/40'
          }">${a.status}</span>
        </td>
        <td class="py-3 px-3 text-right">
          ${canEdit ? `
            <select class="text-xs bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-300 focus:outline-none" onchange="AlertsPage.updateStatus('${a.id}', this.value)">
              <option value="Open" ${a.status === 'Open' ? 'selected' : ''}>Open</option>
              <option value="Acknowledged" ${a.status === 'Acknowledged' ? 'selected' : ''}>Acknowledged</option>
              <option value="Investigating" ${a.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
              <option value="Resolved" ${a.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
              <option value="False Positive" ${a.status === 'False Positive' ? 'selected' : ''}>False Positive</option>
            </select>
          ` : `
            <span class="text-xs text-slate-500 font-mono">Read Only</span>
          `}
        </td>
      </tr>
    `).join('');
  },

  toggleRowCheck(id, isChecked) {
    if (isChecked) this.selectedAlertIds.add(id);
    else this.selectedAlertIds.delete(id);
    this.updateBulkButtonState();
  },

  async updateStatus(alertId, newStatus) {
    try {
      await api.patch(`/alerts/${alertId}`, { status: newStatus });
      showToast(`Alert ${alertId} updated to ${newStatus}`, 'success');
      await this.fetchAlerts();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }
};

window.AlertsPage = AlertsPage;
