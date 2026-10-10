const DevicesPage = {
  currentSkip: 0,
  limit: 25,
  currentDrawerDeviceId: null,
  currentPreset: 'all',

  async load() {
    this.bindFilters();
    await this.fetchDevices();
  },

  bindFilters() {
    // 1-Click Preset Filter Chips
    document.querySelectorAll('.preset-btn').forEach(btn => {
      btn.onclick = () => {
        const preset = btn.getAttribute('data-preset');
        this.setPreset(preset);
      };
    });

    const searchInput = document.getElementById('devices-search');
    if (searchInput) {
      searchInput.oninput = this.debounce(() => {
        this.currentSkip = 0;
        this.fetchDevices();
      }, 300);
    }

    ['filter-status', 'filter-risk', 'filter-dept', 'filter-os', 'filter-network', 'filter-ownership'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.onchange = () => {
          this.currentSkip = 0;
          this.fetchDevices();
        };
      }
    });

    const prevBtn = document.getElementById('devices-prev');
    const nextBtn = document.getElementById('devices-next');
    if (prevBtn) {
      prevBtn.onclick = () => {
        if (this.currentSkip >= this.limit) {
          this.currentSkip -= this.limit;
          this.fetchDevices();
        }
      };
    }
    if (nextBtn) {
      nextBtn.onclick = () => {
        this.currentSkip += this.limit;
        this.fetchDevices();
      };
    }
  },

  setPreset(preset) {
    this.currentPreset = preset;
    this.currentSkip = 0;

    // Update active chip styling
    document.querySelectorAll('.preset-btn').forEach(btn => {
      const p = btn.getAttribute('data-preset');
      if (p === preset) {
        btn.className = 'preset-btn px-3 py-1.5 rounded-lg font-semibold transition bg-cyan-950 border border-cyan-500/60 text-cyan-300 shadow-md ring-1 ring-cyan-500/30';
      } else {
        btn.className = 'preset-btn px-3 py-1.5 rounded-lg font-semibold transition bg-slate-900/90 hover:bg-slate-800 border border-slate-700 text-slate-300';
      }
    });

    // Reset or preset specific dropdown values for clarity
    const statusSelect = document.getElementById('filter-status');
    const riskSelect = document.getElementById('filter-risk');
    const netSelect = document.getElementById('filter-network');

    if (preset === 'all') {
      if (statusSelect) statusSelect.value = '';
      if (riskSelect) riskSelect.value = '';
      if (netSelect) netSelect.value = '';
    } else if (preset === 'critical-risk') {
      if (riskSelect) riskSelect.value = 'Critical';
    } else if (preset === 'compliant') {
      if (statusSelect) statusSelect.value = 'Compliant';
    } else if (preset === 'public-wifi') {
      if (netSelect) netSelect.value = 'public_wifi';
    }

    this.fetchDevices();
  },

  debounce(func, wait) {
    let timeout;
    return (...args) => {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  },

  async fetchDevices() {
    const search = document.getElementById('devices-search')?.value.trim() || '';
    const status = document.getElementById('filter-status')?.value || '';
    const risk = document.getElementById('filter-risk')?.value || '';
    const dept = document.getElementById('filter-dept')?.value || '';
    const os = document.getElementById('filter-os')?.value || '';
    const net = document.getElementById('filter-network')?.value || '';
    const ownership = document.getElementById('filter-ownership')?.value || '';

    const params = new URLSearchParams({
      skip: this.currentSkip,
      limit: this.limit,
      sort_by: 'risk_score',
      order: 'desc'
    });

    if (search) params.append('search', search);
    if (status) params.append('status', status);
    if (risk) params.append('risk_level', risk);
    if (dept) params.append('department', dept);
    if (os) params.append('os_name', os);
    if (net) params.append('network_type', net);
    if (ownership) params.append('ownership', ownership);

    // Apply preset specific filters
    if (this.currentPreset === 'missing-av') {
      params.append('antivirus_enabled', 'false');
    } else if (this.currentPreset === 'unencrypted') {
      params.append('disk_encryption', 'false');
    }

    const res = await api.get(`/devices/?${params.toString()}`);
    this.renderTable(res);
  },

  renderTable(data) {
    const tbody = document.getElementById('devices-table-body');
    if (!tbody) return;

    document.getElementById('devices-pagination-info').textContent =
      `Showing ${data.skip + 1}–${Math.min(data.skip + data.limit, data.total)} of ${data.total} devices`;

    document.getElementById('devices-prev').disabled = data.skip === 0;
    document.getElementById('devices-next').disabled = data.skip + data.limit >= data.total;

    if (data.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-slate-400">No matching endpoints found.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.items.map(d => `
      <tr class="border-b border-slate-800/60 hover:bg-slate-800/40 transition cursor-pointer" onclick="DevicesPage.openDrawer('${d.device_id}')">
        <td class="py-3 px-3 font-mono font-semibold text-cyan-400">${d.device_id}</td>
        <td class="py-3 px-3">
          <div class="font-medium text-slate-200">${d.hostname}</div>
          <div class="text-xs text-slate-400">${d.owner_name} (${d.department})</div>
        </td>
        <td class="py-3 px-3">
          <span class="px-2 py-0.5 text-xs font-semibold rounded ${
            d.ownership === 'BYOD' ? 'bg-amber-950/60 text-amber-300 border border-amber-800/50' : 'bg-slate-800 text-slate-300'
          }">${d.ownership.toUpperCase()}</span>
          <span class="text-xs text-slate-400 ml-1">${d.os_name}</span>
        </td>
        <td class="py-3 px-3">
          <span class="px-2 py-0.5 text-xs font-semibold rounded ${
            d.compliance_status === 'Compliant' ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/40' :
            d.compliance_status === 'At Risk' ? 'bg-amber-950/60 text-amber-300 border border-amber-800/40' :
            'bg-rose-950/60 text-rose-300 border border-rose-800/40'
          }">${d.compliance_percentage}% (${d.compliance_status})</span>
        </td>
        <td class="py-3 px-3">
          <span class="px-2.5 py-0.5 text-xs font-bold rounded ${
            d.risk_level === 'Critical' ? 'badge-critical' :
            d.risk_level === 'High' ? 'badge-high' :
            d.risk_level === 'Medium' ? 'badge-medium' : 'badge-low'
          }">${d.risk_score} (${d.risk_level})</span>
        </td>
        <td class="py-3 px-3 text-xs text-slate-300">
          <div>${d.network_type.replace('_', ' ')}</div>
          <div class="text-slate-500">${d.wifi_security} ${d.vpn_connected ? '• VPN' : ''}</div>
        </td>
        <td class="py-3 px-3">
          <span class="px-2 py-0.5 text-xs font-semibold rounded ${
            d.ztna_decision === 'ALLOW' ? 'badge-allow' :
            d.ztna_decision === 'ALLOW_WITH_STEP_UP_MFA' ? 'badge-step-up' :
            d.ztna_decision === 'RESTRICT' ? 'badge-restrict' : 'badge-block'
          }">${d.ztna_decision}</span>
        </td>
        <td class="py-3 px-3 text-right" onclick="event.stopPropagation()">
          <button class="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded border border-slate-700" onclick="DevicesPage.openDrawer('${d.device_id}')">
            Drawer ➔
          </button>
        </td>
      </tr>
    `).join('');
  },

  async openDrawer(deviceId) {
    this.currentDrawerDeviceId = deviceId;
    const drawer = document.getElementById('device-drawer');
    if (!drawer) return;
    drawer.classList.remove('hidden');

    const content = document.getElementById('device-drawer-content');
    content.innerHTML = `<div class="p-8 text-center text-slate-400 animate-pulse">Loading telemetry specs...</div>`;

    try {
      const d = await api.get(`/devices/${deviceId}`);
      this.renderDrawerContent(d);
    } catch (err) {
      showToast('Error loading device details: ' + err.message, 'error');
    }
  },

  closeDrawer() {
    const drawer = document.getElementById('device-drawer');
    if (drawer) drawer.classList.add('hidden');
    this.currentDrawerDeviceId = null;
  },

  renderDrawerContent(d) {
    const content = document.getElementById('device-drawer-content');
    if (!content) return;

    const breakdown = d.score_breakdown ? JSON.parse(d.score_breakdown) : {};
    const waterfall = breakdown.waterfall || [];

    const isAdmin = state.isAdmin();

    content.innerHTML = `
      <div class="p-6 space-y-6">
        <!-- Header -->
        <div class="flex items-start justify-between border-b border-slate-800 pb-4">
          <div>
            <div class="flex items-center gap-2">
              <h2 class="text-xl font-bold text-white font-mono">${d.hostname}</h2>
              <span class="px-2 py-0.5 text-xs font-mono font-semibold text-cyan-400 bg-cyan-950/60 border border-cyan-800/40 rounded">${d.device_id}</span>
            </div>
            <p class="text-sm text-slate-400 mt-1">${d.owner_name} &bull; ${d.owner_email} &bull; <span class="text-slate-300 font-medium">${d.department} (${d.role_level})</span></p>
          </div>
          <div class="text-right">
            <span class="px-3 py-1 text-sm font-bold rounded ${
              d.risk_level === 'Critical' ? 'badge-critical' :
              d.risk_level === 'High' ? 'badge-high' :
              d.risk_level === 'Medium' ? 'badge-medium' : 'badge-low'
            }">${d.risk_score} / 100 (${d.risk_level} Risk)</span>
            <div class="text-xs text-slate-400 mt-1">Compliance: <span class="font-bold text-slate-200">${d.compliance_percentage}%</span></div>
          </div>
        </div>

        <!-- ZTNA Access Decision Box -->
        <div class="p-4 rounded-lg border ${
          d.ztna_decision === 'ALLOW' ? 'border-emerald-500/40 bg-emerald-950/20' :
          d.ztna_decision === 'ALLOW_WITH_STEP_UP_MFA' ? 'border-amber-500/40 bg-amber-950/20' :
          d.ztna_decision === 'RESTRICT' ? 'border-orange-500/40 bg-orange-950/20' :
          'border-rose-500/50 bg-rose-950/30'
        }">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold uppercase tracking-wider text-slate-400">Zero Trust Access Decision (ZTNA)</span>
            <span class="px-2.5 py-0.5 text-xs font-bold rounded ${
              d.ztna_decision === 'ALLOW' ? 'badge-allow' :
              d.ztna_decision === 'ALLOW_WITH_STEP_UP_MFA' ? 'badge-step-up' :
              d.ztna_decision === 'RESTRICT' ? 'badge-restrict' : 'badge-block'
            }">${d.ztna_decision}</span>
          </div>
          <p class="text-sm text-slate-200 mt-2">${d.ztna_explanation?.reason || 'Baseline evaluation completed.'}</p>
        </div>

        <!-- Telemetry Specs Grid -->
        <div>
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">Endpoint Telemetry Attributes</h3>
          <div class="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
            <div class="p-2.5 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">OS Version</span>
              <span class="font-medium text-slate-200">${d.os_version}</span>
            </div>
            <div class="p-2.5 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">Patch Status</span>
              <span class="font-medium ${d.days_since_patch > 30 ? 'text-amber-400 font-bold' : 'text-slate-200'}">
                ${d.days_since_patch} days ago (${d.pending_critical_patches} pending crit)
              </span>
            </div>
            <div class="p-2.5 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">Disk Encryption</span>
              <span class="font-medium ${d.disk_encryption ? 'text-emerald-400' : 'text-rose-400 font-bold'}">
                ${d.disk_encryption ? 'Active (BitLocker/FV)' : 'Disabled ⚠'}
              </span>
            </div>
            <div class="p-2.5 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">EDR Agent</span>
              <span class="font-medium ${d.edr_agent_running ? 'text-emerald-400' : 'text-rose-400 font-bold'}">
                ${d.edr_agent_running ? 'Running & Healthy' : 'Offline / Stopped ⚠'}
              </span>
            </div>
            <div class="p-2.5 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">Antivirus & Sig Age</span>
              <span class="font-medium ${d.antivirus_enabled ? 'text-slate-200' : 'text-rose-400 font-bold'}">
                ${d.antivirus_enabled ? `Active (${d.antivirus_signature_age_days}d old)` : 'Disabled ⚠'}
              </span>
            </div>
            <div class="p-2.5 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">TPM & Secure Boot</span>
              <span class="font-medium ${d.tpm_present && d.secure_boot ? 'text-emerald-400' : 'text-amber-400'}">
                ${d.tpm_present && d.secure_boot ? 'TPM 2.0 + Secure Boot' : 'Missing Hardware Root'}
              </span>
            </div>
            <div class="p-2.5 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">Root / Jailbreak</span>
              <span class="font-medium ${d.jailbroken_or_rooted ? 'text-rose-400 font-bold' : 'text-emerald-400'}">
                ${d.jailbroken_or_rooted ? 'COMPROMISED / ROOTED 🚨' : 'Intact Kernel'}
              </span>
            </div>
            <div class="p-2.5 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">Network & Wi-Fi</span>
              <span class="font-medium text-slate-200">
                ${d.network_type} &bull; ${d.wifi_security} ${d.vpn_connected ? '(VPN Active)' : '(No VPN)'}
              </span>
            </div>
            <div class="p-2.5 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">User Access Context</span>
              <span class="font-medium text-slate-200">
                MFA: ${d.mfa_enabled ? 'Enforced' : 'Missing'} &bull; ${d.access_sensitivity} data
              </span>
            </div>
          </div>
        </div>

        <!-- "Why This Score?" Risk Waterfall -->
        <div>
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Explainable Risk Score Breakdown</h3>
          <div class="space-y-2 p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-xs">
            ${waterfall.map(w => `
              <div class="flex items-center justify-between">
                <span class="text-slate-300">${w.name}</span>
                <span class="font-mono font-bold ${w.value > 15 ? 'text-rose-400' : w.value > 5 ? 'text-amber-400' : 'text-slate-400'}">
                  +${w.value} pts
                </span>
              </div>
              ${w.details && w.details.length > 0 ? `
                <div class="text-[11px] text-rose-300/80 pl-2 border-l border-rose-500/40">
                  ${w.details.join('<br>')}
                </div>
              ` : ''}
            `).join('')}
          </div>
        </div>

        <!-- Policy Pass / Fail Checklist -->
        <div>
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Policy Compliance Checklist</h3>
          <div class="space-y-2 max-h-48 overflow-y-auto pr-1 text-xs">
            ${d.failed_policy_details.map(p => `
              <div class="p-2 rounded bg-rose-950/20 border border-rose-900/40 flex items-start gap-2">
                <span class="text-rose-400 font-bold">✕</span>
                <div>
                  <span class="font-mono font-bold text-rose-300">${p.id}</span>: <span class="text-slate-200">${p.name}</span>
                  <p class="text-slate-400 text-[11px] mt-0.5">${p.description}</p>
                </div>
              </div>
            `).join('')}
            ${d.passed_policy_details.map(p => `
              <div class="p-2 rounded bg-slate-900/40 border border-slate-800 flex items-start gap-2">
                <span class="text-emerald-400 font-bold">✓</span>
                <div>
                  <span class="font-mono text-slate-400">${p.id}</span>: <span class="text-slate-300">${p.name}</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Remediation Plan & Apply Fix Button -->
        <div class="pt-2 border-t border-slate-800">
          <div class="flex items-center justify-between mb-3">
            <div>
              <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400">Corrective Action Plan</h3>
              <p class="text-xs text-slate-400">Projected risk after fix: <span class="font-bold text-emerald-400">${d.projected_risk_score}</span></p>
            </div>
            ${isAdmin && d.remediation_recommendations.length > 0 ? `
              <button id="btn-apply-drawer-remediation" class="px-3 py-1.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold text-xs rounded-lg shadow-lg shadow-emerald-950/50 transition">
                ⚡ Apply All Fixes Now
              </button>
            ` : ''}
          </div>
          <div class="space-y-2 text-xs">
            ${d.remediation_recommendations.map(r => `
              <div class="p-2.5 rounded bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                <div>
                  <div class="font-semibold text-slate-200">${r.title}</div>
                  <div class="text-[11px] text-slate-400">${r.action} &bull; Effort: ${r.estimated_effort}</div>
                </div>
                <span class="font-bold text-emerald-400 font-mono">-${r.risk_reduction_points} pts</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;

    const remBtn = document.getElementById('btn-apply-drawer-remediation');
    if (remBtn) {
      remBtn.onclick = async () => {
        remBtn.disabled = true;
        remBtn.innerHTML = `Applying fixes...`;
        try {
          const res = await api.post(`/devices/${d.device_id}/remediate`, {});
          showToast(res.message, 'success');
          // Reload drawer
          await this.openDrawer(d.device_id);
          // Reload background table & dashboard
          await this.fetchDevices();
        } catch (err) {
          showToast(err.message, 'error');
        }
      };
    }
  }
};

window.DevicesPage = DevicesPage;
