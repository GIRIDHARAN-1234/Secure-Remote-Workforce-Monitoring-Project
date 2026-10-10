const PoliciesPage = {
  policies: [],

  async load() {
    this.bindEvents();
    await this.fetchPolicies();
  },

  bindEvents() {
    const reevaluateBtn = document.getElementById('btn-policies-reevaluate');
    if (reevaluateBtn) {
      reevaluateBtn.onclick = async () => {
        reevaluateBtn.disabled = true;
        reevaluateBtn.innerHTML = `Re-evaluating Fleet...`;
        try {
          const res = await api.post('/policies/reevaluate', {});
          showToast(res.message, 'success');
        } catch (err) {
          showToast(err.message, 'error');
        } finally {
          reevaluateBtn.disabled = false;
          reevaluateBtn.innerHTML = `⚡ Re-evaluate Fleet`;
        }
      };
    }

    const resetBtn = document.getElementById('btn-policies-reset');
    if (resetBtn) {
      resetBtn.onclick = async () => {
        if (!confirm('Are you sure you want to reset all policies to default values?')) return;
        try {
          const res = await api.post('/policies/reset-defaults', {});
          showToast(res.message, 'success');
          await this.fetchPolicies();
        } catch (err) {
          showToast(err.message, 'error');
        }
      };
    }
  },

  async fetchPolicies() {
    this.policies = await api.get('/policies/');
    this.renderPolicies();
  },

  renderPolicies() {
    const container = document.getElementById('policies-grid');
    if (!container) return;

    const isAdmin = state.isAdmin();

    container.innerHTML = this.policies.map(p => `
      <div class="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
        <div class="flex items-start justify-between">
          <div>
            <div class="flex items-center gap-2">
              <span class="font-mono font-bold text-xs px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/50">${p.id}</span>
              <span class="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-medium">${p.category}</span>
            </div>
            <h3 class="text-base font-bold text-white mt-2">${p.name}</h3>
          </div>
          <span class="px-2 py-0.5 text-xs font-bold rounded ${
            p.severity === 'critical' ? 'badge-critical' :
            p.severity === 'high' ? 'badge-high' :
            p.severity === 'medium' ? 'badge-medium' : 'badge-low'
          }">${p.severity.toUpperCase()}</span>
        </div>

        <p class="text-xs text-slate-400 leading-relaxed">${p.description}</p>

        <!-- Controls: Weight & Enable Toggle -->
        <div class="pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
          <div class="flex items-center gap-2">
            <span class="text-slate-400">Weight:</span>
            ${isAdmin ? `
              <input type="number" step="0.5" min="1" max="20" value="${p.weight}" class="w-16 px-2 py-1 bg-slate-900 border border-slate-700 rounded text-center text-cyan-300 font-mono font-bold" onchange="PoliciesPage.updateWeight('${p.id}', this.value)">
            ` : `
              <span class="font-mono font-bold text-slate-300">${p.weight}</span>
            `}
          </div>

          <div class="flex items-center gap-3">
            ${isAdmin ? `
              <button class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 text-xs" onclick="PoliciesPage.openParamsModal('${p.id}')">
                Params ⚙
              </button>
              <label class="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" ${p.enabled ? 'checked' : ''} class="sr-only peer" onchange="PoliciesPage.togglePolicy('${p.id}', this.checked)">
                <div class="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600"></div>
              </label>
            ` : `
              <span class="px-2 py-0.5 rounded text-xs ${p.enabled ? 'text-emerald-400 bg-emerald-950/40' : 'text-slate-500 bg-slate-800'}">
                ${p.enabled ? 'Enabled' : 'Disabled'}
              </span>
            `}
          </div>
        </div>
      </div>
    `).join('');
  },

  async togglePolicy(policyId, isEnabled) {
    try {
      await api.patch(`/policies/${policyId}`, { enabled: isEnabled });
      showToast(`Policy ${policyId} ${isEnabled ? 'enabled' : 'disabled'}. Fleet re-evaluated.`, 'success');
      await this.fetchPolicies();
    } catch (err) {
      showToast(err.message, 'error');
    }
  },

  async updateWeight(policyId, weightVal) {
    try {
      const weight = parseFloat(weightVal);
      await api.patch(`/policies/${policyId}`, { weight });
      showToast(`Weight for ${policyId} updated to ${weight}. Fleet re-evaluated.`, 'success');
      await this.fetchPolicies();
    } catch (err) {
      showToast(err.message, 'error');
    }
  },

  openParamsModal(policyId) {
    const policy = this.policies.find(p => p.id === policyId);
    if (!policy) return;

    const modal = document.getElementById('policy-params-modal');
    if (!modal) return;
    modal.classList.remove('hidden');

    document.getElementById('policy-params-title').textContent = `Parameters: ${policy.id} - ${policy.name}`;
    document.getElementById('policy-params-json').value = JSON.stringify(policy.parameters || {}, null, 2);

    document.getElementById('btn-save-policy-params').onclick = async () => {
      try {
        const rawJson = document.getElementById('policy-params-json').value;
        const parsed = JSON.parse(rawJson);
        await api.patch(`/policies/${policyId}`, { parameters: parsed });
        showToast(`Parameters for ${policyId} saved. Fleet re-evaluated.`, 'success');
        modal.classList.add('hidden');
        await this.fetchPolicies();
      } catch (err) {
        showToast('Invalid JSON: ' + err.message, 'error');
      }
    };
  }
};

window.PoliciesPage = PoliciesPage;
