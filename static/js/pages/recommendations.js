const RecommendationsPage = {
  async load() {
    await this.fetchFleetRecommendations();
    await this.populateDeviceSelect();
  },

  async fetchFleetRecommendations() {
    const list = await api.get('/recommendations/fleet');
    const container = document.getElementById('fleet-recommendations-list');
    if (!container) return;

    const isAdmin = state.isAdmin();

    if (list.length === 0) {
      container.innerHTML = `<div class="p-8 text-center text-slate-400">All fleet endpoints are compliant. No corrective actions required!</div>`;
      return;
    }

    container.innerHTML = list.map((r, idx) => `
      <div class="glass-panel p-5 rounded-xl border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div class="flex items-start gap-4">
          <div class="w-10 h-10 rounded-lg flex items-center justify-center font-bold font-mono text-base ${
            idx === 0 ? 'bg-rose-950/80 text-rose-400 border border-rose-700/50' :
            idx < 3 ? 'bg-amber-950/80 text-amber-400 border border-amber-700/50' :
            'bg-slate-800 text-slate-300 border border-slate-700'
          }">
            #${idx + 1}
          </div>
          <div>
            <div class="flex items-center gap-2">
              <span class="px-2 py-0.5 text-xs font-bold rounded ${
                r.priority === 'P1' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                r.priority === 'P2' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                'bg-slate-800 text-slate-300'
              }">${r.priority}</span>
              <span class="font-mono text-xs text-cyan-400 font-bold">${r.policy_id}</span>
              <span class="text-xs text-slate-400">${r.category} &bull; Effort: ${r.estimated_effort}</span>
            </div>
            <h3 class="text-base font-bold text-white mt-1">${r.title}</h3>
            <p class="text-xs text-slate-400 mt-1">${r.action_description}</p>
          </div>
        </div>

        <div class="flex items-center gap-6 w-full md:w-auto justify-between md:justify-end border-t md:border-t-0 pt-3 md:pt-0 border-slate-800">
          <div class="text-left md:text-right">
            <div class="text-xs text-slate-400">Impact</div>
            <div class="text-sm font-bold text-slate-200">${r.affected_devices_count} endpoints affected</div>
            <div class="text-xs font-mono font-bold text-emerald-400">-${r.total_risk_reduction_points.toFixed(0)} risk points</div>
          </div>

          ${isAdmin ? `
            <button class="px-3 py-1.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs rounded-lg shadow-lg shadow-cyan-950/50 transition whitespace-nowrap" onclick="RecommendationsPage.applyFleetFix('${r.policy_id}')">
              ⚡ Remediate All (${r.affected_devices_count})
            </button>
          ` : `
            <span class="text-xs text-slate-500 font-mono">Admin Only</span>
          `}
        </div>
      </div>
    `).join('');
  },

  async applyFleetFix(policyId) {
    if (!confirm(`Apply bulk automated fix for policy ${policyId} across all failing devices?`)) return;

    try {
      const res = await api.post('/devices/remediate-bulk', { policy_id: policyId });
      showToast(res.message, 'success');
      await this.fetchFleetRecommendations();
    } catch (err) {
      showToast(err.message, 'error');
    }
  },

  async populateDeviceSelect() {
    const select = document.getElementById('recs-device-select');
    if (!select) return;

    const res = await api.get('/devices/?limit=100&sort_by=risk_score&order=desc');
    select.innerHTML = `<option value="">-- Choose an Endpoint to Review Plan --</option>` +
      res.items.map(d => `<option value="${d.device_id}">${d.device_id} - ${d.hostname} (${d.risk_level} Risk: ${d.risk_score})</option>`).join('');

    select.onchange = async () => {
      const devId = select.value;
      if (!devId) {
        document.getElementById('single-device-rec-container').innerHTML = '';
        return;
      }
      await this.loadDevicePlan(devId);
    };
  },

  async loadDevicePlan(devId) {
    const container = document.getElementById('single-device-rec-container');
    if (!container) return;

    container.innerHTML = `<div class="p-6 text-center text-slate-400 animate-pulse">Calculating prioritized actions...</div>`;

    try {
      const data = await api.get(`/recommendations/device/${devId}`);
      container.innerHTML = `
        <div class="glass-panel p-5 rounded-xl border border-slate-800 space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 class="font-bold text-white">${data.hostname} (<span class="font-mono text-cyan-400">${data.device_id}</span>)</h3>
              <p class="text-xs text-slate-400">Current Risk: <span class="font-bold text-rose-400 font-mono">${data.current_risk_score}</span> &bull; Projected Risk: <span class="font-bold text-emerald-400 font-mono">${data.projected_risk_score}</span></p>
            </div>
            <span class="text-xs font-bold font-mono px-2 py-1 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/50">
              Potential Reduction: -${data.potential_reduction} pts
            </span>
          </div>

          <div class="space-y-2 text-xs">
            ${data.recommendations.map(r => `
              <div class="p-3 rounded bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                <div>
                  <div class="flex items-center gap-2">
                    <span class="font-bold ${r.priority === 'P1' ? 'text-rose-400' : 'text-amber-400'}">${r.priority}</span>
                    <span class="font-semibold text-slate-200">${r.title}</span>
                  </div>
                  <p class="text-[11px] text-slate-400 mt-0.5">${r.action} &bull; Effort: ${r.estimated_effort}</p>
                </div>
                <span class="font-mono font-bold text-emerald-400 whitespace-nowrap">-${r.risk_reduction_points} pts</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    } catch (err) {
      showToast(err.message, 'error');
    }
  }
};

window.RecommendationsPage = RecommendationsPage;
