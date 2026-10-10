const SimulatorPage = {
  async load() {
    await this.populateOptions();
    this.bindEvents();
  },

  async populateOptions() {
    // 1. Devices select
    const devSelect = document.getElementById('ztna-sim-device');
    if (devSelect) {
      const devRes = await api.get('/devices/?limit=100&sort_by=risk_score&order=desc');
      devSelect.innerHTML = devRes.items.map(d => `
        <option value="${d.device_id}">
          ${d.device_id} - ${d.hostname} (${d.owner_name} &bull; ${d.risk_level} Risk: ${d.risk_score})
        </option>
      `).join('');
    }

    // 2. Resources select
    const resSelect = document.getElementById('ztna-sim-resource');
    if (resSelect) {
      const resList = await api.get('/ztna/resources');
      resSelect.innerHTML = resList.map(r => `
        <option value="${r.name}">${r.name} (${r.sensitivity.toUpperCase()} Sensitivity)</option>
      `).join('');
    }
  },

  bindEvents() {
    const btn = document.getElementById('btn-evaluate-ztna');
    if (btn) {
      btn.onclick = async () => {
        await this.runSimulation();
      };
    }
  },

  async runSimulation() {
    const deviceId = document.getElementById('ztna-sim-device')?.value;
    const resourceName = document.getElementById('ztna-sim-resource')?.value;

    if (!deviceId || !resourceName) {
      showToast('Please select both a device and target resource.', 'warning');
      return;
    }

    const container = document.getElementById('ztna-result-container');
    container.innerHTML = `<div class="p-8 text-center text-slate-400 animate-pulse">Evaluating dynamic Zero Trust access control policy...</div>`;

    try {
      const res = await api.post('/ztna/evaluate', {
        device_id: deviceId,
        resource_name: resourceName
      });

      this.renderSimulationResult(res);
    } catch (err) {
      showToast(err.message, 'error');
    }
  },

  renderSimulationResult(res) {
    const container = document.getElementById('ztna-result-container');
    if (!container) return;

    container.innerHTML = `
      <div class="glass-panel p-6 rounded-xl border border-slate-800 space-y-6 animate-fade-in">
        <!-- Decision Banner -->
        <div class="p-5 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${
          res.decision === 'ALLOW' ? 'bg-emerald-950/30 border-emerald-500/50' :
          res.decision === 'ALLOW_WITH_STEP_UP_MFA' ? 'bg-amber-950/30 border-amber-500/50' :
          res.decision === 'RESTRICT' ? 'bg-orange-950/30 border-orange-500/50' :
          'bg-rose-950/40 border-rose-500/60'
        }">
          <div>
            <div class="text-xs uppercase tracking-wider font-bold text-slate-400">Zero Trust Access Verdict</div>
            <div class="text-2xl font-black mt-1 ${
              res.decision === 'ALLOW' ? 'text-emerald-400' :
              res.decision === 'ALLOW_WITH_STEP_UP_MFA' ? 'text-amber-400' :
              res.decision === 'RESTRICT' ? 'text-orange-400' : 'text-rose-400'
            }">${res.decision}</div>
            <p class="text-sm text-slate-200 mt-1">${res.reason}</p>
          </div>

          <div class="text-left sm:text-right">
            <span class="text-xs text-slate-400">Target Asset</span>
            <div class="font-bold text-slate-200">${res.resource_name}</div>
            <span class="px-2 py-0.5 text-[11px] font-mono font-bold rounded bg-slate-800 text-cyan-300">
              Sensitivity: ${res.resource_sensitivity.toUpperCase()}
            </span>
          </div>
        </div>

        <!-- Rule Path Checklist -->
        <div>
          <h4 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">Evaluated Policy Rules Path</h4>
          <div class="space-y-2">
            ${res.rule_path.map(r => `
              <div class="p-3 rounded-lg border flex items-start gap-3 text-xs ${
                r.passed ? 'bg-slate-900/60 border-slate-800 text-slate-300' : 'bg-rose-950/20 border-rose-900/40 text-rose-300'
              }">
                <span class="font-bold text-sm ${r.passed ? 'text-emerald-400' : 'text-rose-400'}">
                  ${r.passed ? '✓' : '✕'}
                </span>
                <div>
                  <div class="font-bold font-mono text-slate-200">${r.rule_id}: ${r.name}</div>
                  <div class="text-[11px] mt-0.5 opacity-80">${r.detail}</div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- How to Change Access Verdict / Suggestions -->
        <div>
          <h4 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">Actionable Remediation to Alter Verdict</h4>
          <div class="p-4 rounded-lg bg-slate-900/80 border border-slate-800 space-y-2 text-xs">
            ${res.remediation_suggestions.map(s => `
              <div class="flex items-center gap-2 text-slate-300">
                <span class="text-cyan-400 font-bold">&bull;</span>
                <span>${s}</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }
};

window.SimulatorPage = SimulatorPage;
