const DashboardPage = {
  charts: {},

  async load() {
    try {
      await Promise.all([
        this.fetchStats(),
        this.fetchCharts(),
        this.fetchRiskiestDevices(),
        this.fetchGeoAnomalies()
      ]);
    } catch (err) {
      showToast('Error loading dashboard: ' + err.message, 'error');
    }
  },

  async fetchStats() {
    const stats = await api.get('/dashboard/stats');
    
    document.getElementById('stat-total-devices').textContent = stats.total_devices;
    document.getElementById('stat-compliance-pct').textContent = stats.compliance_percentage + '%';
    document.getElementById('stat-avg-risk').textContent = stats.avg_risk_score;
    document.getElementById('stat-critical-devices').textContent = stats.critical_devices_count;
    document.getElementById('stat-open-alerts').textContent = stats.open_alerts_count;
    document.getElementById('stat-byod-pct').textContent = stats.byod_percentage + '%';
    document.getElementById('stat-unpatched-pct').textContent = stats.unpatched_percentage + '%';

    // Posture Score & Letter Grade
    const scoreVal = document.getElementById('stat-posture-score');
    const gradeVal = document.getElementById('stat-letter-grade');
    if (scoreVal) scoreVal.textContent = stats.security_posture_score + '/100';
    if (gradeVal) {
      gradeVal.textContent = stats.letter_grade;
      gradeVal.className = `text-4xl font-black ${
        stats.letter_grade === 'A' ? 'text-emerald-400' :
        stats.letter_grade === 'B' ? 'text-cyan-400' :
        stats.letter_grade === 'C' ? 'text-amber-400' :
        stats.letter_grade === 'D' ? 'text-orange-400' : 'text-rose-500'
      }`;
    }
  },

  async fetchCharts() {
    const data = await api.get('/dashboard/charts');

    // Destroy existing chart instances to avoid canvas re-use errors
    Object.values(this.charts).forEach(c => c && c.destroy());

    const isLight = document.body.classList.contains('light-theme');
    const textColor = isLight ? '#475569' : '#94a3b8';
    const gridColor = isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.06)';

    // 1. Risk Level Distribution (Doughnut)
    const ctxRisk = document.getElementById('chart-risk-dist').getContext('2d');
    this.charts.risk = new Chart(ctxRisk, {
      type: 'doughnut',
      data: {
        labels: data.risk_distribution.labels,
        datasets: [{
          data: data.risk_distribution.data,
          backgroundColor: ['#10b981', '#f59e0b', '#f97316', '#ef4444'],
          borderWidth: 2,
          borderColor: isLight ? '#ffffff' : '#0f172a'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: textColor, font: { size: 11 } } }
        },
        cutout: '68%'
      }
    });

    // 2. Department Compliance (Bar)
    const ctxDept = document.getElementById('chart-dept-compliance').getContext('2d');
    this.charts.dept = new Chart(ctxDept, {
      type: 'bar',
      data: {
        labels: data.department_compliance.labels,
        datasets: [{
          label: 'Compliance %',
          data: data.department_compliance.data,
          backgroundColor: 'rgba(6, 182, 212, 0.7)',
          borderColor: '#06b6d4',
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: textColor, font: { size: 10 } }, grid: { display: false } },
          y: { min: 0, max: 100, ticks: { color: textColor, font: { size: 10 } }, grid: { color: gridColor } }
        },
        plugins: { legend: { display: false } }
      }
    });

    // 3. Risk Trend Over Time (Line)
    const ctxTrend = document.getElementById('chart-risk-trend').getContext('2d');
    this.charts.trend = new Chart(ctxTrend, {
      type: 'line',
      data: {
        labels: data.risk_trend.labels,
        datasets: [{
          label: 'Avg Fleet Risk',
          data: data.risk_trend.data,
          borderColor: '#f59e0b',
          backgroundColor: 'rgba(245, 158, 11, 0.12)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: textColor, maxTicksLimit: 8, font: { size: 10 } }, grid: { display: false } },
          y: { ticks: { color: textColor, font: { size: 10 } }, grid: { color: gridColor } }
        },
        plugins: { legend: { display: false } }
      }
    });

    // 4. Top Failed Policies (Horizontal Bar)
    const ctxPolicies = document.getElementById('chart-top-policies').getContext('2d');
    this.charts.policies = new Chart(ctxPolicies, {
      type: 'bar',
      indexAxis: 'y',
      data: {
        labels: data.top_failed_policies.labels,
        datasets: [{
          label: 'Failed Devices',
          data: data.top_failed_policies.data,
          backgroundColor: 'rgba(239, 68, 68, 0.7)',
          borderColor: '#ef4444',
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: textColor, font: { size: 10 } }, grid: { color: gridColor } },
          y: { ticks: { color: textColor, font: { size: 10 } }, grid: { display: false } }
        },
        plugins: { legend: { display: false } }
      }
    });

    // 5. Network Type Risk (Bar)
    const ctxNet = document.getElementById('chart-network-risk').getContext('2d');
    this.charts.net = new Chart(ctxNet, {
      type: 'bar',
      data: {
        labels: data.network_risk.labels,
        datasets: [{
          label: 'Avg Risk Index',
          data: data.network_risk.data,
          backgroundColor: ['#10b981', '#06b6d4', '#f59e0b', '#ef4444'],
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: textColor, font: { size: 10 } }, grid: { display: false } },
          y: { min: 0, max: 100, ticks: { color: textColor, font: { size: 10 } }, grid: { color: gridColor } }
        },
        plugins: { legend: { display: false } }
      }
    });

    // 6. OS Distribution (Doughnut)
    const ctxOS = document.getElementById('chart-os-dist').getContext('2d');
    this.charts.os = new Chart(ctxOS, {
      type: 'doughnut',
      data: {
        labels: data.os_distribution.labels,
        datasets: [{
          data: data.os_distribution.data,
          backgroundColor: ['#3b82f6', '#8b5cf6', '#ec4899', '#10b981', '#f59e0b'],
          borderWidth: 2,
          borderColor: isLight ? '#ffffff' : '#0f172a'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: textColor, font: { size: 10 } } }
        },
        cutout: '60%'
      }
    });
  },

  async fetchRiskiestDevices() {
    const list = await api.get('/dashboard/riskiest?limit=8');
    const tbody = document.getElementById('dashboard-riskiest-table');
    if (!tbody) return;

    tbody.innerHTML = list.map(d => `
      <tr class="border-b border-slate-800/60 hover:bg-slate-800/40 transition">
        <td class="py-2.5 px-3 font-mono text-cyan-400 font-semibold">${d.device_id}</td>
        <td class="py-2.5 px-3">
          <div class="font-medium text-slate-200">${d.hostname}</div>
          <div class="text-xs text-slate-400">${d.owner_name} (${d.department})</div>
        </td>
        <td class="py-2.5 px-3">
          <span class="px-2 py-0.5 text-xs font-bold rounded ${
            d.risk_level === 'Critical' ? 'badge-critical' :
            d.risk_level === 'High' ? 'badge-high' :
            d.risk_level === 'Medium' ? 'badge-medium' : 'badge-low'
          }">${d.risk_score} (${d.risk_level})</span>
        </td>
        <td class="py-2.5 px-3">
          <span class="px-2 py-0.5 text-xs font-semibold rounded ${
            d.ztna_decision === 'ALLOW' ? 'badge-allow' :
            d.ztna_decision === 'ALLOW_WITH_STEP_UP_MFA' ? 'badge-step-up' :
            d.ztna_decision === 'RESTRICT' ? 'badge-restrict' : 'badge-block'
          }">${d.ztna_decision}</span>
        </td>
        <td class="py-2.5 px-3 text-right">
          <button class="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded border border-slate-700 transition" onclick="DevicesPage.openDrawer('${d.device_id}')">
            Inspect
          </button>
        </td>
      </tr>
    `).join('');
  },

  async fetchGeoAnomalies() {
    const anomalies = await api.get('/dashboard/geo-anomalies');
    const container = document.getElementById('dashboard-geo-anomalies');
    if (!container) return;

    if (anomalies.length === 0) {
      container.innerHTML = `<div class="text-xs text-slate-400 py-4 text-center">No active geolocation anomalies detected.</div>`;
      return;
    }

    container.innerHTML = anomalies.slice(0, 5).map(a => `
      <div class="p-2.5 rounded border border-rose-900/40 bg-rose-950/20 flex items-center justify-between text-xs">
        <div>
          <span class="font-semibold text-rose-300 font-mono">${a.device_id}</span>
          <span class="text-slate-300 ml-1">(${a.owner_name})</span>
          <div class="text-rose-400/80 mt-0.5">
            ${a.impossible_travel ? '🚨 Impossible Travel Velocity Detected' : `Location: ${a.geo_country}`}
          </div>
        </div>
        <button class="px-2 py-0.5 bg-rose-900/40 hover:bg-rose-800/60 text-rose-200 rounded border border-rose-700/50" onclick="DevicesPage.openDrawer('${a.device_id}')">
          Review
        </button>
      </div>
    `).join('');
  }
};

window.DashboardPage = DashboardPage;
