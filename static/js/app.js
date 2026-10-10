const App = {
  activePollingInterval: null,

  async init() {
    state.init();
    this.bindGlobalEvents();

    // Check existing auth session
    if (api.token || localStorage.getItem('sentinel_user')) {
      try {
        const me = await api.get('/auth/me');
        state.setUser(me);
        this.navigate('dashboard');
        this.startLiveTelemetryPolling();
      } catch (e) {
        state.setUser(null);
        api.setToken(null);
        this.showAuth();
      }
    } else {
      this.showAuth();
    }
  },

  showAuth() {
    this.stopLiveTelemetryPolling();
    state.setUser(null);
    const authWrapper = document.getElementById('auth-wrapper');
    const appWrapper = document.getElementById('app-wrapper');
    if (authWrapper) authWrapper.classList.remove('hidden');
    if (appWrapper) appWrapper.classList.add('hidden');
    AuthPage.init();
  },

  bindGlobalEvents() {
    // Nav items
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const page = link.getAttribute('data-page');
        this.navigate(page);
      });
    });

    // Theme toggle
    const themeBtn = document.getElementById('btn-toggle-theme');
    if (themeBtn) {
      themeBtn.onclick = () => {
        const next = state.theme === 'dark' ? 'light' : 'dark';
        state.setTheme(next);
        themeBtn.textContent = next === 'dark' ? '🌙' : '☀';
        // Reload dashboard charts if currently on dashboard
        if (state.activePage === 'dashboard' && window.DashboardPage) {
          DashboardPage.fetchCharts();
        }
      };
    }

    // Logout button
    const logoutBtn = document.getElementById('btn-logout');
    if (logoutBtn) {
      logoutBtn.onclick = async () => {
        try {
          await api.post('/auth/logout', {});
        } catch (e) {}
        api.setToken(null);
        state.setUser(null);
        showToast('Logged out securely.', 'info');
        this.showAuth();
      };
    }

    // Live drift button (in top demo banner)
    const driftBtn = document.getElementById('btn-trigger-drift');
    if (driftBtn) {
      driftBtn.onclick = async () => {
        driftBtn.disabled = true;
        driftBtn.innerHTML = `Simulating Drift...`;
        try {
          const res = await api.post('/simulator/mutate', { count: 4 });
          const count = res.mutations?.length || 0;
          showToast(`⚡ Injected live telemetry drift across ${count} endpoints!`, 'warning');
          // Refresh active page
          this.refreshCurrentPage();
        } catch (err) {
          showToast(err.message, 'error');
        } finally {
          driftBtn.disabled = false;
          driftBtn.innerHTML = `⚡ Mutate Drift`;
        }
      };
    }

    // Session expired listener
    window.addEventListener('auth:expired', () => {
      showToast('Session expired. Please log in again.', 'warning');
      this.showAuth();
    });
  },

  navigate(pageId) {
    if (!state.user) {
      this.showAuth();
      return;
    }

    state.activePage = pageId;

    // Update active nav styling
    document.querySelectorAll('.nav-link').forEach(link => {
      const p = link.getAttribute('data-page');
      if (p === pageId) {
        link.classList.add('bg-cyan-950/60', 'text-cyan-400', 'border-l-4', 'border-cyan-400');
        link.classList.remove('text-slate-400');
      } else {
        link.classList.remove('bg-cyan-950/60', 'text-cyan-400', 'border-l-4', 'border-cyan-400');
        link.classList.add('text-slate-400');
      }
    });

    // Hide all pages, show target page
    document.querySelectorAll('.page-view').forEach(view => {
      view.classList.add('hidden');
    });

    const targetView = document.getElementById(`page-${pageId}`);
    if (targetView) {
      targetView.classList.remove('hidden');
    }

    // Update Header title & explainable subtitle
    const headerTitle = document.getElementById('header-page-title');
    const headerSub = document.getElementById('header-page-subtitle');
    if (headerTitle) {
      const titles = {
        dashboard: '📊 Security Posture Dashboard',
        devices: '💻 Colleague Devices & Health Fleet',
        alerts: '🚨 Threat Detection & Security Alerts',
        recommendations: '💡 Prioritized Remediation Plans',
        policies: '📋 Security Compliance Policies (19 Rules)',
        simulator: '🎯 Zero Trust Access Simulator (ZTNA)',
        'import-export': '📥 Data Ingestion & Executive Reports',
        users: '👥 User Logins & Role Management',
        audit: '📜 Tamper-Evident Security Audit Log',
        profile: '⚙ Operator Profile & Two-Factor Auth (2FA)'
      };
      headerTitle.textContent = titles[pageId] || 'SentinelEdge Console';
    }
    if (headerSub) {
      const subtitles = {
        dashboard: 'Live fleet risk score, security letter grade, and active threat trends.',
        devices: 'Search any colleague to check antivirus status, disk encryption, and device posture.',
        alerts: 'Real-time security incidents mapped to MITRE ATT&CK techniques with status triage.',
        recommendations: 'Recommended 1-click fixes ranked by effort and risk-reduction ROI to protect fleet.',
        policies: '19 baseline rules governing passwords, encryption, malware protection, and network safety.',
        simulator: 'Interactive test bench: check if a colleague\'s laptop can safely access corporate apps.',
        'import-export': 'Import device telemetry CSVs or generate compliance audit reports.',
        users: 'Manage operator credentials, assign Admin / Analyst roles, and view account statuses.',
        audit: 'Comprehensive audit history tracking logins, policy changes, and remediation actions.',
        profile: 'Update personal credentials and configure Time-based One-Time Password (TOTP) MFA.'
      };
      headerSub.textContent = subtitles[pageId] || '';
    }

    // Trigger page load
    this.refreshCurrentPage();
  },

  refreshCurrentPage() {
    const pageId = state.activePage;
    if (pageId === 'dashboard' && window.DashboardPage) DashboardPage.load();
    else if (pageId === 'devices' && window.DevicesPage) DevicesPage.load();
    else if (pageId === 'alerts' && window.AlertsPage) AlertsPage.load();
    else if (pageId === 'policies' && window.PoliciesPage) PoliciesPage.load();
    else if (pageId === 'recommendations' && window.RecommendationsPage) RecommendationsPage.load();
    else if (pageId === 'simulator' && window.SimulatorPage) SimulatorPage.load();
    else if (pageId === 'import-export' && window.ImportExportPage) ImportExportPage.load();
    else if (pageId === 'users' && window.UsersPage) UsersPage.load();
    else if (pageId === 'audit' && window.AuditPage) AuditPage.load();
    else if (pageId === 'profile' && window.ProfilePage) ProfilePage.load();
  },

  startLiveTelemetryPolling() {
    this.stopLiveTelemetryPolling();
    // Poll every 15 seconds to keep stats and new alerts synchronized
    this.activePollingInterval = setInterval(async () => {
      if (state.user && state.activePage === 'dashboard') {
        try {
          await DashboardPage.fetchStats();
        } catch (e) {}
      }
    }, 15000);
  },

  stopLiveTelemetryPolling() {
    if (this.activePollingInterval) {
      clearInterval(this.activePollingInterval);
      this.activePollingInterval = null;
    }
  }
};

window.App = App;

// Bootstrap on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
