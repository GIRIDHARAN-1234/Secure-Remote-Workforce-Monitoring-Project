const state = {
  user: null,
  activePage: 'dashboard',
  theme: localStorage.getItem('sentinel_theme') || 'dark',
  unreadAlerts: 0,
  
  init() {
    const savedUser = localStorage.getItem('sentinel_user');
    if (savedUser) {
      try {
        this.user = JSON.parse(savedUser);
      } catch (e) {
        this.user = null;
      }
    }
    this.applyTheme(this.theme);
  },

  setUser(user) {
    this.user = user;
    if (user) {
      localStorage.setItem('sentinel_user', JSON.stringify(user));
    } else {
      localStorage.removeItem('sentinel_user');
    }
    this.updateUserUI();
  },

  setTheme(theme) {
    this.theme = theme;
    localStorage.setItem('sentinel_theme', theme);
    this.applyTheme(theme);
  },

  applyTheme(theme) {
    if (theme === 'light') {
      document.body.classList.add('light-theme');
    } else {
      document.body.classList.remove('light-theme');
    }
  },

  updateUserUI() {
    const userRoleBadge = document.getElementById('header-user-role');
    const userNameDisplay = document.getElementById('header-user-name');
    const userEmailDisplay = document.getElementById('header-user-email');
    const authWrapper = document.getElementById('auth-wrapper');
    const appWrapper = document.getElementById('app-wrapper');

    if (this.user) {
      if (authWrapper) authWrapper.classList.add('hidden');
      if (appWrapper) appWrapper.classList.remove('hidden');

      if (userNameDisplay) userNameDisplay.textContent = this.user.full_name || 'Security Operator';
      if (userEmailDisplay) userEmailDisplay.textContent = this.user.email || '';
      if (userRoleBadge) {
        userRoleBadge.textContent = (this.user.role || 'viewer').toUpperCase();
        userRoleBadge.className = `px-2 py-0.5 text-xs font-semibold rounded ${
          this.user.role === 'admin' ? 'bg-purple-900/60 text-purple-300 border border-purple-500/40' :
          this.user.role === 'analyst' ? 'bg-cyan-900/60 text-cyan-300 border border-cyan-500/40' :
          'bg-slate-700/60 text-slate-300 border border-slate-600/40'
        }`;
      }

      // Hide or show RBAC restricted navigation items
      document.querySelectorAll('[data-role-required]').forEach(el => {
        const allowed = el.getAttribute('data-role-required').split(',');
        if (allowed.includes(this.user.role)) {
          el.classList.remove('hidden');
        } else {
          el.classList.add('hidden');
        }
      });
    } else {
      if (authWrapper) authWrapper.classList.remove('hidden');
      if (appWrapper) appWrapper.classList.add('hidden');
    }
  },

  // Role check helpers
  isAdmin() {
    return this.user && this.user.role === 'admin';
  },
  isAnalystOrAdmin() {
    return this.user && (this.user.role === 'admin' || this.user.role === 'analyst');
  }
};

// Global Toast System
function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  const typeStyles = {
    success: 'bg-emerald-950/90 border-emerald-500 text-emerald-200',
    error: 'bg-rose-950/90 border-rose-500 text-rose-200',
    warning: 'bg-amber-950/90 border-amber-500 text-amber-200',
    info: 'bg-cyan-950/90 border-cyan-500 text-cyan-200',
  };

  const icons = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ',
  };

  toast.className = `flex items-center gap-3 px-4 py-3 rounded-lg border shadow-xl backdrop-blur-md transform transition-all duration-300 ease-out translate-y-2 opacity-0 text-sm font-medium ${typeStyles[type] || typeStyles.info}`;
  toast.innerHTML = `
    <span class="font-bold text-base">${icons[type] || 'ℹ'}</span>
    <span class="flex-1">${message}</span>
    <button class="text-xs opacity-60 hover:opacity-100 ml-2" onclick="this.parentElement.remove()">✕</button>
  `;

  container.appendChild(toast);

  // Animate in
  setTimeout(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  }, 10);

  // Auto remove
  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

window.state = state;
window.showToast = showToast;
