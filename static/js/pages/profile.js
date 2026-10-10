const ProfilePage = {
  async load() {
    await this.fetchProfile();
    this.bindEvents();
  },

  async fetchProfile() {
    try {
      const user = await api.get('/auth/me');
      state.setUser(user);

      document.getElementById('profile-name').textContent = user.full_name;
      document.getElementById('profile-email').textContent = user.email;
      document.getElementById('profile-role').textContent = user.role.toUpperCase();

      const mfaStatusText = document.getElementById('profile-mfa-status');
      const mfaBtn = document.getElementById('btn-toggle-mfa');

      if (user.mfa_enabled) {
        mfaStatusText.textContent = 'Active (Protected by Authenticator App)';
        mfaStatusText.className = 'text-xs font-semibold text-emerald-400';
        mfaBtn.textContent = 'Disable Two-Factor Auth';
        mfaBtn.className = 'px-3 py-1.5 bg-rose-900/40 hover:bg-rose-800/60 text-rose-300 border border-rose-700/50 rounded-lg text-xs font-semibold transition';
        mfaBtn.onclick = () => this.disableMFA();
      } else {
        mfaStatusText.textContent = 'Disabled (Single Password Factor Only)';
        mfaStatusText.className = 'text-xs font-semibold text-amber-400';
        mfaBtn.textContent = 'Setup Two-Factor Auth (TOTP)';
        mfaBtn.className = 'px-3 py-1.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-cyan-950/50 transition';
        mfaBtn.onclick = () => this.setupMFA();
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  },

  bindEvents() {
    const pwdForm = document.getElementById('profile-password-form');
    if (pwdForm) {
      pwdForm.onsubmit = async (e) => {
        e.preventDefault();
        const oldPassword = document.getElementById('profile-old-pwd').value;
        const newPassword = document.getElementById('profile-new-pwd').value;

        try {
          const res = await api.post('/auth/change-password', {
            old_password: oldPassword,
            new_password: newPassword
          });
          showToast(res.message, 'success');
          pwdForm.reset();
        } catch (err) {
          showToast(err.message, 'error');
        }
      };
    }
  },

  async setupMFA() {
    try {
      const data = await api.post('/auth/mfa/setup', {});
      const modal = document.getElementById('profile-mfa-modal');
      if (!modal) return;
      modal.classList.remove('hidden');

      document.getElementById('mfa-qr-image').src = data.qr_code_base64;
      document.getElementById('mfa-secret-text').textContent = data.secret;

      document.getElementById('btn-verify-mfa-setup').onclick = async () => {
        const code = document.getElementById('mfa-verify-code').value.trim();
        if (!code) {
          showToast('Please enter the 6-digit verification code.', 'warning');
          return;
        }

        try {
          const res = await api.post('/auth/mfa/verify', { code });
          showToast(res.message, 'success');
          modal.classList.add('hidden');
          await this.fetchProfile();
        } catch (err) {
          showToast(err.message, 'error');
        }
      };
    } catch (err) {
      showToast(err.message, 'error');
    }
  },

  async disableMFA() {
    const code = prompt('Please enter your current 6-digit authenticator code to confirm disabling MFA:');
    if (!code) return;

    try {
      const res = await api.post('/auth/mfa/disable', { code });
      showToast(res.message, 'success');
      await this.fetchProfile();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }
};

window.ProfilePage = ProfilePage;
