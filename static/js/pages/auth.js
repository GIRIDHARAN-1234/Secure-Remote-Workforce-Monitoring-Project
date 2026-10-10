const AuthPage = {
  init() {
    this.bindEvents();
    this.setupPasswordStrengthMeter();
  },

  bindEvents() {
    // Switch between Login and Register tabs
    document.querySelectorAll('.auth-tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const tab = e.target.getAttribute('data-tab');
        this.switchAuthTab(tab);
      });
    });

    // Quick demo autofill buttons
    document.querySelectorAll('.demo-creds-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const email = btn.getAttribute('data-email');
        const pwd = btn.getAttribute('data-pwd');
        document.getElementById('login-email').value = email;
        document.getElementById('login-password').value = pwd;
        showToast(`Loaded ${btn.getAttribute('data-role')} credentials. Ready to login!`, 'info');
      });
    });

    // Login submit
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await this.handleLogin();
      });
    }

    // Register submit
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
      registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await this.handleRegister();
      });
    }

    // Forgot password trigger
    const forgotLink = document.getElementById('forgot-password-link');
    if (forgotLink) {
      forgotLink.addEventListener('click', (e) => {
        e.preventDefault();
        this.openForgotPasswordModal();
      });
    }
  },

  switchAuthTab(tab) {
    const loginSection = document.getElementById('login-section');
    const registerSection = document.getElementById('register-section');
    const loginTabBtn = document.getElementById('tab-btn-login');
    const registerTabBtn = document.getElementById('tab-btn-register');

    if (tab === 'login') {
      loginSection.classList.remove('hidden');
      registerSection.classList.add('hidden');
      loginTabBtn.classList.add('border-cyan-500', 'text-cyan-400');
      loginTabBtn.classList.remove('border-transparent', 'text-slate-400');
      registerTabBtn.classList.remove('border-cyan-500', 'text-cyan-400');
      registerTabBtn.classList.add('border-transparent', 'text-slate-400');
    } else {
      loginSection.classList.add('hidden');
      registerSection.classList.remove('hidden');
      registerTabBtn.classList.add('border-cyan-500', 'text-cyan-400');
      registerTabBtn.classList.remove('border-transparent', 'text-slate-400');
      loginTabBtn.classList.remove('border-cyan-500', 'text-cyan-400');
      loginTabBtn.classList.add('border-transparent', 'text-slate-400');
    }
  },

  setupPasswordStrengthMeter() {
    const pwdInput = document.getElementById('register-password');
    const meterFill = document.getElementById('pwd-strength-bar');
    const meterText = document.getElementById('pwd-strength-text');

    if (!pwdInput) return;

    pwdInput.addEventListener('input', () => {
      const val = pwdInput.value;
      const score = this.calculatePasswordScore(val);
      
      const levels = [
        { pct: '10%', color: 'bg-rose-500', text: 'Too short (min 10 chars)', textColor: 'text-rose-400' },
        { pct: '30%', color: 'bg-rose-500', text: 'Weak', textColor: 'text-rose-400' },
        { pct: '60%', color: 'bg-amber-500', text: 'Medium (needs symbols/digits)', textColor: 'text-amber-400' },
        { pct: '85%', color: 'bg-cyan-500', text: 'Good', textColor: 'text-cyan-400' },
        { pct: '100%', color: 'bg-emerald-500', text: 'Very Strong', textColor: 'text-emerald-400' },
      ];

      const res = levels[score];
      meterFill.style.width = res.pct;
      meterFill.className = `h-1.5 rounded-full transition-all duration-300 ${res.color}`;
      meterText.textContent = res.text;
      meterText.className = `text-xs mt-1 ${res.textColor}`;
    });
  },

  calculatePasswordScore(pwd) {
    if (!pwd || pwd.length < 6) return 0;
    let score = 0;
    if (pwd.length >= 10) score += 1;
    if (/[A-Z]/.test(pwd)) score += 1;
    if (/[a-z]/.test(pwd)) score += 1;
    if (/\d/.test(pwd)) score += 1;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(pwd)) score += 1;

    if (pwd.length < 10) return 0;
    if (score < 3) return 1;
    if (score === 3 || score === 4) return 2;
    if (score === 5 && pwd.length >= 12) return 4;
    return 3;
  },

  async handleLogin() {
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const totpCode = document.getElementById('login-totp-code') ? document.getElementById('login-totp-code').value.trim() : null;

    const btn = document.getElementById('btn-submit-login');
    btn.disabled = true;
    btn.innerHTML = `<span class="inline-block animate-spin mr-2">⟳</span> Authenticating...`;

    try {
      const data = await api.post('/auth/login', {
        email,
        password,
        totp_code: totpCode || null
      });

      if (data.mfa_required) {
        // Show MFA Prompt Modal
        this.openMFAPromptModal(email, password);
        return;
      }

      api.setToken(data.access_token);
      state.setUser(data.user);
      showToast(`Welcome back, ${data.user.full_name}! Authenticated as ${data.user.role.toUpperCase()}`, 'success');
      App.navigate('dashboard');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = `Authenticate & Launch Console`;
    }
  },

  openMFAPromptModal(email, password) {
    const modal = document.getElementById('mfa-login-modal');
    if (!modal) return;
    modal.classList.remove('hidden');

    const submitBtn = document.getElementById('mfa-login-submit');
    submitBtn.onclick = async () => {
      const code = document.getElementById('mfa-login-code').value.trim();
      if (!code) {
        showToast('Please enter the 6-digit MFA code.', 'warning');
        return;
      }

      try {
        const data = await api.post('/auth/login', {
          email,
          password,
          totp_code: code
        });
        modal.classList.add('hidden');
        api.setToken(data.access_token);
        state.setUser(data.user);
        showToast('Two-factor verification successful!', 'success');
        App.navigate('dashboard');
      } catch (err) {
        showToast(err.message, 'error');
      }
    };
  },

  async handleRegister() {
    const fullName = document.getElementById('register-name').value.trim();
    const email = document.getElementById('register-email').value.trim();
    const password = document.getElementById('register-password').value;
    const role = document.getElementById('register-role').value;

    const btn = document.getElementById('btn-submit-register');
    btn.disabled = true;
    btn.innerHTML = `<span class="inline-block animate-spin mr-2">⟳</span> Registering...`;

    try {
      await api.post('/auth/register', {
        full_name: fullName,
        email,
        password,
        role
      });
      showToast('Registration successful! Please log in.', 'success');
      this.switchAuthTab('login');
      document.getElementById('login-email').value = email;
      document.getElementById('login-password').value = '';
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = `Create Operator Account`;
    }
  },

  openForgotPasswordModal() {
    const modal = document.getElementById('forgot-password-modal');
    if (!modal) return;
    modal.classList.remove('hidden');

    const resetBanner = document.getElementById('forgot-token-banner');
    resetBanner.classList.add('hidden');

    document.getElementById('btn-request-reset').onclick = async () => {
      const email = document.getElementById('forgot-email').value.trim();
      if (!email) {
        showToast('Please enter your email.', 'warning');
        return;
      }
      try {
        const res = await api.post('/auth/forgot-password', { email });
        showToast(res.message, 'info');
        if (res.demo_reset_token) {
          resetBanner.classList.remove('hidden');
          document.getElementById('forgot-token-display').textContent = res.demo_reset_token;
          document.getElementById('reset-token-input').value = res.demo_reset_token;
        }
      } catch (err) {
        showToast(err.message, 'error');
      }
    };

    document.getElementById('btn-perform-reset').onclick = async () => {
      const token = document.getElementById('reset-token-input').value.trim();
      const newPassword = document.getElementById('reset-new-password').value;

      try {
        const res = await api.post('/auth/reset-password', { token, new_password: newPassword });
        showToast(res.message, 'success');
        modal.classList.add('hidden');
        this.switchAuthTab('login');
      } catch (err) {
        showToast(err.message, 'error');
      }
    };
  }
};

window.AuthPage = AuthPage;
