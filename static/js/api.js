const API_BASE = '/api/v1';

class ApiClient {
  constructor() {
    this.token = localStorage.getItem('sentinel_token') || null;
    this.isRefreshing = false;
    this.refreshSubscribers = [];
  }

  setToken(token) {
    this.token = token;
    if (token) {
      localStorage.setItem('sentinel_token', token);
    } else {
      localStorage.removeItem('sentinel_token');
    }
  }

  onRefreshed(token) {
    this.refreshSubscribers.forEach(cb => cb(token));
    this.refreshSubscribers = [];
  }

  subscribeTokenRefresh(cb) {
    this.refreshSubscribers.push(cb);
  }

  async request(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;
    const headers = {
      ...options.headers,
    };

    if (!(options.body instanceof FormData)) {
      headers['Content-Type'] = headers['Content-Type'] || 'application/json';
    }

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const config = {
      ...options,
      headers,
      credentials: 'include', // sends cookies
    };

    try {
      let response = await fetch(url, config);

      // Handle 401 & Silent Refresh
      if (response.status === 401 && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/refresh')) {
        if (!this.isRefreshing) {
          this.isRefreshing = true;
          try {
            const refreshResp = await fetch(`${API_BASE}/auth/refresh`, {
              method: 'POST',
              credentials: 'include',
              headers: { 'Content-Type': 'application/json' },
            });

            if (refreshResp.ok) {
              const refreshData = await refreshResp.json();
              this.setToken(refreshData.access_token);
              this.isRefreshing = false;
              this.onRefreshed(refreshData.access_token);
              // Retry original request
              headers['Authorization'] = `Bearer ${refreshData.access_token}`;
              return (await fetch(url, { ...config, headers })).json();
            } else {
              this.isRefreshing = false;
              this.setToken(null);
              window.dispatchEvent(new CustomEvent('auth:expired'));
              throw new Error('Session expired. Please log in again.');
            }
          } catch (err) {
            this.isRefreshing = false;
            this.setToken(null);
            window.dispatchEvent(new CustomEvent('auth:expired'));
            throw err;
          }
        } else {
          // Wait for active refresh
          return new Promise(resolve => {
            this.subscribeTokenRefresh(newToken => {
              headers['Authorization'] = `Bearer ${newToken}`;
              resolve(fetch(url, { ...config, headers }).then(r => r.json()));
            });
          });
        }
      }

      if (response.status === 204) return null;

      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('text/csv') || contentType.includes('application/pdf')) {
        return response.blob();
      }

      const data = await response.json();
      if (!response.ok) {
        const errorMsg = data.detail || data.message || 'An unexpected error occurred';
        throw new Error(errorMsg);
      }
      return data;
    } catch (err) {
      throw err;
    }
  }

  get(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'GET' });
  }

  post(endpoint, body, options = {}) {
    const isForm = body instanceof FormData;
    return this.request(endpoint, {
      ...options,
      method: 'POST',
      body: isForm ? body : JSON.stringify(body)
    });
  }

  patch(endpoint, body, options = {}) {
    return this.request(endpoint, {
      ...options,
      method: 'PATCH',
      body: JSON.stringify(body)
    });
  }

  delete(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'DELETE' });
  }
}

const api = new ApiClient();
window.api = api;
