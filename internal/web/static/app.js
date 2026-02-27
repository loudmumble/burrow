function dashboard() {
  return {
    sessions: [],
    selected: null,
    selectedSessionData: null,
    tunnels: [],
    routes: [],
    token: null,
    newTunnel: { direction: 'local', listen: '', remote: '', protocol: 'tcp' },
    newRoute: { cidr: '' },
    connected: false,
    errorMessage: '',

    // ── Helpers ──────────────────────────────────────────────────────────────

    formatBytes(n) {
      if (!n || n === 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
      return (n / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
    },

    timeAgo(ts) {
      if (!ts) return '—';
      const diff = Date.now() - new Date(ts).getTime();
      const secs = Math.floor(diff / 1000);
      if (secs < 10) return 'just now';
      if (secs < 60) return secs + 's ago';
      const mins = Math.floor(secs / 60);
      if (mins < 60) return mins + 'm ago';
      const hrs = Math.floor(mins / 60);
      if (hrs < 24) return hrs + 'h ago';
      const days = Math.floor(hrs / 24);
      return days + 'd ago';
    },

    osIcon(os) {
      if (!os) return '◌';
      const lower = os.toLowerCase();
      if (lower.includes('linux')) return '🐧';
      if (lower.includes('windows') || lower.includes('win')) return '🪟';
      if (lower.includes('darwin') || lower.includes('mac')) return '🍎';
      if (lower.includes('freebsd') || lower.includes('bsd')) return '👹';
      if (lower.includes('android')) return '🤖';
      return '◌';
    },

    directionBadgeClass(dir) {
      const map = { local: 'badge badge-local', remote: 'badge badge-remote', reverse: 'badge badge-reverse' };
      return map[dir] || 'badge badge-local';
    },

    protoBadgeClass(proto) {
      const map = { tcp: 'badge badge-tcp', udp: 'badge badge-udp' };
      return map[proto] || 'badge badge-tcp';
    },

    truncateId(id) {
      if (!id) return '';
      return id.length > 14 ? id.substring(0, 14) + '…' : id;
    },

    copyToClipboard(text) {
      if (!text) return;
      navigator.clipboard.writeText(text).catch(() => {});
    },

    // ── Init ─────────────────────────────────────────────────────────────────

    init() {
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.has('token')) {
        this.token = urlParams.get('token');
        localStorage.setItem('burrow_token', this.token);
        window.history.replaceState({}, document.title, window.location.pathname);
      } else {
        this.token = localStorage.getItem('burrow_token');
      }
      this.fetchSessions();
      this.connectSSE();
      setInterval(() => this.fetchSessions(), 5000);
    },

    authHeaders(extra) {
      const h = Object.assign({}, extra || {});
      if (this.token) h['Authorization'] = 'Bearer ' + this.token;
      return h;
    },

    showError(msg) {
      this.errorMessage = msg;
      setTimeout(() => { if (this.errorMessage === msg) this.errorMessage = ''; }, 15000);
    },

    dismissError() {
      this.errorMessage = '';
    },

    handleFetchError(res, context) {
      if (res.status === 401) {
        this.showError('Authentication failed (401). Check your API token. If using a self-signed certificate, ensure you have accepted it in your browser.');
        return true;
      }
      if (!res.ok) {
        this.showError(context + ': server returned status ' + res.status);
        return true;
      }
      return false;
    },

    // ── API calls ─────────────────────────────────────────────────────────────

    async fetchSessions() {
      try {
        const res = await fetch('/api/sessions', { headers: this.authHeaders() });
        if (this.handleFetchError(res, 'Fetch sessions')) return;
        this.sessions = await res.json();
        if (this.selected) {
          this.selectedSessionData = this.sessions.find(s => s.id === this.selected) || null;
        }
      } catch (e) {
        this.showError('Cannot reach server. If using HTTPS with a self-signed certificate, open the server URL directly in your browser and accept the certificate first.');
        console.error('fetch sessions:', e);
      }
    },

    async selectSession(id) {
      this.selected = id;
      this.selectedSessionData = this.sessions.find(s => s.id === id) || null;
      try {
        const opts = { headers: this.authHeaders() };
        const [tRes, rRes] = await Promise.all([
          fetch('/api/sessions/' + id + '/tunnels', opts),
          fetch('/api/sessions/' + id + '/routes', opts)
        ]);
        if (this.handleFetchError(tRes, 'Fetch tunnels')) return;
        if (this.handleFetchError(rRes, 'Fetch routes')) return;
        this.tunnels = await tRes.json();
        this.routes = await rRes.json();
      } catch (e) {
        this.showError('Failed to load session details. Check your connection and certificate.');
        console.error('fetch detail:', e);
      }
    },

    connectSSE() {
      let url = '/api/events';
      if (this.token) url += '?token=' + encodeURIComponent(this.token);
      const es = new EventSource(url);
      es.onopen = () => {
        this.connected = true;
      };
      es.onmessage = (e) => {
        try {
          const evt = JSON.parse(e.data);
          if (evt.type && evt.type.startsWith('session.')) this.fetchSessions();
          if (evt.type && (evt.type.startsWith('tunnel.') || evt.type.startsWith('route.'))) {
            if (this.selected) this.selectSession(this.selected);
          }
        } catch (err) {
          console.error('sse parse:', err);
        }
      };
      es.onerror = () => {
        this.connected = false;
        console.warn('SSE connection lost, will auto-reconnect');
      };
    },

    async addTunnel() {
      if (!this.selected) return;
      try {
        const res = await fetch('/api/sessions/' + this.selected + '/tunnels', {
          method: 'POST',
          headers: Object.assign({ 'Content-Type': 'application/json' }, this.authHeaders()),
          body: JSON.stringify({
            direction: this.newTunnel.direction,
            listen: this.newTunnel.listen,
            remote: this.newTunnel.remote,
            protocol: this.newTunnel.protocol
          })
        });
        if (this.handleFetchError(res, 'Add tunnel')) return;
        if (res.ok) {
          this.newTunnel = { direction: 'local', listen: '', remote: '', protocol: 'tcp' };
          this.selectSession(this.selected);
        }
      } catch (e) {
        this.showError('Failed to add tunnel. Check your connection.');
        console.error('add tunnel:', e);
      }
    },

    async removeTunnel(id) {
      if (!this.selected) return;
      try {
        const res = await fetch('/api/sessions/' + this.selected + '/tunnels/' + id, {
          method: 'DELETE',
          headers: this.authHeaders()
        });
        if (this.handleFetchError(res, 'Remove tunnel')) return;
        this.selectSession(this.selected);
      } catch (e) {
        this.showError('Failed to remove tunnel. Check your connection.');
        console.error('remove tunnel:', e);
      }
    },

    async addRoute() {
      if (!this.selected) return;
      try {
        const res = await fetch('/api/sessions/' + this.selected + '/routes', {
          method: 'POST',
          headers: Object.assign({ 'Content-Type': 'application/json' }, this.authHeaders()),
          body: JSON.stringify({ cidr: this.newRoute.cidr })
        });
        if (this.handleFetchError(res, 'Add route')) return;
        if (res.ok) {
          this.newRoute = { cidr: '' };
          this.selectSession(this.selected);
        }
      } catch (e) {
        this.showError('Failed to add route. Check your connection.');
        console.error('add route:', e);
      }
    },

    async removeRoute(cidr) {
      if (!this.selected) return;
      try {
        const res = await fetch('/api/sessions/' + this.selected + '/routes/' + encodeURIComponent(cidr), {
          method: 'DELETE',
          headers: this.authHeaders()
        });
        if (this.handleFetchError(res, 'Remove route')) return;
        this.selectSession(this.selected);
      } catch (e) {
        this.showError('Failed to remove route. Check your connection.');
        console.error('remove route:', e);
      }
    }
  };
}
