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

    // TUN state
    tunLoading: false,

    // Exec state
    execInput: '',
    execOutput: null,
    execError: '',
    execLoading: false,

    // Download state
    downloadPath: '',
    downloadResult: null,
    downloadFileName: '',
    downloadSize: '',
    downloadError: '',
    downloadLoading: false,
    _downloadData: null,

    // Upload state
    uploadPath: '',
    uploadFileData: null,
    uploadFileName: '',
    uploadError: '',
    uploadSuccess: '',
    uploadLoading: false,

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

    async stopTunnel(id) {
      if (!this.selected) return;
      try {
        const res = await fetch('/api/sessions/' + this.selected + '/tunnels/' + id + '/stop', {
          method: 'POST',
          headers: this.authHeaders()
        });
        if (this.handleFetchError(res, 'Stop tunnel')) return;
        this.selectSession(this.selected);
      } catch (e) {
        this.showError('Failed to stop tunnel. Check your connection.');
        console.error('stop tunnel:', e);
      }
    },

    async startTunnel(id) {
      if (!this.selected) return;
      try {
        const res = await fetch('/api/sessions/' + this.selected + '/tunnels/' + id + '/start', {
          method: 'POST',
          headers: this.authHeaders()
        });
        if (this.handleFetchError(res, 'Start tunnel')) return;
        this.selectSession(this.selected);
      } catch (e) {
        this.showError('Failed to start tunnel. Check your connection.');
        console.error('start tunnel:', e);
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
    },

    // ── TUN controls ─────────────────────────────────────────────────────────

    async startTun() {
      if (!this.selected) return;
      this.tunLoading = true;
      try {
        const res = await fetch('/api/sessions/' + this.selected + '/tun', {
          method: 'POST',
          headers: this.authHeaders()
        });
        if (this.handleFetchError(res, 'Start TUN')) return;
        this.fetchSessions();
      } catch (e) {
        this.showError('Failed to start TUN interface.');
        console.error('start tun:', e);
      } finally {
        this.tunLoading = false;
      }
    },

    async stopTun() {
      if (!this.selected) return;
      this.tunLoading = true;
      try {
        const res = await fetch('/api/sessions/' + this.selected + '/tun', {
          method: 'DELETE',
          headers: this.authHeaders()
        });
        if (this.handleFetchError(res, 'Stop TUN')) return;
        this.fetchSessions();
      } catch (e) {
        this.showError('Failed to stop TUN interface.');
        console.error('stop tun:', e);
      } finally {
        this.tunLoading = false;
      }
    },

    // ── Command execution ────────────────────────────────────────────────────

    async execCommand() {
      if (!this.selected || !this.execInput.trim()) return;
      this.execLoading = true;
      this.execOutput = null;
      this.execError = '';
      try {
        const res = await fetch('/api/sessions/' + this.selected + '/exec', {
          method: 'POST',
          headers: Object.assign({ 'Content-Type': 'application/json' }, this.authHeaders()),
          body: JSON.stringify({ command: this.execInput.trim() })
        });
        if (this.handleFetchError(res, 'Execute command')) return;
        const data = await res.json();
        this.execOutput = data.output || '';
        this.execError = data.error || '';
      } catch (e) {
        this.showError('Failed to execute command.');
        console.error('exec:', e);
      } finally {
        this.execLoading = false;
      }
    },

    // ── File download ────────────────────────────────────────────────────────

    async downloadFile() {
      if (!this.selected || !this.downloadPath.trim()) return;
      this.downloadLoading = true;
      this.downloadResult = null;
      this.downloadError = '';
      this._downloadData = null;
      try {
        const res = await fetch('/api/sessions/' + this.selected + '/download', {
          method: 'POST',
          headers: Object.assign({ 'Content-Type': 'application/json' }, this.authHeaders()),
          body: JSON.stringify({ file_path: this.downloadPath.trim() })
        });
        if (this.handleFetchError(res, 'Download file')) return;
        const data = await res.json();
        if (data.error) {
          this.downloadError = data.error;
          this.downloadResult = true;
          return;
        }
        this.downloadFileName = data.file_name || this.downloadPath.split(/[/\\]/).pop();
        this.downloadSize = this.formatBytes(data.size || 0);
        this._downloadData = data.data; // base64-encoded
        this.downloadResult = true;
      } catch (e) {
        this.showError('Failed to download file.');
        console.error('download:', e);
      } finally {
        this.downloadLoading = false;
      }
    },

    saveDownload() {
      if (!this._downloadData) return;
      try {
        const raw = atob(this._downloadData);
        const bytes = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
        const blob = new Blob([bytes], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = this.downloadFileName || 'download';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      } catch (e) {
        this.showError('Failed to save file.');
        console.error('save download:', e);
      }
    },

    // ── File upload ──────────────────────────────────────────────────────────

    handleFileSelect(event) {
      const file = event.target.files[0];
      if (!file) return;
      this.uploadFileName = file.name;
      const reader = new FileReader();
      reader.onload = () => {
        // Convert ArrayBuffer to base64
        const bytes = new Uint8Array(reader.result);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        this.uploadFileData = btoa(binary);
      };
      reader.readAsArrayBuffer(file);
    },

    async uploadFile() {
      if (!this.selected || !this.uploadPath.trim() || !this.uploadFileData) return;
      this.uploadLoading = true;
      this.uploadError = '';
      this.uploadSuccess = '';
      try {
        const res = await fetch('/api/sessions/' + this.selected + '/upload', {
          method: 'POST',
          headers: Object.assign({ 'Content-Type': 'application/json' }, this.authHeaders()),
          body: JSON.stringify({
            file_path: this.uploadPath.trim(),
            data: this.uploadFileData
          })
        });
        if (this.handleFetchError(res, 'Upload file')) return;
        const data = await res.json();
        if (data.error) {
          this.uploadError = data.error;
          return;
        }
        this.uploadSuccess = 'Uploaded ' + this.formatBytes(data.size || 0) + ' to ' + this.uploadPath;
        this.uploadPath = '';
        this.uploadFileData = null;
        this.uploadFileName = '';
      } catch (e) {
        this.showError('Failed to upload file.');
        console.error('upload:', e);
      } finally {
        this.uploadLoading = false;
      }
    }
  };
}
