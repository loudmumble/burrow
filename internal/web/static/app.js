function dashboard() {
  return {
    sessions: [],
    selected: null,
    tunnels: [],
    routes: [],
    token: null,
    newTunnel: { direction: 'local', listen: '', remote: '', protocol: 'tcp' },
    newRoute: { cidr: '' },
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

    async fetchSessions() {
      try {
        const res = await fetch('/api/sessions', { headers: this.authHeaders() });
        if (res.status === 401) { console.error('Unauthorized: invalid or missing token'); return; }
        if (res.ok) this.sessions = await res.json();
      } catch (e) {
        console.error('fetch sessions:', e);
      }
    },

    async selectSession(id) {
      this.selected = id;
      try {
        const opts = { headers: this.authHeaders() };
        const [tunnels, routes] = await Promise.all([
          fetch('/api/sessions/' + id + '/tunnels', opts).then(r => r.json()),
          fetch('/api/sessions/' + id + '/routes', opts).then(r => r.json())
        ]);
        this.tunnels = tunnels;
        this.routes = routes;
      } catch (e) {
        console.error('fetch detail:', e);
      }
    },

    connectSSE() {
      let url = '/api/events';
      if (this.token) url += '?token=' + encodeURIComponent(this.token);
      const es = new EventSource(url);
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
        if (res.ok) {
          this.newTunnel = { direction: 'local', listen: '', remote: '', protocol: 'tcp' };
          this.selectSession(this.selected);
        }
      } catch (e) {
        console.error('add tunnel:', e);
      }
    },
    async removeTunnel(id) {
      if (!this.selected) return;
      try {
        await fetch('/api/sessions/' + this.selected + '/tunnels/' + id, {
          method: 'DELETE',
          headers: this.authHeaders()
        });
        this.selectSession(this.selected);
      } catch (e) {
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
        if (res.ok) {
          this.newRoute = { cidr: '' };
          this.selectSession(this.selected);
        }
      } catch (e) {
        console.error('add route:', e);
      }
    },
    async removeRoute(cidr) {
      if (!this.selected) return;
      try {
        await fetch('/api/sessions/' + this.selected + '/routes/' + encodeURIComponent(cidr), {
          method: 'DELETE',
          headers: this.authHeaders()
        });
        this.selectSession(this.selected);
      } catch (e) {
        console.error('remove route:', e);
      }
    }
  };
}
