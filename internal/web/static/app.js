function dashboard() {
  return {
    sessions: [],
    selected: null,
    tunnels: [],
    routes: [],
    newTunnel: { direction: 'local', listen: '', remote: '', protocol: 'tcp' },
    newRoute: { cidr: '' },

    init() {
      this.fetchSessions();
      this.connectSSE();
      setInterval(() => this.fetchSessions(), 5000);
    },

    async fetchSessions() {
      try {
        const res = await fetch('/api/sessions');
        if (res.ok) this.sessions = await res.json();
      } catch (e) {
        console.error('fetch sessions:', e);
      }
    },

    async selectSession(id) {
      this.selected = id;
      try {
        const [tunnels, routes] = await Promise.all([
          fetch('/api/sessions/' + id + '/tunnels').then(r => r.json()),
          fetch('/api/sessions/' + id + '/routes').then(r => r.json())
        ]);
        this.tunnels = tunnels;
        this.routes = routes;
      } catch (e) {
        console.error('fetch detail:', e);
      }
    },

    connectSSE() {
      const es = new EventSource('/api/events');
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
          headers: { 'Content-Type': 'application/json' },
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
        await fetch('/api/sessions/' + this.selected + '/tunnels/' + id, { method: 'DELETE' });
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
          headers: { 'Content-Type': 'application/json' },
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
        await fetch('/api/sessions/' + this.selected + '/routes/' + encodeURIComponent(cidr), { method: 'DELETE' });
        this.selectSession(this.selected);
      } catch (e) {
        console.error('remove route:', e);
      }
    }
  };
}
