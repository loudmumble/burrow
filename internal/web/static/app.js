function dashboard() {
  return {
    sessions: [],
    selected: null,
    tunnels: [],
    routes: [],
    newTunnel: { direction: 'local', listen: '', remote: '', protocol: 'tcp' },
    newRoute: { cidr: '' },

    init() {
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.has("token")) {
        this.token = urlParams.get("token");
        localStorage.setItem("burrow_token", this.token);
        window.history.replaceState({}, document.title, window.location.pathname);
      } else {
        this.token = localStorage.getItem("burrow_token");
        const res = await fetch("/api/sessions", {
          headers: this.token ? { "Authorization": "Bearer " + this.token } : {}
        });
        if (res.status === 401) {
          console.error("Unauthorized: Invalid or missing token");
          return;
        }
        if (res.ok) this.sessions = await res.json();
      this.connectSSE();
      setInterval(() => this.fetchSessions(), 5000);
        const fetchOpts = this.token ? { headers: { "Authorization": "Bearer " + this.token } } : {};
        const [tunnels, routes] = await Promise.all([
          fetch("/api/sessions/" + id + "/tunnels", fetchOpts).then(r => r.json()),
          fetch("/api/sessions/" + id + "/routes", fetchOpts).then(r => r.json())
        ]);
        const res = await fetch('/api/sessions');
        if (res.ok) this.sessions = await res.json();
      } catch (e) {
        console.error('fetch sessions:', e);
      }
    },
    connectSSE() {
      let url = "/api/events";
      if (this.token) {
        url += "?token=" + encodeURIComponent(this.token);
      }
      const es = new EventSource(url);
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
        const res = await fetch("/api/sessions/" + this.selected + "/tunnels", {
          method: "POST",
          headers: { 
            "Content-Type": "application/json",
            ...(this.token ? { "Authorization": "Bearer " + this.token } : {})
          },
          body: JSON.stringify({
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
        await fetch("/api/sessions/" + this.selected + "/tunnels/" + id, { 
          method: "DELETE",
          headers: this.token ? { "Authorization": "Bearer " + this.token } : {}
        });
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            direction: this.newTunnel.direction,
            listen: this.newTunnel.listen,
            remote: this.newTunnel.remote,
        const res = await fetch("/api/sessions/" + this.selected + "/routes", {
          method: "POST",
          headers: { 
            "Content-Type": "application/json",
            ...(this.token ? { "Authorization": "Bearer " + this.token } : {})
          },
          body: JSON.stringify({ cidr: this.newRoute.cidr })
          this.newTunnel = { direction: 'local', listen: '', remote: '', protocol: 'tcp' };
          this.selectSession(this.selected);
        }
      } catch (e) {
        console.error('add tunnel:', e);
      }
    },

    async removeTunnel(id) {
      try {
        await fetch("/api/sessions/" + this.selected + "/routes/" + encodeURIComponent(cidr), { 
          method: "DELETE",
          headers: this.token ? { "Authorization": "Bearer " + this.token } : {}
        });
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
