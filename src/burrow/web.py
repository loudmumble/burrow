import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from .config import BurrowConfig

_TUNNELS: list[dict] = []
_PIVOTS: list[dict] = []
_TARGETS: list[dict] = []


def create_app(config: BurrowConfig | None = None) -> FastAPI:
    cfg = config or BurrowConfig()

    app = FastAPI(
        title="Burrow",
        description="Network Pivoting and Tunneling Tool",
        version="0.1.0b1",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    return app


from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.get("/")
def index() -> HTMLResponse:
    return HTMLResponse(_WEB_UI)


@router.get("/health")
def health_check() -> dict:
    return {"status": "ok", "service": "burrow", "version": "0.1.0b1"}


@router.get("/api/tunnels")
def list_tunnels() -> dict:
    return {"tunnels": _TUNNELS, "count": len(_TUNNELS)}


@router.post("/api/tunnels")
def create_tunnel(data: dict) -> dict:
    tunnel = {
        "id": f"tunnel_{len(_TUNNELS) + 1}",
        "type": data.get("type", "local"),
        "local": data.get("local", "127.0.0.1:8080"),
        "remote": data.get("remote", "10.0.0.1:80"),
        "protocol": data.get("protocol", "tcp"),
        "status": "active",
    }
    _TUNNELS.append(tunnel)
    return {"tunnel": tunnel, "message": "Tunnel created"}


@router.delete("/api/tunnels/{tunnel_id}")
def delete_tunnel(tunnel_id: str) -> dict:
    global _TUNNELS
    _TUNNELS = [t for t in _TUNNELS if t["id"] != tunnel_id]
    return {"message": "Tunnel deleted"}


@router.get("/api/pivots")
def list_pivots() -> dict:
    return {"pivots": _PIVOTS, "count": len(_PIVOTS)}


@router.post("/api/pivots")
def create_pivot(data: dict) -> dict:
    hops = data.get("hops", [])
    pivot = {
        "id": f"pivot_{len(_PIVOTS) + 1}",
        "hops": hops,
        "depth": len(hops),
        "status": "active",
    }
    _PIVOTS.append(pivot)
    return {"pivot": pivot, "message": "Pivot chain created"}


@router.get("/api/targets")
def list_targets() -> dict:
    return {"targets": _TARGETS, "count": len(_TARGETS)}


@router.post("/api/discover")
def discover_network(data: dict) -> dict:
    network = data.get("network", "192.168.1")
    global _TARGETS
    _TARGETS = [
        {"ip": f"{network}.{i}", "services": ["22", "80"], "pivot_ports": ["443"]}
        for i in [10, 20, 50, 100]
    ]
    return {"targets": _TARGETS, "count": len(_TARGETS)}


_WEB_UI = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Burrow — Network Pivoting</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a12;--surface:#12121f;--border:#1e1e35;--text:#e0e0f0;--dim:#666;--accent:#ff9f43;--accent2:#e67e22;--danger:#ff4466;--safe:#00cc66;--cyan:#00ccff}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}
.container{max-width:1200px;margin:0 auto;padding:2rem}
header{text-align:center;margin-bottom:2rem}
header h1{font-size:3rem;background:linear-gradient(135deg,var(--accent),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-weight:800;letter-spacing:4px;animation:glow 2s ease-in-out infinite alternate}
@keyframes glow{from{filter:drop-shadow(0 0 10px rgba(255,159,67,0.3))}to{filter:drop-shadow(0 0 20px rgba(0,204,255,0.5))}}
header p{color:var(--dim);margin-top:0.5rem;font-size:1.1rem}
.dashboard{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:2rem}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;text-align:center}
.stat-card .value{font-size:2rem;font-weight:700;color:var(--accent)}
.stat-card .label{color:var(--dim);font-size:0.85rem;text-transform:uppercase}
.tabs{display:flex;gap:0.5rem;margin-bottom:1.5rem;border-bottom:1px solid var(--border);padding-bottom:0.5rem}
.tab{padding:0.5rem 1rem;background:transparent;border:none;color:var(--dim);cursor:pointer;border-radius:8px 8px 0 0}
.tab:hover{color:var(--text)}
.tab.active{background:var(--surface);color:var(--accent)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem}
.card h2{color:var(--accent);margin-bottom:1rem;font-size:1.2rem}
.form-group{margin-bottom:1rem}
.form-group label{display:block;margin-bottom:0.3rem;color:var(--dim);font-size:0.9rem}
.form-group input{width:100%;padding:0.7rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text)}
.form-group input:focus{outline:none;border-color:var(--accent)}
.btn{padding:0.6rem 1.2rem;border:none;border-radius:6px;cursor:pointer;font-size:0.9rem;font-weight:600}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{opacity:0.9}
.btn-danger{background:var(--danger);color:#fff}
.hidden{display:none}
.tunnel-list{max-height:400px;overflow-y:auto}
.tunnel-item{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:0.5rem;display:flex;justify-content:space-between;align-items:center}
.tunnel-item .info{font-family:monospace}
.tunnel-item .status{font-size:0.8rem;padding:0.2rem 0.5rem;border-radius:4px;background:rgba(0,204,102,0.15);color:var(--safe)}
.target-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1rem}
.target-card{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:1rem}
.target-card .ip{font-weight:600;font-family:monospace;color:var(--accent)}
.target-card .services{color:var(--dim);font-size:0.85rem;margin-top:0.3rem}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>BURROW</h1>
        <p>Network Pivoting and Tunneling Tool</p>
    </header>

    <div class="dashboard">
        <div class="stat-card">
            <div class="value" id="tunnelCount">0</div>
            <div class="label">Active Tunnels</div>
        </div>
        <div class="stat-card">
            <div class="value" id="pivotCount">0</div>
            <div class="label">Pivot Chains</div>
        </div>
        <div class="stat-card">
            <div class="value" id="targetCount">0</div>
            <div class="label">Discovered Targets</div>
        </div>
    </div>

    <div class="tabs">
        <button class="tab active" data-tab="tunnels">Tunnels</button>
        <button class="tab" data-tab="pivots">Pivots</button>
        <button class="tab" data-tab="discover">Discover</button>
    </div>

    <div id="tab-tunnels" class="tab-content">
        <div class="card">
            <h2>Create Tunnel</h2>
            <form id="tunnelForm">
                <div class="form-group">
                    <label>Type</label>
                    <select id="tunnelType"><option value="local">Local Forward</option><option value="reverse">Reverse</option></select>
                </div>
                <div class="form-group">
                    <label>Local Address (host:port)</label>
                    <input type="text" id="localAddr" value="127.0.0.1:8080">
                </div>
                <div class="form-group">
                    <label>Remote Address (host:port)</label>
                    <input type="text" id="remoteAddr" value="10.0.0.1:80">
                </div>
                <button type="submit" class="btn btn-primary">Create Tunnel</button>
            </form>
        </div>
        <div class="card">
            <h2>Active Tunnels</h2>
            <div class="tunnel-list" id="tunnelList"><p style="color:var(--dim)">No tunnels</p></div>
        </div>
    </div>

    <div id="tab-pivots" class="tab-content hidden">
        <div class="card">
            <h2>Create Pivot Chain</h2>
            <form id="pivotForm">
                <div class="form-group">
                    <label>Hops (comma-separated host:port)</label>
                    <input type="text" id="hopsInput" placeholder="10.0.0.1:22,10.0.0.2:443">
                </div>
                <button type="submit" class="btn btn-primary">Create Pivot</button>
            </form>
        </div>
        <div class="card">
            <h2>Pivot Chains</h2>
            <div class="tunnel-list" id="pivotList"><p style="color:var(--dim)">No pivots</p></div>
        </div>
    </div>

    <div id="tab-discover" class="tab-content hidden">
        <div class="card">
            <h2>Network Discovery</h2>
            <form id="discoverForm">
                <div class="form-group">
                    <label>Network Prefix (e.g. 192.168.1)</label>
                    <input type="text" id="networkPrefix" value="192.168.1">
                </div>
                <button type="submit" class="btn btn-primary">Scan Network</button>
            </form>
        </div>
        <div class="card">
            <h2>Targets</h2>
            <div class="target-grid" id="targetList"><p style="color:var(--dim)">No targets discovered</p></div>
        </div>
    </div>
</div>

<script>
const API = '';

async function loadStats() {
    const [t, p, ta] = await Promise.all([
        fetch(API + '/api/tunnels').then(r => r.json()),
        fetch(API + '/api/pivots').then(r => r.json()),
        fetch(API + '/api/targets').then(r => r.json())
    ]);
    document.getElementById('tunnelCount').textContent = t.count;
    document.getElementById('pivotCount').textContent = p.count;
    document.getElementById('targetCount').textContent = ta.count;
}

async function loadTunnels() {
    const d = await fetch(API + '/api/tunnels').then(r => r.json());
    if (!d.tunnels.length) {
        document.getElementById('tunnelList').innerHTML = '<p style="color:var(--dim)">No tunnels</p>';
        return;
    }
    document.getElementById('tunnelList').innerHTML = d.tunnels.map(t => `
        <div class="tunnel-item">
            <div class="info">${t.local} → ${t.remote}</div>
            <span class="status">${t.status}</span>
        </div>
    `).join('');
}

async function loadPivots() {
    const d = await fetch(API + '/api/pivots').then(r => r.json());
    if (!d.pivots.length) {
        document.getElementById('pivotList').innerHTML = '<p style="color:var(--dim)">No pivots</p>';
        return;
    }
    document.getElementById('pivotList').innerHTML = d.pivots.map(p => `
        <div class="tunnel-item">
            <div class="info">${p.hops.join(' → ')}</div>
            <span class="status">${p.depth} hops</span>
        </div>
    `).join('');
}

async function loadTargets() {
    const d = await fetch(API + '/api/targets').then(r => r.json());
    if (!d.targets.length) {
        document.getElementById('targetList').innerHTML = '<p style="color:var(--dim)">No targets discovered</p>';
        return;
    }
    document.getElementById('targetList').innerHTML = d.targets.map(t => `
        <div class="target-card">
            <div class="ip">${t.ip}</div>
            <div class="services">Services: ${t.services.join(', ')}</div>
        </div>
    `).join('');
}

document.getElementById('tunnelForm').addEventListener('submit', async e => {
    e.preventDefault();
    await fetch(API + '/api/tunnels', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            type: document.getElementById('tunnelType').value,
            local: document.getElementById('localAddr').value,
            remote: document.getElementById('remoteAddr').value
        })
    });
    loadTunnels();
    loadStats();
});

document.getElementById('pivotForm').addEventListener('submit', async e => {
    e.preventDefault();
    const hops = document.getElementById('hopsInput').value.split(',').map(h => h.trim());
    await fetch(API + '/api/pivots', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({hops})
    });
    loadPivots();
    loadStats();
});

document.getElementById('discoverForm').addEventListener('submit', async e => {
    e.preventDefault();
    await fetch(API + '/api/discover', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({network: document.getElementById('networkPrefix').value})
    });
    loadTargets();
    loadStats();
});

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab).classList.remove('hidden');
    });
});

loadStats();
loadTunnels();
loadPivots();
loadTargets();
</script>
</body>
</html>"""
