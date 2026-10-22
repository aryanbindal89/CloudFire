import socket
import struct
import time
import subprocess
import os
import sqlite3
import threading
import webbrowser
import platform
import uvicorn
from collections import defaultdict
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

# ==========================================
# MODULE 1: DATABASE MANAGER
# ==========================================
class DatabaseManager:
    def __init__(self, db_path="cloudfire.db"):
        self.db_path = db_path
        self.init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        with self._get_conn() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS traffic (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, ip TEXT, protocol TEXT, size INTEGER)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS blocks (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, ip TEXT, reason TEXT)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS syslogs (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, level TEXT, msg TEXT)''')

    def log_event(self, level, msg):
        with self._get_conn() as conn:
            conn.execute("INSERT INTO syslogs (level, msg) VALUES (?, ?)", (level, msg))

    def log_traffic(self, ip, proto, size):
        with self._get_conn() as conn:
            conn.execute("INSERT INTO traffic (ip, protocol, size) VALUES (?, ?, ?)", (ip, proto, size))

    def log_block(self, ip, reason):
        with self._get_conn() as conn:
            conn.execute("INSERT INTO blocks (ip, reason) VALUES (?, ?)", (ip, reason))

    def remove_block(self, ip):
        with self._get_conn() as conn:
            conn.execute("DELETE FROM blocks WHERE ip = ?", (ip,))

    def fetch_all(self, query):
        with self._get_conn() as conn:
            return conn.execute(query).fetchall()

    def fetch_one(self, query):
        with self._get_conn() as conn:
            return conn.execute(query).fetchone()

db = DatabaseManager()

# ==========================================
# MODULE 2: ACTIVE DEFENSE ENGINE (SNIFFER)
# ==========================================
class DefenseEngine:
    def __init__(self, max_packets=20, time_window=3):
        self.MAX_PACKETS = max_packets
        self.TIME_WINDOW = time_window
        self.whitelist = ['127.0.0.1']
        self.tracker = defaultdict(list)
        self.blocked_ips = set()
        
        # Restore previously blocked IPs from DB
        for row in db.fetch_all("SELECT ip FROM blocks"):
            self.blocked_ips.add(row[0])

    def block_ip(self, ip, reason):
        if ip in self.blocked_ips or ip in self.whitelist: return
        
        db.log_event("CRITICAL", f"Threat Detected: {ip} ({reason})")
        cmd = f'netsh advfirewall firewall add rule name="CloudFire_Block_{ip}" dir=in action=block remoteip={ip}'
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        self.blocked_ips.add(ip)
        db.log_block(ip, reason)
        db.log_event("SUCCESS", f"OS-Level Ban applied to {ip}")

    def unblock_ip(self, ip):
        if ip in self.blocked_ips:
            cmd = f'netsh advfirewall firewall delete rule name="CloudFire_Block_{ip}"'
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.blocked_ips.remove(ip)
            db.remove_block(ip)
            db.log_event("INFO", f"Ban lifted for {ip} by Admin.")
            return True
        return False

    def run(self):
        local_ip = socket.gethostbyname(socket.gethostname())
        self.whitelist.append(local_ip)
        db.log_event("INFO", f"Engine started on {local_ip} | OS: {platform.system()}")

        try:
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((local_ip, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except PermissionError:
            print("[!] ERROR: Must run as Administrator!")
            db.log_event("ERROR", "Boot failed: Admin privileges missing.")
            os._exit(1)

        while True:
            try:
                raw_data, _ = sniffer.recvfrom(65535)
                iph = struct.unpack('!BBHHHBBH4s4s', raw_data[0:20])
                src_ip = socket.inet_ntoa(iph[8])
                proto = "TCP" if iph[6] == 6 else ("UDP" if iph[6] == 17 else ("ICMP" if iph[6] == 1 else "OTHER"))

                if src_ip not in self.blocked_ips and src_ip not in self.whitelist:
                    db.log_traffic(src_ip, proto, len(raw_data))
                    now = time.time()
                    self.tracker[src_ip].append(now)
                    self.tracker[src_ip] = [t for t in self.tracker[src_ip] if now - t <= self.TIME_WINDOW]
                    
                    if len(self.tracker[src_ip]) > self.MAX_PACKETS:
                        self.block_ip(src_ip, "DDoS/Flood Attack")
            except Exception: pass

engine = DefenseEngine()

# ==========================================
# MODULE 3: FASTAPI & SPA FRONTEND
# ==========================================
app = FastAPI(title="CloudFire SaaS")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def spa_frontend():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CloudFire WAF Console</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
        <style>
            :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --accent: #3b82f6; --danger: #ef4444; --success: #10b981; }
            body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; margin: 0; display: flex; height: 100vh; overflow: hidden; }
            
            /* Sidebar */
            .sidebar { width: 250px; background: #0b1120; padding: 20px; display: flex; flex-direction: column; gap: 10px; border-right: 1px solid #334155; }
            .logo { font-size: 1.5em; font-weight: 800; color: var(--accent); margin-bottom: 30px; letter-spacing: 1px; }
            .nav-item { padding: 12px 15px; background: transparent; color: #94a3b8; border: none; text-align: left; font-size: 1em; font-weight: 600; cursor: pointer; border-radius: 8px; transition: 0.2s; }
            .nav-item:hover { background: #1e293b; color: white; }
            .nav-item.active { background: var(--accent); color: white; }
            
            /* Main Content */
            .content { flex: 1; padding: 30px; overflow-y: auto; }
            .page { display: none; animation: fadeIn 0.3s ease; }
            .page.active { display: block; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
            
            /* Dashboard Cards */
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .card { background: var(--card); padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); border-top: 4px solid var(--accent); }
            .card.red { border-top-color: var(--danger); }
            .card h3 { margin: 0 0 10px 0; color: #94a3b8; font-size: 0.9em; text-transform: uppercase; }
            .card h1 { margin: 0; font-size: 2.8em; }
            
            /* Tables */
            .table-wrap { background: var(--card); border-radius: 12px; padding: 20px; overflow: hidden; }
            table { width: 100%; border-collapse: collapse; text-align: left; }
            th { padding: 15px; color: #94a3b8; font-size: 0.85em; text-transform: uppercase; border-bottom: 2px solid #334155; }
            td { padding: 15px; border-bottom: 1px solid #334155; font-size: 0.95em; }
            .badge { padding: 5px 10px; border-radius: 20px; font-size: 0.8em; font-weight: bold; }
            .bg-red { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
            .bg-green { background: rgba(16, 185, 129, 0.2); color: var(--success); }
            .btn-unblock { background: var(--danger); color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-weight: 600; }
            .btn-unblock:hover { background: #b91c1c; }

            /* Terminal */
            .terminal { background: #000; color: #0f0; font-family: monospace; padding: 20px; border-radius: 8px; height: 60vh; overflow-y: auto; }
            .term-line { margin-bottom: 5px; border-bottom: 1px dashed #222; padding-bottom: 5px;}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="logo">🛡️ CloudFire</div>
            <button class="nav-item active" onclick="switchTab('dashboard')">📊 Dashboard</button>
            <button class="nav-item" onclick="switchTab('traffic')">📡 Live Traffic</button>
            <button class="nav-item" onclick="switchTab('system')">⚙️ System Logs</button>
        </div>

        <div class="content">
            <!-- TAB 1: DASHBOARD -->
            <div id="dashboard" class="page active">
                <h2>Security Overview</h2>
                <div class="grid">
                    <div class="card"><h3>Packets Scanned</h3><h1 id="stat-req">0</h1></div>
                    <div class="card red"><h3>Threats Neutralized</h3><h1 id="stat-block">0</h1></div>
                </div>
                <div class="table-wrap">
                    <h3>Active OS Blocks (Blocklist)</h3>
                    <table>
                        <thead><tr><th>Time</th><th>Attacker IP</th><th>Reason</th><th>Action</th></tr></thead>
                        <tbody id="blocklist-ui"></tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 2: TRAFFIC -->
            <div id="traffic" class="page">
                <h2>Raw Packet Monitor</h2>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Timestamp</th><th>Source IP</th><th>Protocol</th><th>Payload Size</th></tr></thead>
                        <tbody id="traffic-ui"></tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 3: LOGS -->
            <div id="system" class="page">
                <h2>System & Engine Logs</h2>
                <div class="terminal" id="sys-ui"></div>
            </div>
        </div>

        <script>
            // SPA Tab Switching Logic
            function switchTab(tabId) {
                document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
                document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
                document.getElementById(tabId).classList.add('active');
                event.target.classList.add('active');
            }

            // API calls
            async function unblockIP(ip) {
                await fetch(`/api/unblock/${ip}`, {method: 'POST'});
                fetchData(); // Refresh UI instantly
            }

            async function fetchData() {
                try {
                    // Stats
                    const stats = await (await fetch('/api/stats')).json();
                    document.getElementById('stat-req').innerText = stats.reqs;
                    document.getElementById('stat-block').innerText = stats.blocks;

                    // Blocklist
                    const blocks = await (await fetch('/api/blocks')).json();
                    document.getElementById('blocklist-ui').innerHTML = blocks.map(b => 
                        `<tr><td>${b.time}</td><td><span class="badge bg-red">${b.ip}</span></td><td>${b.reason}</td>
                        <td><button class="btn-unblock" onclick="unblockIP('${b.ip}')">Unblock</button></td></tr>`
                    ).join('');

                    // Traffic
                    const traffic = await (await fetch('/api/traffic')).json();
                    document.getElementById('traffic-ui').innerHTML = traffic.map(t => 
                        `<tr><td style="color:#94a3b8">${t.time}</td><td>${t.ip}</td>
                        <td><span class="badge bg-green">${t.proto}</span></td><td>${t.size} Bytes</td></tr>`
                    ).join('');

                    // Syslogs
                    const logs = await (await fetch('/api/syslogs')).json();
                    document.getElementById('sys-ui').innerHTML = logs.map(l => 
                        `<div class="term-line">[${l.time}] [${l.level}] ${l.msg}</div>`
                    ).join('');
                } catch(e) {}
            }

            setInterval(fetchData, 1500);
            fetchData();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

# --- API Endpoints ---
@app.get("/api/stats")
def api_stats():
    r = db.fetch_one("SELECT COUNT(*) FROM traffic")
    b = db.fetch_one("SELECT COUNT(*) FROM blocks")
    return {"reqs": r[0] if r else 0, "blocks": b[0] if b else 0}

@app.get("/api/blocks")
def api_blocks():
    return [{"time": r[1], "ip": r[2], "reason": r[3]} for r in db.fetch_all("SELECT * FROM blocks ORDER BY id DESC")]

@app.get("/api/traffic")
def api_traffic():
    return [{"time": r[1], "ip": r[2], "proto": r[3], "size": r[4]} for r in db.fetch_all("SELECT * FROM traffic ORDER BY id DESC LIMIT 50")]

@app.get("/api/syslogs")
def api_syslogs():
    return [{"time": r[1], "level": r[2], "msg": r[3]} for r in db.fetch_all("SELECT * FROM syslogs ORDER BY id DESC LIMIT 100")]

@app.post("/api/unblock/{ip}")
def api_unblock(ip: str):
    success = engine.unblock_ip(ip)
    return {"status": "success" if success else "failed"}

# ==========================================
# LAUNCHER
# ==========================================
if __name__ == "__main__":
    print("\n[*] Initializing CloudFire Advanced Architecture...")
    threading.Thread(target=engine.run, daemon=True).start()
    threading.Timer(1.5, lambda: webbrowser.open("http://127.0.0.1:8000")).start()
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="error")