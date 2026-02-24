"""FastAPI web dashboard for Leatt."""

import threading
from pathlib import Path
from typing import Optional
from datetime import datetime

from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger("web")


class WebDashboard:
    """Web dashboard server using FastAPI."""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.config = get_config()
        
        self._app = None
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        
        self._fastapi_available = self._check_fastapi()
        
        if self._fastapi_available:
            self._create_app()
    
    def _check_fastapi(self) -> bool:
        """Check if FastAPI is available."""
        try:
            from fastapi import FastAPI
            from fastapi.responses import HTMLResponse
            import uvicorn
            return True
        except ImportError:
            logger.warning("FastAPI/uvicorn not available, web dashboard disabled")
            return False
    
    def _create_app(self) -> None:
        """Create the FastAPI application."""
        from fastapi import FastAPI, Request
        from fastapi.responses import HTMLResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
        
        self._app = FastAPI(
            title="Leatt Dashboard",
            description="Data Leak Prevention monitoring dashboard",
            version="0.1.0",
        )
        
        self._setup_routes()
        
        logger.info("FastAPI application created")
    
    def _setup_routes(self) -> None:
        """Setup API routes."""
        from fastapi import Request
        from fastapi.responses import HTMLResponse, JSONResponse
        
        app = self._app
        
        @app.get("/", response_class=HTMLResponse)
        async def index():
            """Main dashboard page."""
            return self._render_dashboard()
        
        @app.get("/api/status")
        async def get_status():
            """Get current system status."""
            from ..utils.database import get_database
            
            db = get_database()
            unacked_alerts = db.get_unacknowledged_alerts()
            
            return {
                "status": "running",
                "timestamp": datetime.utcnow().isoformat(),
                "unacknowledged_alerts": len(unacked_alerts),
                "learning_mode": self.config.learning_mode,
            }
        
        @app.get("/api/alerts")
        async def get_alerts(limit: int = 50):
            """Get recent alerts."""
            from ..utils.database import get_database
            
            db = get_database()
            alerts = db.get_recent_alerts(limit)
            
            return [
                {
                    "id": alert.id,
                    "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                    "severity": alert.severity,
                    "source": alert.source,
                    "process_name": alert.process_name,
                    "process_pid": alert.process_pid,
                    "description": alert.description,
                    "details": alert.details,
                    "acknowledged": alert.acknowledged,
                }
                for alert in alerts
            ]
        
        @app.post("/api/alerts/{alert_id}/acknowledge")
        async def acknowledge_alert(alert_id: int):
            """Acknowledge an alert."""
            from ..utils.database import get_database
            
            db = get_database()
            with db.get_session() as session:
                from ..utils.database import Alert
                alert = session.query(Alert).filter_by(id=alert_id).first()
                if alert:
                    alert.acknowledged = True
                    session.commit()
                    return {"success": True}
            
            return {"success": False, "error": "Alert not found"}
        
        @app.get("/api/processes")
        async def get_processes():
            """Get monitored processes."""
            from ..utils.database import get_database
            
            db = get_database()
            with db.get_session() as session:
                from ..utils.database import ProcessRecord
                processes = session.query(ProcessRecord).order_by(
                    ProcessRecord.last_seen.desc()
                ).limit(100).all()
                
                return [
                    {
                        "id": proc.id,
                        "pid": proc.pid,
                        "name": proc.name,
                        "path": proc.path,
                        "user": proc.user,
                        "is_trusted": proc.is_trusted,
                        "risk_score": proc.risk_score,
                        "first_seen": proc.first_seen.isoformat() if proc.first_seen else None,
                        "last_seen": proc.last_seen.isoformat() if proc.last_seen else None,
                    }
                    for proc in processes
                ]
        
        @app.get("/api/network")
        async def get_network_events(limit: int = 50):
            """Get recent network events."""
            from ..utils.database import get_database
            
            db = get_database()
            with db.get_session() as session:
                from ..utils.database import NetworkEvent
                events = session.query(NetworkEvent).order_by(
                    NetworkEvent.timestamp.desc()
                ).limit(limit).all()
                
                return [
                    {
                        "id": event.id,
                        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                        "process_name": event.process_name,
                        "process_pid": event.process_pid,
                        "remote_address": event.remote_address,
                        "remote_port": event.remote_port,
                        "bytes_sent": event.bytes_sent,
                        "bytes_received": event.bytes_received,
                    }
                    for event in events
                ]
        
        @app.get("/api/files")
        async def get_file_events(limit: int = 50, sensitive_only: bool = False):
            """Get recent file events."""
            from ..utils.database import get_database
            
            db = get_database()
            with db.get_session() as session:
                from ..utils.database import FileEvent
                query = session.query(FileEvent)
                if sensitive_only:
                    query = query.filter_by(is_sensitive=True)
                events = query.order_by(
                    FileEvent.timestamp.desc()
                ).limit(limit).all()
                
                return [
                    {
                        "id": event.id,
                        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                        "process_name": event.process_name,
                        "file_path": event.file_path,
                        "event_type": event.event_type,
                        "is_sensitive": event.is_sensitive,
                    }
                    for event in events
                ]
        
        @app.get("/api/whitelist")
        async def get_whitelist():
            """Get trusted process whitelist."""
            from ..trust.whitelist import Whitelist
            
            whitelist = Whitelist()
            entries = whitelist.get_all()
            
            return [
                {
                    "name": entry.name,
                    "path": entry.path,
                    "hash_sha256": entry.hash_sha256,
                    "publisher": entry.publisher,
                    "added_by": entry.added_by,
                    "reason": entry.reason,
                }
                for entry in entries
            ]
        
        @app.post("/api/whitelist")
        async def add_to_whitelist(request: Request):
            """Add a process to whitelist."""
            from ..trust.whitelist import Whitelist
            
            data = await request.json()
            whitelist = Whitelist()
            
            entry = whitelist.add(
                name=data.get("name"),
                path=data.get("path"),
                reason=data.get("reason"),
                added_by="user",
            )
            
            return {"success": True, "name": entry.name}
        
        @app.get("/api/config")
        async def get_config_info():
            """Get current configuration."""
            return {
                "app_name": self.config.app_name,
                "version": self.config.app_version,
                "learning_mode": self.config.learning_mode,
                "process_monitoring": self.config.process_monitoring_enabled,
                "file_monitoring": self.config.file_monitoring_enabled,
                "network_monitoring": self.config.network_monitoring_enabled,
                "registry_monitoring": self.config.registry_monitoring_enabled,
                "notifications_enabled": self.config.notifications_enabled,
                "ml_enabled": self.config.ml_enabled,
            }
        
        @app.get("/api/stats")
        async def get_stats():
            """Get system statistics."""
            from ..utils.database import get_database
            
            db = get_database()
            with db.get_session() as session:
                from ..utils.database import Alert, ProcessRecord, NetworkEvent, FileEvent
                
                return {
                    "total_alerts": session.query(Alert).count(),
                    "unacknowledged_alerts": session.query(Alert).filter_by(acknowledged=False).count(),
                    "monitored_processes": session.query(ProcessRecord).count(),
                    "network_events": session.query(NetworkEvent).count(),
                    "file_events": session.query(FileEvent).count(),
                }
    
    def _render_dashboard(self) -> str:
        """Render the main dashboard HTML."""
        return """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Leatt Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }
        
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 0;
            border-bottom: 1px solid #334155;
            margin-bottom: 20px;
        }
        
        .logo { font-size: 24px; font-weight: bold; color: #22c55e; }
        .logo span { color: #64748b; font-size: 12px; margin-left: 10px; }
        
        .status { display: flex; align-items: center; gap: 8px; }
        .status-dot {
            width: 10px; height: 10px; border-radius: 50%;
            background: #22c55e; animation: pulse 2s infinite;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: #1e293b;
            border-radius: 10px;
            padding: 15px;
            border: 1px solid #334155;
        }
        .stat-card h3 { font-size: 12px; color: #94a3b8; margin-bottom: 5px; }
        .stat-card .value { font-size: 28px; font-weight: bold; }
        .stat-card.alert .value { color: #ef4444; }
        .stat-card.info .value { color: #3b82f6; }
        
        .tabs { display: flex; gap: 8px; margin-bottom: 15px; }
        .tab {
            padding: 8px 16px; border-radius: 6px; cursor: pointer;
            background: #334155; color: #94a3b8; border: none; font-size: 13px;
        }
        .tab.active { background: #22c55e; color: white; }
        
        .section {
            background: #1e293b;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 15px;
            border: 1px solid #334155;
            overflow: hidden;
        }
        .section h2 { font-size: 16px; margin-bottom: 12px; color: #f1f5f9; }
        
        .table-wrapper { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; table-layout: fixed; }
        th, td { padding: 10px 8px; text-align: left; border-bottom: 1px solid #334155; }
        th { color: #94a3b8; font-weight: 500; font-size: 11px; text-transform: uppercase; white-space: nowrap; }
        td { font-size: 13px; }
        
        .col-time { width: 140px; }
        .col-severity { width: 80px; }
        .col-source { width: 120px; }
        .col-process { width: 120px; }
        .col-desc { width: auto; }
        .col-actions { width: 140px; }
        .col-pid { width: 60px; }
        .col-name { width: 150px; }
        .col-path { width: auto; min-width: 200px; }
        .col-trust { width: 70px; }
        .col-risk { width: 80px; }
        
        .truncate {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 100%;
            display: block;
        }
        
        .severity {
            padding: 3px 6px; border-radius: 4px;
            font-size: 10px; font-weight: 600; display: inline-block;
        }
        .severity.low { background: #1e3a5f; color: #60a5fa; }
        .severity.medium { background: #422006; color: #fbbf24; }
        .severity.high { background: #450a0a; color: #f87171; }
        .severity.critical { background: #7f1d1d; color: #fca5a5; }
        
        .btn {
            padding: 5px 10px; border-radius: 4px; border: none;
            cursor: pointer; font-size: 12px; transition: all 0.2s;
        }
        .btn-icon { padding: 5px 8px; background: #334155; color: #94a3b8; }
        .btn-icon:hover { background: #475569; color: white; }
        .btn-dismiss { background: #475569; color: #e2e8f0; }
        .btn-dismiss:hover { background: #64748b; }
        .btn-trust { background: #166534; color: white; }
        .btn-trust:hover { background: #15803d; }
        
        .actions { display: flex; gap: 5px; }
        .dismissed { color: #64748b; font-style: italic; font-size: 12px; }
        
        .trusted { color: #22c55e; }
        .untrusted { color: #ef4444; }
        .risk-low { color: #22c55e; }
        .risk-med { color: #fbbf24; }
        .risk-high { color: #ef4444; }
        
        .empty-state { text-align: center; padding: 30px; color: #64748b; }
        .refresh-info { font-size: 11px; color: #64748b; margin-top: 10px; }
        
        .modal {
            display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.7); z-index: 1000; align-items: center; justify-content: center;
        }
        .modal.active { display: flex; }
        .modal-content {
            background: #1e293b; border-radius: 12px; padding: 20px;
            max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto;
            border: 1px solid #334155;
        }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .modal-header h3 { font-size: 16px; }
        .modal-close { background: none; border: none; color: #94a3b8; font-size: 20px; cursor: pointer; }
        .modal-body pre {
            background: #0f172a; padding: 12px; border-radius: 6px;
            font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all;
        }
        .detail-row { margin-bottom: 10px; }
        .detail-label { color: #94a3b8; font-size: 11px; text-transform: uppercase; margin-bottom: 3px; }
        .detail-value { font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">Leatt <span>v0.1.0</span></div>
            <div class="status">
                <div class="status-dot"></div>
                <span id="status-text">Monitoring actif</span>
            </div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card alert">
                <h3>Alertes actives</h3>
                <div class="value" id="stat-alerts">-</div>
            </div>
            <div class="stat-card info">
                <h3>Processus</h3>
                <div class="value" id="stat-processes">-</div>
            </div>
            <div class="stat-card info">
                <h3>Events reseau</h3>
                <div class="value" id="stat-network">-</div>
            </div>
            <div class="stat-card info">
                <h3>Events fichiers</h3>
                <div class="value" id="stat-files">-</div>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('alerts')">Alertes</button>
            <button class="tab" onclick="showTab('processes')">Processus</button>
            <button class="tab" onclick="showTab('network')">Reseau</button>
            <button class="tab" onclick="showTab('files')">Fichiers</button>
        </div>
        
        <div class="section" id="alerts-section">
            <h2>Alertes recentes</h2>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th class="col-time">Date</th>
                            <th class="col-severity">Niveau</th>
                            <th class="col-source">Source</th>
                            <th class="col-process">Processus</th>
                            <th class="col-desc">Description</th>
                            <th class="col-actions">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="alerts-table"></tbody>
                </table>
            </div>
        </div>
        
        <div class="section" id="processes-section" style="display:none;">
            <h2>Processus surveilles</h2>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th class="col-pid">PID</th>
                            <th class="col-name">Nom</th>
                            <th class="col-path">Chemin</th>
                            <th class="col-trust">Confiance</th>
                            <th class="col-risk">Risque</th>
                            <th class="col-time">Vu</th>
                        </tr>
                    </thead>
                    <tbody id="processes-table"></tbody>
                </table>
            </div>
        </div>
        
        <div class="section" id="network-section" style="display:none;">
            <h2>Activite reseau</h2>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th class="col-time">Date</th>
                            <th class="col-process">Processus</th>
                            <th>Adresse</th>
                            <th>Port</th>
                            <th>Envoye</th>
                        </tr>
                    </thead>
                    <tbody id="network-table"></tbody>
                </table>
            </div>
        </div>
        
        <div class="section" id="files-section" style="display:none;">
            <h2>Activite fichiers</h2>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th class="col-time">Date</th>
                            <th class="col-process">Processus</th>
                            <th>Chemin</th>
                            <th>Action</th>
                            <th>Sensible</th>
                        </tr>
                    </thead>
                    <tbody id="files-table"></tbody>
                </table>
            </div>
        </div>
        
        <p class="refresh-info">Actualisation toutes les 15 secondes</p>
    </div>
    
    <div class="modal" id="detail-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Details de l'alerte</h3>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body" id="modal-body"></div>
        </div>
    </div>
    
    <script>
        let currentTab = 'alerts';
        let alertsCache = [];
        
        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.section').forEach(s => s.style.display = 'none');
            document.querySelector(`[onclick="showTab('${tab}')"]`).classList.add('active');
            document.getElementById(`${tab}-section`).style.display = 'block';
            currentTab = tab;
            loadData();
        }
        
        async function loadStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('stat-alerts').textContent = data.unacknowledged_alerts;
                document.getElementById('stat-processes').textContent = data.monitored_processes;
                document.getElementById('stat-network').textContent = data.network_events;
                document.getElementById('stat-files').textContent = data.file_events;
            } catch (e) { console.error('Stats error:', e); }
        }
        
        async function loadAlerts() {
            try {
                const res = await fetch('/api/alerts?limit=30');
                alertsCache = await res.json();
                const tbody = document.getElementById('alerts-table');
                
                if (alertsCache.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Aucune alerte</td></tr>';
                    return;
                }
                
                tbody.innerHTML = alertsCache.map(a => `
                    <tr>
                        <td>${formatTime(a.timestamp)}</td>
                        <td><span class="severity ${a.severity}">${a.severity.toUpperCase()}</span></td>
                        <td><span class="truncate" title="${a.source}">${a.source.split(':')[0]}</span></td>
                        <td><span class="truncate" title="${a.process_name || ''}">${a.process_name || '-'}</span></td>
                        <td><span class="truncate" title="${a.description}">${a.description}</span></td>
                        <td class="actions">
                            ${a.acknowledged ? '<span class="dismissed">Ignore</span>' : `
                                <button class="btn btn-icon" onclick="inspectAlert(${a.id})" title="Inspecter">🔍</button>
                                <button class="btn btn-dismiss" onclick="dismissAlert(${a.id})">Ignorer</button>
                            `}
                        </td>
                    </tr>
                `).join('');
            } catch (e) { console.error('Alerts error:', e); }
        }
        
        async function loadProcesses() {
            try {
                const res = await fetch('/api/processes');
                const data = await res.json();
                const tbody = document.getElementById('processes-table');
                
                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Aucun processus</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.map(p => `
                    <tr>
                        <td>${p.pid}</td>
                        <td><span class="truncate" title="${p.name}">${p.name}</span></td>
                        <td><span class="truncate" title="${p.path || ''}">${p.path || '-'}</span></td>
                        <td class="${p.is_trusted ? 'trusted' : 'untrusted'}">${p.is_trusted ? '✓ Oui' : '✗ Non'}</td>
                        <td class="${getRiskClass(p.risk_score)}">${p.risk_score.toFixed(0)}</td>
                        <td>${formatTime(p.last_seen)}</td>
                    </tr>
                `).join('');
            } catch (e) { console.error('Processes error:', e); }
        }
        
        async function loadNetwork() {
            try {
                const res = await fetch('/api/network?limit=30');
                const data = await res.json();
                const tbody = document.getElementById('network-table');
                
                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Aucun evenement</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.map(n => `
                    <tr>
                        <td>${formatTime(n.timestamp)}</td>
                        <td><span class="truncate">${n.process_name || '-'}</span></td>
                        <td>${n.remote_address}</td>
                        <td>${n.remote_port}</td>
                        <td>${formatBytes(n.bytes_sent)}</td>
                    </tr>
                `).join('');
            } catch (e) { console.error('Network error:', e); }
        }
        
        async function loadFiles() {
            try {
                const res = await fetch('/api/files?limit=30');
                const data = await res.json();
                const tbody = document.getElementById('files-table');
                
                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Aucun evenement</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.map(f => `
                    <tr>
                        <td>${formatTime(f.timestamp)}</td>
                        <td><span class="truncate">${f.process_name || '-'}</span></td>
                        <td><span class="truncate" title="${f.file_path}">${f.file_path}</span></td>
                        <td>${f.event_type}</td>
                        <td>${f.is_sensitive ? '⚠️ Oui' : 'Non'}</td>
                    </tr>
                `).join('');
            } catch (e) { console.error('Files error:', e); }
        }
        
        async function dismissAlert(id) {
            await fetch(`/api/alerts/${id}/acknowledge`, { method: 'POST' });
            loadAlerts();
            loadStats();
        }
        
        function inspectAlert(id) {
            const alert = alertsCache.find(a => a.id === id);
            if (!alert) return;
            
            let detailsHtml = '';
            if (alert.details) {
                try {
                    const details = typeof alert.details === 'string' ? alert.details : JSON.stringify(alert.details, null, 2);
                    detailsHtml = `
                        <div class="detail-row">
                            <div class="detail-label">Donnees brutes</div>
                            <pre>${details}</pre>
                        </div>
                    `;
                } catch (e) {}
            }
            
            const body = document.getElementById('modal-body');
            body.innerHTML = `
                <div class="detail-row">
                    <div class="detail-label">Niveau</div>
                    <div class="detail-value"><span class="severity ${alert.severity}">${alert.severity.toUpperCase()}</span></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Date</div>
                    <div class="detail-value">${new Date(alert.timestamp).toLocaleString('fr-FR')}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Source</div>
                    <div class="detail-value">${alert.source}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Processus</div>
                    <div class="detail-value">${alert.process_name || '-'} (PID: ${alert.process_pid || '-'})</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Description</div>
                    <div class="detail-value">${alert.description}</div>
                </div>
                ${detailsHtml}
            `;
            document.getElementById('detail-modal').classList.add('active');
        }
        
        function closeModal() {
            document.getElementById('detail-modal').classList.remove('active');
        }
        
        document.getElementById('detail-modal').addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) closeModal();
        });
        
        function formatTime(ts) {
            if (!ts) return '-';
            const d = new Date(ts);
            return d.toLocaleTimeString('fr-FR', {hour: '2-digit', minute: '2-digit'}) + ' ' + 
                   d.toLocaleDateString('fr-FR', {day: '2-digit', month: '2-digit'});
        }
        
        function formatBytes(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }
        
        function getRiskClass(score) {
            if (score >= 60) return 'risk-high';
            if (score >= 30) return 'risk-med';
            return 'risk-low';
        }
        
        function loadData() {
            loadStats();
            switch (currentTab) {
                case 'alerts': loadAlerts(); break;
                case 'processes': loadProcesses(); break;
                case 'network': loadNetwork(); break;
                case 'files': loadFiles(); break;
            }
        }
        
        loadData();
        setInterval(loadData, 15000);
    </script>
</body>
</html>
"""
    
    def run(self) -> None:
        """Run the web server."""
        if not self._fastapi_available:
            logger.info("Web dashboard not available")
            return
        
        import uvicorn
        
        logger.info(f"Starting web dashboard at http://{self.host}:{self.port}")
        self._running = True
        
        config = uvicorn.Config(
            self._app,
            host=self.host,
            port=self.port,
            log_level="warning",
        )
        
        self._server = uvicorn.Server(config)
        self._server.run()
    
    def stop(self) -> None:
        """Stop the web server."""
        self._running = False
        if self._server:
            self._server.should_exit = True
        logger.info("Web dashboard stopped")
    
    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running
    
    @property
    def url(self) -> str:
        """Get the dashboard URL."""
        return f"http://{self.host}:{self.port}"
