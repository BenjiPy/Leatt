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
            name = data.get("name", "").strip()
            
            if not name:
                return {"success": False, "error": "Process name required"}
            
            whitelist = Whitelist()
            
            entry = whitelist.add(
                name=name,
                path=data.get("path"),
                reason=data.get("reason"),
                added_by="user",
            )
            
            if entry is None:
                return {"success": False, "error": "Process already whitelisted"}
            
            return {"success": True, "name": entry.name}
        
        @app.delete("/api/whitelist/{name}")
        async def remove_from_whitelist(name: str):
            """Remove a process from whitelist."""
            from ..trust.whitelist import Whitelist
            
            whitelist = Whitelist()
            success = whitelist.remove(name)
            
            return {"success": success}
        
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Leatt Dashboard</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #16161f;
            --bg-hover: #1e1e2a;
            --border: #2a2a3a;
            --text-primary: #f0f0f5;
            --text-secondary: #8888a0;
            --text-muted: #5a5a70;
            --accent: #00d4aa;
            --accent-dim: rgba(0, 212, 170, 0.15);
            --danger: #ff4757;
            --warning: #ffa502;
            --info: #3498ff;
            --success: #00d4aa;
            --gradient-1: linear-gradient(135deg, #00d4aa 0%, #00a080 100%);
            --gradient-2: linear-gradient(135deg, #3498ff 0%, #1e6fd9 100%);
            --gradient-danger: linear-gradient(135deg, #ff4757 0%, #c0392b 100%);
            --glass: rgba(22, 22, 31, 0.8);
            --shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            --shadow-glow: 0 0 40px rgba(0, 212, 170, 0.1);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
        }
        
        .bg-pattern {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background-image: radial-gradient(circle at 20% 50%, rgba(0, 212, 170, 0.03) 0%, transparent 50%),
                              radial-gradient(circle at 80% 20%, rgba(52, 152, 255, 0.03) 0%, transparent 50%);
            pointer-events: none; z-index: 0;
        }
        
        .container { max-width: 1600px; margin: 0 auto; padding: 24px; position: relative; z-index: 1; }
        
        header {
            display: flex; justify-content: space-between; align-items: center;
            padding: 20px 24px; margin-bottom: 24px;
            background: var(--glass); backdrop-filter: blur(20px);
            border-radius: 16px; border: 1px solid var(--border);
            box-shadow: var(--shadow);
        }
        
        .logo {
            display: flex; align-items: center; gap: 14px;
        }
        .logo-brand {
            display: flex; align-items: center; gap: 10px;
            font-size: 28px; font-weight: 800; letter-spacing: -0.5px;
            background: linear-gradient(135deg, #00d4aa 0%, #00f5c4 50%, #00d4aa 100%);
            -webkit-background-clip: text; background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 30px rgba(0, 212, 170, 0.3);
        }
        .logo-icon {
            width: 38px; height: 38px; border-radius: 10px;
            background: linear-gradient(135deg, #00d4aa 0%, #00a085 100%);
            display: flex; align-items: center; justify-content: center;
            font-size: 20px; box-shadow: 0 4px 15px rgba(0, 212, 170, 0.4);
        }
        .version {
            color: var(--text-secondary); font-size: 11px; font-weight: 600;
            padding: 5px 10px; background: var(--bg-secondary);
            border: 1px solid var(--border); border-radius: 6px;
            letter-spacing: 0.5px;
        }
        
        .status { display: flex; align-items: center; gap: 10px; }
        .status-indicator {
            display: flex; align-items: center; gap: 8px;
            padding: 8px 16px; border-radius: 20px;
            background: var(--accent-dim); border: 1px solid var(--accent);
        }
        .status-dot {
            width: 8px; height: 8px; border-radius: 50%;
            background: var(--accent);
            box-shadow: 0 0 12px var(--accent);
            animation: pulse 2s ease-in-out infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.2); opacity: 0.7; }
        }
        .status-text { font-size: 13px; font-weight: 500; color: var(--accent); }
        
        .stats-grid {
            display: grid; grid-template-columns: repeat(4, 1fr);
            gap: 16px; margin-bottom: 24px;
        }
        @media (max-width: 1200px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
        @media (max-width: 600px) { .stats-grid { grid-template-columns: 1fr; } }
        
        .stat-card {
            background: var(--bg-card); border-radius: 16px;
            padding: 20px 24px; border: 1px solid var(--border);
            transition: all 0.3s ease; position: relative; overflow: hidden;
        }
        .stat-card::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
            background: var(--gradient-2); opacity: 0; transition: opacity 0.3s;
        }
        .stat-card:hover { transform: translateY(-4px); box-shadow: var(--shadow); }
        .stat-card:hover::before { opacity: 1; }
        .stat-card.alert::before { background: var(--gradient-danger); opacity: 1; }
        .stat-card h3 { font-size: 11px; font-weight: 600; color: var(--text-muted); 
                        text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
        .stat-card .value { font-size: 36px; font-weight: 700; }
        .stat-card.alert .value { color: var(--danger); }
        .stat-card.info .value { color: var(--info); }
        
        .tabs {
            display: flex; gap: 6px; margin-bottom: 20px;
            background: var(--bg-card); padding: 6px; border-radius: 12px;
            border: 1px solid var(--border); width: fit-content;
        }
        .tab {
            padding: 10px 20px; border-radius: 8px; cursor: pointer;
            background: transparent; color: var(--text-secondary);
            border: none; font-size: 13px; font-weight: 500;
            transition: all 0.2s ease;
        }
        .tab:hover { color: var(--text-primary); background: var(--bg-hover); }
        .tab.active {
            background: var(--gradient-1); color: var(--bg-primary);
            box-shadow: 0 4px 12px rgba(0, 212, 170, 0.3);
        }
        
        .section {
            background: var(--bg-card); border-radius: 16px;
            padding: 24px; margin-bottom: 20px;
            border: 1px solid var(--border);
            box-shadow: var(--shadow);
        }
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        .section h2 { font-size: 18px; font-weight: 600; color: var(--text-primary); }
        
        .filter-bar {
            display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
            padding: 12px 16px; background: var(--bg-secondary);
            border-radius: 10px; margin-bottom: 16px;
        }
        .filter-label { font-size: 12px; color: var(--text-muted); font-weight: 500; }
        .filter-group { display: flex; gap: 6px; }
        .filter-btn {
            padding: 6px 14px; border-radius: 6px; border: 1px solid var(--border);
            background: var(--bg-card); color: var(--text-secondary);
            font-size: 12px; font-weight: 500; cursor: pointer;
            transition: all 0.2s ease;
        }
        .filter-btn:hover { border-color: var(--text-muted); color: var(--text-primary); }
        .filter-btn.active {
            border-color: var(--accent); color: var(--accent);
            background: var(--accent-dim);
        }
        .filter-select {
            padding: 6px 12px; border-radius: 6px; border: 1px solid var(--border);
            background: var(--bg-card); color: var(--text-primary);
            font-size: 12px; cursor: pointer;
        }
        .filter-select:focus { outline: none; border-color: var(--accent); }
        
        .table-wrapper { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th {
            padding: 12px 16px; text-align: left;
            font-size: 10px; font-weight: 600; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 1px;
            border-bottom: 1px solid var(--border);
            background: var(--bg-secondary);
        }
        th:first-child { border-radius: 8px 0 0 0; }
        th:last-child { border-radius: 0 8px 0 0; }
        td {
            padding: 14px 16px; font-size: 13px; color: var(--text-primary);
            border-bottom: 1px solid var(--border);
            transition: background 0.2s;
        }
        tr:hover td { background: var(--bg-hover); }
        tr:last-child td { border-bottom: none; }
        
        .truncate {
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
            max-width: 100%; display: block;
        }
        
        .badge {
            display: inline-flex; align-items: center; justify-content: center;
            padding: 4px 10px; border-radius: 6px;
            font-size: 10px; font-weight: 600; text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge.low { background: rgba(52, 152, 255, 0.15); color: #3498ff; }
        .badge.medium { background: rgba(255, 165, 2, 0.15); color: #ffa502; }
        .badge.high { background: rgba(255, 71, 87, 0.15); color: #ff4757; }
        .badge.critical { background: rgba(255, 71, 87, 0.25); color: #ff6b7a; animation: blink 1s infinite; }
        @keyframes blink { 50% { opacity: 0.7; } }
        
        .btn {
            padding: 8px 14px; border-radius: 8px; border: none;
            font-size: 12px; font-weight: 500; cursor: pointer;
            transition: all 0.2s ease; display: inline-flex;
            align-items: center; gap: 6px;
        }
        .btn-icon { padding: 8px; background: var(--bg-hover); color: var(--text-secondary); }
        .btn-icon:hover { background: var(--border); color: var(--text-primary); transform: scale(1.05); }
        .btn-primary { background: var(--gradient-1); color: var(--bg-primary); }
        .btn-primary:hover { box-shadow: 0 4px 12px rgba(0, 212, 170, 0.3); transform: translateY(-2px); }
        .btn-secondary { background: var(--bg-hover); color: var(--text-primary); border: 1px solid var(--border); }
        .btn-secondary:hover { border-color: var(--text-muted); }
        .btn-danger { background: var(--gradient-danger); color: white; }
        .btn-danger:hover { box-shadow: 0 4px 12px rgba(255, 71, 87, 0.3); }
        .btn-sm { padding: 6px 10px; font-size: 11px; }
        
        .actions { display: flex; gap: 6px; }
        .dismissed { color: var(--text-muted); font-size: 11px; font-style: italic; }
        
        .trust-badge { display: inline-flex; align-items: center; gap: 4px; font-weight: 500; }
        .trust-badge.trusted { color: var(--success); }
        .trust-badge.untrusted { color: var(--danger); }
        .risk-value { font-weight: 600; font-family: 'SF Mono', monospace; }
        .risk-low { color: var(--success); }
        .risk-med { color: var(--warning); }
        .risk-high { color: var(--danger); }
        .anomaly-badge {
            display: inline-block; padding: 2px 6px; border-radius: 4px;
            background: rgba(255, 165, 2, 0.2); color: var(--warning);
            font-size: 9px; font-weight: 600; margin-left: 6px;
        }
        
        .empty-state {
            text-align: center; padding: 48px 24px; color: var(--text-muted);
        }
        .empty-state-icon { font-size: 48px; margin-bottom: 12px; opacity: 0.5; }
        .empty-state-text { font-size: 14px; }
        
        .modal {
            display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.8); backdrop-filter: blur(8px);
            z-index: 1000; align-items: center; justify-content: center;
        }
        .modal.active { display: flex; }
        .modal-content {
            background: var(--bg-card); border-radius: 20px; padding: 28px;
            max-width: 600px; width: 90%; max-height: 85vh; overflow-y: auto;
            border: 1px solid var(--border); box-shadow: var(--shadow);
            animation: modalIn 0.3s ease;
        }
        @keyframes modalIn { from { opacity: 0; transform: scale(0.95) translateY(20px); } }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-header h3 { font-size: 18px; font-weight: 600; }
        .modal-close {
            width: 32px; height: 32px; border-radius: 8px;
            background: var(--bg-hover); border: none; color: var(--text-secondary);
            font-size: 18px; cursor: pointer; transition: all 0.2s;
        }
        .modal-close:hover { background: var(--border); color: var(--text-primary); }
        .modal-body pre {
            background: var(--bg-primary); padding: 16px; border-radius: 10px;
            font-size: 12px; overflow-x: auto; white-space: pre-wrap;
            word-break: break-all; font-family: 'SF Mono', monospace;
        }
        .detail-row { margin-bottom: 16px; }
        .detail-label { font-size: 10px; font-weight: 600; color: var(--text-muted);
                        text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
        .detail-value { font-size: 14px; color: var(--text-primary); }
        
        .whitelist-header { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
        .whitelist-input {
            flex: 1; min-width: 200px; padding: 12px 16px; border-radius: 10px;
            border: 1px solid var(--border); background: var(--bg-secondary);
            color: var(--text-primary); font-size: 13px;
            transition: all 0.2s;
        }
        .whitelist-input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-dim); }
        .whitelist-input::placeholder { color: var(--text-muted); }
        
        .whitelist-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }
        .whitelist-item {
            background: var(--bg-secondary); padding: 16px; border-radius: 12px;
            border: 1px solid var(--border);
            display: flex; justify-content: space-between; align-items: center;
            transition: all 0.2s;
        }
        .whitelist-item:hover { border-color: var(--text-muted); }
        .whitelist-item .info { flex: 1; }
        .whitelist-item .name { font-weight: 600; font-size: 14px; margin-bottom: 4px; }
        .whitelist-item .meta { font-size: 11px; color: var(--text-muted); }
        .whitelist-item .type-badge {
            font-size: 9px; padding: 2px 6px; border-radius: 4px;
            background: var(--bg-hover); color: var(--text-muted);
            text-transform: uppercase; margin-left: 8px;
        }
        
        .footer-info {
            text-align: center; font-size: 11px; color: var(--text-muted);
            margin-top: 20px; padding: 16px;
        }
        
        .note-box {
            padding: 12px 16px; background: rgba(52, 152, 255, 0.1);
            border: 1px solid rgba(52, 152, 255, 0.2); border-radius: 8px;
            font-size: 12px; color: var(--info); margin-top: 12px;
        }
        
        .toast {
            position: fixed; bottom: 24px; right: 24px;
            padding: 14px 20px; border-radius: 10px;
            background: var(--bg-card); border: 1px solid var(--border);
            box-shadow: var(--shadow); font-size: 13px;
            animation: toastIn 0.3s ease; z-index: 2000;
        }
        .toast.error { border-color: var(--danger); }
        .toast.success { border-color: var(--success); }
        @keyframes toastIn { from { opacity: 0; transform: translateY(20px); } }
    </style>
</head>
<body>
    <div class="bg-pattern"></div>
    <div class="container">
        <header>
            <div class="logo">
                <div class="logo-brand">
                    <span class="logo-icon">🛡️</span>
                    LEATT
                </div>
                <span class="version">v0.1.0</span>
            </div>
            <div class="status">
                <div class="status-indicator">
                    <div class="status-dot"></div>
                    <span class="status-text">Monitoring Active</span>
                </div>
            </div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card alert">
                <h3>Active Alerts</h3>
                <div class="value" id="stat-alerts">0</div>
            </div>
            <div class="stat-card info">
                <h3>Processes</h3>
                <div class="value" id="stat-processes">0</div>
            </div>
            <div class="stat-card info">
                <h3>Network Events</h3>
                <div class="value" id="stat-network">0</div>
            </div>
            <div class="stat-card info">
                <h3>File Events</h3>
                <div class="value" id="stat-files">0</div>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('alerts')">🔔 Alerts</button>
            <button class="tab" onclick="showTab('processes')">⚙️ Processes</button>
            <button class="tab" onclick="showTab('network')">🌐 Network</button>
            <button class="tab" onclick="showTab('files')">📁 Files</button>
            <button class="tab" onclick="showTab('whitelist')">✓ Whitelist</button>
        </div>
        
        <div class="section" id="alerts-section">
            <div class="section-header">
                <h2>🔔 Recent Alerts</h2>
            </div>
            <div class="filter-bar">
                <span class="filter-label">Severity:</span>
                <select class="filter-select" id="filter-severity" onchange="renderAlerts()">
                    <option value="all">All Levels</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <span class="filter-label" style="margin-left: 12px;">Source:</span>
                <div class="filter-group">
                    <button class="filter-btn active" id="alert-filter-all" onclick="setAlertTrustFilter('all')">All</button>
                    <button class="filter-btn" id="alert-filter-untrusted" onclick="setAlertTrustFilter('untrusted')">✗ Untrusted only</button>
                </div>
                <div class="filter-group" style="margin-left: 12px;">
                    <button class="filter-btn" id="filter-unack" onclick="toggleFilter('unack')">
                        Unacknowledged only
                    </button>
                </div>
            </div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Severity</th>
                            <th>Source</th>
                            <th>Process</th>
                            <th>Description</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="alerts-table"></tbody>
                </table>
            </div>
        </div>
        
        <div class="section" id="processes-section" style="display:none;">
            <div class="section-header">
                <h2>⚙️ Monitored Processes</h2>
            </div>
            <div class="filter-bar">
                <span class="filter-label">Filter:</span>
                <div class="filter-group">
                    <button class="filter-btn active" id="filter-all" onclick="setTrustFilter('all')">All</button>
                    <button class="filter-btn" id="filter-trusted" onclick="setTrustFilter('trusted')">✓ Trusted</button>
                    <button class="filter-btn" id="filter-untrusted" onclick="setTrustFilter('untrusted')">✗ Untrusted</button>
                    <button class="filter-btn" id="filter-risky" onclick="setTrustFilter('risky')">⚠ Has Risk</button>
                </div>
            </div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>PID</th>
                            <th>Name</th>
                            <th>Path</th>
                            <th>Trusted</th>
                            <th>Risk</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody id="processes-table"></tbody>
                </table>
            </div>
            <div class="note-box">
                ℹ️ Trusted processes can still have risk scores if they exhibit anomalous behavior (potential hijacking/injection)
            </div>
        </div>
        
        <div class="section" id="network-section" style="display:none;">
            <div class="section-header">
                <h2>🌐 Network Activity</h2>
            </div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Process</th>
                            <th>Address</th>
                            <th>Port</th>
                            <th>Sent</th>
                        </tr>
                    </thead>
                    <tbody id="network-table"></tbody>
                </table>
            </div>
        </div>
        
        <div class="section" id="files-section" style="display:none;">
            <div class="section-header">
                <h2>📁 File Activity</h2>
            </div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Process</th>
                            <th>Path</th>
                            <th>Action</th>
                            <th>Sensitive</th>
                        </tr>
                    </thead>
                    <tbody id="files-table"></tbody>
                </table>
            </div>
        </div>
        
        <div class="section" id="whitelist-section" style="display:none;">
            <div class="section-header">
                <h2>✓ Trusted Processes (Whitelist)</h2>
            </div>
            <div class="whitelist-header">
                <input type="text" class="whitelist-input" id="whitelist-name" placeholder="Process name (e.g., myapp.exe)">
                <input type="text" class="whitelist-input" id="whitelist-reason" placeholder="Reason (optional)">
                <button class="btn btn-primary" onclick="addToWhitelist()">+ Add to Whitelist</button>
            </div>
            <div class="whitelist-grid" id="whitelist-grid"></div>
        </div>
        
        <div class="footer-info">
            Auto-refresh every 15 seconds • Leatt Data Leak Prevention
        </div>
    </div>
    
    <div id="toast-container"></div>
    
    <div class="modal" id="detail-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Alert Details</h3>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body" id="modal-body"></div>
        </div>
    </div>
    
    <script>
        let currentTab = 'alerts';
        let alertsCache = [];
        let processesCache = [];
        let whitelistCache = [];
        let trustFilter = 'all';
        let alertTrustFilter = 'all';
        let filterUnackOnly = false;
        
        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.section').forEach(s => s.style.display = 'none');
            document.querySelector(`[onclick="showTab('${tab}')"]`).classList.add('active');
            document.getElementById(`${tab}-section`).style.display = 'block';
            currentTab = tab;
            loadData();
        }
        
        function setTrustFilter(filter) {
            trustFilter = filter;
            document.querySelectorAll('#processes-section .filter-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('filter-' + filter).classList.add('active');
            renderProcesses();
        }
        
        function setAlertTrustFilter(filter) {
            alertTrustFilter = filter;
            document.getElementById('alert-filter-all').classList.toggle('active', filter === 'all');
            document.getElementById('alert-filter-untrusted').classList.toggle('active', filter === 'untrusted');
            renderAlerts();
        }
        
        function toggleFilter(type) {
            if (type === 'unack') {
                filterUnackOnly = !filterUnackOnly;
                document.getElementById('filter-unack').classList.toggle('active', filterUnackOnly);
                renderAlerts();
            }
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
                const res = await fetch('/api/alerts?limit=50');
                alertsCache = await res.json();
                renderAlerts();
            } catch (e) { console.error('Alerts error:', e); }
        }
        
        function renderAlerts() {
            const tbody = document.getElementById('alerts-table');
            const severityFilter = document.getElementById('filter-severity').value;
            const trustedNames = new Set(whitelistCache.map(w => w.name.toLowerCase()));
            
            let filtered = alertsCache;
            
            if (severityFilter !== 'all') {
                filtered = filtered.filter(a => a.severity === severityFilter);
            }
            if (filterUnackOnly) {
                filtered = filtered.filter(a => !a.acknowledged);
            }
            if (alertTrustFilter === 'untrusted') {
                filtered = filtered.filter(a => !a.process_name || !trustedNames.has(a.process_name.toLowerCase()));
            }
            
            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state">
                    <div class="empty-state-icon">✅</div>
                    <div class="empty-state-text">No alerts matching filters</div>
                </div></td></tr>`;
                return;
            }
            
            tbody.innerHTML = filtered.slice(0, 30).map(a => `
                <tr>
                    <td>${formatTime(a.timestamp)}</td>
                    <td><span class="badge ${a.severity}">${a.severity.toUpperCase()}</span></td>
                    <td><span class="truncate" title="${a.source}">${a.source.split(':')[0]}</span></td>
                    <td><span class="truncate" title="${a.process_name || ''}">${a.process_name || '-'}</span></td>
                    <td><span class="truncate" title="${a.description}">${a.description}</span></td>
                    <td class="actions">
                        ${a.acknowledged ? '<span class="dismissed">Dismissed</span>' : `
                            <button class="btn btn-icon btn-sm" onclick="inspectAlert(${a.id})" title="Inspect">🔍</button>
                            ${a.process_name ? `<button class="btn btn-primary btn-sm" onclick="trustProcess('${a.process_name}')" title="Trust">✓</button>` : ''}
                            <button class="btn btn-secondary btn-sm" onclick="dismissAlert(${a.id})">Dismiss</button>
                        `}
                    </td>
                </tr>
            `).join('');
        }
        
        async function loadProcesses() {
            try {
                const res = await fetch('/api/processes');
                processesCache = await res.json();
                renderProcesses();
            } catch (e) { console.error('Processes error:', e); }
        }
        
        function renderProcesses() {
            const tbody = document.getElementById('processes-table');
            
            let filtered = processesCache;
            
            if (trustFilter === 'trusted') {
                filtered = filtered.filter(p => p.is_trusted);
            } else if (trustFilter === 'untrusted') {
                filtered = filtered.filter(p => !p.is_trusted);
            } else if (trustFilter === 'risky') {
                filtered = filtered.filter(p => p.risk_score > 0);
            }
            
            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state">
                    <div class="empty-state-icon">📭</div>
                    <div class="empty-state-text">No processes matching filter</div>
                </div></td></tr>`;
                return;
            }
            
            filtered.sort((a, b) => b.risk_score - a.risk_score);
            
            tbody.innerHTML = filtered.map(p => `
                <tr>
                    <td><span style="font-family: 'SF Mono', monospace; font-size: 12px;">${p.pid}</span></td>
                    <td><span class="truncate" title="${p.name}" style="font-weight: 500;">${p.name}</span></td>
                    <td><span class="truncate" title="${p.path || ''}" style="color: var(--text-secondary); font-size: 12px;">${p.path || '-'}</span></td>
                    <td>
                        <span class="trust-badge ${p.is_trusted ? 'trusted' : 'untrusted'}">
                            ${p.is_trusted ? '✓ Trusted' : '✗ Untrusted'}
                        </span>
                        ${p.is_trusted && p.risk_score > 0 ? '<span class="anomaly-badge">ANOMALY</span>' : ''}
                    </td>
                    <td><span class="risk-value ${getRiskClass(p.risk_score)}">${p.risk_score.toFixed(0)}</span></td>
                    <td style="color: var(--text-secondary);">${formatTime(p.last_seen)}</td>
                </tr>
            `).join('');
        }
        
        async function loadNetwork() {
            try {
                const res = await fetch('/api/network?limit=30');
                const data = await res.json();
                const tbody = document.getElementById('network-table');
                
                if (data.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state">
                        <div class="empty-state-icon">🌐</div>
                        <div class="empty-state-text">No network events yet</div>
                    </div></td></tr>`;
                    return;
                }
                
                tbody.innerHTML = data.map(n => `
                    <tr>
                        <td style="color: var(--text-secondary);">${formatTime(n.timestamp)}</td>
                        <td><span class="truncate" style="font-weight: 500;">${n.process_name || '-'}</span></td>
                        <td><code style="background: var(--bg-secondary); padding: 2px 6px; border-radius: 4px; font-size: 11px;">${n.remote_address}</code></td>
                        <td><span style="color: var(--info);">${n.remote_port}</span></td>
                        <td><span style="font-weight: 500;">${formatBytes(n.bytes_sent)}</span></td>
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
                    tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state">
                        <div class="empty-state-icon">📁</div>
                        <div class="empty-state-text">No file events yet</div>
                    </div></td></tr>`;
                    return;
                }
                
                tbody.innerHTML = data.map(f => `
                    <tr>
                        <td style="color: var(--text-secondary);">${formatTime(f.timestamp)}</td>
                        <td><span class="truncate" style="font-weight: 500;">${f.process_name || '-'}</span></td>
                        <td><span class="truncate" title="${f.file_path}" style="font-size: 12px; color: var(--text-secondary);">${f.file_path}</span></td>
                        <td><span class="badge low">${f.event_type}</span></td>
                        <td>${f.is_sensitive ? '<span class="badge high">⚠ SENSITIVE</span>' : '<span style="color: var(--text-muted);">No</span>'}</td>
                    </tr>
                `).join('');
            } catch (e) { console.error('Files error:', e); }
        }
        
        async function loadWhitelist() {
            try {
                const res = await fetch('/api/whitelist');
                const data = await res.json();
                whitelistCache = data;
                const grid = document.getElementById('whitelist-grid');
                
                if (data.length === 0) {
                    grid.innerHTML = `<div class="empty-state">
                        <div class="empty-state-icon">📋</div>
                        <div class="empty-state-text">No whitelist entries</div>
                    </div>`;
                    return;
                }
                
                grid.innerHTML = data.map(w => `
                    <div class="whitelist-item">
                        <div class="info">
                            <div class="name">${w.name}<span class="type-badge">${w.added_by}</span></div>
                            <div class="meta">${w.reason || 'No reason specified'}</div>
                        </div>
                        ${w.added_by !== 'system' ? `<button class="btn btn-danger btn-sm" onclick="removeFromWhitelist('${w.name}')">✕</button>` : ''}
                    </div>
                `).join('');
            } catch (e) { console.error('Whitelist error:', e); }
        }
        
        function showToast(message, type = 'success') {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;
            toast.textContent = message;
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }
        
        async function addToWhitelist() {
            const name = document.getElementById('whitelist-name').value.trim();
            const reason = document.getElementById('whitelist-reason').value.trim();
            
            if (!name) {
                showToast('Please enter a process name', 'error');
                return;
            }
            
            const res = await fetch('/api/whitelist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, reason })
            });
            const data = await res.json();
            
            if (data.success) {
                showToast(`Added "${name}" to whitelist`, 'success');
                document.getElementById('whitelist-name').value = '';
                document.getElementById('whitelist-reason').value = '';
                loadWhitelist();
            } else {
                showToast(data.error || 'Failed to add', 'error');
            }
        }
        
        async function removeFromWhitelist(name) {
            if (!confirm(`Remove "${name}" from whitelist?`)) return;
            await fetch(`/api/whitelist/${encodeURIComponent(name)}`, { method: 'DELETE' });
            showToast(`Removed "${name}" from whitelist`, 'success');
            loadWhitelist();
        }
        
        async function trustProcess(name) {
            const res = await fetch('/api/whitelist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, reason: 'Trusted from alert' })
            });
            const data = await res.json();
            
            if (data.success) {
                showToast(`"${name}" is now trusted`, 'success');
            } else {
                showToast(data.error || 'Already trusted', 'error');
            }
            loadAlerts();
            loadStats();
        }
        
        async function dismissAlert(id) {
            await fetch(`/api/alerts/${id}/acknowledge`, { method: 'POST' });
            showToast('Alert dismissed', 'success');
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
                            <div class="detail-label">Raw Data</div>
                            <pre>${details}</pre>
                        </div>
                    `;
                } catch (e) {}
            }
            
            const body = document.getElementById('modal-body');
            body.innerHTML = `
                <div class="detail-row">
                    <div class="detail-label">Severity</div>
                    <div class="detail-value"><span class="badge ${alert.severity}">${alert.severity.toUpperCase()}</span></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Time</div>
                    <div class="detail-value">${new Date(alert.timestamp).toLocaleString()}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Source</div>
                    <div class="detail-value"><code style="background: var(--bg-secondary); padding: 4px 8px; border-radius: 4px;">${alert.source}</code></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Process</div>
                    <div class="detail-value" style="font-weight: 500;">${alert.process_name || '-'} <span style="color: var(--text-muted);">(PID: ${alert.process_pid || '-'})</span></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Description</div>
                    <div class="detail-value">${alert.description}</div>
                </div>
                ${detailsHtml}
                ${alert.process_name ? `
                <div style="margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--border);">
                    <button class="btn btn-primary" onclick="trustProcess('${alert.process_name}'); closeModal();">
                        ✓ Trust this process
                    </button>
                </div>
                ` : ''}
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
            return d.toLocaleTimeString('en-US', {hour: '2-digit', minute: '2-digit'}) + ' ' + 
                   d.toLocaleDateString('en-US', {month: 'short', day: 'numeric'});
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
            loadWhitelist();
            switch (currentTab) {
                case 'alerts': loadAlerts(); break;
                case 'processes': loadProcesses(); break;
                case 'network': loadNetwork(); break;
                case 'files': loadFiles(); break;
                case 'whitelist': break;
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
