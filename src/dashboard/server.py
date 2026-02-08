"""
Dashboard server - Flask-based SIEM interface for drift monitoring.
Real-time WebSocket updates, tool tracking, OWASP scanning, and honeypot monitoring.

v0.1.2: Added honeypot configuration panel and OWASP threat display.
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading

try:
    from ..baseline import BaselineManager
    from ..detector import DriftDetector
    from ..models import DriftReport, BehaviorTrace, ToolInvocation, DecisionCycle, Severity
    from ..owasp import OWASPScanner
    from ..honeypot import HoneypotMonitor
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from baseline import BaselineManager
    from detector import DriftDetector
    from models import DriftReport, BehaviorTrace, ToolInvocation, DecisionCycle, Severity
    from owasp import OWASPScanner
    from honeypot import HoneypotMonitor


class DriftDashboard:
    """
    SIEM-like dashboard for monitoring agent behavioral drift.
    
    Features:
    - Real-time drift score monitoring via WebSocket
    - Tool event tracking with live updates
    - OWASP threat detection and alerts
    - Honeypot tool configuration and monitoring
    - Historical trend visualization
    """
    
    def __init__(
        self,
        storage_dir: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 5001,
    ):
        self.storage_dir = Path(storage_dir or os.environ.get(
            "AGENT_DRIFT_DIR",
            os.path.expanduser("~/.agent-drift")
        ))
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.host = host
        self.port = port
        
        # Initialize components
        self.baseline_manager = BaselineManager(str(self.storage_dir))
        self.honeypot_monitor = HoneypotMonitor(str(self.storage_dir))
        self.owasp_scanner = OWASPScanner()
        self.detector = DriftDetector(
            self.baseline_manager,
            honeypot_monitor=self.honeypot_monitor,
            owasp_scanner=self.owasp_scanner,
        )
        
        # Data stores
        self.drift_history: List[Dict] = []
        self.alerts: List[Dict] = []
        self.max_history = 1000
        
        # Real-time tracking
        self.current_trace: Optional[BehaviorTrace] = None
        self.session_start: float = 0
        self.tool_count: int = 0
        self.recent_tools: List[Dict] = []
        self.owasp_detections: List[Dict] = []
        self._lock = threading.Lock()
        
        self._load_history()
        
        # Create Flask app
        self.app = create_app(self)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode='threading')
        
        self._setup_socketio()
    
    def _setup_socketio(self):
        """Setup WebSocket handlers."""
        
        @self.socketio.on('connect')
        def handle_connect():
            emit('connected', {'status': 'ok'})
            emit('full_state', self.get_full_state())
        
        @self.socketio.on('request_update')
        def handle_update_request():
            emit('full_state', self.get_full_state())
    
    def broadcast(self, event: str, data: dict):
        """Broadcast event to all connected clients."""
        self.socketio.emit(event, data)
    
    def ensure_session(self):
        """Ensure a monitoring session is active."""
        with self._lock:
            if not self.current_trace:
                self.session_start = time.time()
                self.current_trace = BehaviorTrace(
                    run_id=f"session-{int(self.session_start)}",
                    start_time=self.session_start,
                    end_time=0,
                )
                self.tool_count = 0
                print(f"  [NEW] Session: {self.current_trace.run_id}")
    
    def track_tool(self, tool_name: str, success: bool = True, duration_ms: float = 100.0,
                   args: dict = None, output: str = None):
        """Track a tool call and broadcast update."""
        self.ensure_session()
        
        with self._lock:
            now = time.time()
            
            # Check honeypot
            is_honeypot = self.honeypot_monitor.is_honeypot(tool_name)
            honeypot_alert = None
            
            if is_honeypot:
                honeypot_alert = self.honeypot_monitor.check_tool(
                    tool_name, 
                    self.current_trace.run_id,
                    args
                )
                if honeypot_alert:
                    self.current_trace.honeypot_alerts.append(honeypot_alert)
                    
                    # Create alert
                    alert = {
                        'id': f"honeypot-{int(now * 1000)}",
                        'level': 'CRITICAL',
                        'type': 'honeypot',
                        'run_id': self.current_trace.run_id,
                        'tool': tool_name,
                        'timestamp': now,
                        'acknowledged': False,
                    }
                    self.alerts.append(alert)
                    print(f"  [CRITICAL] HONEYPOT ACCESS: {tool_name}")
            
            # Add to trace
            self.current_trace.tool_invocations.append(
                ToolInvocation(
                    tool_name=tool_name,
                    timestamp=now,
                    duration_ms=duration_ms,
                    success=success,
                    arg_count=len(args) if args else 0,
                    arg_types=list(args.keys()) if args else [],
                    is_honeypot=is_honeypot,
                )
            )
            
            # Track recent
            tool_event = {
                'tool': tool_name,
                'time': now,
                'success': success,
                'duration_ms': duration_ms,
                'is_honeypot': is_honeypot,
            }
            self.recent_tools.append(tool_event)
            if len(self.recent_tools) > 200:
                self.recent_tools = self.recent_tools[-200:]
            
            self.tool_count += 1
            
            # OWASP scan args/output
            owasp_detections = []
            if args:
                for key, val in args.items():
                    if isinstance(val, str):
                        detections = self.owasp_scanner.scan(val, source=f"tool:{tool_name}:{key}")
                        for d in detections:
                            owasp_detections.append(d.to_dict())
                            self.current_trace.owasp_detections.append(d)
            
            if output and isinstance(output, str):
                detections = self.owasp_scanner.scan(output, source=f"tool:{tool_name}:output")
                for d in detections:
                    owasp_detections.append(d.to_dict())
                    self.current_trace.owasp_detections.append(d)
            
            if owasp_detections:
                self.owasp_detections.extend(owasp_detections)
                for det in owasp_detections:
                    if det.get('severity') == 'CRITICAL':
                        self.alerts.append({
                            'id': f"owasp-{int(now * 1000)}",
                            'level': 'CRITICAL',
                            'type': 'owasp',
                            'detection': det,
                            'timestamp': now,
                            'acknowledged': False,
                        })
        
        # Broadcast
        self.broadcast('tool_event', {
            'tool': tool_event,
            'tool_count': self.tool_count,
            'honeypot_alert': honeypot_alert.to_dict() if honeypot_alert else None,
            'owasp_detections': owasp_detections if owasp_detections else None,
        })
        
        log_msg = f"  [OK] {tool_name}"
        if is_honeypot:
            log_msg = f"  [CRITICAL] HONEYPOT: {tool_name}"
        elif owasp_detections:
            log_msg += f" [OWASP: {len(owasp_detections)} detections]"
        print(log_msg)
    
    def check_content(self, content: str, source: str = "unknown") -> List[Dict]:
        """Check content for OWASP threats."""
        detections = self.owasp_scanner.scan(content, source)
        
        if detections:
            now = time.time()
            for det in detections:
                det_dict = det.to_dict()
                self.owasp_detections.append(det_dict)
                
                if det.severity == Severity.CRITICAL:
                    self.alerts.append({
                        'id': f"owasp-{int(now * 1000)}",
                        'level': 'CRITICAL',
                        'type': 'owasp',
                        'source': source,
                        'detection': det_dict,
                        'timestamp': now,
                        'acknowledged': False,
                    })
            
            self.broadcast('owasp_detected', {
                'source': source,
                'detections': [d.to_dict() for d in detections],
            })
        
        return [d.to_dict() for d in detections]
    
    def end_session(self) -> Optional[DriftReport]:
        """End monitoring session and generate drift report."""
        with self._lock:
            if not self.current_trace:
                return None
            
            trace = self.current_trace
            trace.end_time = time.time()
            
            if trace.tool_invocations:
                trace.decision_cycles.append(
                    DecisionCycle(1, trace.start_time, trace.end_time,
                                  len(trace.tool_invocations), 0, 0)
                )
            
            report = self.detector.detect(trace)
            self.add_drift_report(report)
            
            self.current_trace = None
            return report
    
    def get_full_state(self) -> Dict[str, Any]:
        """Get complete dashboard state."""
        self._load_history()
        
        return {
            'drift_history': self.drift_history[-100:],
            'alerts': self.alerts[-50:],
            'baseline': self.baseline_manager.get_baseline_info(),
            'honeypot': self.honeypot_monitor.get_status(),
            'stats': self._calculate_stats(),
            'timestamp': time.time(),
            'monitoring': self.current_trace is not None,
            'session_duration': time.time() - self.session_start if self.current_trace else 0,
            'tool_count': self.tool_count,
            'recent_tools': self.recent_tools[-50:],
            'owasp_detections': self.owasp_detections[-30:],
        }
    
    def _calculate_stats(self) -> Dict[str, Any]:
        """Calculate summary statistics."""
        if not self.drift_history:
            return {
                'total_runs': 0,
                'avg_drift_score': 0,
                'critical_count': 0,
                'high_count': 0,
                'honeypot_alerts': len(self.honeypot_monitor.get_alerts()),
                'owasp_detections': len(self.owasp_detections),
            }
        
        now = time.time()
        day_ago = now - 86400
        
        recent = [h for h in self.drift_history if h.get('timestamp', 0) > day_ago]
        all_scores = [h['overall_drift_score'] for h in self.drift_history]
        
        return {
            'total_runs': len(self.drift_history),
            'avg_drift_score': sum(all_scores) / len(all_scores) if all_scores else 0,
            'critical_count': sum(1 for h in self.drift_history if h.get('alert_level') == 'CRITICAL'),
            'high_count': sum(1 for h in self.drift_history if h.get('alert_level') == 'HIGH'),
            'last_24h_runs': len(recent),
            'honeypot_alerts': len(self.honeypot_monitor.get_alerts()),
            'owasp_detections': len(self.owasp_detections),
        }
    
    def add_drift_report(self, report: DriftReport):
        """Add a new drift report."""
        report_dict = report.to_dict()
        report_dict['timestamp'] = time.time()
        
        self.drift_history.append(report_dict)
        
        if len(self.drift_history) > self.max_history:
            self.drift_history = self.drift_history[-self.max_history:]
        
        if report.alert_level in ('HIGH', 'CRITICAL'):
            alert = {
                'id': f"alert-{int(time.time() * 1000)}",
                'level': report.alert_level,
                'type': 'drift',
                'run_id': report.run_id,
                'score': report.overall_drift_score,
                'anomalies': report.anomalies,
                'timestamp': time.time(),
                'acknowledged': False,
            }
            self.alerts.append(alert)
        
        self._save_history()
        self._save_report(report_dict)
        
        self.broadcast('drift_update', {
            'report': report_dict,
            'stats': self._calculate_stats(),
        })
    
    def _save_report(self, report_dict: dict):
        """Save report to disk."""
        reports_dir = self.storage_dir / "reports"
        reports_dir.mkdir(exist_ok=True)
        with open(reports_dir / f"{report_dict.get('run_id', 'unknown')}.json", 'w') as f:
            json.dump(report_dict, f, indent=2)
    
    def _load_history(self):
        """Load historical data from disk."""
        seen_ids = {h.get('run_id') for h in self.drift_history}
        
        reports_dir = self.storage_dir / "reports"
        if reports_dir.exists():
            for report_file in sorted(reports_dir.glob("*.json")):
                try:
                    with open(report_file) as f:
                        report = json.load(f)
                    
                    run_id = report.get('run_id')
                    if run_id and run_id not in seen_ids:
                        if 'timestamp' not in report:
                            report['timestamp'] = report_file.stat().st_mtime
                        elif isinstance(report['timestamp'], str):
                            try:
                                dt = datetime.fromisoformat(report['timestamp'].replace('Z', '+00:00'))
                                report['timestamp'] = dt.timestamp()
                            except:
                                report['timestamp'] = report_file.stat().st_mtime
                        
                        self.drift_history.append(report)
                        seen_ids.add(run_id)
                except (json.JSONDecodeError, KeyError):
                    continue
        
        self.drift_history.sort(key=lambda h: h.get('timestamp', 0))
    
    def _save_history(self):
        """Save historical data to disk."""
        history_file = self.storage_dir / "dashboard_history.json"
        with open(history_file, 'w') as f:
            json.dump({
                'drift_history': self.drift_history[-500:],
                'alerts': self.alerts[-200:],
            }, f)
    
    def run(self, debug: bool = False):
        """Run the dashboard server."""
        print()
        print("  Agent Drift - SIEM Dashboard v0.1.2")
        print("  " + "=" * 50)
        print(f"  Dashboard:  http://{self.host}:{self.port}")
        print()
        print("  Agent Integration:")
        print(f"    POST /tool     - Track tool usage")
        print(f"    POST /check    - Check content for OWASP threats")
        print(f"    POST /end      - End session, get drift report")
        print()
        print("  Honeypot API:")
        print(f"    GET  /api/honeypot        - List honeypots")
        print(f"    POST /api/honeypot        - Add honeypot")
        print(f"    DELETE /api/honeypot/<t>  - Remove honeypot")
        print()
        print("  " + "=" * 50)
        print()
        
        self.socketio.run(self.app, host=self.host, port=self.port, debug=debug, allow_unsafe_werkzeug=True)


def create_app(dashboard: Optional[DriftDashboard] = None) -> Flask:
    """Create Flask application."""
    
    template_dir = Path(__file__).parent / "templates"
    static_dir = Path(__file__).parent / "static"
    
    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )
    app.config['SECRET_KEY'] = os.environ.get('DRIFT_SECRET_KEY', 'agent-drift-dev-key')
    app.dashboard = dashboard
    
    @app.route('/')
    def index():
        return render_template('dashboard.html')
    
    # Tool tracking API
    @app.route('/tool', methods=['POST', 'OPTIONS'])
    @app.route('/api/tool', methods=['POST', 'OPTIONS'])
    def api_track_tool():
        if request.method == 'OPTIONS':
            return _cors_response()
        
        data = request.get_json(silent=True) or {}
        tool = data.get('tool') or data.get('name') or 'unknown'
        success = data.get('success', True)
        duration = data.get('duration_ms', 100.0)
        args = data.get('args')
        output = data.get('output')
        
        if app.dashboard:
            app.dashboard.track_tool(tool, success, duration, args, output)
        
        return jsonify({'ok': True})
    
    @app.route('/check', methods=['POST', 'OPTIONS'])
    @app.route('/api/check', methods=['POST', 'OPTIONS'])
    def api_check_content():
        if request.method == 'OPTIONS':
            return _cors_response()
        
        data = request.get_json(silent=True) or {}
        content = data.get('content') or data.get('text') or ''
        source = data.get('source', 'api')
        
        detections = []
        if app.dashboard:
            detections = app.dashboard.check_content(content, source)
        
        return jsonify({
            'ok': True,
            'detections': detections,
            'has_threat': len(detections) > 0,
            'critical': any(d.get('severity') == 'CRITICAL' for d in detections),
        })
    
    @app.route('/end', methods=['POST', 'OPTIONS'])
    @app.route('/api/end', methods=['POST', 'OPTIONS'])
    def api_end_session():
        if request.method == 'OPTIONS':
            return _cors_response()
        
        if app.dashboard:
            report = app.dashboard.end_session()
            if report:
                return jsonify(report.to_dict())
        
        return jsonify({'ok': True, 'message': 'No active session'})
    
    @app.route('/reset', methods=['POST', 'OPTIONS'])
    @app.route('/api/reset', methods=['POST', 'OPTIONS'])
    def api_reset_baseline():
        if request.method == 'OPTIONS':
            return _cors_response()
        
        if app.dashboard:
            app.dashboard.baseline_manager.reset_baseline()
            print("  [OK] Baseline reset")
        
        return jsonify({'ok': True, 'message': 'Baseline reset'})
    
    # State API
    @app.route('/api/state')
    def api_state():
        if app.dashboard:
            return jsonify(app.dashboard.get_full_state())
        return jsonify({'error': 'Dashboard not initialized'}), 500
    
    @app.route('/api/history')
    def api_history():
        limit = request.args.get('limit', 100, type=int)
        if app.dashboard:
            app.dashboard._load_history()
            return jsonify(app.dashboard.drift_history[-limit:])
        return jsonify([])
    
    @app.route('/api/alerts')
    def api_alerts():
        if app.dashboard:
            return jsonify(app.dashboard.alerts[-50:])
        return jsonify([])
    
    # Honeypot API
    @app.route('/api/honeypot', methods=['GET', 'POST', 'OPTIONS'])
    def api_honeypot():
        if request.method == 'OPTIONS':
            return _cors_response()
        
        if not app.dashboard:
            return jsonify({'error': 'Dashboard not initialized'}), 500
        
        if request.method == 'GET':
            return jsonify({
                'tools': app.dashboard.honeypot_monitor.list_tools(),
                'status': app.dashboard.honeypot_monitor.get_status(),
            })
        
        # POST - add honeypot
        data = request.get_json(silent=True) or {}
        tool = data.get('tool')
        if not tool:
            return jsonify({'error': 'Tool name required'}), 400
        
        added = app.dashboard.honeypot_monitor.add_tool(tool)
        return jsonify({'ok': True, 'added': added, 'tool': tool})
    
    @app.route('/api/honeypot/<tool_name>', methods=['DELETE', 'OPTIONS'])
    def api_honeypot_delete(tool_name):
        if request.method == 'OPTIONS':
            return _cors_response()
        
        if app.dashboard:
            removed = app.dashboard.honeypot_monitor.remove_tool(tool_name)
            return jsonify({'ok': True, 'removed': removed, 'tool': tool_name})
        return jsonify({'error': 'Dashboard not initialized'}), 500
    
    @app.route('/api/honeypot/alerts')
    def api_honeypot_alerts():
        limit = request.args.get('limit', 50, type=int)
        if app.dashboard:
            alerts = app.dashboard.honeypot_monitor.get_alerts(limit=limit)
            return jsonify([a.to_dict() for a in alerts])
        return jsonify([])
    
    @app.route('/api/baseline')
    def api_baseline():
        if app.dashboard:
            return jsonify(app.dashboard.baseline_manager.get_baseline_info())
        return jsonify({'exists': False})
    
    @app.route('/api/stats')
    def api_stats():
        if app.dashboard:
            return jsonify(app.dashboard._calculate_stats())
        return jsonify({})
    
    @app.route('/health')
    def health():
        return jsonify({'ok': True, 'version': '0.1.2'})
    
    def _cors_response():
        response = app.make_response('')
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response
    
    @app.after_request
    def add_cors(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    
    return app


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Agent Drift Dashboard')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5001, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--storage-dir', help='Data storage directory')
    
    args = parser.parse_args()
    
    dashboard = DriftDashboard(
        storage_dir=args.storage_dir,
        host=args.host,
        port=args.port,
    )
    dashboard.run(debug=args.debug)


if __name__ == '__main__':
    main()
