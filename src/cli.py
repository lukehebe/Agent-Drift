#!/usr/bin/env python3
"""
Command-line interface for Agent Drift v0.1.2

Features:
- Drift monitoring and detection
- OWASP Top 10 LLM security scanning
- Honeypot tool management
- SIEM dashboard
"""

import sys
import os
import json
import argparse
from datetime import datetime
from pathlib import Path

from .baseline import BaselineManager
from .detector import DriftDetector
from .vectorizer import BehaviorVectorizer
from .honeypot import HoneypotMonitor, get_recommended_honeypots
from .owasp import OWASPScanner


# Optional dashboard import
try:
    from .dashboard import DriftDashboard
    DASHBOARD_AVAILABLE = True
except ImportError:
    DASHBOARD_AVAILABLE = False


def get_storage_dir() -> Path:
    """Get the storage directory."""
    return Path(os.environ.get(
        "AGENT_DRIFT_DIR",
        os.path.expanduser("~/.agent-drift")
    ))


def cmd_status(args):
    """Show current drift detection status."""
    storage_dir = get_storage_dir()
    baseline_mgr = BaselineManager(storage_dir=str(storage_dir))
    honeypot_mgr = HoneypotMonitor(storage_dir=str(storage_dir))
    
    print("Agent Drift Status")
    print("=" * 40)
    
    # Baseline info
    info = baseline_mgr.get_baseline_info()
    if info["exists"]:
        print(f"[OK] Baseline: EXISTS")
        print(f"     Created: {info['created_at']}")
        print(f"     Updated: {info['updated_at']}")
        print(f"     Runs: {info['run_count']}")
        print(f"     Tools tracked: {info['tool_count']}")
        if info.get('poisoning_warning'):
            print(f"     [WARNING] Baseline drift detected!")
    else:
        print("[--] Baseline: NOT FOUND")
        print("     Run 'agent-drift start' to begin monitoring")
    
    # Honeypot info
    hp_status = honeypot_mgr.get_status()
    print(f"\n[HP] Honeypot Tools: {hp_status['tool_count']}")
    if hp_status['configured_tools']:
        for tool in hp_status['configured_tools'][:5]:
            print(f"     - {tool}")
        if hp_status['tool_count'] > 5:
            print(f"     ... and {hp_status['tool_count'] - 5} more")
    
    if hp_status['total_alerts'] > 0:
        print(f"     [CRITICAL] Total alerts: {hp_status['total_alerts']}")
        print(f"     [CRITICAL] Recent (24h): {hp_status['recent_alerts']}")


def cmd_honeypot_add(args):
    """Add a honeypot tool."""
    storage_dir = get_storage_dir()
    honeypot_mgr = HoneypotMonitor(storage_dir=str(storage_dir))
    
    if honeypot_mgr.add_tool(args.tool_name):
        print(f"[OK] Added honeypot tool: {args.tool_name}")
    else:
        print(f"[--] Tool already configured: {args.tool_name}")


def cmd_honeypot_remove(args):
    """Remove a honeypot tool."""
    storage_dir = get_storage_dir()
    honeypot_mgr = HoneypotMonitor(storage_dir=str(storage_dir))
    
    if honeypot_mgr.remove_tool(args.tool_name):
        print(f"[OK] Removed honeypot tool: {args.tool_name}")
    else:
        print(f"[--] Tool not found: {args.tool_name}")


def cmd_honeypot_list(args):
    """List all honeypot tools."""
    storage_dir = get_storage_dir()
    honeypot_mgr = HoneypotMonitor(storage_dir=str(storage_dir))
    
    tools = honeypot_mgr.list_tools()
    
    if tools:
        print("Configured Honeypot Tools:")
        print("-" * 30)
        for tool in tools:
            print(f"  {tool}")
        print(f"\nTotal: {len(tools)} tools")
    else:
        print("No honeypot tools configured.")
        print("\nRecommended honeypots:")
        for tool in get_recommended_honeypots()[:5]:
            print(f"  {tool}")
        print("\nAdd with: agent-drift honeypot add <tool_name>")


def cmd_honeypot_clear(args):
    """Clear all honeypot tools."""
    storage_dir = get_storage_dir()
    honeypot_mgr = HoneypotMonitor(storage_dir=str(storage_dir))
    
    if not args.force:
        response = input("Clear all honeypot tools? [y/N] ")
        if response.lower() != 'y':
            print("Cancelled.")
            sys.exit(0)
    
    honeypot_mgr.clear_all()
    print("[OK] All honeypot tools cleared")


def cmd_honeypot_alerts(args):
    """Show honeypot alerts."""
    storage_dir = get_storage_dir()
    honeypot_mgr = HoneypotMonitor(storage_dir=str(storage_dir))
    
    alerts = honeypot_mgr.get_alerts(limit=args.limit)
    
    if alerts:
        print("Honeypot Alerts")
        print("=" * 60)
        for alert in alerts:
            ts = datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n[CRITICAL] {ts}")
            print(f"  Tool: {alert.tool_name}")
            print(f"  Run: {alert.run_id}")
            if alert.args:
                print(f"  Args: {json.dumps(alert.args)[:100]}")
    else:
        print("No honeypot alerts recorded.")


def cmd_baseline_show(args):
    """Show the current baseline."""
    storage_dir = get_storage_dir()
    baseline_mgr = BaselineManager(storage_dir=str(storage_dir))
    
    if not baseline_mgr.has_baseline():
        print("[--] No baseline exists")
        sys.exit(1)
    
    baseline = baseline_mgr.baseline
    
    if args.json:
        print(json.dumps(baseline.to_dict(), indent=2))
        return
    
    print("Baseline Summary")
    print("=" * 40)
    print(f"Created: {baseline.created_at}")
    print(f"Updated: {baseline.updated_at}")
    print(f"Runs: {baseline.run_count}")
    print(f"Historical vectors: {len(baseline.historical_vectors)}")
    
    v = baseline.vector
    
    print(f"\nTools:")
    for tool, count in sorted(v.tool_frequency.items(), key=lambda x: -x[1]):
        print(f"   {tool}: {count}")
    
    print(f"\nTiming:")
    print(f"   Mean tool duration: {v.mean_tool_duration_ms:.2f}ms")
    print(f"   Mean inter-tool delay: {v.mean_inter_tool_delay_ms:.2f}ms")
    print(f"   Total duration: {v.total_duration_ms:.2f}ms")
    
    print(f"\nDecision Patterns:")
    print(f"   Total cycles: {v.total_cycles}")
    print(f"   Tools per cycle: {v.mean_tools_per_cycle:.2f}")
    print(f"   Retry rate: {v.retry_rate:.2%}")


def cmd_baseline_reset(args):
    """Reset the baseline."""
    storage_dir = get_storage_dir()
    baseline_mgr = BaselineManager(storage_dir=str(storage_dir))
    
    if not baseline_mgr.has_baseline():
        print("[--] No baseline to reset")
        sys.exit(1)
    
    if not args.force:
        response = input("This will delete the current baseline. Continue? [y/N] ")
        if response.lower() != 'y':
            print("Cancelled.")
            sys.exit(0)
    
    baseline_mgr.reset_baseline()
    print("[OK] Baseline reset. Next run will create new baseline.")


def cmd_baseline_export(args):
    """Export baseline to file."""
    storage_dir = get_storage_dir()
    baseline_mgr = BaselineManager(storage_dir=str(storage_dir))
    
    if not baseline_mgr.has_baseline():
        print("[--] No baseline to export")
        sys.exit(1)
    
    baseline_mgr.export_baseline(args.output)
    print(f"[OK] Baseline exported to: {args.output}")


def cmd_baseline_import(args):
    """Import baseline from file."""
    storage_dir = get_storage_dir()
    baseline_mgr = BaselineManager(storage_dir=str(storage_dir))
    
    if baseline_mgr.has_baseline() and not args.force:
        response = input("This will overwrite the existing baseline. Continue? [y/N] ")
        if response.lower() != 'y':
            print("Cancelled.")
            sys.exit(0)
    
    baseline_mgr.import_baseline(args.input)
    print(f"[OK] Baseline imported from: {args.input}")


def cmd_history(args):
    """Show drift detection history."""
    storage_dir = get_storage_dir()
    
    reports_dir = storage_dir / "reports"
    if not reports_dir.exists():
        print("No history available.")
        return
    
    report_files = sorted(reports_dir.glob("*.json"), reverse=True)[:args.limit]
    
    print("Drift Detection History")
    print("=" * 60)
    
    for report_file in report_files:
        with open(report_file) as f:
            report = json.load(f)
        
        alert = report.get("alert_level", "unknown")
        score = report.get("overall_drift_score", 0)
        
        if alert == "CRITICAL":
            level = "[CRITICAL]"
        elif alert == "HIGH":
            level = "[HIGH]    "
        else:
            level = "[OK]      "
        
        print(f"{level} {report.get('run_id', 'unknown')} | Score: {score:.3f} | {report.get('timestamp', 'unknown')}")
        
        # Show honeypot alerts
        honeypot_alerts = report.get("honeypot_alerts", [])
        if honeypot_alerts:
            for hp in honeypot_alerts:
                print(f"           HONEYPOT: {hp.get('tool_name', 'unknown')}")
        
        anomalies = report.get("anomalies", [])
        if anomalies and args.verbose:
            for a in anomalies[:3]:
                print(f"           {a}")


def cmd_scan(args):
    """Scan content for OWASP threats."""
    scanner = OWASPScanner()
    
    content = args.content
    if args.file:
        with open(args.file) as f:
            content = f.read()
    
    detections = scanner.scan(content, source=args.source or "cli")
    
    if not detections:
        print("[OK] No OWASP threats detected")
        return
    
    print(f"OWASP Threat Scan Results")
    print("=" * 50)
    
    for detection in detections:
        severity = detection.severity.value
        print(f"\n[{severity}] {detection.category.value}: {detection.name}")
        print(f"  {detection.description}")
        if detection.matches:
            print(f"  Matches: {detection.matches[:3]}")
    
    print(f"\nTotal: {len(detections)} threats detected")
    
    if scanner.has_critical(detections):
        sys.exit(2)
    elif scanner.has_high_or_above(detections):
        sys.exit(1)


def cmd_start(args):
    """Start drift monitor with SIEM dashboard."""
    import webbrowser
    import threading
    
    if not DASHBOARD_AVAILABLE:
        print("[ERROR] Dashboard requires additional dependencies.")
        print("        Install with: pip install agent-drift-detector[dashboard]")
        print("        Or: pip install flask flask-socketio")
        sys.exit(1)
    
    storage_dir = get_storage_dir()
    honeypot_mgr = HoneypotMonitor(storage_dir=str(storage_dir))
    
    print()
    print("  Agent Drift - Behavioral Security Monitor v0.1.2")
    print("  " + "=" * 50)
    print()
    
    # Status info
    hp_count = len(honeypot_mgr.list_tools())
    print(f"  [HP] Honeypot tools: {hp_count}")
    if hp_count == 0:
        print("       Tip: Add honeypots with 'agent-drift honeypot add <tool>'")
    
    print()
    print(f"  Dashboard: http://localhost:{args.port}")
    print(f"  Storage:   {storage_dir}")
    print()
    print("  " + "=" * 50)
    print()
    
    # Open browser
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f'http://localhost:{args.port}')).start()
    
    # Start dashboard
    dashboard = DriftDashboard(
        storage_dir=str(storage_dir),
        host='0.0.0.0',
        port=args.port,
    )
    dashboard.run(debug=False)


def cmd_setup(args):
    """Setup OpenClaw integration."""
    import subprocess
    
    # Find setup script
    setup_script = Path(__file__).parent.parent / "setup-openclaw.py"
    
    if not setup_script.exists():
        # Try alternate location
        import importlib.util
        spec = importlib.util.find_spec("src")
        if spec and spec.origin:
            setup_script = Path(spec.origin).parent.parent / "setup-openclaw.py"
    
    if setup_script.exists():
        subprocess.run([sys.executable, str(setup_script)])
    else:
        print("[ERROR] Setup script not found")
        print()
        print("  Manual setup:")
        print("  1. Set DRIFT_MONITOR=1 in your environment")
        print("  2. Start agent-drift: agent-drift start")
        print("  3. Run OpenClaw: DRIFT_MONITOR=1 openclaw gateway")
        print()
        print("  See: https://github.com/lukehebe/agent-drift#setup")
        sys.exit(1)


def cmd_simulate(args):
    """Run attack simulations to test detection."""
    storage_dir = get_storage_dir()
    
    print("Attack Simulation Mode")
    print("=" * 50)
    print("Running simulated attacks against the detector")
    print()
    
    if not args.yes:
        response = input("Continue? [y/N] ")
        if response.lower() != 'y':
            print("Cancelled.")
            sys.exit(0)
    
    import subprocess
    
    test_file = Path(__file__).parent.parent / "tests" / "test_comprehensive.py"
    
    if test_file.exists():
        print(f"\nRunning attack simulations from {test_file}")
        print("-" * 50)
        
        result = subprocess.run(
            ["python", "-m", "pytest", str(test_file), "-v", "-k", "attack", "--tb=short"],
            cwd=str(test_file.parent.parent),
        )
        
        if result.returncode == 0:
            print("\n[OK] All attack simulations passed - detector is working!")
        else:
            print("\n[WARNING] Some simulations failed - review output above")
        
        sys.exit(result.returncode)
    else:
        print("[ERROR] Test file not found. Run from package directory.")
        sys.exit(1)


def print_drift_report(report):
    """Print a drift report in a readable format."""
    if report.alert_level == "CRITICAL":
        print("\n[CRITICAL] Significant behavioral drift detected!")
    elif report.alert_level == "HIGH":
        print("\n[HIGH] Behavioral drift detected")
    else:
        print("\n[OK] Behavior within expected bounds")
    
    print(f"\nDrift Score: {report.overall_drift_score:.3f}")
    print("-" * 40)
    
    print("Component Scores:")
    for comp, score in sorted(report.component_scores.items(), key=lambda x: -x[1]):
        bar = "#" * int(score * 20)
        print(f"   {comp:20} [{bar:20}] {score:.3f}")
    
    if report.honeypot_alerts:
        print(f"\n[CRITICAL] Honeypot Alerts ({len(report.honeypot_alerts)}):")
        for hp in report.honeypot_alerts:
            print(f"   HONEYPOT ACCESS: {hp.get('tool_name', 'unknown')}")
    
    if report.owasp_detections:
        print(f"\nOWASP Detections ({len(report.owasp_detections)}):")
        for det in report.owasp_detections[:5]:
            print(f"   [{det.get('severity', '?')}] {det.get('category', '?')}: {det.get('name', '?')}")
    
    if report.anomalies:
        print(f"\nAnomalies ({len(report.anomalies)}):")
        for anomaly in report.anomalies[:10]:
            print(f"   {anomaly}")


def main():
    parser = argparse.ArgumentParser(
        prog="agent-drift",
        description="Agent Drift - Runtime behavioral monitoring for AI agents"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # status command
    status_parser = subparsers.add_parser("status", help="Show current status")
    status_parser.set_defaults(func=cmd_status)
    
    # honeypot subcommands
    honeypot_parser = subparsers.add_parser("honeypot", help="Honeypot tool management")
    honeypot_sub = honeypot_parser.add_subparsers(dest="honeypot_cmd")
    
    hp_add = honeypot_sub.add_parser("add", help="Add honeypot tool")
    hp_add.add_argument("tool_name", help="Tool name to mark as honeypot")
    hp_add.set_defaults(func=cmd_honeypot_add)
    
    hp_remove = honeypot_sub.add_parser("remove", help="Remove honeypot tool")
    hp_remove.add_argument("tool_name", help="Tool name to remove")
    hp_remove.set_defaults(func=cmd_honeypot_remove)
    
    hp_list = honeypot_sub.add_parser("list", help="List honeypot tools")
    hp_list.set_defaults(func=cmd_honeypot_list)
    
    hp_clear = honeypot_sub.add_parser("clear", help="Clear all honeypot tools")
    hp_clear.add_argument("-f", "--force", action="store_true", help="Skip confirmation")
    hp_clear.set_defaults(func=cmd_honeypot_clear)
    
    hp_alerts = honeypot_sub.add_parser("alerts", help="Show honeypot alerts")
    hp_alerts.add_argument("-n", "--limit", type=int, default=20, help="Number of alerts")
    hp_alerts.set_defaults(func=cmd_honeypot_alerts)
    
    # baseline subcommands
    baseline_parser = subparsers.add_parser("baseline", help="Baseline management")
    baseline_sub = baseline_parser.add_subparsers(dest="baseline_cmd")
    
    show_parser = baseline_sub.add_parser("show", help="Show baseline")
    show_parser.add_argument("--json", action="store_true", help="Output as JSON")
    show_parser.set_defaults(func=cmd_baseline_show)
    
    reset_parser = baseline_sub.add_parser("reset", help="Reset baseline")
    reset_parser.add_argument("-f", "--force", action="store_true", help="Skip confirmation")
    reset_parser.set_defaults(func=cmd_baseline_reset)
    
    export_parser = baseline_sub.add_parser("export", help="Export baseline")
    export_parser.add_argument("output", help="Output file path")
    export_parser.set_defaults(func=cmd_baseline_export)
    
    import_parser = baseline_sub.add_parser("import", help="Import baseline")
    import_parser.add_argument("input", help="Input file path")
    import_parser.add_argument("-f", "--force", action="store_true", help="Skip confirmation")
    import_parser.set_defaults(func=cmd_baseline_import)
    
    # history command
    history_parser = subparsers.add_parser("history", help="Show detection history")
    history_parser.add_argument("-n", "--limit", type=int, default=10, help="Number of entries")
    history_parser.add_argument("-v", "--verbose", action="store_true", help="Show anomaly details")
    history_parser.set_defaults(func=cmd_history)
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan content for OWASP threats")
    scan_parser.add_argument("content", nargs="?", help="Content to scan")
    scan_parser.add_argument("-f", "--file", help="File to scan")
    scan_parser.add_argument("-s", "--source", help="Source identifier")
    scan_parser.set_defaults(func=cmd_scan)
    
    # simulate command
    simulate_parser = subparsers.add_parser("simulate", help="Run attack simulations")
    simulate_parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    simulate_parser.set_defaults(func=cmd_simulate)
    
    # setup command
    setup_parser = subparsers.add_parser("setup", help="Setup OpenClaw integration (one-time)")
    setup_parser.set_defaults(func=cmd_setup)
    
    # start command
    start_parser = subparsers.add_parser("start", help="Start drift monitor")
    start_parser.add_argument("--port", type=int, default=5001, help="Dashboard port")
    start_parser.add_argument("--no-browser", action="store_true", help="Don't open browser")
    start_parser.set_defaults(func=cmd_start)
    
    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        args.func(args)
    elif len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
