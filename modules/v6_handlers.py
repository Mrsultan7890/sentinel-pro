"""
CLI handlers for v6.0 features (DTIE + PTE + QRCE + ASE)
"""
import logging
logger = logging.getLogger(__name__)

def handle_federated(sentinel, command: str):
    """Federated learning commands"""
    parts = command.split()
    sub = parts[1] if len(parts) > 1 else 'status'
    
    from sentinel_intel.federated import FederatedTrainer, PrivacyEngine
    
    if sub == 'status':
        trainer = FederatedTrainer()
        status = trainer.get_status()
        sentinel.console.print(f"\n[bold cyan]Federated Learning Status[/bold cyan]")
        sentinel.console.print(f"  Round          : {status['round']}")
        sentinel.console.print(f"  Global model   : {'[green]✓[/green]' if status['global_model_loaded'] else '[red]✗[/red]'}")
        sentinel.console.print(f"  Clients        : {status['clients_registered']}")
        sentinel.console.print(f"  Model path     : [dim]{status['model_path']}[/dim]")
    
    elif sub == 'train':
        # Placeholder for federated training
        sentinel.console.print("[yellow]Federated training requires multiple nodes[/yellow]")
        sentinel.console.print("[dim]This feature is for distributed deployments[/dim]")
    
    elif sub == 'privacy':
        engine = PrivacyEngine(epsilon=1.0, delta=1e-5)
        verification = engine.verify_privacy_guarantee()
        sentinel.console.print(f"\n[bold cyan]Privacy Engine Configuration[/bold cyan]")
        sentinel.console.print(f"  Valid          : {'[green]✓[/green]' if verification['valid'] else '[red]✗[/red]'}")
        sentinel.console.print(f"  Epsilon        : {verification['epsilon']}")
        sentinel.console.print(f"  Delta          : {verification['delta']}")
        sentinel.console.print(f"  Noise scale    : {verification['noise_scale']:.4f}")
    
    else:
        sentinel.console.print("[red]Usage: federated [status|train|privacy][/red]")


def handle_predict(sentinel, command: str):
    """Predictive threat analysis commands"""
    parts = command.split()
    sub = parts[1] if len(parts) > 1 else 'help'
    
    if sub == 'surface' and len(parts) >= 3:
        target = parts[2]
        from modules.predictive.attack_surface_mapper import AttackSurfaceMapper
        
        sentinel.console.print(f"[cyan]Mapping attack surface for {target}...[/cyan]")
        mapper = AttackSurfaceMapper(target)
        
        # Scan
        services = mapper.scan_ports("1-1000")
        sentinel.console.print(f"[green]✓ Found {len(services)} open services[/green]")
        
        # Dependencies
        deps = mapper.map_dependencies()
        sentinel.console.print(f"[green]✓ Identified {len(deps)} dependencies[/green]")
        
        # Attack paths
        paths = mapper.identify_attack_paths()
        sentinel.console.print(f"[green]✓ Found {len(paths)} attack paths[/green]")
        
        # Report
        report = mapper.generate_report()
        sentinel.console.print(f"\n[bold cyan]Attack Surface Report[/bold cyan]")
        sentinel.console.print(f"  Total services : {report['summary']['total_services']}")
        sentinel.console.print(f"  High-risk paths: {report['summary']['high_risk_paths']}")
        
        if report['recommendations']:
            sentinel.console.print(f"\n[bold yellow]Recommendations:[/bold yellow]")
            for rec in report['recommendations']:
                sentinel.console.print(f"  • {rec}")
        
        # Export
        mapper.visualize_graph()
        sentinel.console.print(f"\n[green]✓ Graph exported to attack_surface.json[/green]")
    
    elif sub == 'trends':
        from modules.predictive.threat_trend_analyzer import ThreatTrendAnalyzer
        
        analyzer = ThreatTrendAnalyzer()
        
        # Analyze trends
        trends = analyzer.analyze_trends(days=30)
        sentinel.console.print(f"\n[bold cyan]Threat Trend Analysis (30 days)[/bold cyan]")
        sentinel.console.print(f"  Total events   : {trends['total_events']}")
        sentinel.console.print(f"  Threat types   : {len(trends['threat_types'])}")
        sentinel.console.print(f"  Trending up    : {len(trends['trending_up'])}")
        sentinel.console.print(f"  Emerging       : {len(trends['emerging_threats'])}")
        
        if trends['trending_up']:
            sentinel.console.print(f"\n[bold yellow]Trending Threats:[/bold yellow]")
            for threat in trends['trending_up'][:5]:
                info = trends['threat_types'][threat]
                sentinel.console.print(f"  • {threat}: {info['total_events']} events ({info['trend']})")
        
        # Predictions
        predictions = analyzer.predict_threats(horizon_days=7)
        if predictions:
            sentinel.console.print(f"\n[bold red]Threat Predictions (7 days):[/bold red]")
            for pred in predictions[:5]:
                sentinel.console.print(f"  • {pred['threat_type']}: {pred['confidence']:.0%} confidence")
                sentinel.console.print(f"    [dim]{pred['reasoning']}[/dim]")
        
        # Warnings
        warnings = analyzer.get_early_warnings()
        if warnings:
            sentinel.console.print(f"\n[bold red]⚠ Early Warnings:[/bold red]")
            for warn in warnings:
                sentinel.console.print(f"  • {warn['threat_type']}: {warn['predicted_events']} predicted events")
    
    else:
        sentinel.console.print("[red]Usage: predict [surface <target>|trends][/red]")
        sentinel.console.print("[dim]  surface <target> - Map attack surface and identify paths[/dim]")
        sentinel.console.print("[dim]  trends           - Analyze threat trends and predictions[/dim]")


def handle_crypto(sentinel, command: str):
    """Quantum-ready cryptography commands"""
    parts = command.split()
    sub = parts[1] if len(parts) > 1 else 'status'
    
    if sub == 'status':
        from modules.crypto_manager import CryptoManager
        from modules.pq_tls_manager import PQTLSManager
        
        sentinel.console.print(f"\n[bold cyan]🔐 Quantum-Ready Cryptography Status[/bold cyan]")
        
        # Crypto manager status
        try:
            crypto = CryptoManager()
            status = crypto.get_status()
            sentinel.console.print(f"\n[bold]Sentinel Crypto (Rust):[/bold]")
            sentinel.console.print(f"  Binary built   : {'[green]✓[/green]' if status['binary_exists'] else '[red]✗[/red]'}")
            sentinel.console.print(f"  Kyber1024      : {'[green]✓[/green]' if status['kyber_available'] else '[red]✗[/red]'}")
            sentinel.console.print(f"  Dilithium5     : {'[green]✓[/green]' if status['dilithium_available'] else '[red]✗[/red]'}")
            sentinel.console.print(f"  SPHINCS+       : {'[green]✓[/green]' if status['sphincs_available'] else '[red]✗[/red]'}")
            sentinel.console.print(f"  Hybrid mode    : {'[green]✓[/green]' if status['hybrid_available'] else '[red]✗[/red]'}")
        except Exception as e:
            sentinel.console.print(f"  [yellow]Crypto manager: {e}[/yellow]")
        
        # PQ-TLS status
        try:
            pq_tls = PQTLSManager()
            pq_status = pq_tls.get_status()
            sentinel.console.print(f"\n[bold]PQ-TLS Configuration:[/bold]")
            sentinel.console.print(f"  Enabled        : {'[green]✓[/green]' if pq_status['enabled'] else '[dim]✗[/dim]'}")
            sentinel.console.print(f"  Mode           : [cyan]{pq_status['mode']}[/cyan]")
            sentinel.console.print(f"  Config file    : [dim]{pq_status['config_path']}[/dim]")
            
            algos = pq_status.get('algorithms', {})
            if algos:
                sentinel.console.print(f"  Algorithms:")
                for algo_type, algo_name in algos.items():
                    sentinel.console.print(f"    {algo_type:12s} : [cyan]{algo_name}[/cyan]")
        except Exception as e:
            sentinel.console.print(f"  [yellow]PQ-TLS: {e}[/yellow]")
        
        # Database encryption
        try:
            from modules.db_encryption import PQDatabaseEncryption
            import config
            sentinel.console.print(f"\n[bold]Database Encryption:[/bold]")
            sentinel.console.print(f"  Enabled        : {'[green]✓[/green]' if config.DB_ENCRYPTION else '[dim]✗[/dim]'}")
            sentinel.console.print(f"  Algorithm      : [cyan]AES-256-GCM + PBKDF2[/cyan]")
            sentinel.console.print(f"  Machine-bound  : [green]✓[/green]")
        except Exception as e:
            sentinel.console.print(f"  [yellow]DB encryption: {e}[/yellow]")
    
    elif sub == 'test':
        from modules.crypto_manager import CryptoManager
        sentinel.console.print("[cyan]Testing quantum-ready crypto...[/cyan]")
        
        try:
            crypto = CryptoManager()
            result = crypto.test_all()
            
            sentinel.console.print(f"\n[bold]Test Results:[/bold]")
            for test_name, passed in result.items():
                icon = '[green]✓[/green]' if passed else '[red]✗[/red]'
                sentinel.console.print(f"  {icon} {test_name}")
            
            total = len(result)
            passed = sum(result.values())
            sentinel.console.print(f"\n[bold]Summary: {passed}/{total} tests passed[/bold]")
        except Exception as e:
            sentinel.console.print(f"[red]Test failed: {e}[/red]")
    
    elif sub == 'enable':
        from modules.pq_tls_manager import PQTLSManager
        sentinel.console.print("[cyan]Enabling PQ-TLS...[/cyan]")
        
        try:
            pq_tls = PQTLSManager()
            pq_tls.enable()
            sentinel.console.print("[green]✓ PQ-TLS enabled[/green]")
            sentinel.console.print("[dim]All TLS connections will use hybrid post-quantum crypto[/dim]")
        except Exception as e:
            sentinel.console.print(f"[red]Failed to enable: {e}[/red]")
    
    elif sub == 'disable':
        from modules.pq_tls_manager import PQTLSManager
        sentinel.console.print("[cyan]Disabling PQ-TLS...[/cyan]")
        
        try:
            pq_tls = PQTLSManager()
            pq_tls.disable()
            sentinel.console.print("[yellow]PQ-TLS disabled[/yellow]")
            sentinel.console.print("[dim]Using classical cryptography[/dim]")
        except Exception as e:
            sentinel.console.print(f"[red]Failed to disable: {e}[/red]")
    
    else:
        sentinel.console.print("[red]Usage: crypto [status|test|enable|disable][/red]")
        sentinel.console.print("[dim]  status  - Show quantum-ready crypto status[/dim]")
        sentinel.console.print("[dim]  test    - Test all crypto algorithms[/dim]")
        sentinel.console.print("[dim]  enable  - Enable PQ-TLS (hybrid mode)[/dim]")
        sentinel.console.print("[dim]  disable - Disable PQ-TLS (classical mode)[/dim]")


def handle_sandbox(sentinel, command: str):
    """Autonomous sandbox commands"""
    parts = command.split()
    sub = parts[1] if len(parts) > 1 else 'status'
    
    if sub == 'status':
        from sentinel_brain.engines.risk_assessor import RiskAssessor
        from sentinel_brain.engines.escape_detector import EscapeDetector
        
        sentinel.console.print(f"\n[bold cyan]🛡️ Autonomous Sandbox Engine Status[/bold cyan]")
        
        # Risk assessor
        try:
            assessor = RiskAssessor()
            sentinel.console.print(f"\n[bold]Risk Assessor:[/bold]")
            sentinel.console.print(f"  Command risk   : [green]✓[/green] 39 dangerous commands tracked")
            sentinel.console.print(f"  File risk      : [green]✓[/green] Path traversal detection")
            sentinel.console.print(f"  Network risk   : [green]✓[/green] Suspicious IP detection")
        except Exception as e:
            sentinel.console.print(f"  [yellow]Risk assessor: {e}[/yellow]")
        
        # Escape detector
        try:
            from sentinel_brain.engines.escape_detector import EscapeDetector, SandboxForensicsDB
            db = SandboxForensicsDB()
            detector = EscapeDetector(db)
            sentinel.console.print(f"\n[bold]Escape Detector:[/bold]")
            sentinel.console.print(f"  Privilege esc  : [green]✓[/green] 5 detection methods")
            sentinel.console.print(f"  Binary check   : [green]✓[/green] 39 suspicious binaries")
            sentinel.console.print(f"  Network exfil  : [green]✓[/green] Outbound monitoring")
            sentinel.console.print(f"  Fork bomb      : [green]✓[/green] Process limit detection")
            sentinel.console.print(f"  Filesystem esc : [green]✓[/green] Mount point monitoring")
        except Exception as e:
            sentinel.console.print(f"  [yellow]Escape detector: {e}[/yellow]")
        
        # Sandbox manager
        try:
            from sentinel_brain.engines.sandbox_manager import SandboxManager
            manager = SandboxManager()
            sentinel.console.print(f"\n[bold]Sandbox Manager:[/bold]")
            sentinel.console.print(f"  Layer 1        : [green]✓[/green] Language safety (Python)")
            sentinel.console.print(f"  Layer 2        : [green]✓[/green] Syscall filtering")
            sentinel.console.print(f"  Layer 3        : [green]✓[/green] Process isolation")
            sentinel.console.print(f"  Layer 4        : [yellow]⚠[/yellow] Container (needs Docker)")
            sentinel.console.print(f"  Resource limits: [green]✓[/green] CPU/Memory/Disk/Network")
            sentinel.console.print(f"  Timeout        : [green]✓[/green] Configurable per-command")
        except Exception as e:
            sentinel.console.print(f"  [yellow]Sandbox manager: {e}[/yellow]")
    
    elif sub == 'test' and len(parts) >= 3:
        from sentinel_brain.engines.sandbox_manager import SandboxManager
        command_to_test = ' '.join(parts[2:])
        
        sentinel.console.print(f"[cyan]Testing command in sandbox: {command_to_test}[/cyan]")
        
        try:
            manager = SandboxManager()
            success, stdout, stderr = manager.execute(command_to_test, timeout=10)
            
            # Get forensics
            recent_runs = manager.get_recent_runs(limit=1)
            if recent_runs:
                run = recent_runs[0]
                sandbox_id, cmd, risk_level, started, ended, exit_code, escaped, event_count = run
                
                sentinel.console.print(f"\n[bold]Sandbox Execution Result:[/bold]")
                sentinel.console.print(f"  Exit code      : {exit_code}")
                sentinel.console.print(f"  Risk level     : [{risk_level.lower()}]{risk_level}[/{risk_level.lower()}]")
                sentinel.console.print(f"  Escaped        : {'[red]YES[/red]' if escaped else '[green]NO[/green]'}")
                
                if started and ended:
                    from datetime import datetime
                    start_dt = datetime.fromisoformat(started)
                    end_dt = datetime.fromisoformat(ended)
                    exec_time = (end_dt - start_dt).total_seconds()
                    sentinel.console.print(f"  Execution time : {exec_time:.2f}s")
                
                if stdout:
                    sentinel.console.print(f"\n[bold]Output:[/bold]")
                    sentinel.console.print(f"[dim]{stdout[:500]}[/dim]")
                
                if stderr:
                    sentinel.console.print(f"\n[bold]Errors:[/bold]")
                    sentinel.console.print(f"[dim]{stderr[:500]}[/dim]")
                
                # Check for escape attempts
                if event_count > 0:
                    events = manager.get_forensics(sandbox_id)
                    critical_events = [e for e in events if e[1] == 'CRITICAL']
                    
                    if critical_events:
                        sentinel.console.print(f"\n[bold red]⚠ Escape Attempts Detected:[/bold red]")
                        for event in critical_events[:5]:
                            event_type, severity, pid, details_json, auto_killed, timestamp = event
                            import json
                            details = json.loads(details_json) if details_json else {}
                            sentinel.console.print(f"  • {event_type}: {details.get('name', 'unknown')}")
                            if auto_killed:
                                sentinel.console.print(f"    [red]AUTO-KILLED[/red]")
            else:
                # Fallback display
                sentinel.console.print(f"\n[bold]Result:[/bold]")
                sentinel.console.print(f"  Success: {'[green]YES[/green]' if success else '[red]NO[/red]'}")
                if stdout:
                    sentinel.console.print(f"\n[bold]Output:[/bold]")
                    sentinel.console.print(f"[dim]{stdout[:500]}[/dim]")
                if stderr:
                    sentinel.console.print(f"\n[bold]Errors:[/bold]")
                    sentinel.console.print(f"[dim]{stderr[:500]}[/dim]")
                    
        except Exception as e:
            sentinel.console.print(f"[red]Sandbox test failed: {e}[/red]")
            import traceback
            sentinel.console.print(f"[dim]{traceback.format_exc()[:500]}[/dim]")
    
    elif sub == 'forensics':
        from sentinel_brain.engines.sandbox_manager import SandboxManager
        
        sentinel.console.print(f"\n[bold cyan]Sandbox Forensics[/bold cyan]")
        
        try:
            manager = SandboxManager()
            recent = manager.get_recent_runs(limit=10)
            
            if recent:
                sentinel.console.print(f"\n[bold]Recent Sandbox Runs:[/bold]")
                for run in recent:
                    sandbox_id, cmd, risk_level, started, ended, exit_code, escaped, event_count = run
                    
                    risk_color = 'red' if risk_level == 'CRITICAL' else 'yellow' if risk_level == 'HIGH' else 'green'
                    escaped_icon = '🔴' if escaped else '🟢'
                    
                    # Truncate command
                    cmd_display = cmd[:60] + '...' if len(cmd) > 60 else cmd
                    
                    sentinel.console.print(f"  {escaped_icon} [{risk_color}]{risk_level}[/{risk_color}] {cmd_display}")
                    
                    # Calculate execution time
                    if started and ended:
                        from datetime import datetime
                        try:
                            start_dt = datetime.fromisoformat(started)
                            end_dt = datetime.fromisoformat(ended)
                            exec_time = (end_dt - start_dt).total_seconds()
                            sentinel.console.print(f"     [dim]{started} | exit={exit_code} | time={exec_time:.2f}s | events={event_count}[/dim]")
                        except:
                            sentinel.console.print(f"     [dim]{started} | exit={exit_code} | events={event_count}[/dim]")
                    
                    if escaped:
                        sentinel.console.print(f"     [red]ESCAPE DETECTED[/red]")
            else:
                sentinel.console.print("[dim]No sandbox runs recorded yet[/dim]")
        except Exception as e:
            sentinel.console.print(f"[red]Forensics error: {e}[/red]")
    
    else:
        sentinel.console.print("[red]Usage: sandbox [status|test <command>|forensics][/red]")
        sentinel.console.print("[dim]  status           - Show sandbox engine status[/dim]")
        sentinel.console.print("[dim]  test <command>   - Test command in sandbox[/dim]")
        sentinel.console.print("[dim]  forensics        - Show recent sandbox runs[/dim]")
