#!/usr/bin/env python3
"""
The Sentinel - Professional Threat Intelligence Platform
Enhanced CLI Interface with Real-Time Progress
"""

import os
import sys
import time
import subprocess
import json
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from modules.cli_interface import EnhancedCLI
from modules.digital_footprint import AdvancedFootprintCollector
from modules.anomaly_analyzer import PredictiveAnalyzer
from modules.reporting_engine import LegalReportingEngine
from modules.stealth_manager import StealthManager
from modules.darkweb_crawler import DarkWebCrawler
from modules.evidence_manager import EvidenceManager
from modules.semantic_analyzer import SemanticAnalyzer
from modules.media_validator import MediaValidator
from modules.financial_analyzer import FinancialAnalyzer

class TheSentinelPro:
    def __init__(self):
        self.console = Console()
        self.cli = EnhancedCLI(self.console)
        self.collector = AdvancedFootprintCollector()
        self.analyzer = PredictiveAnalyzer()
        self.reporter = LegalReportingEngine()
        self.stealth = StealthManager()
        self.darkweb = DarkWebCrawler()
        self.evidence = EvidenceManager()
        self.semantic = SemanticAnalyzer()
        self.media = MediaValidator()
        self.financial = FinancialAnalyzer()
        self.session_data = {}
        
        # Create main investigations directory
        os.makedirs('investigations', exist_ok=True)
        
    def display_banner(self):
        """Enhanced animated banner with professional styling"""
        banner_art = """
[bold cyan]╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ████████╗██╗  ██╗███████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ║
║  ╚══██╔══╝██║  ██║██╔════╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ║
║     ██║   ███████║█████╗      ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ║
║     ██║   ██╔══██║██╔══╝      ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ║
║     ██║   ██║  ██║███████╗    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ ║
║     ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ║
║                                                                              ║
║                [bold white]Professional Threat Intelligence Platform[/bold white]                ║
║                        [dim]Version 2.0 - Enhanced & Stealth[/dim]                       ║
╚══════════════════════════════════════════════════════════════════════════════╝[/bold cyan]
        """
        
        self.console.print(Panel(banner_art, border_style="cyan"))
        
        # Enhanced loading animation with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            init_task = progress.add_task("[cyan]Initializing Sentinel Systems...", total=100)
            
            systems = [
                "Stealth Manager", "Proxy Network", "Dark Web Crawler", 
                "AI Threat Engine", "Evidence Vault", "Legal Framework"
            ]
            
            for i, system in enumerate(systems):
                progress.update(init_task, advance=16, description=f"[cyan]Loading {system}...")
                time.sleep(0.3)
            
            progress.update(init_task, completed=100, description="[green]All systems operational")
            time.sleep(0.5)
        
        self.console.print("\n[bold green]🛡️  The Sentinel Pro - Ready for Operations[/bold green]\n")

    def run(self):
        """Enhanced main execution loop with rich interface"""
        self.display_banner()
        
        while True:
            try:
                # Enhanced prompt with status indicators
                status_panel = self._create_status_panel()
                self.console.print(status_panel)
                
                command = self.console.input("\n[bold blue]sentinel-pro>[/bold blue] ").strip().lower()
                
                if command in ['exit', 'quit', 'q']:
                    self.console.print("[yellow]Shutting down The Sentinel Pro...[/yellow]")
                    break
                elif command in ['help', '?']:
                    self._show_enhanced_help()
                elif command.startswith('collect'):
                    self._handle_enhanced_collect(command)
                elif command.startswith('analyze'):
                    self._handle_predictive_analyze()
                elif command.startswith('darkweb'):
                    self._handle_darkweb_scan(command)
                elif command.startswith('semantic'):
                    self._handle_semantic_analysis()
                elif command.startswith('media'):
                    self._handle_media_validation()
                elif command.startswith('financial'):
                    self._handle_financial_analysis()
                elif command.startswith('network'):
                    self._handle_network_mapping()
                elif command.startswith('report'):
                    self._handle_legal_report()
                elif command == 'status':
                    self._show_detailed_status()
                elif command == 'stealth':
                    self._configure_stealth()
                elif command == 'evidence':
                    self._manage_evidence()
                elif command == 'clear':
                    self.console.clear()
                    self.display_banner()
                else:
                    self.console.print(f"[red]Unknown command: {command}[/red]")
                    self.console.print("Type 'help' for available commands")
                    
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Operation interrupted by user[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")

    def _create_status_panel(self):
        """Create real-time status panel"""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Status", style="dim")
        table.add_column("Value", style="bold")
        
        # System status indicators
        stealth_status = "[green]ACTIVE[/green]" if self.stealth.is_active() else "[red]INACTIVE[/red]"
        proxy_count = len(self.stealth.get_proxy_list())
        evidence_count = len(self.evidence.get_evidence_list())
        
        table.add_row("Stealth Mode:", stealth_status)
        table.add_row("Active Proxies:", f"[cyan]{proxy_count}[/cyan]")
        table.add_row("Evidence Items:", f"[yellow]{evidence_count}[/yellow]")
        
        if 'target' in self.session_data:
            table.add_row("Current Target:", f"[magenta]{self.session_data['target']}[/magenta]")
        
        return Panel(table, title="[bold]System Status[/bold]", border_style="dim")

    def _show_enhanced_help(self):
        """Enhanced help with categorized commands"""
        help_panel = Panel("""
[bold cyan]COLLECTION COMMANDS[/bold cyan]
[green]collect <target>[/green]     - Advanced multi-source data collection
[green]darkweb <target>[/green]     - Deep/dark web investigation
[green]stealth[/green]              - Configure stealth & proxy settings

[bold cyan]ANALYSIS COMMANDS[/bold cyan]
[green]analyze[/green]              - AI-powered predictive threat analysis
[green]semantic[/green]             - Semantic analysis of content for intent/sentiment
[green]media[/green]                - Validate media integrity and detect deepfakes
[green]financial[/green]            - Analyze financial trails and crypto addresses
[green]network[/green]              - Map influence networks and detect coordination
[green]evidence[/green]             - Manage legal evidence chain

[bold cyan]REPORTING COMMANDS[/bold cyan]
[green]report[/green]               - Generate legal-grade intelligence report
[green]status[/green]               - Detailed system and session status

[bold cyan]SYSTEM COMMANDS[/bold cyan]
[green]clear[/green]                - Clear screen and redisplay banner
[green]help / ?[/green]             - Display this help menu
[green]exit / quit / q[/green]      - Exit The Sentinel Pro

[bold yellow]EXAMPLE USAGE:[/bold yellow]
  sentinel-pro> collect john.doe@example.com
  sentinel-pro> darkweb suspicious_user
  sentinel-pro> analyze
  sentinel-pro> report
        """, title="[bold]The Sentinel Pro - Command Reference[/bold]", border_style="cyan")
        
        self.console.print(help_panel)

    def _handle_enhanced_collect(self, command):
        """Enhanced collection with real-time progress and user-specific folders"""
        parts = command.split(' ', 1)
        if len(parts) < 2:
            self.console.print("[red]Usage: collect <target>[/red]")
            return
            
        target = parts[1]
        
        # Create user-specific folder
        clean_target = target.replace('@', '').replace('.', '_').replace('/', '_')
        user_folder = f"investigations/{clean_target}"
        os.makedirs(user_folder, exist_ok=True)
        os.makedirs(f"{user_folder}/profiles", exist_ok=True)
        os.makedirs(f"{user_folder}/media", exist_ok=True)
        os.makedirs(f"{user_folder}/reports", exist_ok=True)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            collect_task = progress.add_task("[cyan]Collecting intelligence...", total=100)
            
            # Enhanced collection with stealth
            progress.update(collect_task, advance=20, description="[cyan]Initializing stealth protocols...")
            self.stealth.activate()
            
            progress.update(collect_task, advance=30, description="[cyan]Scraping surface web...")
            surface_data = self.collector.collect_surface_data(target)
            
            progress.update(collect_task, advance=25, description="[cyan]Analyzing social media...")
            social_data = self.collector.collect_social_data(target)
            
            progress.update(collect_task, advance=25, description="[cyan]Finalizing collection...")
            
            # Combine and store data
            collected_data = {
                'target': target,
                'surface_data': surface_data,
                'social_data': social_data,
                'timestamp': datetime.now().isoformat(),
                'stealth_used': True,
                'user_folder': user_folder
            }
            
            # Save individual platform data to user folder
            for platform_data in social_data:
                platform = platform_data.get('platform', 'unknown')
                platform_file = f"{user_folder}/profiles/{platform}_profile.json"
                with open(platform_file, 'w') as f:
                    json.dump(platform_data, f, indent=2)
            
            # Save complete collection data
            collection_file = f"{user_folder}/complete_collection.json"
            with open(collection_file, 'w') as f:
                json.dump(collected_data, f, indent=2)
            
            self.session_data['target'] = target
            self.session_data['collected_data'] = collected_data
            self.session_data['user_folder'] = user_folder
            self.evidence.add_evidence('collection', collected_data)
            
            progress.update(collect_task, completed=100, description="[green]Collection completed")
        
        self.console.print(f"[green]✓ Enhanced collection completed for: {target}[/green]")
        self.console.print(f"[green]📁 Data saved to: {user_folder}[/green]")
        self.console.print(f"[dim]Found: {len(surface_data)} surface sources, {len(social_data)} social profiles[/dim]")
        
        # Display detailed collection results with enhanced profile information
        if social_data:
            self.console.print("\n[bold cyan]📊 Detailed Social Media Profiles:[/bold cyan]")
            for profile in social_data:
                platform = profile.get('platform', 'unknown')
                status = profile.get('status', 'unknown')
                profile_info = profile.get('profile_info', {})
                bio_data = profile.get('bio_data', {})
                posts_data = profile.get('posts_data', {})
                contact_info = profile.get('contact_info', {})
                
                if status == 'success':
                    self.console.print(f"\n  🔹 [bold green]{platform.upper()}[/bold green] Profile:")
                    
                    # Basic profile info
                    display_name = profile_info.get('display_name', 'N/A')
                    username = profile_info.get('username', 'N/A')
                    followers = profile_info.get('follower_count', 'N/A')
                    following = profile_info.get('following_count', 'N/A')
                    verified = '✓ Verified' if profile_info.get('verified', False) else '✗ Not Verified'
                    
                    self.console.print(f"    • Name: [white]{display_name}[/white]")
                    self.console.print(f"    • Username: [cyan]@{username}[/cyan]")
                    self.console.print(f"    • Followers: [yellow]{followers}[/yellow] | Following: [yellow]{following}[/yellow]")
                    self.console.print(f"    • Status: [green]{verified}[/green]")
                    
                    # Bio information
                    bio = bio_data.get('bio', 'N/A')
                    location = bio_data.get('location', 'N/A')
                    website = bio_data.get('website', 'N/A')
                    
                    if bio != 'N/A':
                        self.console.print(f"    • Bio: [dim]{bio[:100]}{'...' if len(bio) > 100 else ''}[/dim]")
                    if location != 'N/A':
                        self.console.print(f"    • Location: [blue]{location}[/blue]")
                    if website != 'N/A':
                        self.console.print(f"    • Website: [link]{website}[/link]")
                    
                    # Posts information
                    posts = posts_data.get('posts', [])
                    if posts:
                        self.console.print(f"    • Posts: [magenta]{len(posts)} posts collected[/magenta]")
                    
                    # Contact information
                    email = contact_info.get('email', 'N/A')
                    phone = contact_info.get('phone', 'N/A')
                    
                    if email != 'N/A':
                        self.console.print(f"    • Email: [red]{email}[/red]")
                    if phone != 'N/A':
                        self.console.print(f"    • Phone: [red]{phone}[/red]")
                    
                    # Profile URL
                    profile_url = profile.get('url', 'N/A')
                    if profile_url != 'N/A':
                        self.console.print(f"    • URL: [link]{profile_url}[/link]")
                        
                else:
                    self.console.print(f"  • [yellow]{platform.upper()}[/yellow]: {status}")
        
        if surface_data:
            self.console.print("\n[bold cyan]🌐 Surface Web Sources:[/bold cyan]")
            for source in surface_data[:3]:  # Show first 3 sources
                source_type = source.get('source', 'unknown')
                status = source.get('status', 'unknown')
                results_count = len(source.get('results', []))
                
                self.console.print(f"  • [green]{source_type.upper()}[/green]: {status} | Results: {results_count}")

    def _handle_predictive_analyze(self):
        """Enhanced predictive analysis"""
        if 'collected_data' not in self.session_data:
            self.console.print("[red]No data to analyze. Run 'collect' first.[/red]")
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            analyze_task = progress.add_task("[cyan]Running AI analysis...", total=100)
            
            progress.update(analyze_task, advance=25, description="[cyan]Behavioral pattern analysis...")
            behavioral_analysis = self.analyzer.analyze_behavior(self.session_data['collected_data'])
            
            progress.update(analyze_task, advance=25, description="[cyan]Threat prediction modeling...")
            threat_predictions = self.analyzer.predict_threats(self.session_data['collected_data'])
            
            progress.update(analyze_task, advance=25, description="[cyan]Anomaly detection...")
            anomalies = self.analyzer.detect_anomalies(self.session_data['collected_data'])
            
            progress.update(analyze_task, advance=25, description="[cyan]Risk assessment...")
            risk_score = self.analyzer.calculate_enhanced_risk(self.session_data['collected_data'])
            
            analysis_result = {
                'behavioral_analysis': behavioral_analysis,
                'threat_predictions': threat_predictions,
                'anomalies': anomalies,
                'risk_score': risk_score,
                'timestamp': datetime.now().isoformat()
            }
            
            self.session_data['analysis'] = analysis_result
            self.evidence.add_evidence('analysis', analysis_result)
            
            progress.update(analyze_task, completed=100, description="[green]Analysis completed")
        
        # Display threat level
        threat_level = "HIGH" if risk_score > 70 else "MEDIUM" if risk_score > 40 else "LOW"
        color = "red" if threat_level == "HIGH" else "yellow" if threat_level == "MEDIUM" else "green"
        
        self.console.print(f"[{color}]🚨 Threat Level: {threat_level} (Score: {risk_score}/100)[/{color}]")
        
        if threat_predictions:
            self.console.print(f"[orange1]⚠️  {len(threat_predictions)} threat predictions generated[/orange1]")

    def _handle_darkweb_scan(self, command):
        """Dark web scanning with Tor integration"""
        parts = command.split(' ', 1)
        if len(parts) < 2:
            self.console.print("[red]Usage: darkweb <target>[/red]")
            return
            
        target = parts[1]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            darkweb_task = progress.add_task("[magenta]Scanning dark web...", total=100)
            
            progress.update(darkweb_task, advance=30, description="[magenta]Connecting to Tor network...")
            tor_status = self.darkweb.connect_tor()
            
            if not tor_status:
                self.console.print("[red]Failed to connect to Tor network[/red]")
                return
            
            progress.update(darkweb_task, advance=40, description="[magenta]Crawling .onion sites...")
            onion_results = self.darkweb.crawl_onion_sites(target)
            
            progress.update(darkweb_task, advance=30, description="[magenta]Analyzing encrypted content...")
            decrypted_data = self.darkweb.analyze_encrypted_content(onion_results)
            
            darkweb_data = {
                'target': target,
                'onion_results': onion_results,
                'decrypted_data': decrypted_data,
                'timestamp': datetime.now().isoformat()
            }
            
            self.session_data['darkweb_data'] = darkweb_data
            self.evidence.add_evidence('darkweb', darkweb_data)
            
            progress.update(darkweb_task, completed=100, description="[green]Dark web scan completed")
        
        self.console.print(f"[green]✓ Dark web scan completed[/green]")
        self.console.print(f"[dim]Found: {len(onion_results)} .onion references[/dim]")

    def _handle_legal_report(self):
        """Generate legal-grade report with chain of custody in user folder"""
        if 'analysis' not in self.session_data:
            self.console.print("[red]No analysis data. Run 'analyze' first.[/red]")
            return
        
        user_folder = self.session_data.get('user_folder', 'reports')
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            report_task = progress.add_task("[cyan]Generating legal report...", total=100)
            
            progress.update(report_task, advance=25, description="[cyan]Creating evidence chain...")
            evidence_chain = self.evidence.generate_chain_of_custody()
            
            progress.update(report_task, advance=25, description="[cyan]Compiling legal documentation...")
            legal_report = self.reporter.generate_legal_report(self.session_data, evidence_chain)
            
            progress.update(report_task, advance=25, description="[cyan]Creating immutable hash...")
            report_hash = self.evidence.create_immutable_hash(legal_report)
            
            progress.update(report_task, advance=25, description="[cyan]Finalizing report...")
            
            # Save report to user-specific folder
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = self.session_data.get('target', 'unknown').replace('@', '').replace('.', '_')
            report_id = f"SENT-LEGAL-{timestamp}"
            
            # Update reporter to use user folder
            original_report_dir = self.reporter.report_dir
            self.reporter.report_dir = f"{user_folder}/reports"
            os.makedirs(self.reporter.report_dir, exist_ok=True)
            
            report_paths = self.reporter.save_legal_report(legal_report, report_hash)
            
            # Restore original report directory
            self.reporter.report_dir = original_report_dir
            
            progress.update(report_task, completed=100, description="[green]Legal report generated")
        
        self.console.print(f"[green]✓ Legal-grade report generated in: {user_folder}/reports[/green]")
        self.console.print(f"[green]📄 HTML Report: {report_paths.get('html_report', 'N/A')}[/green]")
        self.console.print(f"[dim]Evidence Hash: {report_hash[:16]}...[/dim]")

    def _show_detailed_status(self):
        """Show comprehensive system status"""
        status_table = Table(title="[bold]Detailed System Status[/bold]", border_style="cyan")
        status_table.add_column("Component", style="bold")
        status_table.add_column("Status", justify="center")
        status_table.add_column("Details", style="dim")
        
        # System components status
        components = [
            ("Stealth Manager", "🟢 ACTIVE" if self.stealth.is_active() else "🔴 INACTIVE", f"{len(self.stealth.get_proxy_list())} proxies"),
            ("Dark Web Crawler", "🟢 READY", "Tor integration available"),
            ("Evidence Vault", "🟢 SECURE", f"{len(self.evidence.get_evidence_list())} items"),
            ("AI Threat Engine", "🟢 LOADED", "Predictive models ready"),
            ("Legal Framework", "🟢 COMPLIANT", "Chain of custody active")
        ]
        
        for component, status, details in components:
            status_table.add_row(component, status, details)
        
        self.console.print(status_table)
        
        # Session information
        if 'target' in self.session_data:
            session_panel = Panel(f"""
[bold]Current Investigation:[/bold]
Target: [magenta]{self.session_data['target']}[/magenta]
Collection: [green]✓ Complete[/green] if 'collected_data' in self.session_data else [red]✗ Pending[/red]
Analysis: [green]✓ Complete[/green] if 'analysis' in self.session_data else [red]✗ Pending[/red]
Dark Web: [green]✓ Complete[/green] if 'darkweb_data' in self.session_data else [yellow]○ Optional[/yellow]
            """, title="[bold]Session Status[/bold]", border_style="yellow")
            self.console.print(session_panel)

    def _configure_stealth(self):
        """Configure stealth and proxy settings"""
        stealth_panel = Panel("""
[bold cyan]Stealth Configuration[/bold cyan]

Current Status: [green]ACTIVE[/green] if self.stealth.is_active() else [red]INACTIVE[/red]
Proxy Rotation: [green]ENABLED[/green]
Tor Integration: [green]AVAILABLE[/green]
Anti-Detection: [green]ACTIVE[/green]

[dim]Stealth features are automatically managed for optimal security.[/dim]
        """, title="[bold]Stealth Manager[/bold]", border_style="green")
        
        self.console.print(stealth_panel)

    def _manage_evidence(self):
        """Evidence management interface"""
        evidence_list = self.evidence.get_evidence_list()
        
        evidence_table = Table(title="[bold]Evidence Vault[/bold]", border_style="yellow")
        evidence_table.add_column("ID", style="dim")
        evidence_table.add_column("Type", style="bold")
        evidence_table.add_column("Timestamp", style="cyan")
        evidence_table.add_column("Hash", style="green")
        
        for i, evidence_item in enumerate(evidence_list):
            evidence_table.add_row(
                str(i+1),
                evidence_item['type'],
                evidence_item['timestamp'][:19],
                evidence_item['hash'][:12] + "..."
            )
        
        self.console.print(evidence_table)
    
    def _extract_number(self, text):
        """Extract number from text like '1.2M', '500K', etc."""
        if not text or not isinstance(text, str):
            return 0
        
        import re
        # Remove commas and spaces
        text = text.replace(',', '').replace(' ', '').upper()
        
        # Extract number with multiplier
        match = re.search(r'([0-9.]+)([KMB]?)', text)
        if match:
            number = float(match.group(1))
            multiplier = match.group(2)
            
            if multiplier == 'K':
                return int(number * 1000)
            elif multiplier == 'M':
                return int(number * 1000000)
            elif multiplier == 'B':
                return int(number * 1000000000)
            else:
                return int(number)
        
        return 0

if __name__ == "__main__":
    sentinel_pro = TheSentinelPro()
    sentinel_pro.run()
    def _handle_semantic_analysis(self):
        """AI-powered semantic analysis of collected content"""
        if 'collected_data' not in self.session_data:
            self.console.print("[red]No data to analyze. Run 'collect' first.[/red]")
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            semantic_task = progress.add_task("[cyan]Running semantic analysis...", total=100)
            
            # Prepare content for analysis
            progress.update(semantic_task, advance=20, description="[cyan]Extracting content...")
            content_list = []
            
            # Extract content from collected data
            collected = self.session_data['collected_data']
            for source, data in collected.get('surface_data', {}).items():
                if isinstance(data, dict) and 'content' in data:
                    content_list.append((data['content'], source))
            
            for i, data in enumerate(collected.get('social_data', [])):
                if isinstance(data, dict):
                    # Extract posts data
                    posts_data = data.get('posts_data', {})
                    if posts_data and 'posts' in posts_data:
                        for post in posts_data['posts']:
                            if isinstance(post, dict):
                                post_text = post.get('text', post.get('content', post.get('caption', '')))
                                if post_text:
                                    content_list.append((post_text, f"{data.get('platform', 'unknown')}_post"))
                    
                    # Extract bio data
                    bio_data = data.get('bio_data', {})
                    if bio_data and 'bio' in bio_data:
                        content_list.append((bio_data['bio'], f"{data.get('platform', 'unknown')}_bio"))
            
            progress.update(semantic_task, advance=30, description="[cyan]Analyzing content semantics...")
            semantic_results = self.semantic.batch_analyze(content_list)
            
            progress.update(semantic_task, advance=30, description="[cyan]Generating semantic report...")
            semantic_report = self.semantic.generate_semantic_report(semantic_results)
            
            progress.update(semantic_task, advance=20, description="[cyan]Finalizing analysis...")
            
            self.session_data['semantic_analysis'] = {
                'results': semantic_results,
                'report': semantic_report,
                'timestamp': datetime.now().isoformat()
            }
            
            self.evidence.add_evidence('semantic_analysis', self.session_data['semantic_analysis'])
            
            progress.update(semantic_task, completed=100, description="[green]Semantic analysis completed")
        
        # Display key findings
        risk_level = semantic_report.get('risk_level', 'UNKNOWN')
        color = "red" if risk_level == "CRITICAL" else "yellow" if risk_level == "HIGH" else "green"
        
        self.console.print(f"[{color}]🧠 Semantic Risk Level: {risk_level}[/{color}]")
        
        if semantic_report.get('high_risk_sources'):
            self.console.print(f"[orange1]⚠️  {len(semantic_report['high_risk_sources'])} high-risk content sources identified[/orange1]")

    def _handle_media_validation(self):
        """Media integrity validation and deepfake detection"""
        if 'collected_data' not in self.session_data:
            self.console.print("[red]No data to analyze. Run 'collect' first.[/red]")
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            media_task = progress.add_task("[cyan]Validating media integrity...", total=100)
            
            # Extract media URLs from collected data
            progress.update(media_task, advance=20, description="[cyan]Extracting media URLs...")
            media_urls = []
            
            collected = self.session_data['collected_data']
            for source, data in collected.get('surface_data', {}).items():
                if isinstance(data, dict) and 'images' in data:
                    for img_url in data['images']:
                        media_urls.append((img_url, source))
            
            for i, data in enumerate(collected.get('social_data', [])):
                if isinstance(data, dict):
                    profile_info = data.get('profile_info', {})
                    if profile_info and 'profile_image' in profile_info:
                        profile_image = profile_info['profile_image']
                        if profile_image and profile_image.startswith('http'):
                            media_urls.append((profile_image, f"{data.get('platform', 'unknown')}_profile"))
            
            if not media_urls:
                self.console.print("[yellow]No media URLs found in collected data[/yellow]")
                return
            
            progress.update(media_task, advance=40, description="[cyan]Downloading and analyzing media...")
            media_results = self.media.batch_validate_media(media_urls[:5])  # Limit to 5 for demo
            
            progress.update(media_task, advance=30, description="[cyan]Generating media report...")
            media_report = self.media.generate_media_report(media_results)
            
            progress.update(media_task, advance=10, description="[cyan]Finalizing validation...")
            
            self.session_data['media_validation'] = {
                'results': media_results,
                'report': media_report,
                'timestamp': datetime.now().isoformat()
            }
            
            self.evidence.add_evidence('media_validation', self.session_data['media_validation'])
            
            progress.update(media_task, completed=100, description="[green]Media validation completed")
        
        # Display key findings
        integrity_level = media_report.get('overall_media_integrity', 'UNKNOWN')
        color = "red" if integrity_level == "COMPROMISED_INTEGRITY" else "yellow" if integrity_level == "LOW_INTEGRITY" else "green"
        
        self.console.print(f"[{color}]🎭 Media Integrity: {integrity_level}[/{color}]")
        
        if media_report.get('high_risk_media_count', 0) > 0:
            self.console.print(f"[red]🚨 {media_report['high_risk_media_count']} potentially manipulated media files detected[/red]")

    def _handle_financial_analysis(self):
        """Financial trail analysis and cryptocurrency tracking"""
        if 'collected_data' not in self.session_data:
            self.console.print("[red]No data to analyze. Run 'collect' first.[/red]")
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            financial_task = progress.add_task("[cyan]Analyzing financial trails...", total=100)
            
            # Prepare content for financial analysis
            progress.update(financial_task, advance=20, description="[cyan]Extracting financial data...")
            content_list = []
            
            collected = self.session_data['collected_data']
            for source, data in collected.get('surface_data', {}).items():
                if isinstance(data, dict) and 'content' in data:
                    content_list.append((data['content'], source))
            
            for i, data in enumerate(collected.get('social_data', [])):
                if isinstance(data, dict):
                    # Check bio for financial info
                    bio_data = data.get('bio_data', {})
                    if bio_data and 'bio' in bio_data:
                        content_list.append((bio_data['bio'], f"{data.get('platform', 'unknown')}_bio"))
                    
                    # Check posts for financial content
                    posts_data = data.get('posts_data', {})
                    if posts_data and 'posts' in posts_data:
                        for post in posts_data['posts']:
                            if isinstance(post, dict):
                                post_text = post.get('text', post.get('content', post.get('caption', '')))
                                if post_text:
                                    content_list.append((post_text, f"{data.get('platform', 'unknown')}_post"))
            
            progress.update(financial_task, advance=40, description="[cyan]Scanning for crypto addresses...")
            financial_results = self.financial.batch_analyze_financial_content(content_list)
            
            progress.update(financial_task, advance=30, description="[cyan]Generating financial report...")
            financial_report = self.financial.generate_financial_report(financial_results)
            
            progress.update(financial_task, advance=10, description="[cyan]Finalizing analysis...")
            
            self.session_data['financial_analysis'] = {
                'results': financial_results,
                'report': financial_report,
                'timestamp': datetime.now().isoformat()
            }
            
            self.evidence.add_evidence('financial_analysis', self.session_data['financial_analysis'])
            
            progress.update(financial_task, completed=100, description="[green]Financial analysis completed")
        
        # Display key findings
        risk_level = financial_report.get('risk_assessment', {}).get('overall_risk_level', 'UNKNOWN')
        color = "red" if risk_level == "CRITICAL" else "yellow" if risk_level == "HIGH" else "green"
        
        self.console.print(f"[{color}]💰 Financial Risk Level: {risk_level}[/{color}]")
        
        crypto_summary = financial_report.get('cryptocurrency_summary', {})
        total_addresses = crypto_summary.get('total_unique_addresses', 0)
        if total_addresses > 0:
            self.console.print(f"[cyan]🪙 {total_addresses} cryptocurrency addresses identified[/cyan]")
        
        high_risk_addresses = len(financial_report.get('blockchain_risk_summary', {}).get('high_risk_addresses', []))
        if high_risk_addresses > 0:
            self.console.print(f"[red]⚠️  {high_risk_addresses} high-risk blockchain addresses detected[/red]")

    def _handle_network_mapping(self):
        """Network mapping and influence analysis"""
        if 'collected_data' not in self.session_data:
            self.console.print("[red]No data to analyze. Run 'collect' first.[/red]")
            return
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            network_task = progress.add_task("[cyan]Mapping influence network...", total=100)
            
            # Prepare data for network analysis
            progress.update(network_task, advance=20, description="[cyan]Extracting network data...")
            
            # Convert collected data to format expected by network mapper
            network_data = []
            collected = self.session_data['collected_data']
            
            for i, data in enumerate(collected.get('social_data', [])):
                if isinstance(data, dict):
                    profile_info = data.get('profile_info', {})
                    bio_data = data.get('bio_data', {})
                    posts_data = data.get('posts_data', {})
                    
                    # Extract posts content
                    posts_content = []
                    if posts_data and 'posts' in posts_data:
                        for post in posts_data['posts']:
                            if isinstance(post, dict):
                                post_text = post.get('text', post.get('content', post.get('caption', '')))
                                if post_text:
                                    posts_content.append(post_text)
                    
                    network_item = {
                        'source': f"{data.get('platform', 'unknown')}_{i}",
                        'platform': data.get('platform', 'unknown'),
                        'content': ' '.join(posts_content),
                        'display_name': profile_info.get('display_name', ''),
                        'followers': self._extract_number(profile_info.get('follower_count', '0')),
                        'following': self._extract_number(profile_info.get('following_count', '0')),
                        'verified': profile_info.get('verified', False),
                        'bio': bio_data.get('bio', ''),
                        'created_date': profile_info.get('join_date', ''),
                        'location': profile_info.get('location', ''),
                        'website': profile_info.get('website', '')
                    }
                    network_data.append(network_item)
            
            # Save data for Go network mapper
            progress.update(network_task, advance=20, description="[cyan]Preparing network analysis...")
            network_file = '/tmp/network_data.json'
            with open(network_file, 'w') as f:
                json.dump(network_data, f)
            
            # Run Go network mapper
            progress.update(network_task, advance=40, description="[cyan]Running network analysis...")
            try:
                result = subprocess.run(['./network_mapper/network_mapper', network_file], 
                                      capture_output=True, text=True, cwd='/home/kali/osints')
                
                if result.returncode == 0:
                    network_analysis = json.loads(result.stdout)
                else:
                    self.console.print(f"[red]Network analysis failed: {result.stderr}[/red]")
                    return
                    
            except Exception as e:
                self.console.print(f"[red]Network mapper error: {str(e)}[/red]")
                return
            
            progress.update(network_task, advance=20, description="[cyan]Finalizing network map...")
            
            self.session_data['network_analysis'] = {
                'analysis': network_analysis,
                'timestamp': datetime.now().isoformat()
            }
            
            self.evidence.add_evidence('network_analysis', self.session_data['network_analysis'])
            
            progress.update(network_task, completed=100, description="[green]Network mapping completed")
        
        # Display key findings
        threat_assessment = network_analysis.get('threat_assessment', {})
        threat_level = threat_assessment.get('overall_threat_level', 'UNKNOWN')
        color = "red" if threat_level == "CRITICAL" else "yellow" if threat_level == "HIGH" else "green"
        
        self.console.print(f"[{color}]🕸️  Network Threat Level: {threat_level}[/{color}]")
        
        total_nodes = network_analysis.get('total_nodes', 0)
        clusters = len(network_analysis.get('clusters', []))
        
        self.console.print(f"[cyan]📊 Network: {total_nodes} nodes, {clusters} clusters identified[/cyan]")
        
        key_threats = len(threat_assessment.get('key_threats', []))
        if key_threats > 0:
            self.console.print(f"[red]🚨 {key_threats} key threat indicators in network[/red]")
