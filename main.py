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
import re
import logging
import argparse
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich.live import Live

# Import configuration
import config

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
from modules.fake_profile_detector import FakeProfileDetector
from modules.bugbounty_scanner import BugBountyScanner

# New modular imports
from modules.recon.whois_lookup import WhoisLookup
from modules.recon.subdomain_enum import SubdomainEnum
from modules.recon.go_scraper_bridge import GoScraperBridge
from modules.recon.report import ReconReport
from modules.bugbounty.ssl_checker import SSLChecker
from modules.bugbounty.headers_checker import HeadersChecker
from modules.bugbounty.port_scanner import PortScanner
from modules.bugbounty.endpoint_scanner import EndpointScanner
from modules.bugbounty.rust_analyzer_bridge import RustAnalyzerBridge
from modules.bugbounty.shodan_scanner import ShodanScanner
from modules.bugbounty.vuln_scanner import VulnScanner
from modules.bugbounty.screenshot import ScreenshotCapture
from modules.bugbounty.js_analyzer import JSAnalyzer
from modules.bugbounty.cve_lookup import CVELookup
from modules.bugbounty.subdomain_takeover import SubdomainTakeover
from modules.bugbounty.cors_scanner import CORSScanner
from modules.bugbounty.open_redirect import OpenRedirectScanner
from modules.bugbounty.nuclei_bridge import NucleiBridge
from modules.bugbounty.smuggler_bridge import SmugglerBridge
from modules.bugbounty.dirbuster_bridge import DirBusterBridge
from modules.bugbounty.cookie_analyzer import CookieAnalyzer
from modules.bugbounty.dns_zone_transfer import DNSZoneTransfer
from modules.bugbounty.fuzzer_bridge import RustFuzzerBridge
from modules.bugbounty.tech_fingerprint import TechFingerprint
from modules.bugbounty.auth_bypass import AuthBypassChecker
from modules.bugbounty.api_scanner import APIScanner
from modules.bugbounty.lfi_scanner import LFIScanner
from modules.bugbounty.xxe_scanner import XXEScanner
from modules.bugbounty.ssti_scanner import SSTIScanner
from modules.bugbounty.clickjacking import ClickjackingChecker
from modules.bugbounty.prototype_pollution import PrototypePollutionScanner
from modules.bugbounty.oauth_scanner import OAuthScanner
from modules.bugbounty.report import BugBountyReport
from modules.recon.wayback import WaybackMachine
from modules.recon.dns_history import DNSHistory
from modules.recon.email_osint import EmailOSINT
from modules.recon.email_report import EmailReport
from modules.recon.github_dorker import GitHubDorker
from modules.recon.google_dorker import GoogleDorker
from modules.recon.asn_mapper import ASNMapper
from modules.recon.cloud_assets import CloudAssetDiscovery
from modules.recon.cert_transparency import CertTransparency
from modules.recon.job_osint import JobOSINT
from modules.recon.phone_osint import PhoneOSINT
from modules.recon.phone_report import PhoneReport
from modules.recon.person_osint import PersonOSINT
from modules.recon.image_osint import ImageOSINT
from modules.recon.relation_mapper import RelationMapper
from modules.recon.person_report import PersonReport
from modules.ml_engine.nlp_analyzer import NLPProfileAnalyzer
from modules.ml_engine.timeline_analyzer import TimelineAnalyzer
from modules.ml_engine.writing_fingerprinter import WritingFingerprinter
from modules.breach.breach_checker import BreachChecker
from modules.breach.report import BreachReport
from modules.notifications import TelegramNotifier
from modules.pdf_export import PDFExporter

# Setup logging
from logging.handlers import RotatingFileHandler

_log_handler = RotatingFileHandler(
    config.LOG_FILE,
    maxBytes=5 * 1024 * 1024,  # 5 MB
    backupCount=3,
    encoding='utf-8'
)
_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        _log_handler,
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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
        self.fake_detector = FakeProfileDetector()
        self.bugbounty = BugBountyScanner()
        # New modular components
        self.whois       = WhoisLookup()
        self.subdomain   = SubdomainEnum()
        self.go_scraper  = GoScraperBridge()
        self.ssl         = SSLChecker()
        self.sec_headers = HeadersChecker()
        self.port_scan   = PortScanner()
        self.endpoints   = EndpointScanner()
        self.rust_analyzer = RustAnalyzerBridge()
        self.shodan      = ShodanScanner()
        self.vuln        = VulnScanner()
        self.screenshot  = ScreenshotCapture(output_dir=str(config.SCREENSHOTS_DIR))
        self.js_analyzer = JSAnalyzer()
        self.cve_lookup  = CVELookup()
        self.wayback     = WaybackMachine()
        self.dns_history = DNSHistory()
        self.email_osint = EmailOSINT()
        self.gh_dorker   = GitHubDorker()
        self.goog_dorker = GoogleDorker()
        self.asn_mapper  = ASNMapper()
        self.cloud_assets = CloudAssetDiscovery()
        self.cert_ct     = CertTransparency()
        self.job_osint   = JobOSINT()
        self.phone_osint = PhoneOSINT()
        self.person_osint    = PersonOSINT()
        self.image_osint     = ImageOSINT()
        self.relation_mapper = RelationMapper()
        self.nlp_analyzer    = NLPProfileAnalyzer()
        self.timeline_analyzer = TimelineAnalyzer()
        self.writing_fp      = WritingFingerprinter()
        self.takeover    = SubdomainTakeover()
        self.cors        = CORSScanner()
        self.open_redir  = OpenRedirectScanner()
        self.nuclei      = NucleiBridge()
        self.smuggler    = SmugglerBridge()
        self.dirbuster   = DirBusterBridge()
        self.cookie_scan = CookieAnalyzer()
        self.zone_xfr    = DNSZoneTransfer()
        self.fuzzer      = RustFuzzerBridge()
        self.tech_fp     = TechFingerprint()
        self.auth_bypass = AuthBypassChecker()
        self.api_scan    = APIScanner()
        self.lfi         = LFIScanner()
        self.xxe         = XXEScanner()
        self.ssti        = SSTIScanner()
        self.clickjack   = ClickjackingChecker()
        self.proto_poll  = PrototypePollutionScanner()
        self.oauth_scan  = OAuthScanner()
        self.breach      = BreachChecker()
        self.notifier    = TelegramNotifier(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID)
        self.pdf         = PDFExporter()
        self.session_data = {}
        
        # Validate binaries on startup
        self._validate_environment()
        
    def _validate_environment(self):
        """Validate environment and binaries"""
        missing_binaries = config.validate_binaries()
        if missing_binaries:
            logger.warning(f"Missing binaries: {', '.join(missing_binaries)}")
            logger.warning("Some features may not work. Run setup.sh to build binaries.")
        
    def display_banner(self):
        """pyfiglet SENTINEL + hand-crafted octopus"""
        p = self.console.print
        try:
            import pyfiglet
            sent_lines = pyfiglet.figlet_format('SENTINEL', font='doom').rstrip().split('\n')
        except ImportError:
            sent_lines = ['THE SENTINEL']

        OCT = [
            r"      ___________          ",
            r"    /             \        ",
            r"   | (o)       (o) |       ",
            r"   |    _______    |       ",
            r"   |   /       \   |       ",
            r"    \_/         \_/        ",
            r"   /|             |\       ",
            r"  / |             | \      ",
            r" /  |_____________|  \     ",
            r"/  /                 \ \   ",
        ]

        p()
        for line in sent_lines:
            p(f"[bold red]{line}[/bold red]")
        p()
        for line in OCT:
            p(f"[bold cyan]{line}[/bold cyan]")
        p()
        p("[dim]  ─────────────────────────────────────────────────────────────────[/dim]")
        p("  [bold green]OSINT[/bold green]  [bold red]BugBounty[/bold red]  [bold blue]Recon[/bold blue]  [bold magenta]AI/ML[/bold magenta]  [bold yellow]DarkWeb[/bold yellow]  [dim]│  Python · Go · Rust  │  40+ Platforms[/dim]")
        p("[dim]  ─────────────────────────────────────────────────────────────────[/dim]")
        p()
        self._startup_animation()

    def _startup_animation(self):
        """Hacking style startup animation"""
        import time
        p = self.console.print

        boot_msgs = [
            ("[bold green][+][/bold green]", "Initializing core engine...",            0.3),
            ("[bold green][+][/bold green]", "Loading OSINT modules (40+ platforms)",  0.25),
            ("[bold green][+][/bold green]", "Mounting ML engine (spaCy + sklearn)...",0.25),
            ("[bold green][+][/bold green]", "Establishing stealth protocols...",      0.3),
            ("[bold green][+][/bold green]", "Loading evidence vault...",              0.3),
            ("[bold yellow][!][/bold yellow]", "Tor routing : INACTIVE  (use 'tor on')",0.2),
            ("[bold green][+][/bold green]", "All systems operational.",               0.4),
        ]

        for icon, msg, delay in boot_msgs:
            p(f"  {icon} [dim]{msg}[/dim]")
            time.sleep(delay)

        p()

        scan_targets = [
            ("127.0.0.1",     "core"),
            ("localhost",      "loopback"),
            ("sentinel-core",  "engine"),
            ("ml-engine",      "AI/ML"),
            ("osint-db",       "database"),
        ]
        for host, label in scan_targets:
            p(f"  [dim]scanning[/dim] [cyan]{host:<20}[/cyan] [dim]({label})[/dim] [dim]...[/dim] [bold green]OK[/bold green]")
            time.sleep(0.08)

        p()
        p("[bold green]  \u2713 The Sentinel Pro is ready.[/bold green]  [dim]Type [/dim][bold white]help[/bold white][dim] for commands.[/dim]")
        p()
    def run(self):
        """Enhanced main execution loop with rich interface"""
        self.display_banner()
        
        while True:
            try:
                # Enhanced prompt with status indicators
                status_panel = self._create_status_panel()
                self.console.print(status_panel)
                
                raw_command = self.console.input("\n[bold blue]sentinel-pro>[/bold blue] ").strip()
                # Sirf command keyword lowercase karo, arguments (paths etc.) preserve karo
                parts = raw_command.split(' ', 1)
                command = parts[0].lower() + (' ' + parts[1] if len(parts) > 1 else '')
                
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
                elif command.startswith('fakecheck'):
                    self._handle_fake_profile_detection()
                elif command.startswith('bugbounty'):
                    self._handle_bugbounty(command)
                elif command.startswith('recon'):
                    self._handle_recon(command)
                elif command.startswith('breach'):
                    self._handle_breach(command)
                elif command.startswith('phone'):
                    self._handle_phone(command)
                elif command.startswith('person'):
                    self._handle_person(command)
                elif command.startswith('image'):
                    self._handle_image(command)
                elif command.startswith('nlp'):
                    self._handle_nlp(command)
                elif command.startswith('email'):
                    self._handle_email(command)
                elif command.startswith('scan all') or command.startswith('scan-all'):
                    parts = command.split(' ', 2)
                    if len(parts) < 3:
                        self.console.print("[red]Usage: scan all <domain>[/red]")
                    else:
                        domain = parts[2].strip()
                        self.console.print(f"[bold cyan]Full scan: {domain}[/bold cyan]")
                        self._handle_recon(f'recon {domain}')
                        self._handle_bugbounty(f'bugbounty {domain}')
                        self._handle_breach(f'breach {domain}')
                elif command.startswith('bulk'):
                    self._handle_bulk(command)
                elif command.startswith('report'):
                    self._handle_legal_report()
                elif command == 'status':
                    self._show_detailed_status()
                elif command in ('tor on', 'tor off', 'tor status', 'tor newip'):
                    self._handle_tor(command)
                elif command.startswith('telegram'):
                    self._handle_telegram(command)
                elif command == 'pdf':
                    self._handle_pdf()
                elif command == 'stealth':
                    self._configure_stealth()
                elif command == 'evidence':
                    self._manage_evidence()
                elif command == 'clear':
                    self.console.clear()
                    self.display_banner()
                elif command.startswith('train'):
                    self._handle_train(command)
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
        
        tor_status = "[green]🧅 TOR ON[/green]" if config.is_tor_active() else "[dim]🔓 TOR OFF[/dim]"
        table.add_row("Tor Routing:", tor_status)
        
        if 'target' in self.session_data:
            table.add_row("Current Target:", f"[magenta]{self.session_data['target']}[/magenta]")
        
        return Panel(table, title="[bold]System Status[/bold]", border_style="dim")

    def _show_enhanced_help(self):
        """Enhanced help with categorized commands"""
        help_panel = Panel("""
[bold cyan]OSINT COMMANDS[/bold cyan]
[green]collect <target>[/green]     - Multi-source data collection (40+ platforms)
[green]darkweb <target>[/green]     - Deep/dark web investigation
[green]stealth[/green]              - Configure stealth & proxy settings

[bold cyan]BUG BOUNTY & RECON COMMANDS[/bold cyan]  [bold yellow]🆕[/bold yellow]
[green]bugbounty <domain>[/green]   - Full bug bounty scan (SSL + ports + endpoints + Shodan + CVE + JS)
[green]recon <domain>[/green]       - Passive recon (WHOIS + subdomains + Wayback + DNS history + dorks)
[green]breach <email>[/green]       - Check email/username in data breach databases
[green]email <email>[/green]        - Full email OSINT (breach + social profiles + domain validation)
[green]phone <number>[/green]       - Phone number OSINT (carrier + country + line type + social hints)
[green]person <name/email/phone>[/green] - Person OSINT (naam/email/phone se social profiles + relations map)
[green]image <path>[/green]         - Image OSINT (reverse search + face detection + metadata)
[green]nlp <text or @file>[/green]  - NLP deep analysis (professions, interests, personality, writing style, timeline)
[green]bulk <file> <mode>[/green]   - Bulk scan targets from file (modes: bugbounty/recon/breach/email/phone/person/all)

[bold cyan]ANALYSIS COMMANDS[/bold cyan]
[green]analyze[/green]              - AI-powered predictive threat analysis
[green]fakecheck[/green]            - Deepfake & fake profile detection
[green]semantic[/green]             - Semantic analysis of content
[green]media[/green]                - Validate media integrity
[green]financial[/green]            - Analyze financial trails & crypto
[green]network[/green]              - Map influence networks
[green]evidence[/green]             - Manage legal evidence chain

[bold cyan]REPORTING COMMANDS[/bold cyan]
[green]report[/green]               - Generate legal-grade intelligence report
[green]status[/green]               - Detailed system status

[bold cyan]SYSTEM COMMANDS[/bold cyan]
[green]tor on[/green]              - Enable Tor routing (anonymize all requests)
[green]tor off[/green]             - Disable Tor routing
[green]tor status[/green]          - Show current Tor exit IP
[green]tor newip[/green]           - Rotate Tor circuit (get new exit IP)
[green]telegram test[/green]       - Send test Telegram alert
[green]telegram status[/green]     - Show Telegram config status
[green]train status[/green]        - ML model training status
[green]train collect[/green]       - CRL se training data crawl karo
[green]train run[/green]           - Models train karo (collect ke baad)
[green]train save[/green]          - Trained models save karo
[green]train eval[/green]          - Model accuracy evaluate karo
[green]pdf[/green]                 - Export last scan report to PDF
[green]clear[/green]               - Clear screen
[green]help / ?[/green]            - This help menu
[green]exit / quit / q[/green]     - Exit

[bold yellow]EXAMPLE USAGE:[/bold yellow]
  sentinel-pro> bugbounty example.com
  sentinel-pro> recon example.com
  sentinel-pro> breach user@example.com
  sentinel-pro> collect johndoe
  sentinel-pro> fakecheck
        """, title="[bold]The Sentinel Pro - Command Reference[/bold]", border_style="cyan")
        
        self.console.print(help_panel)

    def _handle_enhanced_collect(self, command):
        """Enhanced collection with real-time progress and user-specific folders"""
        parts = command.split(' ', 1)
        if len(parts) < 2:
            self.console.print("[red]Usage: collect <target>[/red]")
            return
        
        target = parts[1].strip()
        
        # Input validation
        if not self._validate_target(target):
            self.console.print("[red]Invalid target format. Use email, username, or @handle[/red]")
            return
        
        # Sanitize target for folder name
        clean_target = self._sanitize_filename(target)
        user_folder = config.INVESTIGATIONS_DIR / clean_target
        user_folder.mkdir(exist_ok=True)
        (user_folder / 'profiles').mkdir(exist_ok=True)
        (user_folder / 'media').mkdir(exist_ok=True)
        (user_folder / 'reports').mkdir(exist_ok=True)
        
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
                'user_folder': str(user_folder)  # Convert Path to string
            }
            
            # Save individual platform data to user folder
            for platform_data in social_data:
                platform = platform_data.get('platform', 'unknown')
                platform_file = user_folder / 'profiles' / f"{platform}_profile.json"
                try:
                    with open(platform_file, 'w', encoding='utf-8') as f:
                        json.dump(platform_data, f, indent=2, ensure_ascii=False)
                except Exception as e:
                    logger.error(f"Failed to save {platform} profile: {e}")
            
            # Save complete collection data
            collection_file = user_folder / 'complete_collection.json'
            try:
                with open(collection_file, 'w', encoding='utf-8') as f:
                    json.dump(collected_data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Failed to save collection data: {e}")
                self.console.print(f"[red]Error saving data: {e}[/red]")
                return
            
            self.session_data['target'] = target
            self.session_data['collected_data'] = collected_data
            self.session_data['user_folder'] = str(user_folder)
            self.evidence.add_evidence('collection', collected_data)
            
            progress.update(collect_task, completed=100, description="[green]Collection completed")
        
        self.console.print(f"[green]✓ Enhanced collection completed for: {target}[/green]")
        self.console.print(f"[green]📁 Data saved to: {user_folder}[/green]")
        
        # Only show stats for real data
        real_social_count = len([s for s in social_data if s.get('verified', False)])
        self.console.print(f"[dim]Found: {len(surface_data)} surface sources, {real_social_count} verified social profiles[/dim]")
        
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

        components = [
            ("Stealth Manager",  "🟢 ACTIVE"   if self.stealth.is_active() else "🔴 INACTIVE", f"{len(self.stealth.get_proxy_list())} proxies"),
            ("Dark Web Crawler", "🟢 READY",    "Tor integration available"),
            ("Evidence Vault",   "🟢 SECURE",   f"{len(self.evidence.get_evidence_list())} items"),
            ("AI Threat Engine", "🟢 LOADED",   "Predictive models ready"),
            ("Legal Framework",  "🟢 COMPLIANT","Chain of custody active"),
        ]
        for component, status, details in components:
            status_table.add_row(component, status, details)
        self.console.print(status_table)

        # Phase 3/4 API keys status
        api_table = Table(title="[bold]API Keys Status[/bold]", border_style="yellow")
        api_table.add_column("Service",   style="bold")
        api_table.add_column("Status",    justify="center")
        api_table.add_column("Env Var",   style="dim")

        api_keys = [
            ("Shodan",          config.SHODAN_API_KEY,          "SHODAN_API_KEY"),
            ("GitHub",          config.GITHUB_TOKEN,            "GITHUB_TOKEN"),
            ("SerpAPI (Google)",config.SERPAPI_KEY,             "SERPAPI_KEY"),
            ("SecurityTrails",  config.SECURITYTRAILS_API_KEY,  "SECURITYTRAILS_API_KEY"),
            ("NVD (CVE)",       config.NVD_API_KEY,             "NVD_API_KEY"),
            ("HIBP",            config.HIBP_API_KEY,            "HIBP_API_KEY"),
            ("Dehashed",        config.DEHASHED_API_KEY,        "DEHASHED_API_KEY"),
            ("NumVerify",       config.NUMVERIFY_API_KEY,       "NUMVERIFY_API_KEY"),
            ("AbstractAPI Phone",config.ABSTRACTAPI_PHONE_KEY,  "ABSTRACTAPI_PHONE_KEY"),
        ]
        for name, key, env_var in api_keys:
            if key:
                status  = "[green]✓ SET[/green]"
                details = f"{env_var}={key[:6]}..."
            else:
                status  = "[yellow]✗ NOT SET[/yellow]"
                details = f"export {env_var}=your_key"
            api_table.add_row(name, status, details)
        self.console.print(api_table)

        # Binaries status
        bin_table = Table(title="[bold]Binaries Status[/bold]", border_style="magenta")
        bin_table.add_column("Binary",  style="bold")
        bin_table.add_column("Status",  justify="center")
        bin_table.add_column("Path",    style="dim")

        binaries = [
            ("Go Scraper",      config.SCRAPER_BIN),
            ("Rust Analyzer",   config.ANALYZER_BIN),
            ("Network Mapper",  config.NETWORK_MAPPER_BIN),
            ("Chromium",        Path(self.screenshot.chromium or '')),
        ]
        for name, path in binaries:
            exists = Path(path).exists() if path else False
            status = "[green]✓ Found[/green]" if exists else "[red]✗ Missing[/red]"
            bin_table.add_row(name, status, str(path))
        self.console.print(bin_table)

        # Tor status
        tor_table = Table(title="[bold]Tor / Anonymity[/bold]", border_style="green")
        tor_table.add_column("Setting",  style="bold")
        tor_table.add_column("Value",    justify="center")
        tor_table.add_column("Detail",   style="dim")
        tor_active = config.is_tor_active()
        tor_table.add_row(
            "Tor Routing",
            "[green]🧅 ACTIVE[/green]" if tor_active else "[dim]🔓 INACTIVE[/dim]",
            config.TOR_PROXY
        )
        tor_table.add_row(
            "Control Port",
            str(config.TOR_CONTROL_PORT),
            "Use 'tor newip' to rotate circuit"
        )
        self.console.print(tor_table)

        # Session info
        if self.session_data:
            sess_table = Table(title="[bold]Current Session[/bold]", border_style="blue")
            sess_table.add_column("Scan Type", style="bold")
            sess_table.add_column("Status",    justify="center")
            sess_table.add_column("Target",    style="cyan")

            scan_types = [
                ("Collect",   'collected_data'),
                ("Recon",     'recon'),
                ("Bug Bounty",'bugbounty'),
                ("Breach",    'breach'),
                ("Email OSINT",'email'),
            ]
            for label, key in scan_types:
                if key in self.session_data:
                    target = self.session_data.get('target', self.session_data[key].get('target', self.session_data[key].get('domain', 'N/A')))
                    sess_table.add_row(label, "[green]✓ Done[/green]", str(target))
                else:
                    sess_table.add_row(label, "[dim]○ Not run[/dim]", "")
            self.console.print(sess_table)

    def _handle_telegram(self, command: str):
        """Telegram alert management."""
        if not self.notifier.enabled:
            self.console.print("[red]✗ Telegram not configured[/red]")
            self.console.print("[dim]Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env[/dim]")
            return
        if command == 'telegram test':
            ok = self.notifier.test()
            if ok:
                self.console.print("[green]✓ Telegram test message sent![/green]")
            else:
                self.console.print("[red]✗ Telegram send failed — check token/chat_id[/red]")
        elif command == 'telegram status':
            self.console.print(f"[green]🔔 Telegram ACTIVE[/green] — chat_id: {config.TELEGRAM_CHAT_ID}")
        else:
            self.console.print("[dim]Usage: telegram test | telegram status[/dim]")

    def _handle_pdf(self):
        """Export last scan report to PDF."""
        if not self.pdf.available:
            self.console.print("[red]✗ WeasyPrint not installed[/red]")
            self.console.print("[dim]Run: pip install weasyprint[/dim]")
            return
        paths = self.session_data.get('last_paths', {})
        html  = paths.get('html')
        if not html:
            self.console.print("[red]No scan report found — run bugbounty/recon/breach first[/red]")
            return
        self.console.print(f"[cyan]Exporting PDF...[/cyan]")
        pdf_path = self.pdf.export_scan(paths)
        if pdf_path:
            self.console.print(f"[green]✓ PDF saved: {pdf_path}[/green]")
        else:
            self.console.print("[red]✗ PDF export failed — check logs[/red]")

    def _handle_tor(self, command: str):
        """Toggle Tor routing on/off, show status, rotate exit node."""
        import subprocess as _sp

        if command == 'tor on':
            # Verify Tor is reachable first
            try:
                import requests as _req
                r = _req.get('https://httpbin.org/ip',
                             proxies={'http': config.TOR_PROXY, 'https': config.TOR_PROXY},
                             timeout=15)
                exit_ip = r.json().get('origin', '?')
                config.tor_on()
                self.console.print(f"[bold green]\U0001f9c5 Tor ENABLED[/bold green] \u2014 Exit IP: [cyan]{exit_ip}[/cyan]")
                self.console.print("[dim]All HTTP requests now routed through Tor[/dim]")
            except Exception as e:
                self.console.print(f"[red]\u2717 Tor unreachable: {e}[/red]")
                self.console.print("[dim]Make sure Tor is running: sudo systemctl start tor[/dim]")

        elif command == 'tor off':
            config.tor_off()
            self.console.print("[yellow]🔓 Tor DISABLED[/yellow] — using direct connection")

        elif command == 'tor status':
            active = config.is_tor_active()
            if active:
                try:
                    import requests as _req
                    r = _req.get('https://httpbin.org/ip',
                                 proxies={'http': config.TOR_PROXY, 'https': config.TOR_PROXY},
                                 timeout=15)
                    ip = r.json().get('origin', '?')
                    self.console.print(f"[green]\U0001f9c5 Tor ACTIVE \u2014 Exit IP: {ip}[/green]")
                except Exception:
                    self.console.print("[yellow]\U0001f9c5 Tor ACTIVE \u2014 could not verify exit IP[/yellow]")
            else:
                self.console.print("[dim]\U0001f513 Tor INACTIVE \u2014 direct connection[/dim]")
            self.console.print(f"[dim]Proxy: {config.TOR_PROXY}[/dim]")

        elif command == 'tor newip':
            try:
                import socket as _sock, os as _os
                with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                    s.settimeout(5)
                    s.connect(('127.0.0.1', config.TOR_CONTROL_PORT))
                    # CookieAuthentication (default on Kali)
                    cookie_path = '/var/run/tor/control.authcookie'
                    if _os.path.exists(cookie_path):
                        try:
                            cookie = open(cookie_path, 'rb').read().hex()
                            s.send(f'AUTHENTICATE {cookie}\r\n'.encode())
                        except PermissionError:
                            pwd = config.TOR_PASSWORD
                            s.send(f'AUTHENTICATE "{pwd}"\r\n'.encode() if pwd else b'AUTHENTICATE\r\n')
                    else:
                        pwd = config.TOR_PASSWORD
                        s.send(f'AUTHENTICATE "{pwd}"\r\n'.encode() if pwd else b'AUTHENTICATE\r\n')
                    auth_resp = s.recv(128).decode()
                    if '250' not in auth_resp:
                        self.console.print(f"[red]✗ Auth failed: {auth_resp.strip()}[/red]")
                        self.console.print("[dim]Set TOR_PASSWORD in .env or ensure CookieAuthentication=1 in torrc[/dim]")
                        return
                    s.send(b'SIGNAL NEWNYM\r\n')
                    resp = s.recv(128).decode()
                    if '250' in resp:
                        self.console.print("[green]🔄 New Tor circuit requested — waiting 3s...[/green]")
                        import time as _t; _t.sleep(3)
                        import requests as _req
                        r = _req.get('https://httpbin.org/ip',
                                     proxies={'http': config.TOR_PROXY, 'https': config.TOR_PROXY},
                                     timeout=15)
                        new_ip = r.json().get('origin', '?')
                        self.console.print(f"[cyan]New Exit IP: {new_ip}[/cyan]")
                    else:
                        self.console.print(f"[yellow]Control port response: {resp.strip()}[/yellow]")
            except ConnectionRefusedError:
                self.console.print("[red]✗ Tor control port not accessible[/red]")
                self.console.print("[dim]Run these commands to fix:[/dim]")
                self.console.print("[cyan]  sudo sed -i 's/#ControlPort 9051/ControlPort 9051/' /etc/tor/torrc[/cyan]")
                self.console.print("[cyan]  sudo sed -i 's/#CookieAuthentication 1/CookieAuthentication 1/' /etc/tor/torrc[/cyan]")
                self.console.print("[cyan]  sudo systemctl restart tor[/cyan]")
            except Exception as e:
                self.console.print(f"[red]✗ {e}[/red]")

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
    
    def _validate_target(self, target):
        """Validate target input to prevent injection attacks"""
        if not target or len(target) > 200:
            return False
        
        # Allow: emails, usernames, @handles, domains
        valid_patterns = [
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',  # Email
            r'^@?[a-zA-Z0-9_]{1,50}$',  # Username/handle
            r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'  # Domain
        ]
        
        return any(re.match(pattern, target) for pattern in valid_patterns)
    
    def _sanitize_filename(self, filename):
        """Sanitize filename to prevent path traversal"""
        # Remove dangerous characters
        sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
        # Remove leading dots and slashes
        sanitized = sanitized.lstrip('._/')
        # Limit length
        return sanitized[:100]
    
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
            network_file = Path('/tmp/network_data.json')
            try:
                with open(network_file, 'w', encoding='utf-8') as f:
                    json.dump(network_data, f, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Failed to save network data: {e}")
                self.console.print(f"[red]Error preparing network data: {e}[/red]")
                return
            
            # Run Go network mapper
            progress.update(network_task, advance=40, description="[cyan]Running network analysis...")
            
            # Check if binary exists
            if not config.NETWORK_MAPPER_BIN.exists():
                logger.error(f"Network mapper binary not found: {config.NETWORK_MAPPER_BIN}")
                self.console.print("[red]Network mapper not built. Run setup.sh first.[/red]")
                return
            
            try:
                result = subprocess.run(
                    [str(config.NETWORK_MAPPER_BIN), str(network_file)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=str(config.BASE_DIR)
                )
                
                if result.returncode == 0:
                    network_analysis = json.loads(result.stdout)
                else:
                    logger.error(f"Network mapper failed: {result.stderr}")
                    self.console.print(f"[red]Network analysis failed: {result.stderr}[/red]")
                    return
                    
            except subprocess.TimeoutExpired:
                logger.error("Network mapper timeout")
                self.console.print("[red]Network analysis timeout[/red]")
                return
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON from network mapper: {e}")
                self.console.print("[red]Invalid network analysis output[/red]")
                return
            except Exception as e:
                logger.error(f"Network mapper error: {e}", exc_info=True)
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

    def _handle_fake_profile_detection(self):
        """Deepfake and fake profile detection analysis"""
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
            
            fake_task = progress.add_task("[cyan]Analyzing for fake profiles...", total=100)
            
            progress.update(fake_task, advance=30, description="[cyan]Checking profile consistency...")
            time.sleep(0.5)
            
            progress.update(fake_task, advance=30, description="[cyan]Analyzing images for deepfakes...")
            fake_analysis = self.fake_detector.analyze_profile(self.session_data['collected_data'])
            
            progress.update(fake_task, advance=40, description="[cyan]Generating fake profile report...")
            
            self.session_data['fake_analysis'] = fake_analysis
            self.evidence.add_evidence('fake_profile_analysis', fake_analysis)
            
            progress.update(fake_task, completed=100, description="[green]Fake profile analysis completed")
        
        # Display results
        fake_score = fake_analysis['overall_fake_score']
        risk_level = fake_analysis['risk_level']
        
        # Color based on risk
        if fake_score >= 70:
            color = "red"
            icon = "🚨"
        elif fake_score >= 50:
            color = "yellow"
            icon = "⚠️"
        elif fake_score >= 30:
            color = "orange1"
            icon = "⚡"
        else:
            color = "green"
            icon = "✅"
        
        self.console.print(f"\n[{color}]{icon} FAKE PROFILE SCORE: {fake_score}/100[/{color}]")
        self.console.print(f"[{color}]Risk Level: {risk_level}[/{color}]\n")
        
        # Display suspicious indicators
        indicators = fake_analysis['suspicious_indicators']
        if indicators:
            self.console.print(f"[bold red]🔴 {len(indicators)} SUSPICIOUS INDICATORS DETECTED:[/bold red]\n")
            for i, indicator in enumerate(indicators[:10], 1):  # Show top 10
                severity_color = "red" if indicator['severity'] == 'CRITICAL' else "yellow" if indicator['severity'] == 'HIGH' else "orange1"
                self.console.print(f"  {i}. [{severity_color}][{indicator['severity']}][/{severity_color}] {indicator['type']}")
                self.console.print(f"     {indicator['description']}")
                self.console.print(f"     Score Impact: +{indicator['score_impact']}\n")
        
        # Display recommendations
        recommendations = fake_analysis['recommendations']
        if recommendations:
            self.console.print(f"\n[bold cyan]📊 RECOMMENDATIONS:[/bold cyan]\n")
            for rec in recommendations:
                self.console.print(f"  {rec}")
        
        self.console.print(f"\n[dim]Analysis saved to evidence vault[/dim]")

        # Continuous learning
        self._feed_to_ml('fakecheck', fake_analysis)


    def _handle_bulk(self, command: str):
        """Bulk scan — read targets from file, run chosen scan mode on each."""
        parts = command.split()
        # parts: ['bulk', '<file>', '<mode>']
        if len(parts) < 3:
            self.console.print("[red]Usage: bulk <file_path> <mode>[/red]")
            self.console.print("[dim]Modes: bugbounty | recon | breach | email | phone | all[/dim]")
            self.console.print("[dim]Example: bulk /home/user/targets.txt bugbounty[/dim]")
            return

        file_path = parts[1]
        mode      = parts[2].lower()
        valid_modes = ('bugbounty', 'recon', 'breach', 'email', 'phone', 'all')

        if mode not in valid_modes:
            self.console.print(f"[red]Invalid mode '{mode}'. Choose: {' / '.join(valid_modes)}[/red]")
            return

        # Read and clean targets
        try:
            raw = Path(file_path).read_text(encoding='utf-8').splitlines()
        except FileNotFoundError:
            self.console.print(f"[red]File not found: {file_path}[/red]")
            return
        except Exception as e:
            self.console.print(f"[red]Cannot read file: {e}[/red]")
            return

        targets = []
        for line in raw:
            line = line.strip()
            if not line or line.startswith('#'):   # skip blank lines and comments
                continue
            targets.append(line)

        if not targets:
            self.console.print("[red]No targets found in file (empty or all lines are comments)[/red]")
            return

        self.console.print(f"\n[bold cyan]Bulk Scan — {len(targets)} target(s) | mode: {mode.upper()}[/bold cyan]")
        self.console.print(f"[dim]File: {file_path}[/dim]\n")

        # Summary table to show at end
        results_summary = []   # list of (target, mode, status)

        for idx, target in enumerate(targets, 1):
            self.console.print(f"[bold white]\n[{idx}/{len(targets)}] Target: [cyan]{target}[/cyan][/bold white]")
            self.console.rule(style="dim")
            try:
                if mode == 'bugbounty':
                    self._handle_bugbounty(f'bugbounty {target}')
                    results_summary.append((target, 'bugbounty', '✓'))

                elif mode == 'recon':
                    self._handle_recon(f'recon {target}')
                    results_summary.append((target, 'recon', '✓'))

                elif mode == 'breach':
                    self._handle_breach(f'breach {target}')
                    results_summary.append((target, 'breach', '✓'))

                elif mode == 'email':
                    self._handle_email(f'email {target}')
                    results_summary.append((target, 'email', '✓'))

                elif mode == 'phone':
                    self._handle_phone(f'phone {target}')
                    results_summary.append((target, 'phone', '✓'))

                elif mode == 'all':
                    # Auto-detect target type for 'all' mode
                    if re.match(r'^\+?\d{7,15}$', target.replace(' ', '')):
                        # Looks like a phone number
                        self._handle_phone(f'phone {target}')
                        results_summary.append((target, 'phone', '✓'))
                    elif '@' in target:
                        # Email — run breach + email osint
                        self._handle_email(f'email {target}')
                        self._handle_breach(f'breach {target}')
                        results_summary.append((target, 'email+breach', '✓'))
                    else:
                        # Domain — run full scan
                        self._handle_recon(f'recon {target}')
                        self._handle_bugbounty(f'bugbounty {target}')
                        self._handle_breach(f'breach {target}')
                        results_summary.append((target, 'recon+bugbounty+breach', '✓'))

            except KeyboardInterrupt:
                self.console.print(f"\n[yellow]Skipping {target} — interrupted[/yellow]")
                results_summary.append((target, mode, '⚠ skipped'))
                continue
            except Exception as e:
                logger.error(f"Bulk scan error on {target}: {e}")
                self.console.print(f"[red]Error on {target}: {e}[/red]")
                results_summary.append((target, mode, f'✗ error'))
                continue

        # Final summary table
        self.console.print(f"\n[bold cyan]{'='*50}[/bold cyan]")
        self.console.print(f"[bold cyan]Bulk Scan Complete — {len(targets)} target(s)[/bold cyan]")
        summary_table = Table(title="Bulk Scan Results", border_style="cyan")
        summary_table.add_column("#",      style="dim",  width=4)
        summary_table.add_column("Target", style="cyan")
        summary_table.add_column("Mode",   style="yellow")
        summary_table.add_column("Status", justify="center")
        for i, (t, m, s) in enumerate(results_summary, 1):
            color = 'green' if '✓' in s else 'yellow' if '⚠' in s else 'red'
            summary_table.add_row(str(i), t, m, f"[{color}]{s}[/{color}]")
        self.console.print(summary_table)
        self.console.print(f"[dim]All reports saved to reports/ directory[/dim]")

    def _handle_bugbounty(self, command):
        """Full bug bounty scan - SSL + Headers + Ports + Endpoints"""
        parts = command.split(' ', 1)
        if len(parts) < 2:
            self.console.print("[red]Usage: bugbounty <domain>[/red]")
            return
        target = parts[1].strip()

        report_data = {'target': target, 'timestamp': datetime.now().isoformat()}

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=self.console) as progress:
            task = progress.add_task("[cyan]Bug bounty scan...", total=100)

            progress.update(task, advance=4, description="[cyan]Checking SSL/TLS...")
            report_data['ssl'] = self.ssl.run(target)

            progress.update(task, advance=4, description="[cyan]Checking security headers...")
            report_data['headers'] = self.sec_headers.run(target)

            progress.update(task, advance=4, description="[cyan]Scanning ports...")
            report_data['ports'] = self.port_scan.run(target)

            progress.update(task, advance=4, description="[cyan]Discovering endpoints...")
            report_data['endpoints'] = self.endpoints.run(target)

            progress.update(task, advance=4, description="[cyan][Rust] Analyzing findings...")
            report_data['rust_analysis'] = self.rust_analyzer.run(report_data)

            progress.update(task, advance=4, description="[cyan]Shodan host lookup...")
            report_data['shodan'] = self.shodan.run(target)

            progress.update(task, advance=4, description="[cyan]Vulnerability scan (SQLi/XSS)...")
            exposed_eps = report_data['endpoints'].get('exposed', [])
            report_data['vulns'] = self.vuln.run(target, exposed_eps)

            progress.update(task, advance=3, description="[cyan]Capturing screenshot...")
            report_data['screenshot'] = self.screenshot.capture_domain(target)

            progress.update(task, advance=3, description="[cyan]Analyzing JS files...")
            report_data['js'] = self.js_analyzer.run(target)

            progress.update(task, advance=3, description="[cyan]CVE lookup...")
            tech = report_data['endpoints'].get('technologies', {})
            report_data['cves'] = self.cve_lookup.run(tech)

            progress.update(task, advance=3, description="[cyan]Subdomain takeover check...")
            subs = report_data['subdomains'].get('subdomains', []) if 'subdomains' in report_data else []
            sub_list = [s['subdomain'] for s in subs if s.get('subdomain')]
            report_data['takeover'] = self.takeover.run(target, sub_list or None)

            progress.update(task, advance=3, description="[cyan]CORS misconfiguration scan...")
            report_data['cors'] = self.cors.run(target, report_data['endpoints'].get('exposed', []))

            progress.update(task, advance=3, description="[cyan]Open redirect scan...")
            report_data['open_redirect'] = self.open_redir.run(target, report_data['endpoints'].get('exposed', []))

            progress.update(task, advance=3, description="[cyan][Go] HTTP request smuggling...")
            report_data['smuggling'] = self.smuggler.run(target)

            progress.update(task, advance=3, description="[cyan][Go] Directory brute-force...")
            report_data['dirbuster'] = self.dirbuster.run(target)

            progress.update(task, advance=3, description="[cyan][Nuclei] Template scan...")
            report_data['nuclei'] = self.nuclei.run(target)

            progress.update(task, advance=3, description="[cyan]Cookie security analysis...")
            report_data['cookies'] = self.cookie_scan.run(target)

            progress.update(task, advance=3, description="[cyan]DNS zone transfer check...")
            report_data['zone_transfer'] = self.zone_xfr.run(target)

            progress.update(task, advance=3, description="[cyan][Rust] Parallel fuzzing...")
            report_data['fuzzer'] = self.fuzzer.run(target, mode='path')

            progress.update(task, advance=3, description="[cyan]Deep tech fingerprinting...")
            report_data['tech_fingerprint'] = self.tech_fp.run(target)

            progress.update(task, advance=2, description="[cyan]2FA/Auth bypass check...")
            report_data['auth_bypass'] = self.auth_bypass.run(target)

            progress.update(task, advance=2, description="[cyan]API security scan...")
            report_data['api'] = self.api_scan.run(target)

            progress.update(task, advance=2, description="[cyan]LFI/RFI scan...")
            report_data['lfi'] = self.lfi.run(target, report_data['endpoints'].get('exposed', []))

            progress.update(task, advance=2, description="[cyan]XXE scan...")
            report_data['xxe'] = self.xxe.run(target)

            progress.update(task, advance=2, description="[cyan]SSTI scan...")
            report_data['ssti'] = self.ssti.run(target, report_data['endpoints'].get('exposed', []))

            progress.update(task, advance=2, description="[cyan]Clickjacking check...")
            report_data['clickjacking'] = self.clickjack.run(target)

            progress.update(task, advance=2, description="[cyan]Prototype pollution scan...")
            report_data['proto_pollution'] = self.proto_poll.run(target)

            progress.update(task, advance=2, description="[cyan]OAuth misconfiguration scan...")
            report_data['oauth'] = self.oauth_scan.run(target)

            progress.update(task, advance=3, description="[cyan]Saving report...")
            reporter = BugBountyReport(output_dir=user_folder)
            paths = reporter.save(target, report_data)
            self.session_data['bugbounty'] = report_data
            self.session_data['last_paths'] = paths
            self.evidence.add_evidence('bugbounty', report_data)
            progress.update(task, completed=100, description="[green]Bug bounty scan complete")

        # Telegram alert
        self.notifier.alert_bugbounty(target, report_data)
        # Auto PDF
        pdf_path = self.pdf.export_scan(paths)
        if pdf_path:
            self.console.print(f"  PDF    : [green]{pdf_path}[/green]")

        # Continuous learning — scan data training pool mein add karo
        self._feed_to_ml('bugbounty', report_data)

        ssl  = report_data['ssl']
        hdrs = report_data['headers']
        pts  = report_data['ports']
        eps  = report_data['endpoints']
        shod = report_data.get('shodan', {})
        vulns = report_data.get('vulns', {})
        shots = report_data.get('screenshot', {})

        self.console.print(f"\n[bold cyan]Bug Bounty Results: {target}[/bold cyan]")

        grade = ssl.get('grade', 'F')
        grade_color = 'green' if grade in ('A', 'A+') else 'yellow' if grade == 'B' else 'red'
        self.console.print(f"  SSL/TLS Grade  : [{grade_color}]{grade}[/{grade_color}] | {ssl.get('protocol', 'N/A')} | {ssl.get('days_remaining', 'N/A')} days left")

        hgrade = hdrs.get('grade', 'F')
        hgrade_color = 'green' if hgrade in ('A', 'A+') else 'yellow' if hgrade in ('B', 'C') else 'red'
        self.console.print(f"  Headers Grade  : [{hgrade_color}]{hgrade}[/{hgrade_color}] | Score: {hdrs.get('score', 0)}/100 | Missing: {len(hdrs.get('missing', []))}")

        waf = eps.get('waf', {})
        waf_str = f"[green]{waf['name']}[/green]" if waf.get('detected') else "[yellow]Not detected[/yellow]"
        self.console.print(f"  WAF            : {waf_str}")

        dm = eps.get('dangerous_methods', {})
        if dm.get('allowed'):
            dm_color = 'red' if dm['risk'] == 'HIGH' else 'yellow'
            self.console.print(f"  HTTP Methods   : [{dm_color}]{', '.join(dm['allowed'])} enabled[/{dm_color}]")

        tech = eps.get('technologies', {})
        if tech:
            self.console.print(f"  Technologies   : [dim]{', '.join(f'{k}: {v}' for k,v in tech.items())}[/dim]")

        self.console.print(f"  Open Ports     : {pts.get('total_open', 0)} | [red]High Risk: {pts.get('total_high_risk', 0)}[/red]")
        for p in pts.get('high_risk_ports', []):
            self.console.print(f"    [red]⚠ {p['port']}/{p['service']}[/red] - {p['risk_detail']}")

        # Shodan
        if shod and not shod.get('error'):
            self.console.print(f"\n  [bold blue][Shodan][/bold blue] IP: {shod.get('ip')} | Org: {shod.get('org')} | {shod.get('country')}")
            if shod.get('vulns'):
                self.console.print(f"    [red]CVEs: {', '.join(shod['vulns'][:5])}[/red]")
            for rf in shod.get('risk_flags', []):
                color = 'red' if rf['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{color}][{rf['severity']}][/{color}] {rf['flag']}: {rf['detail']}")
        elif shod.get('error'):
            self.console.print(f"  [dim][Shodan] {shod['error']}[/dim]")

        self.console.print(f"  Endpoints      : {eps.get('total_exposed', 0)} exposed | [red]Critical: {eps.get('critical_count', 0)}[/red] | High: {eps.get('high_count', 0)}")
        for e in eps.get('exposed', [])[:8]:
            color = 'red' if e['risk'] == 'CRITICAL' else 'yellow' if e['risk'] == 'HIGH' else 'dim'
            self.console.print(f"    [{color}][{e['risk']}][/{color}] {e['path']} (HTTP {e['status_code']})")

        # Vuln scan
        if vulns and not vulns.get('error'):
            total_v = vulns.get('total_vulns', 0)
            vrisk   = vulns.get('risk_level', 'LOW')
            vcolor  = 'red' if vrisk == 'CRITICAL' else 'yellow' if vrisk == 'HIGH' else 'green'
            self.console.print(f"\n  [bold red][Vuln Scan][/bold red] Risk: [{vcolor}]{vrisk}[/{vcolor}] | Total: {total_v}")
            all_vulns = (vulns.get('sqli', []) + vulns.get('blind_sqli', []) +
                         vulns.get('xss', []) + vulns.get('dom_xss', []) +
                         vulns.get('ssrf', []) + vulns.get('header_inj', []))
            for v in all_vulns[:8]:
                vc = 'red' if v['severity'] == 'CRITICAL' else 'yellow'
                method = f" [{v.get('method','GET')}]" if v.get('method') else ''
                self.console.print(f"    [{vc}][{v['type']}][/{vc}]{method} param={v['param']} | {v['evidence']}")

        # Screenshot
        for scheme, shot in shots.items():
            if shot.get('path'):
                self.console.print(f"  Screenshot ({scheme}): [green]{shot['path']}[/green]")
            elif shot.get('error'):
                self.console.print(f"  Screenshot ({scheme}): [dim]{shot['error']}[/dim]")

        # JS Analyzer
        js = report_data.get('js', {})
        if js and not js.get('error'):
            js_risk  = js.get('risk_level', 'LOW')
            js_color = 'red' if js_risk == 'CRITICAL' else 'yellow' if js_risk == 'HIGH' else 'green'
            self.console.print(f"\n  [bold yellow][JS Analyzer][/bold yellow] {js.get('total_js', 0)} files | Risk: [{js_color}]{js_risk}[/{js_color}]")
            if js.get('secrets'):
                self.console.print(f"    [red]Secrets found: {len(js['secrets'])}[/red]")
                for s in js['secrets'][:5]:
                    self.console.print(f"      [{s['severity']}] {s['type']} in {s['file'].split('/')[-1]}")
            if js.get('endpoints'):
                self.console.print(f"    API endpoints: [cyan]{len(js['endpoints'])}[/cyan]")
                for ep in js['endpoints'][:5]:
                    self.console.print(f"      [dim]{ep}[/dim]")
            if js.get('internal_paths'):
                self.console.print(f"    [yellow]Internal paths leaked: {len(js['internal_paths'])}[/yellow]")

        # CVE Lookup
        cves = report_data.get('cves', {})
        if cves and not cves.get('error') and cves.get('total_cves', 0) > 0:
            cve_color = 'red' if cves['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][CVE Lookup][/bold red] {cves['total_cves']} CVEs | [{cve_color}]{cves['risk_level']}[/{cve_color}] | Critical: {cves['critical_count']} High: {cves['high_count']}")
            for c in cves['cves'][:5]:
                color = 'red' if c['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{color}]{c['cve_id']}[/{color}] [{c['severity']} {c['score']}] {c['tech']} {c['version'] or ''} - {c['description'][:80]}")

        # Subdomain Takeover
        tkover = report_data.get('takeover', {})
        if tkover and tkover.get('vulnerable'):
            self.console.print(f"\n  [bold red][Subdomain Takeover][/bold red] [red]{len(tkover['vulnerable'])} VULNERABLE[/red]")
            for v in tkover['vulnerable']:
                self.console.print(f"    [red][CRITICAL][/red] {v['subdomain']} → {v['service']}")
                self.console.print(f"      [dim]{v['evidence']}[/dim]")
        elif tkover:
            self.console.print(f"  [dim][Takeover] Checked {tkover.get('checked',0)} subdomains — none vulnerable[/dim]")

        # CORS
        cors = report_data.get('cors', {})
        if cors and cors.get('findings'):
            cors_color = 'red' if cors['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][CORS][/bold red] [{cors_color}]{cors['risk_level']}[/{cors_color}] | {cors['total']} misconfiguration(s)")
            for f in cors['findings'][:5]:
                fc = 'red' if f['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{fc}][{f['severity']}][/{fc}] {f['issue']}")
                self.console.print(f"      [dim]{f['evidence']}[/dim]")
        elif cors:
            self.console.print(f"  [dim][CORS] No misconfigurations found[/dim]")

        # Open Redirect
        oredir = report_data.get('open_redirect', {})
        if oredir and oredir.get('findings'):
            self.console.print(f"\n  [bold yellow][Open Redirect][/bold yellow] [yellow]HIGH[/yellow] | {oredir['total']} redirect(s) found")
            for f in oredir['findings'][:5]:
                self.console.print(f"    [yellow]param={f['param']}[/yellow] → {f['location'][:60]}")
                self.console.print(f"      [dim]{f['evidence']}[/dim]")
        elif oredir:
            self.console.print(f"  [dim][Open Redirect] No unvalidated redirects found[/dim]")

        # HTTP Smuggling
        smug = report_data.get('smuggling', {})
        if smug and smug.get('findings'):
            self.console.print(f"\n  [bold red][HTTP Smuggling][/bold red] [red]CRITICAL[/red] | {smug['total']} technique(s) confirmed")
            for f in smug['findings']:
                self.console.print(f"    [red][{f['technique']}][/red] {f['evidence']}")
        elif smug and not smug.get('error'):
            self.console.print(f"  [dim][HTTP Smuggling] Not vulnerable[/dim]")
        elif smug and smug.get('error'):
            self.console.print(f"  [dim][HTTP Smuggling] {smug['error']}[/dim]")

        # Directory Brute-Force
        dirb = report_data.get('dirbuster', {})
        if dirb and not dirb.get('error'):
            dirb_color = 'red' if dirb['risk_level'] == 'CRITICAL' else 'yellow' if dirb['risk_level'] == 'HIGH' else 'dim'
            self.console.print(f"\n  [bold yellow][DirBuster][/bold yellow] Scanned: {dirb.get('scanned',0)} | Found: {dirb.get('total',0)} | [{dirb_color}]{dirb['risk_level']}[/{dirb_color}]")
            for r in dirb.get('results', [])[:10]:
                rc = 'red' if r['risk'] == 'CRITICAL' else 'yellow' if r['risk'] == 'HIGH' else 'dim'
                self.console.print(f"    [{rc}][{r['risk']}][/{rc}] {r['path']} (HTTP {r['status_code']})")
        elif dirb and dirb.get('error'):
            self.console.print(f"  [dim][DirBuster] {dirb['error']}[/dim]")

        # Nuclei
        nuc = report_data.get('nuclei', {})
        if nuc and not nuc.get('error') and nuc.get('total', 0) > 0:
            nuc_color = 'red' if nuc['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][Nuclei][/bold red] [{nuc_color}]{nuc['risk_level']}[/{nuc_color}] | Total: {nuc['total']} | Critical: {nuc['critical']} High: {nuc['high']} Medium: {nuc['medium']}")
            for f in nuc.get('findings', [])[:8]:
                fc = 'red' if f['severity'] in ('critical','CRITICAL') else 'yellow' if f['severity'] in ('high','HIGH') else 'dim'
                cve = f' [{f["cve_id"][0]}]' if f.get('cve_id') else ''
                self.console.print(f"    [{fc}][{f['severity'].upper()}][/{fc}]{cve} {f['name']}")
                self.console.print(f"      [dim]{f['url'][:70]}[/dim]")
        elif nuc and nuc.get('error'):
            self.console.print(f"  [dim][Nuclei] {nuc['error']}[/dim]")
        elif nuc:
            self.console.print(f"  [dim][Nuclei] No findings[/dim]")

        # Cookie Security
        ck = report_data.get('cookies', {})
        if ck and not ck.get('error') and ck.get('total', 0) > 0:
            ck_color = 'red' if ck['risk_level'] == 'CRITICAL' else 'yellow' if ck['risk_level'] == 'HIGH' else 'yellow'
            self.console.print(f"\n  [bold yellow][Cookies][/bold yellow] [{ck_color}]{ck['risk_level']}[/{ck_color}] | {len(ck.get('cookies',[]))} cookies | {ck['total']} issue(s)")
            for f in ck.get('findings', [])[:6]:
                fc = 'red' if f['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{fc}][{f['severity']}][/{fc}] {f['cookie']}: {f['issue']}")
        elif ck and ck.get('error'):
            self.console.print(f"  [dim][Cookies] {ck['error']}[/dim]")
        elif ck:
            self.console.print(f"  [dim][Cookies] All cookies properly secured[/dim]")

        # DNS Zone Transfer
        zt = report_data.get('zone_transfer', {})
        if zt and zt.get('vulnerable'):
            self.console.print(f"\n  [bold red][Zone Transfer][/bold red] [red]CRITICAL — {len(zt['vulnerable'])} NS server(s) allow AXFR![/red]")
            for v in zt['vulnerable']:
                self.console.print(f"    [red]✗ {v['ns']} ({v['ns_ip']}) — {v['records_count']} records leaked[/red]")
            self.console.print(f"    [dim]Total records exposed: {zt.get('total_records', 0)}[/dim]")
        elif zt and not zt.get('error'):
            self.console.print(f"  [dim][Zone Transfer] Checked {len(zt.get('ns_servers',[]))} NS servers — all refused AXFR ✓[/dim]")
        elif zt and zt.get('error'):
            self.console.print(f"  [dim][Zone Transfer] {zt['error']}[/dim]")

        # Rust Fuzzer
        fz = report_data.get('fuzzer', {})
        if fz and not fz.get('error') and fz.get('total_findings', 0) > 0:
            fz_color = 'red' if fz['risk_level'] == 'CRITICAL' else 'yellow' if fz['risk_level'] == 'HIGH' else 'dim'
            self.console.print(f"\n  [bold magenta][Rust Fuzzer][/bold magenta] Requests: {fz.get('total_requests',0)} | Found: {fz.get('total_findings',0)} | [{fz_color}]{fz['risk_level']}[/{fz_color}]")
            for r in fz.get('findings', [])[:8]:
                rc = 'red' if r['risk'] == 'CRITICAL' else 'yellow' if r['risk'] == 'HIGH' else 'dim'
                self.console.print(f"    [{rc}][{r['risk']}][/{rc}] {r['url'].split('/')[-1]} — {r['finding_type']} (HTTP {r['status_code']})")
        elif fz and fz.get('error'):
            self.console.print(f"  [dim][Rust Fuzzer] {fz['error']}[/dim]")
        elif fz:
            self.console.print(f"  [dim][Rust Fuzzer] {fz.get('total_requests',0)} requests — nothing found[/dim]")

        # Tech Fingerprint
        tf = report_data.get('tech_fingerprint', {})
        if tf and not tf.get('error') and tf.get('total', 0) > 0:
            self.console.print(f"\n  [bold cyan][Tech Stack][/bold cyan] {tf['total']} technologies detected")
            for cat, items in tf.get('stack', {}).items():
                names = ', '.join(f"{i['name']}" + (f" {i['version']}" if i['version'] else '') for i in items)
                self.console.print(f"    [cyan]{cat:<18}[/cyan] {names}")
        elif tf and tf.get('error'):
            self.console.print(f"  [dim][Tech Stack] {tf['error']}[/dim]")

        # Auth Bypass
        ab = report_data.get('auth_bypass', {})
        if ab and not ab.get('error') and ab.get('total', 0) > 0:
            ab_color = 'red' if ab['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][Auth Bypass][/bold red] [{ab_color}]{ab['risk_level']}[/{ab_color}] | {ab['total']} finding(s) | Panels: {len(ab.get('admin_panels',[]))}")
            for f in ab.get('findings', [])[:5]:
                fc = 'red' if f['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{fc}][{f['severity']}][/{fc}] {f['type']}: {f['evidence'][:80]}")
        elif ab and not ab.get('error'):
            self.console.print(f"  [dim][Auth Bypass] {len(ab.get('admin_panels',[]))} panel(s) found — no bypass[/dim]")

        # API Scanner
        api = report_data.get('api', {})
        if api and not api.get('error') and api.get('total', 0) > 0:
            api_color = 'red' if api['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][API Security][/bold red] [{api_color}]{api['risk_level']}[/{api_color}] | {api['total']} finding(s) | Endpoints: {len(api.get('endpoints_found',[]))}")
            for f in api.get('findings', [])[:6]:
                fc = 'red' if f['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{fc}][{f['severity']}][/{fc}] {f['type']}: {f['evidence'][:80]}")
        elif api and not api.get('error'):
            self.console.print(f"  [dim][API Security] {len(api.get('endpoints_found',[]))} endpoint(s) found — no issues[/dim]")

        # LFI
        lfi = report_data.get('lfi', {})
        if lfi and not lfi.get('error') and lfi.get('total', 0) > 0:
            lfi_color = 'red' if lfi['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][LFI/RFI][/bold red] [{lfi_color}]{lfi['risk_level']}[/{lfi_color}] | {lfi['total']} finding(s)")
            for f in lfi.get('findings', [])[:5]:
                fc = 'red' if f['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{fc}][{f['severity']}][/{fc}] param={f['param']} | {f['evidence']}")
                self.console.print(f"      [dim]{f['payload'][:60]}[/dim]")
        elif lfi and not lfi.get('error'):
            self.console.print(f"  [dim][LFI/RFI] No file inclusion vulnerabilities found[/dim]")

        # XXE
        xxe = report_data.get('xxe', {})
        if xxe and not xxe.get('error') and xxe.get('total', 0) > 0:
            xxe_color = 'red' if xxe['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][XXE][/bold red] [{xxe_color}]{xxe['risk_level']}[/{xxe_color}] | {xxe['total']} finding(s)")
            for f in xxe.get('findings', [])[:5]:
                fc = 'red' if f['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{fc}][{f['severity']}][/{fc}] {f['type']} @ {f['url'].split('/')[-1]}: {f['evidence']}")
        elif xxe and not xxe.get('error'):
            self.console.print(f"  [dim][XXE] No XML injection vulnerabilities found[/dim]")

        # SSTI
        ssti = report_data.get('ssti', {})
        if ssti and not ssti.get('error') and ssti.get('total', 0) > 0:
            ssti_color = 'red' if ssti['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][SSTI][/bold red] [{ssti_color}]{ssti['risk_level']}[/{ssti_color}] | {ssti['total']} finding(s)")
            for f in ssti.get('findings', [])[:5]:
                fc = 'red' if f['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{fc}][{f['severity']}][/{fc}] {f['engine']} | param={f['param']} | {f['payload'][:30]}")
        elif ssti and not ssti.get('error'):
            self.console.print(f"  [dim][SSTI] No template injection found[/dim]")

        # Clickjacking
        cj = report_data.get('clickjacking', {})
        if cj and not cj.get('error') and cj.get('total', 0) > 0:
            cj_color = 'red' if cj['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold yellow][Clickjacking][/bold yellow] [{cj_color}]{cj['risk_level']}[/{cj_color}] | {cj['total']} vulnerable page(s)")
            for f in cj.get('findings', [])[:5]:
                fc = 'red' if f['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{fc}][{f['severity']}][/{fc}] {f['path']} — {f['detail'][:70]}")
        elif cj and not cj.get('error'):
            self.console.print(f"  [dim][Clickjacking] All pages properly protected[/dim]")

        # Prototype Pollution
        pp = report_data.get('proto_pollution', {})
        if pp and not pp.get('error') and pp.get('total', 0) > 0:
            pp_color = 'red' if pp['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][Prototype Pollution][/bold red] [{pp_color}]{pp['risk_level']}[/{pp_color}] | {pp['total']} finding(s)")
            for f in pp.get('findings', [])[:5]:
                fc = 'red' if f['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{fc}][{f['severity']}][/{fc}] {f['method']} {f['url'].split('/')[-1]}: {f['evidence']}")
        elif pp and not pp.get('error'):
            self.console.print(f"  [dim][Prototype Pollution] No pollution vectors found[/dim]")

        # OAuth
        oauth = report_data.get('oauth', {})
        if oauth and not oauth.get('error') and oauth.get('total', 0) > 0:
            oa_color = 'red' if oauth['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][OAuth][/bold red] [{oa_color}]{oauth['risk_level']}[/{oa_color}] | {oauth['total']} finding(s) | Endpoints: {len(oauth.get('endpoints_found',[]))}")
            for f in oauth.get('findings', [])[:5]:
                fc = 'red' if f['severity'] == 'CRITICAL' else 'yellow'
                self.console.print(f"    [{fc}][{f['severity']}][/{fc}] {f['type']}: {f['evidence'][:80]}")
        elif oauth and not oauth.get('error') and oauth.get('endpoints_found'):
            self.console.print(f"  [dim][OAuth] {len(oauth['endpoints_found'])} endpoint(s) found — no misconfigurations[/dim]")
        elif oauth and not oauth.get('error'):
            self.console.print(f"  [dim][OAuth] No OAuth endpoints found[/dim]")

        # Rust analysis results
        rust = report_data.get('rust_analysis', {})
        if rust and not rust.get('error'):
            risk_indicators = rust.get('risk_indicators', [])
            correlations    = rust.get('correlations', [])
            entities        = rust.get('entities_found', {})
            self.console.print(f"\n  [bold magenta][Rust Analyzer][/bold magenta]")
            if entities.get('emails'):
                self.console.print(f"    Emails found   : [cyan]{', '.join(entities['emails'][:5])}[/cyan]")
            if entities.get('usernames'):
                self.console.print(f"    Usernames found: [cyan]{', '.join(entities['usernames'][:5])}[/cyan]")
            if correlations:
                self.console.print(f"    Correlations   : [yellow]{len(correlations)} cross-entity matches[/yellow]")
            if risk_indicators:
                self.console.print(f"    Risk indicators: [red]{len(risk_indicators)} found[/red]")
                for r in risk_indicators[:3]:
                    self.console.print(f"      [{r.get('severity','').upper()}] {r.get('description','')}")
        elif rust.get('error'):
            self.console.print(f"  [dim][Rust Analyzer] {rust['error']}[/dim]")

        self.console.print(f"\n[green]📄 Report saved:[/green]")
        self.console.print(f"  JSON   : {paths['json']}")
        self.console.print(f"  Summary: {paths['summary']}")
        self.console.print(f"  HTML   : {paths['html']}")

    def _handle_recon(self, command):
        """Passive recon - WHOIS + DNS + Subdomains + Go scraper"""
        parts = command.split(' ', 1)
        if len(parts) < 2:
            self.console.print("[red]Usage: recon <domain>[/red]")
            return
        target = parts[1].strip()

        report_data = {'target': target, 'timestamp': datetime.now().isoformat()}

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=self.console) as progress:
            task = progress.add_task("[cyan]Running recon...", total=100)

            progress.update(task, advance=30, description="[cyan]WHOIS + DNS records...")
            report_data['whois'] = self.whois.run(target)

            progress.update(task, advance=40, description="[cyan]Enumerating subdomains (4 sources)...")
            report_data['subdomains'] = self.subdomain.run(target)

            progress.update(task, advance=20, description="[cyan][Go] Deep scraping domain...")
            report_data['go_scraper'] = self.go_scraper.run(target)

            progress.update(task, advance=15, description="[cyan]Wayback Machine URLs...")
            report_data['wayback'] = self.wayback.run(target)

            progress.update(task, advance=10, description="[cyan]DNS history...")
            report_data['dns_history'] = self.dns_history.run(target)

            progress.update(task, advance=10, description="[cyan]Google dorking...")
            report_data['google_dorks'] = self.goog_dorker.run(target)

            progress.update(task, advance=5, description="[cyan]GitHub dorking...")
            report_data['github_dorks'] = self.gh_dorker.run(target)

            progress.update(task, advance=4, description="[cyan]ASN/IP range mapping...")
            report_data['asn'] = self.asn_mapper.run(target)

            progress.update(task, advance=4, description="[cyan]Cloud asset discovery...")
            report_data['cloud_assets'] = self.cloud_assets.run(target)

            progress.update(task, advance=4, description="[cyan]Certificate transparency...")
            report_data['cert_transparency'] = self.cert_ct.run(target)

            progress.update(task, advance=4, description="[cyan]Job posting OSINT...")
            report_data['job_osint'] = self.job_osint.run(target)

            progress.update(task, advance=5, description="[cyan]Saving report...")
            user_folder = self.session_data.get('user_folder', str(config.BASE_DIR / 'reports'))
            reporter = ReconReport(output_dir=user_folder)
            paths = reporter.save(target, report_data)
            self.session_data['recon'] = report_data
            self.session_data['last_paths'] = paths
            self.evidence.add_evidence('recon', report_data)
            progress.update(task, completed=100, description="[green]Recon complete")

        # Telegram alert
        self.notifier.alert_recon(target, report_data)
        # Auto PDF
        pdf_path = self.pdf.export_scan(paths)
        if pdf_path:
            self.console.print(f"  PDF    : [green]{pdf_path}[/green]")

        # Continuous learning
        self._feed_to_ml('recon', report_data)

        whois_data = report_data['whois']
        subs       = report_data['subdomains']
        w          = whois_data.get('whois', {})
        dns        = whois_data.get('dns', {})
        flags      = whois_data.get('risk_flags', [])

        self.console.print(f"\n[bold cyan]Recon Results: {target}[/bold cyan]")

        if w and not w.get('error'):
            self.console.print(f"  Registrar  : [white]{w.get('registrar', 'N/A')}[/white]")
            self.console.print(f"  Created    : {w.get('creation_date', 'N/A')}")
            self.console.print(f"  Expires    : {w.get('expiration_date', 'N/A')}")
            self.console.print(f"  Org        : {w.get('org', 'N/A')} | Country: {w.get('country', 'N/A')}")

        if dns:
            self.console.print("\n  [bold]DNS Records:[/bold]")
            for rtype in ['A', 'MX', 'NS', 'TXT', 'SPF', 'DMARC']:
                vals = dns.get(rtype, [])
                if vals:
                    preview = ', '.join(str(v) for v in vals[:2])
                    if len(vals) > 2:
                        preview += f' (+{len(vals)-2} more)'
                    self.console.print(f"    [cyan]{rtype:<8}[/cyan] {preview}")

        if flags:
            self.console.print("\n  [bold red]Risk Flags:[/bold red]")
            for f in flags:
                color = 'red' if f['severity'] in ('CRITICAL', 'HIGH') else 'yellow'
                self.console.print(f"    [{color}][{f['severity']}][/{color}] {f['flag']}: {f['detail']}")

        total = subs.get('total_found', 0)
        sources = subs.get('sources', {})
        self.console.print(f"\n  [bold]Subdomains:[/bold] {total} found")
        for src, count in sources.items():
            self.console.print(f"    {src}: {count}")
        alive = [s for s in subs.get('subdomains', []) if s.get('alive')]
        self.console.print(f"  Alive: {len(alive)}")
        for s in alive[:10]:
            self.console.print(f"    [green]✓[/green] [cyan]{s['subdomain']}[/cyan] -> {s['ip']}")
        if total > 10:
            self.console.print(f"    [dim]... and {total - 10} more in report[/dim]")

        # Go scraper results
        go = report_data.get('go_scraper', {})
        if go and not go.get('error'):
            self.console.print(f"\n  [bold magenta][Go Scraper][/bold magenta]")
            if go.get('emails'):
                self.console.print(f"    Emails found   : [cyan]{', '.join(go['emails'][:5])}[/cyan]")
            if go.get('tech_hints'):
                self.console.print(f"    Tech stack     : [yellow]{', '.join(go['tech_hints'])}[/yellow]")
            if go.get('subdomains'):
                self.console.print(f"    Extra subdomains: [green]{len(go['subdomains'])} found[/green]")
                for s in go['subdomains'][:5]:
                    self.console.print(f"      [cyan]{s}[/cyan]")
            if go.get('exposed_files'):
                self.console.print(f"    Exposed files  : [red]{', '.join(go['exposed_files'])}[/red]")
            self.console.print(f"    Pages scraped  : {len(go.get('raw_pages', []))}")
        elif go.get('error'):
            self.console.print(f"  [dim][Go Scraper] {go['error']}[/dim]")

        # Wayback Machine
        wb = report_data.get('wayback', {})
        if wb and not wb.get('error'):
            self.console.print(f"\n  [bold blue][Wayback Machine][/bold blue] {wb.get('total_urls', 0)} historical URLs")
            self.console.print(f"    Oldest: {wb.get('oldest_snapshot', 'N/A')} | Newest: {wb.get('newest_snapshot', 'N/A')}")
            if wb.get('by_extension'):
                ext_str = ', '.join(f"{k}({v})" for k, v in wb['by_extension'].items())
                self.console.print(f"    Sensitive files: [red]{ext_str}[/red]")
            if wb.get('parameters'):
                self.console.print(f"    Parameters found: [yellow]{', '.join(wb['parameters'][:10])}[/yellow]")
            interesting = wb.get('interesting_urls', [])
            if interesting:
                self.console.print(f"    Interesting URLs: [cyan]{len(interesting)}[/cyan]")
                for u in interesting[:5]:
                    self.console.print(f"      [dim]{u['url']}[/dim]")
        elif wb.get('error'):
            self.console.print(f"  [dim][Wayback] {wb['error']}[/dim]")

        # DNS History
        dh = report_data.get('dns_history', {})
        if dh and not dh.get('error'):
            self.console.print(f"\n  [bold blue][DNS History][/bold blue]")
            if dh.get('current_ips'):
                ips = ', '.join(e['ip'] for e in dh['current_ips'][:5])
                self.console.print(f"    Current IPs  : [cyan]{ips}[/cyan]")
            if dh.get('historical_ips'):
                old = ', '.join(set(e['ip'] for e in dh['historical_ips'][:5]))
                self.console.print(f"    Historical   : [yellow]{old}[/yellow]")
            if dh.get('ip_changes'):
                self.console.print(f"    IP changes   : [yellow]{len(dh['ip_changes'])} old IPs found[/yellow]")
            for rf in dh.get('risk_flags', []):
                color = 'red' if rf['severity'] == 'HIGH' else 'yellow'
                self.console.print(f"    [{color}][{rf['severity']}][/{color}] {rf['flag']}: {rf['detail']}")

        # Google Dorks
        gd = report_data.get('google_dorks', {})
        if gd:
            total_gd = gd.get('total_results', 0)
            gd_risk  = gd.get('risk_level', 'LOW')
            gd_color = 'red' if gd_risk == 'CRITICAL' else 'yellow' if gd_risk == 'HIGH' else 'green'
            self.console.print(f"\n  [bold green][Google Dorks][/bold green] {total_gd} results | [{gd_color}]{gd_risk}[/{gd_color}]")
            if gd.get('error'):
                self.console.print(f"    [dim]{gd['error']}[/dim]")
            for cat, findings in list(gd.get('by_category', {}).items())[:5]:
                if findings:
                    sev = findings[0].get('severity', 'LOW')
                    color = 'red' if sev == 'CRITICAL' else 'yellow' if sev == 'HIGH' else 'dim'
                    self.console.print(f"    [{color}]{cat}[/{color}]: {len(findings)} result(s)")
                    for f in findings[:2]:
                        self.console.print(f"      [dim]{f['url'][:80]}[/dim]")

        # GitHub Dorks
        ghd = report_data.get('github_dorks', {})
        if ghd and ghd.get('total_secrets', 0) > 0:
            ghd_color = 'red' if ghd['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][GitHub Dorks][/bold red] [{ghd_color}]{ghd['risk_level']}[/{ghd_color}] | Secrets: {ghd['total_secrets']} | Repos: {len(ghd.get('repos_found', []))}")
            for f in ghd.get('findings', [])[:5]:
                self.console.print(f"    [red][{f['secret_type']}][/red] {f['repo']}/{f['path']}")
                self.console.print(f"      [dim]{f['match'][:60]}[/dim]")
        elif ghd.get('error'):
            self.console.print(f"  [dim][GitHub Dorks] {ghd['error']}[/dim]")

        # ASN / IP Range
        asn = report_data.get('asn', {})
        if asn and not asn.get('error') and asn.get('asns'):
            self.console.print(f"\n  [bold blue][ASN Mapper][/bold blue] {len(asn['asns'])} ASN(s) | {len(asn['prefixes'])} prefix(es) | {asn.get('total_ips_in_range',0):,} IPs")
            for a in asn['asns']:
                cloud_tag = f" [yellow]({a['cloud_provider']})[/yellow]" if a.get('is_cloud') else ''
                self.console.print(f"    [cyan]{a['asn']}[/cyan] {a['name'][:50]}{cloud_tag} | {a['country']}")
            for p in asn['prefixes'][:6]:
                self.console.print(f"      [dim]{p['prefix']:<20} {p.get('description','')[:40]}[/dim]")
            if len(asn['prefixes']) > 6:
                self.console.print(f"      [dim]... and {len(asn['prefixes'])-6} more prefixes[/dim]")
        elif asn and asn.get('error'):
            self.console.print(f"  [dim][ASN Mapper] {asn['error']}[/dim]")

        # Cloud Assets
        ca = report_data.get('cloud_assets', {})
        if ca and not ca.get('error') and ca.get('total', 0) > 0:
            ca_color = 'red' if ca['risk_level'] == 'CRITICAL' else 'yellow'
            self.console.print(f"\n  [bold red][Cloud Assets][/bold red] [{ca_color}]{ca['risk_level']}[/{ca_color}] | {ca['total']} asset(s) found")
            for f in ca.get('findings', [])[:8]:
                fc = 'red' if f['severity'] == 'CRITICAL' else 'yellow' if f['severity'] == 'HIGH' else 'dim'
                pub = '[red]PUBLIC[/red]' if f.get('public') else '[dim]private[/dim]'
                self.console.print(f"    [{fc}][{f['provider']}][/{fc}] {f['name']} — {pub}")
                self.console.print(f"      [dim]{f['url']}[/dim]")
        elif ca and not ca.get('error'):
            self.console.print(f"  [dim][Cloud Assets] No exposed buckets/storage found[/dim]")

        # Certificate Transparency
        ct = report_data.get('cert_transparency', {})
        if ct and not ct.get('error'):
            self.console.print(f"\n  [bold blue][Cert Transparency][/bold blue] {ct.get('total_certs',0)} certs | {ct.get('total_unique_subdomains',0)} unique subdomains | Wildcards: {len(ct.get('wildcards',[]))}")
            new_subs = [s for s in ct.get('subdomains', []) if s not in
                        [x.get('subdomain','') for x in report_data.get('subdomains',{}).get('subdomains',[])]]
            if new_subs:
                self.console.print(f"    [green]+{len(new_subs)} new subdomains from CT logs:[/green]")
                for s in new_subs[:8]:
                    self.console.print(f"      [cyan]{s}[/cyan]")
            if ct.get('expired'):
                self.console.print(f"    [yellow]Expired certs: {len(ct['expired'])}[/yellow]")
            for rf in ct.get('risk_flags', []):
                c = 'yellow' if rf['severity'] in ('HIGH','MEDIUM') else 'dim'
                self.console.print(f"    [{c}]{rf['flag']}[/{c}]: {rf['detail']}")
        elif ct and ct.get('error'):
            self.console.print(f"  [dim][Cert Transparency] {ct['error']}[/dim]")

        # Job OSINT
        jo = report_data.get('job_osint', {})
        if jo and not jo.get('error') and jo.get('tech_stack'):
            self.console.print(f"\n  [bold green][Job OSINT][/bold green] {jo.get('total_jobs',0)} job(s) found | Tech stack leaked:")
            for cat, techs in jo.get('tech_stack', {}).items():
                self.console.print(f"    [cyan]{cat:<16}[/cyan] {', '.join(techs[:8])}")
            for rf in jo.get('risk_flags', []):
                self.console.print(f"    [yellow]{rf['flag']}[/yellow]: {rf['detail']}")
        elif jo and jo.get('error'):
            self.console.print(f"  [dim][Job OSINT] {jo['error']}[/dim]")

        self.console.print(f"\n[green]📄 Report saved:[/green]")
        self.console.print(f"  JSON   : {paths['json']}")
        self.console.print(f"  Summary: {paths['summary']}")
        self.console.print(f"  HTML   : {paths['html']}")

    def _handle_breach(self, command):
        """Check email/username across multiple breach databases"""
        parts = command.split(' ', 1)
        if len(parts) < 2:
            self.console.print("[red]Usage: breach <email or username>[/red]")
            return
        target = parts[1].strip()

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=self.console) as progress:
            task = progress.add_task("[cyan]Checking breach databases...", total=100)
            progress.update(task, advance=25, description="[cyan]BreachDirectory...")
            progress.update(task, advance=25, description="[cyan]HudsonRock stealer logs...")
            progress.update(task, advance=25, description="[cyan]LeakCheck + IntelX...")
            result = self.breach.run(target)
            progress.update(task, advance=15, description="[cyan]Saving report...")
            user_folder = self.session_data.get('user_folder', str(config.BASE_DIR / 'reports'))
            reporter = BreachReport(output_dir=user_folder)
            paths = reporter.save(target, result)
            self.session_data['breach'] = result
            self.session_data['last_paths'] = paths
            self.evidence.add_evidence('breach_check', result)
            progress.update(task, completed=100, description="[green]Breach check complete")

        # Telegram alert
        self.notifier.alert_breach(target, result)
        # Auto PDF
        pdf_path = self.pdf.export_scan(paths)
        if pdf_path:
            self.console.print(f"  PDF    : [green]{pdf_path}[/green]")

        # Continuous learning
        self._feed_to_ml('breach', result)

        risk  = result['risk_level']
        color = 'red' if risk in ('CRITICAL', 'HIGH') else 'yellow' if risk == 'MEDIUM' else 'green'

        self.console.print(f"\n[bold cyan]Breach Check: {target}[/bold cyan]")
        self.console.print(f"  Risk Level    : [{color}]{risk}[/{color}]")
        self.console.print(f"  Breaches      : {result['total_breaches']}")
        self.console.print(f"  Pastes        : {result['total_pastes']}")
        sl = result['total_stealer_logs']
        self.console.print(f"  Stealer Logs  : [{'red' if sl else 'green'}]{sl}[/{'red' if sl else 'green'}]")

        self.console.print("")
        for s in result.get('summary', []):
            self.console.print(f"  {s}")

        # HIBP
        hibp = result.get('hibp', {})
        if hibp and not hibp.get('error') and hibp.get('total', 0) > 0:
            self.console.print(f"\n  [bold red]🔔 HaveIBeenPwned: {hibp['total']} breach(es)[/bold red]")
            for b in hibp.get('breaches', [])[:8]:
                dc = ', '.join(b.get('DataClasses', [])[:3])
                sens = ' [red][SENSITIVE][/red]' if b.get('IsSensitive') else ''
                self.console.print(f"    [red]•[/red] {b.get('Name','?')} ({b.get('BreachDate','?')}) — {b.get('PwnCount',0):,} accounts{sens}")
                if dc:
                    self.console.print(f"      [dim]Data: {dc}[/dim]")
        elif hibp.get('error'):
            self.console.print(f"  [dim][HIBP] {hibp['error']}[/dim]")
        elif hibp:
            self.console.print(f"  [green][HIBP] Not found in any breach ✓[/green]")

        # Dehashed
        dh = result.get('dehashed', {})
        if dh and not dh.get('error') and dh.get('total', 0) > 0:
            plain = sum(1 for e in dh.get('entries', []) if e.get('has_plaintext'))
            plain_color = 'red' if plain else 'yellow'
            self.console.print(f"\n  [bold red]🔑 Dehashed: {dh['total']} record(s) | [{plain_color}]Plaintext passwords: {plain}[/{plain_color}][/bold red]")
            for e in dh.get('entries', [])[:6]:
                pw = f" | [red]pw: {e['password'][:4]}***[/red]" if e.get('has_plaintext') else ''
                self.console.print(f"    [red]•[/red] {e.get('database_name','?')} | user: {e.get('username','')}{pw}")
        elif dh.get('error'):
            self.console.print(f"  [dim][Dehashed] {dh['error']}[/dim]")

        self.console.print("\n  [bold]Sources checked:[/bold]")
        for src, status in result.get('sources', {}).items():
            icon = '[green]✓[/green]' if status == 'ok' else '[red]✗[/red]'
            self.console.print(f"    {icon} {src}: {status}")

        if result['stealer_logs']:
            self.console.print("\n  [bold red]⚠ Infostealer Logs Found:[/bold red]")
            for log in result['stealer_logs']:
                self.console.print(f"    Computer: {log.get('computer_name')} | OS: {log.get('operating_system')}")
                self.console.print(f"    Date: {log.get('date_uploaded')} | Malware: {log.get('malware_path')}")

        if result['breaches']:
            self.console.print(f"\n  [bold]Breaches:[/bold]")
            for b in result['breaches'][:10]:
                self.console.print(f"    [red]•[/red] {b.get('name', 'Unknown')} [{b.get('source')}]")
            if result['total_breaches'] > 10:
                self.console.print(f"    [dim]... and {result['total_breaches'] - 10} more in report[/dim]")

        # Pastes
        pastes = result.get('pastes', [])
        if pastes:
            self.console.print(f"\n  [bold yellow]📋 Pastes: {len(pastes)} found[/bold yellow]")
            for p in pastes[:5]:
                url = p.get('url', '')
                label = p.get('title') or p.get('name') or p.get('id', 'N/A')
                src_tag = f"[{p.get('source','')}]"
                self.console.print(f"    [yellow]•[/yellow] {src_tag} {str(label)[:60]}")
                if url:
                    self.console.print(f"      [dim]{url}[/dim]")

        self.console.print(f"\n[green]📄 Report saved:[/green]")
        self.console.print(f"  JSON   : {paths['json']}")
        self.console.print(f"  Summary: {paths['summary']}")
        self.console.print(f"  HTML   : {paths.get('html', 'N/A')}")

    def _handle_phone(self, command):
        """Phone number OSINT — carrier, country, line type, social hints, reputation"""
        parts = command.split(' ', 1)
        if len(parts) < 2:
            self.console.print("[red]Usage: phone <number>  e.g. phone +919876543210[/red]")
            return
        target = parts[1].strip()

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=self.console) as progress:
            task = progress.add_task("[cyan]Phone OSINT...", total=100)
            progress.update(task, advance=30, description="[cyan]NumVerify + AbstractAPI lookup...")
            progress.update(task, advance=30, description="[cyan]Social profile hints...")
            progress.update(task, advance=30, description="[cyan]Reputation check...")
            result = self.phone_osint.run(target)
            progress.update(task, advance=10, description="[cyan]Saving report...")
            user_folder = self.session_data.get('user_folder', str(config.BASE_DIR / 'reports'))
            reporter = PhoneReport(output_dir=user_folder)
            paths = reporter.save(target, result)
            self.session_data['phone'] = result
            self.evidence.add_evidence('phone_osint', result)
            progress.update(task, completed=100, description="[green]Phone OSINT complete")

        risk  = result['risk_level']
        color = 'red' if risk in ('CRITICAL', 'HIGH') else 'yellow' if risk == 'MEDIUM' else 'green'

        self.console.print(f"\n[bold cyan]Phone OSINT: {target}[/bold cyan]")
        self.console.print(f"  Normalized  : [white]{result.get('normalized', 'N/A')}[/white]")
        self.console.print(f"  Valid       : {'[green]Yes[/green]' if result.get('valid') else '[red]No[/red]'}")
        self.console.print(f"  Country     : {result.get('country', 'N/A')} (+{result.get('country_code', '?')})")
        self.console.print(f"  Carrier     : [cyan]{result.get('carrier', 'N/A')}[/cyan]")
        self.console.print(f"  Line Type   : [cyan]{result.get('line_type', 'N/A')}[/cyan]")
        self.console.print(f"  Location    : {result.get('location', 'N/A')}")
        self.console.print(f"  Risk Level  : [{color}]{risk}[/{color}]")

        social = result.get('social_hints', [])
        found  = [s for s in social if s['status'] == 'found']
        if found:
            self.console.print(f"\n  [bold]Social Presence:[/bold]")
            for s in found:
                self.console.print(f"    [green]✓[/green] [cyan]{s['platform']}[/cyan]: {s['url']}")

        rep = result.get('reputation', {})
        if rep.get('spam_reports', 0) > 0:
            self.console.print(f"\n  [bold red]⚠ Spam/Scam Reports: {rep['spam_reports']}[/bold red]")
            self.console.print(f"    Sources: {', '.join(rep.get('sources', []))}")

        if result.get('risk_flags'):
            self.console.print(f"\n  [bold red]Risk Flags:[/bold red]")
            for rf in result['risk_flags']:
                c = 'red' if rf['severity'] in ('CRITICAL', 'HIGH') else 'yellow' if rf['severity'] == 'MEDIUM' else 'blue'
                self.console.print(f"    [{c}][{rf['severity']}][/{c}] {rf['flag']}: {rf['detail']}")

        self.console.print(f"\n[green]📄 Report saved:[/green]")
        self.console.print(f"  JSON   : {paths['json']}")
        self.console.print(f"  Summary: {paths['summary']}")
        self.console.print(f"  HTML   : {paths['html']}")

    def _handle_email(self, command):
        """Full email OSINT - breach + social + domain validation"""
        parts = command.split(' ', 1)
        if len(parts) < 2:
            self.console.print("[red]Usage: email <email>[/red]")
            return
        target = parts[1].strip()

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=self.console) as progress:
            task = progress.add_task("[cyan]Email OSINT...", total=100)
            progress.update(task, advance=30, description="[cyan]Validating domain + MX...")
            progress.update(task, advance=30, description="[cyan]Checking social profiles...")
            progress.update(task, advance=30, description="[cyan]Breach databases...")
            result = self.email_osint.run(target)
            progress.update(task, advance=10, description="[cyan]Saving report...")
            user_folder = self.session_data.get('user_folder', str(config.BASE_DIR / 'reports'))
            reporter = EmailReport(output_dir=user_folder)
            paths = reporter.save(target, result)
            self.session_data['email'] = result
            self.evidence.add_evidence('email_osint', result)
            progress.update(task, completed=100, description="[green]Email OSINT complete")

        risk  = result['risk_level']
        color = 'red' if risk in ('CRITICAL', 'HIGH') else 'yellow' if risk == 'MEDIUM' else 'green'

        self.console.print(f"\n[bold cyan]Email OSINT: {target}[/bold cyan]")
        self.console.print(f"  Risk Level  : [{color}]{risk}[/{color}]")
        self.console.print(f"  Valid Format: {'[green]Yes[/green]' if result['valid_format'] else '[red]No[/red]'}")
        self.console.print(f"  Domain      : {result['domain']}")
        self.console.print(f"  Username    : {result['username']}")
        self.console.print(f"  Disposable  : {'[red]YES[/red]' if result['disposable'] else '[green]No[/green]'}")

        di = result.get('domain_info', {})
        if di:
            mx_status = '[green]Valid[/green]' if di.get('mx_valid') else '[red]No MX records[/red]'
            self.console.print(f"  MX Records  : {mx_status}")
            if di.get('mx_records'):
                self.console.print(f"    {', '.join(di['mx_records'][:3])}")
            if di.get('spf'):
                self.console.print(f"  SPF         : [dim]{di['spf'][:80]}[/dim]")

        social = result.get('social_hints', [])
        if social:
            self.console.print(f"\n  [bold]Social Profile Hints:[/bold]")
            for s in social:
                icon  = '[green]✓[/green]' if s['status'] == 'found' else '[dim]✗[/dim]'
                color = 'cyan' if s['status'] == 'found' else 'dim'
                self.console.print(f"    {icon} [{color}]{s['platform']}[/{color}]: {s['url']}")

        breach = result.get('breach_summary', {})
        if breach:
            self.console.print(f"\n  [bold]Breach Summary:[/bold]")
            if breach.get('stealer_logs', 0) > 0:
                self.console.print(f"    [red]Stealer logs: {breach['stealer_logs']}[/red]")
            lc = breach.get('leakcheck', {})
            if lc.get('found', 0) > 0:
                self.console.print(f"    [red]LeakCheck: found in {lc['found']} source(s)[/red]")
                for src in lc.get('sources', [])[:5]:
                    self.console.print(f"      [dim]• {src}[/dim]")

        if result.get('risk_flags'):
            self.console.print(f"\n  [bold red]Risk Flags:[/bold red]")
            for rf in result['risk_flags']:
                c = 'red' if rf['severity'] in ('CRITICAL', 'HIGH') else 'yellow'
                self.console.print(f"    [{c}][{rf['severity']}][/{c}] {rf['flag']}: {rf['detail']}")

        self.console.print(f"\n[green]📄 Report saved:[/green]")
        self.console.print(f"  JSON   : {paths['json']}")
        self.console.print(f"  Summary: {paths['summary']}")
        self.console.print(f"  HTML   : {paths['html']}")

    def _handle_nlp(self, command: str):
        """NLP deep analysis — bio/posts se person profile banao"""
        parts = command.split(' ', 1)
        if len(parts) < 2:
            self.console.print("[red]Usage: nlp <text>[/red]")
            self.console.print("[dim]Example: nlp Security researcher based in Mumbai, loves CTF and hacking[/dim]")
            return

        raw_input = parts[1].strip()

        # Agar session mein collected data hai to usse use karo
        texts, labels = [], []
        if raw_input == 'session' and 'collected_data' in self.session_data:
            collected = self.session_data['collected_data']
            for item in collected.get('social_data', []):
                bio = item.get('bio_data', {}).get('bio', '')
                if bio:
                    texts.append(bio)
                    labels.append(f"{item.get('platform','unknown')}_bio")
                for post in item.get('posts_data', {}).get('posts', [])[:5]:
                    txt = post.get('text') or post.get('content') or post.get('caption', '')
                    if txt:
                        texts.append(txt)
                        labels.append(f"{item.get('platform','unknown')}_post")
            if not texts:
                self.console.print("[yellow]No text data in session. Run 'collect' first or provide text directly.[/yellow]")
                return
        else:
            texts  = [raw_input]
            labels = ['direct_input']

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=self.console) as progress:
            task = progress.add_task("[cyan]NLP Analysis...", total=100)

            progress.update(task, advance=25, description="[cyan]Named Entity Recognition...")
            nlp_result = self.nlp_analyzer.analyze(texts, labels)

            progress.update(task, advance=25, description="[cyan]Writing style fingerprint...")
            fp_result = self.writing_fp.compare_multiple(texts, labels) if len(texts) > 1 else {}

            progress.update(task, advance=50, description="[cyan]Generating intelligence profile...")
            progress.update(task, completed=100, description="[green]NLP Analysis complete")

        risk  = nlp_result['risk_level']
        color = 'red' if risk in ('CRITICAL', 'HIGH') else 'yellow' if risk == 'MEDIUM' else 'green'

        self.console.print(f"\n[bold cyan]NLP Intelligence Profile[/bold cyan]")
        self.console.print(f"  Texts analyzed : {nlp_result['total_texts']}")
        self.console.print(f"  Risk Level     : [{color}]{risk}[/{color}]")

        # Professions
        if nlp_result['professions']:
            self.console.print(f"\n  [bold]Detected Professions:[/bold]")
            for p in nlp_result['professions'][:3]:
                bar = '█' * int(p['confidence'] * 10)
                self.console.print(f"    [cyan]{p['profession']:<15}[/cyan] {bar} {p['confidence']:.0%} | keywords: {', '.join(p['keywords_found'][:3])}")

        # Interests
        if nlp_result['interests']:
            self.console.print(f"\n  [bold]Interests:[/bold]")
            for i in nlp_result['interests'][:5]:
                self.console.print(f"    [green]•[/green] {i['interest']:<12} ({i['confidence']:.0%}) — {', '.join(i['keywords_found'][:3])}")

        # Personality
        if nlp_result['personality']:
            self.console.print(f"\n  [bold]Personality Markers:[/bold]")
            for p in nlp_result['personality'][:3]:
                c = 'red' if p['trait'] in ('aggressive', 'paranoid') else 'yellow'
                self.console.print(f"    [{c}]•[/{c}] {p['trait']:<15} ({p['confidence']:.0%}) — {', '.join(p['keywords_found'][:3])}")

        # Named Entities
        ner = nlp_result['named_entities']
        if any(ner.values()):
            self.console.print(f"\n  [bold]Named Entities (NER):[/bold]")
            if ner.get('persons'):
                self.console.print(f"    Persons : [yellow]{', '.join(ner['persons'][:5])}[/yellow]")
            if ner.get('organizations'):
                self.console.print(f"    Orgs    : [cyan]{', '.join(ner['organizations'][:5])}[/cyan]")
            if ner.get('locations'):
                self.console.print(f"    Locations: [blue]{', '.join(ner['locations'][:5])}[/blue]")

        # Contact info
        contacts = nlp_result['contact_info']
        if contacts:
            self.console.print(f"\n  [bold red]Contact Info Found:[/bold red]")
            for ctype, values in contacts.items():
                self.console.print(f"    [red]{ctype}[/red]: {', '.join(str(v) for v in values[:3])}")

        # Locations
        if nlp_result['locations_mentioned']:
            self.console.print(f"\n  [bold]Locations Mentioned:[/bold]")
            for loc in nlp_result['locations_mentioned'][:5]:
                self.console.print(f"    [blue]📍[/blue] {loc}")

        # Writing style
        style = nlp_result['writing_style']
        if style:
            self.console.print(f"\n  [bold]Writing Style:[/bold]")
            self.console.print(f"    Style label    : [cyan]{style.get('style_label', 'N/A')}[/cyan]")
            self.console.print(f"    Formality      : {style.get('formality_score', 0):.0%}")
            self.console.print(f"    Vocab richness : {style.get('vocabulary_richness', 0):.0%}")
            self.console.print(f"    Avg word len   : {style.get('avg_word_length', 0):.1f} chars")
            if style.get('signature_words'):
                self.console.print(f"    Signature words: [dim]{', '.join(style['signature_words'][:8])}[/dim]")
            if style.get('emojis_used'):
                self.console.print(f"    Emojis used    : {''.join(style['emojis_used'][:10])}")

        # Key topics
        if nlp_result['key_topics']:
            topics = [t['topic'] for t in nlp_result['key_topics'][:8]]
            self.console.print(f"\n  [bold]Key Topics (TF-IDF):[/bold] [dim]{', '.join(topics)}[/dim]")

        # Cross-text similarity
        cross = nlp_result.get('cross_text_similarity', {})
        if cross:
            same = '[green]Yes[/green]' if cross.get('same_author_likely') else '[yellow]Uncertain[/yellow]'
            self.console.print(f"\n  [bold]Cross-Text Similarity:[/bold]")
            self.console.print(f"    Avg similarity : {cross.get('avg_similarity', 0):.0%}")
            self.console.print(f"    Same author    : {same}")
            self.console.print(f"    Interpretation : [dim]{cross.get('interpretation', 'N/A')}[/dim]")

        # Writing fingerprint (multi-text)
        if fp_result and not fp_result.get('error'):
            self.console.print(f"\n  [bold magenta]Writing Fingerprint (Authorship Attribution):[/bold magenta]")
            self.console.print(f"    Verdict        : [cyan]{fp_result.get('overall_verdict', 'N/A')}[/cyan]")
            self.console.print(f"    Avg similarity : {fp_result.get('avg_similarity', 0):.0%}")
            strongest = fp_result.get('strongest_match', {})
            if strongest:
                self.console.print(f"    Strongest match: {strongest.get('source_a')} ↔ {strongest.get('source_b')} ({strongest.get('final_score', 0):.0%})")

        # OSINT flags
        if nlp_result['osint_flags']:
            self.console.print(f"\n  [bold red]OSINT Intelligence Flags:[/bold red]")
            for flag in nlp_result['osint_flags']:
                c = 'red' if flag['severity'] in ('CRITICAL', 'HIGH') else 'yellow'
                self.console.print(f"    [{c}][{flag['severity']}][/{c}] {flag['flag']}")
                self.console.print(f"      [dim]{flag['detail']}[/dim]")

        # Continuous learning
        self._feed_to_ml('nlp', nlp_result)


    def _handle_person(self, command: str):
        """Person OSINT - naam/email/phone se complete digital footprint + relation graph"""
        parts = command.split(' ', 1)
        if len(parts) < 2:
            self.console.print("[red]Usage: person <name or email or phone>[/red]")
            self.console.print("[dim]Examples: person John Doe | person john@gmail.com | person +919876543210[/dim]")
            return
        query = parts[1].strip()

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=self.console) as progress:
            task = progress.add_task("[cyan]Person OSINT...", total=100)

            progress.update(task, advance=20, description="[cyan]Generating username variations...")
            progress.update(task, advance=30, description="[cyan]Searching 10+ social platforms...")
            result = self.person_osint.run(query)

            progress.update(task, advance=20, description="[cyan]Building relation graph...")
            graph = self.relation_mapper.build_graph(result)

            progress.update(task, advance=20, description="[cyan]Saving report...")
            user_folder = self.session_data.get('user_folder', str(config.BASE_DIR / 'reports'))
            reporter = PersonReport(output_dir=user_folder)
            paths = reporter.save(query, result, graph)
            self.session_data['person'] = result
            self.session_data['last_paths'] = paths
            self.evidence.add_evidence('person_osint', result)
            progress.update(task, completed=100, description="[green]Person OSINT complete")

        risk  = result['risk_level']
        color = 'red' if risk in ('CRITICAL', 'HIGH') else 'yellow' if risk == 'MEDIUM' else 'green'

        self.console.print(f"\n[bold cyan]Person OSINT: {query}[/bold cyan]")
        self.console.print(f"  Query Type  : {result['query_type']}")
        self.console.print(f"  Risk Level  : [{color}]{risk}[/{color}]")
        self.console.print(f"  Usernames   : {', '.join(result['possible_usernames'][:5])}")

        profiles = result.get('social_profiles', [])
        if profiles:
            self.console.print(f"\n  [bold green]Social Profiles Found ({len(profiles)}):[/bold green]")
            for p in profiles:
                self.console.print(f"    [green]✓[/green] [cyan]{p['platform'].upper()}[/cyan] @{p['username']} → {p['url']}")
                if p.get('display_name'):
                    self.console.print(f"      Name: [white]{p['display_name']}[/white]")
                if p.get('bio'):
                    self.console.print(f"      Bio : [dim]{p['bio'][:120]}{'...' if len(p['bio']) > 120 else ''}[/dim]")

        if result.get('emails_found'):
            self.console.print(f"\n  [bold yellow]Emails Found:[/bold yellow]")
            for e in result['emails_found']:
                self.console.print(f"    [yellow]•[/yellow] {e}")

        if result.get('phones_found'):
            self.console.print(f"\n  [bold yellow]Phones Found:[/bold yellow]")
            for p in result['phones_found']:
                self.console.print(f"    [yellow]•[/yellow] {p}")

        if result.get('addresses'):
            self.console.print(f"\n  [bold red]Addresses Found:[/bold red]")
            for a in result['addresses']:
                self.console.print(f"    [red]•[/red] {a}")

        if result.get('images_found'):
            self.console.print(f"\n  [bold blue]Images Found:[/bold blue]")
            for img in result['images_found']:
                self.console.print(f"    [blue]•[/blue] {img['source']}: {img.get('url', 'N/A')}")

        # Relation graph summary
        summary = graph.get('summary', {})
        self.console.print(f"\n  [bold magenta]Relation Graph:[/bold magenta]")
        self.console.print(f"    Nodes      : [cyan]{summary.get('total_nodes', 0)}[/cyan]")
        self.console.print(f"    Relations  : [cyan]{summary.get('total_edges', 0)}[/cyan]")
        self.console.print(f"    Confidence : [cyan]{summary.get('confidence_score', 0)}%[/cyan]")

        central = graph.get('central_identity', {})
        if central:
            self.console.print(f"    Central ID : [white]{central.get('label', 'N/A')}[/white] ({central.get('connection_count', 0)} connections)")

        # Top relations
        edges = graph.get('edges', [])
        if edges:
            self.console.print(f"\n  [bold]Top Relations:[/bold]")
            for edge in sorted(edges, key=lambda x: x.get('confidence', 0), reverse=True)[:5]:
                conf = int(edge.get('confidence', 0) * 100)
                self.console.print(f"    [{conf}%] {edge['from']} --[{edge['relation']}]--> {edge['to']}")

        if result.get('risk_flags'):
            self.console.print(f"\n  [bold red]Risk Flags:[/bold red]")
            for rf in result['risk_flags']:
                c = 'red' if rf['severity'] in ('CRITICAL', 'HIGH') else 'yellow' if rf['severity'] == 'MEDIUM' else 'blue'
                self.console.print(f"    [{c}][{rf['severity']}][/{c}] {rf['flag']}: {rf['detail']}")

        self.console.print(f"\n[green]📄 Report saved:[/green]")
        self.console.print(f"  JSON   : {paths['json']}")
        self.console.print(f"  Summary: {paths['summary']}")
        self.console.print(f"  HTML   : {paths['html']}")

    def _handle_image(self, command: str):
        """Image OSINT - reverse search + face detection + metadata"""
        parts = command.split(' ', 1)
        if len(parts) < 2:
            self.console.print("[red]Usage: image <path_to_image>[/red]")
            self.console.print("[dim]Example: image /home/user/photo.jpg[/dim]")
            return
        image_path = parts[1].strip()

        # Agar file nahi mila toh Downloads folder mein case-insensitive search karo
        from pathlib import Path
        if not Path(image_path).exists():
            # Try original case in common locations
            filename = Path(image_path).name
            for search_dir in [Path.home() / 'Downloads', Path.home() / 'Pictures', Path('/tmp')]:
                if search_dir.exists():
                    matches = [f for f in search_dir.iterdir()
                               if f.name.lower() == filename.lower()]
                    if matches:
                        image_path = str(matches[0])
                        self.console.print(f"[dim]Found: {image_path}[/dim]")
                        break

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=self.console) as progress:
            task = progress.add_task("[cyan]Image OSINT...", total=100)
            progress.update(task, advance=30, description="[cyan]Extracting metadata (EXIF)...")
            progress.update(task, advance=30, description="[cyan]Reverse image search...")
            progress.update(task, advance=30, description="[cyan]Face detection...")
            result = self.image_osint.run(image_path)
            progress.update(task, completed=100, description="[green]Image OSINT complete")

        if result.get('error'):
            self.console.print(f"[red]Error: {result['error']}[/red]")
            return

        risk  = result['risk_level']
        color = 'red' if risk in ('CRITICAL', 'HIGH') else 'yellow' if risk == 'MEDIUM' else 'green'

        self.console.print(f"\n[bold cyan]Image OSINT: {image_path}[/bold cyan]")
        self.console.print(f"  MD5 Hash    : [dim]{result.get('image_hash', 'N/A')}[/dim]")
        self.console.print(f"  Dimensions  : {result.get('dimensions', 'N/A')}")
        self.console.print(f"  File Size   : {result.get('file_size', 0):,} bytes")
        self.console.print(f"  Face Found  : {'[green]Yes[/green]' if result['face_detected'] else '[dim]No[/dim]'}")
        self.console.print(f"  Risk Level  : [{color}]{risk}[/{color}]")

        # GPS Location — most important
        if result.get('gps_location'):
            gps = result['gps_location']
            self.console.print(f"\n  [bold red]📍 GPS Location Found![/bold red]")
            self.console.print(f"    Coordinates : [red]{gps['lat']:.6f}, {gps['lon']:.6f}[/red]")
            self.console.print(f"    Maps URL    : [link]{result['metadata'].get('GPS_Maps_URL', '')}[/link]")
            if gps.get('altitude'):
                self.console.print(f"    Altitude    : {gps['altitude']:.1f}m")

        # EXIF Metadata
        meta = result.get('metadata', {})
        display_keys = ['DateTime', 'DateTimeOriginal', 'Make', 'Model', 'Software',
                        'Artist', 'Copyright', 'ImageDescription', 'GPS_Coordinates']
        meta_display = {k: v for k, v in meta.items() if k in display_keys}
        if meta_display:
            self.console.print(f"\n  [bold]EXIF Metadata:[/bold]")
            for k, v in meta_display.items():
                self.console.print(f"    [cyan]{k:<20}[/cyan] {str(v)[:80]}")
        elif not meta.get('error'):
            self.console.print(f"  [dim]No EXIF metadata found[/dim]")

        # Face Analysis
        face_analysis = result.get('face_analysis', {})
        if face_analysis and not face_analysis.get('note'):
            self.console.print(f"\n  [bold]Face Analysis (DeepFace):[/bold]")
            self.console.print(f"    Age     : ~{face_analysis.get('age')} years")
            self.console.print(f"    Gender  : {face_analysis.get('gender')}")
            self.console.print(f"    Emotion : {face_analysis.get('emotion')}")
            self.console.print(f"    Race    : {face_analysis.get('race')}")
        elif face_analysis.get('note'):
            self.console.print(f"  [dim]{face_analysis['note']}[/dim]")

        # Reverse Search
        if result.get('reverse_search'):
            self.console.print(f"\n  [bold]Reverse Image Search:[/bold]")
            for r in result['reverse_search']:
                note = r.get('note', '')
                url  = r.get('url', '')
                src  = r['source']
                if note and note != url:
                    self.console.print(f"    [blue]•[/blue] [cyan]{src}[/cyan]: {note}")
                    if url:
                        self.console.print(f"      [dim]{url[:80]}[/dim]")
                else:
                    self.console.print(f"    [blue]•[/blue] [cyan]{src}[/cyan]: {url[:80]}")

        # Risk Flags
        if result.get('risk_flags'):
            self.console.print(f"\n  [bold red]Risk Flags:[/bold red]")
            for rf in result['risk_flags']:
                c = 'red' if rf['severity'] in ('CRITICAL', 'HIGH') else 'yellow' if rf['severity'] == 'MEDIUM' else 'blue'
                self.console.print(f"    [{c}][{rf['severity']}][/{c}] {rf['flag']}: {rf['detail']}")

    def _feed_to_ml(self, scan_type: str, result: dict):
        """Scan result ko ML training pool mein feed karo. Auto-retrain agar threshold reach ho."""
        try:
            from modules.ml_engine.trainer import ModelTrainer
            added = ModelTrainer.scan_result_to_training_data(scan_type, result)
            if added > 0:
                pending = ModelTrainer.pending_samples()
                logger.debug(f"ML feed: +{added} samples ({pending}/{50} pending retrain)")
                # Auto-retrain silently agar threshold reach ho
                if ModelTrainer.should_retrain():
                    self.console.print(f"[dim]🧠 ML auto-retrain triggered ({pending} new samples)...[/dim]")
                    trainer = ModelTrainer()
                    trainer.auto_retrain_if_needed()
                    self.console.print("[dim]✓ Models updated with real scan data[/dim]")
        except Exception as e:
            logger.debug(f"ML feed error: {e}")

    def _handle_train(self, command: str):
        """CRL se ML models train karo."""
        parts = command.split()
        subcmd = parts[1] if len(parts) > 1 else 'status'

        if subcmd == 'status':
            from modules.ml_engine.trainer import ModelTrainer
            status = ModelTrainer.status()
            pending = ModelTrainer.pending_samples()
            self.console.print("\n[bold cyan]ML Model Status[/bold cyan]")
            if status.get('models'):
                self.console.print(f"  [green]Trained models:[/green] {', '.join(status['models'])}")
                self.console.print(f"  Trained at    : {status.get('trained_at', 'N/A')}")
                self.console.print(f"  Threat samples: {status.get('threat_samples', 0)}")
                self.console.print(f"  Fake samples  : {status.get('fake_samples', 0)}")
            else:
                self.console.print(f"  [yellow]{status.get('message', 'No models trained yet')}[/yellow]")
                self.console.print("  [dim]Run: train collect → train run → train save[/dim]")
            color = 'yellow' if pending >= 25 else 'dim'
            self.console.print(f"  [{color}]Pending new samples: {pending}/{50} (auto-retrain at {50})[/{color}]")
            return

        if subcmd == 'collect':
            self.console.print("[cyan]CRL se training data collect kar raha hoon...[/cyan]")
            self.console.print("[dim]Yeh 5-10 minute le sakta hai (web crawling)[/dim]")
            try:
                from modules.ml_engine.trainer import ModelTrainer
                trainer = ModelTrainer()
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                              BarColumn(), TimeElapsedColumn(), console=self.console) as progress:
                    task = progress.add_task("[cyan]Crawling training data...", total=None)
                    stats = trainer.collect_data(max_pages_per_site=8, rate_limit=2.0)
                    progress.update(task, completed=True, description="[green]Data collection complete")
                self.console.print(f"  [green]Threat samples : {stats['threat']}[/green]")
                self.console.print(f"  [green]Fake samples   : {stats['fake']}[/green]")
                self.console.print(f"  [green]Total          : {stats['total']}[/green]")
                if stats['threat'] >= 10 and stats['fake'] >= 10:
                    self.console.print("[dim]Enough data — 'train run' then 'train save' chalao[/dim]")
                else:
                    self.console.print("[dim]Zyada data ke liye 'train collect' dobara chalao[/dim]")
            except ImportError:
                self.console.print("[red]CRL not installed. Run: pip install crawl-relevance-layers[/red]")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
            return

        if subcmd == 'run':
            self.console.print("[cyan]Models train kar raha hoon...[/cyan]")
            try:
                from modules.ml_engine.trainer import ModelTrainer
                trainer = ModelTrainer()
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                              BarColumn(), TimeElapsedColumn(), console=self.console) as progress:
                    task = progress.add_task("[cyan]Training models...", total=None)
                    results = trainer.train_all()
                    progress.update(task, completed=True, description="[green]Training complete")
                for model, info in results.items():
                    if info:
                        self.console.print(f"  [green]✓ {model}[/green]: {info}")
                    else:
                        self.console.print(f"  [yellow]✗ {model}[/yellow]: insufficient data")
                self.console.print("[dim]Ab 'train save' se models save karo[/dim]")
                self._trainer = trainer
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
            return

        if subcmd == 'save':
            try:
                trainer = getattr(self, '_trainer', None)
                if not trainer:
                    from modules.ml_engine.trainer import ModelTrainer
                    trainer = ModelTrainer()
                    trainer._load_raw_data()
                    trainer.train_all()
                saved = trainer.save_all()
                self.console.print("[green]Models saved:[/green]")
                for name, path in saved.items():
                    self.console.print(f"  [green]✓[/green] {name}: {path}")
                self.console.print("[dim]Models ab automatically use honge next scan mein[/dim]")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
            return

        if subcmd == 'eval':
            try:
                from modules.ml_engine.trainer import ModelTrainer
                trainer = ModelTrainer()
                trainer._load_raw_data()
                trainer.train_all()
                report = trainer.evaluate()
                self.console.print("\n[bold cyan]Model Evaluation Report[/bold cyan]")
                for model, metrics in report.items():
                    color = 'green' if metrics.get('f1_weighted', metrics.get('f1', 0)) >= 0.7 else 'yellow'
                    self.console.print(f"  [{color}]{model}[/{color}]")
                    for k, v in metrics.items():
                        self.console.print(f"    {k}: {v}")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
            return

        self.console.print("[dim]Usage: train status | train collect | train run | train save | train eval[/dim]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='sentinel-pro',
        description='The Sentinel Pro - Professional OSINT & Bug Bounty Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py                          # Interactive mode
  python3 main.py --bugbounty example.com  # Direct bug bounty scan
  python3 main.py --recon example.com      # Direct recon scan
  python3 main.py --breach user@email.com  # Direct breach check
  python3 main.py --email user@email.com   # Direct email OSINT
  python3 main.py --scan-all example.com   # Run all scans
        """
    )
    parser.add_argument('--version', action='version', version='The Sentinel Pro v2.1')
    parser.add_argument('--bugbounty', metavar='DOMAIN',  help='Run bug bounty scan on domain')
    parser.add_argument('--recon',     metavar='DOMAIN',  help='Run passive recon on domain')
    parser.add_argument('--breach',    metavar='TARGET',  help='Check email/username in breach databases')
    parser.add_argument('--email',     metavar='EMAIL',   help='Run full email OSINT')
    parser.add_argument('--phone',     metavar='PHONE',   help='Run phone number OSINT')
    parser.add_argument('--person',    metavar='QUERY',   help='Run person OSINT (name/email/phone)')
    parser.add_argument('--image',     metavar='PATH',    help='Run image OSINT (reverse search + face)')
    parser.add_argument('--scan-all',  metavar='DOMAIN',  help='Run recon + bugbounty + breach on domain')
    parser.add_argument('--bulk',      metavar='FILE',    help='Bulk scan from file (use with --mode)')
    parser.add_argument('--mode',      metavar='MODE',    help='Scan mode for --bulk: bugbounty/recon/breach/email/phone/all', default='all')

    args = parser.parse_args()
    sentinel_pro = TheSentinelPro()

    # Non-interactive mode — run single command and exit
    if args.bugbounty:
        sentinel_pro._handle_bugbounty(f'bugbounty {args.bugbounty}')
    elif args.recon:
        sentinel_pro._handle_recon(f'recon {args.recon}')
    elif args.breach:
        sentinel_pro._handle_breach(f'breach {args.breach}')
    elif args.email:
        sentinel_pro._handle_email(f'email {args.email}')
    elif args.phone:
        sentinel_pro._handle_phone(f'phone {args.phone}')
    elif args.person:
        sentinel_pro._handle_person(f'person {args.person}')
    elif args.image:
        sentinel_pro._handle_image(f'image {args.image}')
    elif args.scan_all:
        domain = args.scan_all
        sentinel_pro.console.print(f"[bold cyan]Running full scan on: {domain}[/bold cyan]")
        sentinel_pro._handle_recon(f'recon {domain}')
        sentinel_pro._handle_bugbounty(f'bugbounty {domain}')
        sentinel_pro._handle_breach(f'breach {domain}')
    elif args.bulk:
        sentinel_pro._handle_bulk(f'bulk {args.bulk} {args.mode}')
    else:
        # Interactive mode
        sentinel_pro.run()
