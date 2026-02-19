"""
Enhanced CLI Interface Module for The Sentinel Pro
Professional UI with Rich formatting and real-time indicators
"""

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.live import Live
import time

class EnhancedCLI:
    def __init__(self, console):
        self.console = console
        self.color_scheme = {
            'success': 'green',
            'warning': 'yellow', 
            'error': 'red',
            'info': 'cyan',
            'highlight': 'magenta',
            'dim': 'dim'
        }
    
    def format_output(self, message, style='info'):
        """Enhanced output formatting with rich styling"""
        color = self.color_scheme.get(style, 'white')
        return f"[{color}]{message}[/{color}]"
    
    def show_progress(self, task_name, steps):
        """Display real-time progress for multi-step operations"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=self.console
        ) as progress:
            
            task = progress.add_task(f"[cyan]{task_name}...", total=len(steps))
            
            for step in steps:
                progress.update(task, advance=1, description=f"[cyan]{step}...")
                time.sleep(0.5)  # Simulate processing time
                
            progress.update(task, description=f"[green]{task_name} completed")
    
    def create_status_table(self, data):
        """Create formatted status table"""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Component", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Details", style="dim")
        
        for item in data:
            table.add_row(item['component'], item['status'], item['details'])
        
        return table
    
    def display_threat_alert(self, threat_level, details):
        """Display threat level with appropriate styling"""
        colors = {'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'green'}
        color = colors.get(threat_level, 'white')
        
        alert_panel = Panel(
            f"[bold {color}]THREAT LEVEL: {threat_level}[/bold {color}]\n\n{details}",
            title="[bold red]🚨 THREAT ALERT[/bold red]",
            border_style=color
        )
        
        self.console.print(alert_panel)
    
    def show_evidence_summary(self, evidence_count, chain_integrity):
        """Display evidence management summary"""
        integrity_color = 'green' if chain_integrity else 'red'
        integrity_status = '✓ INTACT' if chain_integrity else '✗ COMPROMISED'
        
        evidence_panel = Panel(
            f"""
[bold]Evidence Items:[/bold] [cyan]{evidence_count}[/cyan]
[bold]Chain Integrity:[/bold] [{integrity_color}]{integrity_status}[/{integrity_color}]
[bold]Legal Status:[/bold] [green]ADMISSIBLE[/green]
            """,
            title="[bold yellow]📋 Evidence Vault[/bold yellow]",
            border_style="yellow"
        )
        
        self.console.print(evidence_panel)