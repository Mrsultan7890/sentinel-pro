#!/usr/bin/env python3
"""
Test script to verify prompt stability with readline arrow keys
"""
import readline
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Setup history
readline.add_history("bugbounty example.com")
readline.add_history("recon target.com")
readline.add_history("breach user@test.com")
readline.add_history("semantic")
readline.add_history("profile list")

def create_status_panel():
    """Create status panel like Sentinel"""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Status", style="dim")
    table.add_column("Value", style="bold")
    
    table.add_row("Evidence Items:", "[yellow]5[/yellow]")
    table.add_row("Tor Routing:", "[green]🧅 TOR ON[/green]")
    table.add_row("Scan Depth:", "[cyan]⚖ NORMAL[/cyan]")
    
    return Panel(table, title="[bold]System Status[/bold]", border_style="dim")

print("\n" + "="*70)
print("  SENTINEL PRO - PROMPT STABILITY TEST")
print("="*70)
print("\nInstructions:")
print("  1. Press ↑ (up arrow) to see previous commands")
print("  2. Press ↓ (down arrow) to navigate forward")
print("  3. Type 'exit' to quit")
print("  4. Press Ctrl+D to exit")
print("\nHistory contains:")
for i in range(1, min(6, readline.get_current_history_length() + 1)):
    cmd = readline.get_history_item(i)
    print(f"  [{i}] {cmd}")
print("\n" + "="*70 + "\n")

# Main loop
command_count = 0
while True:
    try:
        # Print status panel
        status_panel = create_status_panel()
        console.print(status_panel)
        
        # Add spacing (this prevents prompt overwrite)
        console.print()
        
        # Get input with readline support
        raw_command = input("\033[1;34msentinel-pro>\033[0m ").strip()
        
        if not raw_command:
            continue
            
        if raw_command.lower() in ['exit', 'quit', 'q']:
            console.print("[yellow]Exiting test...[/yellow]")
            break
        
        # Echo command
        command_count += 1
        console.print(f"[green]✓[/green] Command #{command_count}: [cyan]{raw_command}[/cyan]")
        console.print()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted (Ctrl+C)[/yellow]")
        break
    except EOFError:
        console.print("\n[yellow]EOF detected (Ctrl+D)[/yellow]")
        break

print("\n" + "="*70)
print(f"  Test completed! Total commands entered: {command_count}")
print("="*70 + "\n")
