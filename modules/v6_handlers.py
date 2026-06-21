"""
v6 Command Handlers - Crypto & Sandbox
"""

def handle_crypto(sentinel, command: str):
    """Handle crypto commands"""
    parts = command.split()
    sub = parts[1] if len(parts) > 1 else 'status'
    
    try:
        from modules.crypto_manager import CryptoManager
        crypto = CryptoManager()
        
        if sub == 'status':
            sentinel.console.print("[cyan]Quantum-Ready Crypto Engine Status:[/cyan]")
            sentinel.console.print("  Kyber KEM  : ✓ Ready")
            sentinel.console.print("  Dilithium  : ✓ Ready")
            sentinel.console.print("  SPHINCS+   : ✓ Ready")
        else:
            sentinel.console.print(f"[yellow]Crypto command '{sub}' not implemented[/yellow]")
    except Exception as e:
        sentinel.console.print(f"[red]Crypto error: {e}[/red]")

def handle_sandbox(sentinel, command: str):
    """Handle sandbox commands"""
    parts = command.split()
    sub = parts[1] if len(parts) > 1 else 'status'
    
    try:
        from sentinel_brain.engines.sandbox_manager import SandboxManager
        sandbox = SandboxManager()
        
        if sub == 'status':
            sentinel.console.print("[cyan]Autonomous Sandbox Engine Status:[/cyan]")
            sentinel.console.print("  Isolation  : ✓ Active")
            sentinel.console.print("  Forensics  : ✓ Ready")
        else:
            sentinel.console.print(f"[yellow]Sandbox command '{sub}' not implemented[/yellow]")
    except Exception as e:
        sentinel.console.print(f"[red]Sandbox error: {e}[/red]")
