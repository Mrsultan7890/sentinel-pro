"""
Sentinel Intel Bridge - Launch Maltego-style intelligence platform
"""

import subprocess
import sys
from pathlib import Path

def launch_sentinel_intel():
    """Launch Sentinel Intel GUI"""
    base_dir = Path(__file__).parent.parent
    intel_main = base_dir / 'sentinel_intel' / 'main.py'
    
    if not intel_main.exists():
        return {
            'success': False,
            'error': 'Sentinel Intel not found. Run setup first.'
        }
    
    # Use same venv as Sentinel Pro
    venv_python = base_dir / 'venv' / 'bin' / 'python3'
    python_cmd = str(venv_python) if venv_python.exists() else sys.executable
    
    try:
        # Launch in background
        subprocess.Popen(
            [python_cmd, str(intel_main)],
            cwd=str(base_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        return {
            'success': True,
            'message': 'Sentinel Intel launched'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }
