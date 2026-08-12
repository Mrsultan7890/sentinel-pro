"""
Sentinel Intel Bridge - Launch Maltego-style intelligence platform
"""

import subprocess
import sys
from pathlib import Path

def launch_sentinel_intel():
    """Launch Sentinel Intel GUI"""
    base_dir = Path(__file__).parent.parent
    intel_dir = base_dir / 'sentinel_intel'

    intel_main_py = intel_dir / 'main.py'
    intel_main_so = list(intel_dir.glob('main*.so'))

    if not intel_main_py.exists() and not intel_main_so:
        return {
            'success': False,
            'error': 'Sentinel Intel not found. Run setup first.'
        }

    venv_python = base_dir / 'venv' / 'bin' / 'python3'
    python_cmd = str(venv_python) if venv_python.exists() else sys.executable

    if intel_main_py.exists():
        cmd = [python_cmd, str(intel_main_py)]
    else:
        cmd = [python_cmd, '-c',
            f'import sys; sys.path.insert(0, "{base_dir}"); '
            f'from sentinel_intel.main import main; main()']

    try:
        subprocess.Popen(
            cmd,
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
