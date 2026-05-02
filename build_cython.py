#!/usr/bin/env python3
"""
Sentinel Pro - Cython Build Script
Compile critical modules to .so files for protection
"""

from setuptools import setup, Extension
from Cython.Build import cythonize
from pathlib import Path
import shutil
import os

# Critical files to compile
CRITICAL_FILES = [
    'modules/license_manager.py',
    'modules/secure_file_manager.py',
    'sentinel_brain/agents/credential_agent.py',
    'config.py',
]

# Compiler directives for maximum protection
COMPILER_DIRECTIVES = {
    'language_level': "3",
    'embedsignature': False,      # Don't embed function signatures
    'boundscheck': False,          # Disable bounds checking (faster)
    'wraparound': False,           # Disable negative indexing
    'cdivision': True,             # C-style division
    'initializedcheck': False,     # Disable initialization checks
}

def build_cython_modules():
    """Compile critical modules with Cython"""
    
    print("="*60)
    print("  SENTINEL PRO - CYTHON BUILD")
    print("="*60)
    
    # Check if files exist
    missing = []
    for file in CRITICAL_FILES:
        if not Path(file).exists():
            missing.append(file)
    
    if missing:
        print(f"\n❌ Missing files:")
        for f in missing:
            print(f"   - {f}")
        return False
    
    print(f"\n📦 Compiling {len(CRITICAL_FILES)} critical modules...\n")
    
    # Compile each file
    for file in CRITICAL_FILES:
        print(f"   Compiling: {file}")
        
        try:
            setup(
                ext_modules=cythonize(
                    file,
                    compiler_directives=COMPILER_DIRECTIVES,
                    build_dir="build"
                ),
                script_args=['build_ext', '--inplace']
            )
            print(f"   ✅ Success: {file}")
        except Exception as e:
            print(f"   ❌ Failed: {file} - {e}")
            return False
    
    print("\n" + "="*60)
    print("  ✅ CYTHON BUILD COMPLETE")
    print("="*60)
    
    # Show compiled files
    print("\n📁 Compiled files (.so):")
    for file in CRITICAL_FILES:
        so_file = file.replace('.py', '.cpython-*.so')
        import glob
        matches = glob.glob(so_file)
        if matches:
            for match in matches:
                size = Path(match).stat().st_size / 1024
                print(f"   {match} ({size:.1f} KB)")
    
    return True

def create_distribution():
    """Create distribution folder with .so files"""
    
    dist_dir = Path('dist_cython')
    
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    
    dist_dir.mkdir()
    
    print(f"\n📦 Creating distribution in {dist_dir}/")
    
    # Copy all files
    for root, dirs, files in os.walk('.'):
        # Skip unwanted directories
        if any(skip in root for skip in ['.git', '__pycache__', 'build', 'dist', '.venv']):
            continue
        
        for file in files:
            src = Path(root) / file
            
            # Skip .py files that have .so versions
            if file.endswith('.py'):
                base = str(src).replace('.py', '')
                if any(Path(f).exists() for f in Path('.').glob(f"{base}.cpython-*.so")):
                    print(f"   Skipping {src} (compiled version exists)")
                    continue
            
            # Copy file
            dst = dist_dir / src
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    
    print(f"\n✅ Distribution created: {dist_dir}/")
    print(f"   Total size: {sum(f.stat().st_size for f in dist_dir.rglob('*') if f.is_file()) / 1024 / 1024:.1f} MB")
    
    return True

if __name__ == "__main__":
    import sys
    
    # Build
    if not build_cython_modules():
        print("\n❌ Build failed!")
        sys.exit(1)
    
    # Create distribution
    if '--dist' in sys.argv:
        create_distribution()
    
    print("\n🎉 Done!")
    print("\nNext steps:")
    print("  1. Test compiled modules: python3 -c 'import modules.license_manager'")
    print("  2. Create distribution: python3 build_cython.py --dist")
    print("  3. Package with PyInstaller: pyinstaller --onefile main.py")
