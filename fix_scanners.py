#!/usr/bin/env python3
"""
Fix all empty pass statements in bug bounty scanners
Replace with proper logging
"""

import os
import re
from pathlib import Path

def fix_file(filepath):
    """Fix empty exception handlers in a file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    
    # Pattern 1: except Exception:\n                pass
    pattern1 = r'(except\s+(?:Exception|.*Error)(?:\s+as\s+\w+)?:\s*)\n(\s+)pass\s*$'
    
    def replace_pass(match):
        except_line = match.group(1)
        indent = match.group(2)
        
        # Extract exception variable if present
        var_match = re.search(r'as\s+(\w+)', except_line)
        exc_var = var_match.group(1) if var_match else 'e'
        
        # If no 'as' clause, add it
        if 'as' not in except_line:
            except_line = except_line.rstrip(':\s') + f' as {exc_var}:'
        
        # Determine context from filepath
        module_name = Path(filepath).stem
        
        return f"{except_line}\n{indent}logger.debug(f\"{module_name} error: {{{exc_var}}}\")"
    
    content = re.sub(pattern1, replace_pass, content, flags=re.MULTILINE)
    
    # Pattern 2: except (Exception1, Exception2):\n                pass
    pattern2 = r'(except\s+\([^)]+\)(?:\s+as\s+\w+)?:\s*)\n(\s+)pass\s*$'
    
    def replace_multi_except(match):
        except_line = match.group(1)
        indent = match.group(2)
        
        var_match = re.search(r'as\s+(\w+)', except_line)
        exc_var = var_match.group(1) if var_match else 'e'
        
        if 'as' not in except_line:
            except_line = except_line.rstrip(':\s') + f' as {exc_var}:'
        
        module_name = Path(filepath).stem
        
        return f"{except_line}\n{indent}logger.debug(f\"{module_name} error: {{{exc_var}}} - {{type({exc_var}).__name__}}\")"
    
    content = re.sub(pattern2, replace_multi_except, content, flags=re.MULTILINE)
    
    # Only write if changed
    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

def main():
    """Fix all Python files in modules/bugbounty/"""
    base_dir = Path('/home/kali/osints/modules/bugbounty')
    
    if not base_dir.exists():
        print(f"Directory not found: {base_dir}")
        return
    
    files_fixed = 0
    
    for py_file in base_dir.glob('*.py'):
        if fix_file(py_file):
            print(f"✓ Fixed: {py_file.name}")
            files_fixed += 1
        else:
            print(f"  Skipped: {py_file.name} (no changes needed)")
    
    print(f"\n{files_fixed} files fixed")

if __name__ == '__main__':
    main()
