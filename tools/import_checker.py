#!/usr/bin/env python3
"""
Import Checker - Comprehensive import validation for Sentinel Pro
Checks: syntax, missing imports, unused imports, import paths
"""

import ast
import os
import sys
import json
from pathlib import Path
from collections import defaultdict

class ImportChecker:
    BUILTINS = set(dir(__builtins__))
    SKIP_DIRS = {'__pycache__', '.git', 'venv', 'env', 'build', 'dist', '.pytest_cache'}
    
    def __init__(self, root_dir):
        self.root = Path(root_dir).resolve()
        self.errors = defaultdict(list)
        self.warnings = defaultdict(list)
        self.stats = {
            'total_files': 0,
            'total_imports': 0,
            'syntax_errors': 0,
            'missing_imports': 0,
            'unused_imports': 0,
        }
        self.all_modules = self._discover_modules()
    
    def _discover_modules(self):
        """Find all Python modules in project"""
        modules = set()
        for py_file in self.root.rglob('*.py'):
            if self._should_skip(py_file):
                continue
            rel = py_file.relative_to(self.root)
            module = str(rel.with_suffix('')).replace(os.sep, '.')
            modules.add(module)
        return modules
    
    def _should_skip(self, path):
        return any(skip in path.parts for skip in self.SKIP_DIRS)
    
    def check_all(self):
        print(f"🔍 Scanning {self.root}")
        print(f"📦 Found {len(self.all_modules)} modules\n")
        
        for py_file in sorted(self.root.rglob('*.py')):
            if self._should_skip(py_file):
                continue
            self.stats['total_files'] += 1
            self._check_file(py_file)
        
        return self._generate_report()
    
    def _check_file(self, filepath):
        rel_path = str(filepath.relative_to(self.root))
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            tree = ast.parse(content, filename=str(filepath))
            
            imports = self._extract_imports(tree)
            usage = self._extract_usage(tree)
            
            self.stats['total_imports'] += len(imports)
            
            # Check each import
            for imp in imports:
                self._validate_import(imp, filepath, rel_path)
            
            # Check unused imports
            unused = self._find_unused(imports, usage)
            if unused:
                self.stats['unused_imports'] += len(unused)
                self.warnings[rel_path].append({
                    'type': 'unused_import',
                    'imports': list(unused)
                })
        
        except SyntaxError as e:
            self.stats['syntax_errors'] += 1
            self.errors[rel_path].append({
                'type': 'syntax_error',
                'line': e.lineno,
                'message': str(e)
            })
        except Exception as e:
            self.errors[rel_path].append({
                'type': 'parse_error',
                'message': str(e)
            })
    
    def _extract_imports(self, tree):
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append({
                        'type': 'import',
                        'module': alias.name,
                        'name': alias.asname or alias.name.split('.')[0],
                        'line': node.lineno
                    })
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                for alias in node.names:
                    imports.append({
                        'type': 'from',
                        'module': module,
                        'name': alias.asname or alias.name,
                        'imported': alias.name,
                        'line': node.lineno
                    })
        return imports
    
    def _extract_usage(self, tree):
        usage = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                usage.add(node.id)
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    usage.add(node.value.id)
        return usage
    
    def _validate_import(self, imp, filepath, rel_path):
        module = imp['module']
        
        # Skip standard library and builtins
        if module in sys.stdlib_module_names or module.split('.')[0] in sys.stdlib_module_names:
            return
        
        # Check if it's a local module
        if module.startswith(('modules', 'sentinel_brain', 'sentinel_proxy', 'sentinel_intel')):
            module_path = module.replace('.', os.sep) + '.py'
            full_path = self.root / module_path
            
            if not full_path.exists():
                # Check if it's a package
                pkg_path = self.root / module.replace('.', os.sep) / '__init__.py'
                if not pkg_path.exists():
                    self.stats['missing_imports'] += 1
                    self.errors[rel_path].append({
                        'type': 'missing_module',
                        'module': module,
                        'line': imp['line'],
                        'message': f"Local module '{module}' not found"
                    })
    
    def _find_unused(self, imports, usage):
        unused = set()
        for imp in imports:
            name = imp['name']
            # Skip special imports
            if name in ('*', '__all__'):
                continue
            if name not in usage:
                unused.add(f"{name} (line {imp['line']})")
        return unused
    
    def _generate_report(self):
        print("\n" + "="*60)
        print("📊 IMPORT AUDIT SUMMARY")
        print("="*60)
        print(f"Total Files Scanned: {self.stats['total_files']}")
        print(f"Total Imports: {self.stats['total_imports']}")
        print(f"Syntax Errors: {self.stats['syntax_errors']}")
        print(f"Missing Imports: {self.stats['missing_imports']}")
        print(f"Unused Imports: {self.stats['unused_imports']}")
        print("="*60)
        
        if self.errors:
            print(f"\n🔴 ERRORS FOUND: {len(self.errors)} files")
            for file, errs in sorted(self.errors.items())[:10]:
                print(f"\n  {file}:")
                for err in errs[:3]:
                    print(f"    - {err['type']}: {err.get('message', '')}")
        
        if self.warnings:
            print(f"\n🟡 WARNINGS: {len(self.warnings)} files with unused imports")
        
        return {
            'stats': self.stats,
            'errors': dict(self.errors),
            'warnings': dict(self.warnings)
        }

if __name__ == '__main__':
    root = sys.argv[1] if len(sys.argv) > 1 else '/home/kali/osints'
    checker = ImportChecker(root)
    result = checker.check_all()
    
    # Save to JSON
    output_file = Path(root) / 'import_audit_report.json'
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n✅ Report saved: {output_file}")
    
    # Exit code based on errors
    sys.exit(1 if result['stats']['syntax_errors'] > 0 or result['stats']['missing_imports'] > 0 else 0)
