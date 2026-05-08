#!/usr/bin/env python3
"""
Circular Import Detector - Find circular dependency chains
"""

import ast
import sys
from pathlib import Path
from collections import defaultdict
import json

class CircularDetector:
    def __init__(self, root_dir):
        self.root = Path(root_dir).resolve()
        self.graph = defaultdict(set)
        self.cycles = []
        
    def build_graph(self):
        """Build import dependency graph"""
        print(f"🔍 Building import graph from {self.root}")
        
        for py_file in self.root.rglob('*.py'):
            if self._should_skip(py_file):
                continue
            
            module = self._file_to_module(py_file)
            imports = self._extract_imports(py_file)
            
            for imp in imports:
                self.graph[module].add(imp)
        
        print(f"📦 Graph built: {len(self.graph)} modules, {sum(len(v) for v in self.graph.values())} edges\n")
    
    def _should_skip(self, path):
        skip = {'__pycache__', '.git', 'venv', 'env', 'build', 'dist'}
        return any(s in path.parts for s in skip)
    
    def _file_to_module(self, filepath):
        """Convert file path to module name"""
        rel = filepath.relative_to(self.root)
        module = str(rel.with_suffix('')).replace('/', '.')
        if module.endswith('.__init__'):
            module = module[:-9]
        return module
    
    def _extract_imports(self, filepath):
        """Extract all imports from a file"""
        imports = set()
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module)
        except:
            pass
        
        return imports
    
    def detect_cycles(self):
        """Detect circular import chains using DFS"""
        print("🔄 Detecting circular imports...")
        
        visited = set()
        rec_stack = set()
        
        def dfs(node, path):
            if node in rec_stack:
                # Found cycle
                cycle_start = path.index(node)
                cycle = path[cycle_start:] + [node]
                self.cycles.append(cycle)
                return True
            
            if node in visited:
                return False
            
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in self.graph.get(node, []):
                # Only check local modules
                if neighbor.startswith(('modules', 'sentinel_brain', 'sentinel_proxy', 'sentinel_intel')):
                    dfs(neighbor, path[:])
            
            rec_stack.remove(node)
            return False
        
        for module in self.graph:
            if module not in visited:
                dfs(module, [])
        
        # Deduplicate cycles
        unique_cycles = []
        seen = set()
        for cycle in self.cycles:
            # Normalize cycle (start from smallest element)
            normalized = tuple(sorted(cycle))
            if normalized not in seen:
                seen.add(normalized)
                unique_cycles.append(cycle)
        
        self.cycles = unique_cycles
        return self.cycles
    
    def report(self):
        """Generate report"""
        print("\n" + "="*60)
        print("🔄 CIRCULAR IMPORT DETECTION REPORT")
        print("="*60)
        print(f"Total Modules: {len(self.graph)}")
        print(f"Total Import Edges: {sum(len(v) for v in self.graph.values())}")
        print(f"Circular Chains Found: {len(self.cycles)}")
        print("="*60)
        
        if self.cycles:
            print("\n🔴 CIRCULAR IMPORT CHAINS:\n")
            for i, cycle in enumerate(self.cycles, 1):
                print(f"  Chain #{i}:")
                for j, module in enumerate(cycle):
                    if j < len(cycle) - 1:
                        print(f"    {module}")
                        print(f"      ↓")
                    else:
                        print(f"    {module} (back to {cycle[0]})")
                print()
        else:
            print("\n✅ No circular imports detected!")
        
        return {
            'total_modules': len(self.graph),
            'total_edges': sum(len(v) for v in self.graph.values()),
            'cycles_found': len(self.cycles),
            'cycles': [
                {'chain': cycle, 'length': len(cycle)}
                for cycle in self.cycles
            ]
        }

if __name__ == '__main__':
    root = sys.argv[1] if len(sys.argv) > 1 else '/home/kali/osints'
    
    detector = CircularDetector(root)
    detector.build_graph()
    detector.detect_cycles()
    result = detector.report()
    
    # Save to JSON
    output_file = Path(root) / 'circular_imports_report.json'
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n✅ Report saved: {output_file}")
    
    # Exit code based on cycles found
    sys.exit(1 if result['cycles_found'] > 0 else 0)
