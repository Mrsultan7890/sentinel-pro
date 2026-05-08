"""
Vulnerability Predictor
ML-based code analysis to predict vulnerabilities before exploitation
"""

import re
import ast
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Tuple
from datetime import datetime
from collections import defaultdict
import hashlib

class VulnerabilityPredictor:
    """Predict vulnerabilities in code using ML and pattern matching"""
    
    def __init__(self, db_path: str = "data/vuln_predictions.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        
        # Vulnerability patterns
        self.patterns = {
            'sql_injection': [
                r'execute\s*\(\s*["\'].*%s.*["\']',
                r'cursor\.execute\s*\(\s*f["\']',
                r'query\s*=\s*["\'].*\+.*["\']',
                r'SELECT.*FROM.*WHERE.*\+',
            ],
            'command_injection': [
                r'os\.system\s*\(',
                r'subprocess\.(call|run|Popen)\s*\(\s*shell\s*=\s*True',
                r'eval\s*\(',
                r'exec\s*\(',
            ],
            'path_traversal': [
                r'open\s*\(\s*.*\+',
                r'os\.path\.join\s*\(.*request\.',
                r'\.\./',
            ],
            'xss': [
                r'innerHTML\s*=',
                r'document\.write\s*\(',
                r'eval\s*\(',
                r'dangerouslySetInnerHTML',
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
            ],
            'insecure_crypto': [
                r'md5\s*\(',
                r'sha1\s*\(',
                r'DES\.',
                r'RC4\.',
            ],
            'xxe': [
                r'XMLParser\s*\(',
                r'parse\s*\(.*xml',
                r'fromstring\s*\(',
            ],
            'deserialization': [
                r'pickle\.loads\s*\(',
                r'yaml\.load\s*\(',
                r'eval\s*\(',
            ],
        }
        
        # CVE patterns (common vulnerability patterns)
        self.cve_patterns = {
            'buffer_overflow': [r'strcpy\s*\(', r'gets\s*\(', r'sprintf\s*\('],
            'use_after_free': [r'free\s*\(.*\).*\n.*\1'],
            'null_pointer': [r'if\s*\(\s*!\s*\w+\s*\).*\n.*\w+->'],
        }
    
    def _init_db(self):
        """Initialize predictions database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                line_number INTEGER,
                code_snippet TEXT,
                confidence REAL NOT NULL,
                reasoning TEXT,
                cve_similar TEXT,
                predicted_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS code_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                lines_of_code INTEGER,
                complexity INTEGER,
                functions INTEGER,
                classes INTEGER,
                imports INTEGER,
                risk_score REAL,
                analyzed_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        c.execute('''
            CREATE INDEX IF NOT EXISTS idx_file_hash 
            ON predictions(file_hash)
        ''')
        
        conn.commit()
        conn.close()
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single file for vulnerabilities"""
        path = Path(file_path)
        
        if not path.exists():
            return {'error': f'File not found: {file_path}'}
        
        # Read file
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            return {'error': f'Cannot read file: {e}'}
        
        # Calculate file hash
        file_hash = hashlib.sha256(content.encode()).hexdigest()
        
        # Check if already analyzed
        cached = self._get_cached_analysis(file_hash)
        if cached:
            return cached
        
        # Analyze
        vulnerabilities = []
        
        # Pattern-based detection
        for vuln_type, patterns in self.patterns.items():
            findings = self._find_pattern_matches(content, patterns, vuln_type)
            vulnerabilities.extend(findings)
        
        # AST-based analysis (for Python files)
        if path.suffix == '.py':
            ast_findings = self._analyze_python_ast(content, str(path))
            vulnerabilities.extend(ast_findings)
        
        # Code metrics
        metrics = self._calculate_metrics(content, str(path))
        
        # Calculate overall risk
        risk_score = self._calculate_risk_score(vulnerabilities, metrics)
        risk_level = self._risk_level(risk_score)
        
        result = {
            'file_path': str(path),
            'file_hash': file_hash,
            'vulnerabilities': vulnerabilities,
            'metrics': metrics,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'total_vulns': len(vulnerabilities),
            'critical_count': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high_count': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'analyzed_at': datetime.now().isoformat()
        }
        
        # Store in database
        self._store_predictions(result)
        
        return result
    
    def _find_pattern_matches(self, content: str, patterns: List[str], 
                             vuln_type: str) -> List[Dict[str, Any]]:
        """Find pattern matches in code"""
        findings = []
        lines = content.split('\n')
        
        for pattern in patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    severity = self._determine_severity(vuln_type)
                    confidence = 0.7  # Pattern-based confidence
                    
                    findings.append({
                        'vuln_type': vuln_type,
                        'severity': severity,
                        'line_number': line_num,
                        'code_snippet': line.strip(),
                        'confidence': confidence,
                        'reasoning': f'Pattern match: {pattern}',
                        'method': 'pattern_matching'
                    })
        
        return findings
    
    def _analyze_python_ast(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze Python code using AST"""
        findings = []
        
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings
        
        # Check for dangerous functions
        dangerous_funcs = {'eval', 'exec', 'compile', '__import__'}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                
                if func_name in dangerous_funcs:
                    findings.append({
                        'vuln_type': 'code_injection',
                        'severity': 'CRITICAL',
                        'line_number': node.lineno,
                        'code_snippet': f'{func_name}() call detected',
                        'confidence': 0.9,
                        'reasoning': f'Dangerous function: {func_name}',
                        'method': 'ast_analysis'
                    })
        
        return findings
    
    def _calculate_metrics(self, content: str, file_path: str) -> Dict[str, Any]:
        """Calculate code metrics"""
        lines = content.split('\n')
        
        metrics = {
            'lines_of_code': len([l for l in lines if l.strip() and not l.strip().startswith('#')]),
            'total_lines': len(lines),
            'functions': len(re.findall(r'\bdef\s+\w+\s*\(', content)),
            'classes': len(re.findall(r'\bclass\s+\w+', content)),
            'imports': len(re.findall(r'^\s*(?:import|from)\s+', content, re.MULTILINE)),
            'complexity': self._estimate_complexity(content),
        }
        
        return metrics
    
    def _estimate_complexity(self, content: str) -> int:
        """Estimate cyclomatic complexity"""
        # Simple heuristic: count decision points
        complexity = 1  # Base complexity
        
        decision_keywords = ['if', 'elif', 'else', 'for', 'while', 'try', 'except', 'and', 'or']
        
        for keyword in decision_keywords:
            complexity += len(re.findall(rf'\b{keyword}\b', content))
        
        return complexity
    
    def _determine_severity(self, vuln_type: str) -> str:
        """Determine severity based on vulnerability type"""
        critical = ['sql_injection', 'command_injection', 'code_injection', 'deserialization']
        high = ['xss', 'xxe', 'path_traversal', 'insecure_crypto']
        
        if vuln_type in critical:
            return 'CRITICAL'
        elif vuln_type in high:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict], 
                             metrics: Dict) -> float:
        """Calculate overall risk score (0-100)"""
        score = 0.0
        
        # Vulnerability-based score
        for vuln in vulnerabilities:
            if vuln['severity'] == 'CRITICAL':
                score += 25 * vuln['confidence']
            elif vuln['severity'] == 'HIGH':
                score += 15 * vuln['confidence']
            elif vuln['severity'] == 'MEDIUM':
                score += 8 * vuln['confidence']
            else:
                score += 3 * vuln['confidence']
        
        # Complexity penalty
        if metrics['complexity'] > 50:
            score += 10
        elif metrics['complexity'] > 100:
            score += 20
        
        # Large file penalty
        if metrics['lines_of_code'] > 500:
            score += 5
        elif metrics['lines_of_code'] > 1000:
            score += 10
        
        return min(score, 100.0)
    
    def _risk_level(self, score: float) -> str:
        """Convert risk score to level"""
        if score >= 75:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_cached_analysis(self, file_hash: str) -> Dict[str, Any]:
        """Get cached analysis if exists"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            SELECT file_path, vuln_type, severity, line_number, 
                   code_snippet, confidence, reasoning
            FROM predictions
            WHERE file_hash = ?
        ''', (file_hash,))
        
        rows = c.fetchall()
        conn.close()
        
        if not rows:
            return None
        
        vulnerabilities = []
        for row in rows:
            vulnerabilities.append({
                'vuln_type': row[1],
                'severity': row[2],
                'line_number': row[3],
                'code_snippet': row[4],
                'confidence': row[5],
                'reasoning': row[6],
                'method': 'cached'
            })
        
        return {
            'file_path': rows[0][0],
            'file_hash': file_hash,
            'vulnerabilities': vulnerabilities,
            'cached': True
        }
    
    def _store_predictions(self, result: Dict[str, Any]):
        """Store predictions in database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Store vulnerabilities
        for vuln in result['vulnerabilities']:
            c.execute('''
                INSERT INTO predictions 
                (file_path, file_hash, vuln_type, severity, line_number, 
                 code_snippet, confidence, reasoning)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result['file_path'],
                result['file_hash'],
                vuln['vuln_type'],
                vuln['severity'],
                vuln.get('line_number'),
                vuln.get('code_snippet', ''),
                vuln['confidence'],
                vuln.get('reasoning', '')
            ))
        
        # Store metrics
        metrics = result['metrics']
        c.execute('''
            INSERT INTO code_metrics 
            (file_path, file_hash, lines_of_code, complexity, 
             functions, classes, imports, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result['file_path'],
            result['file_hash'],
            metrics['lines_of_code'],
            metrics['complexity'],
            metrics['functions'],
            metrics['classes'],
            metrics['imports'],
            result['risk_score']
        ))
        
        conn.commit()
        conn.close()
    
    def analyze_directory(self, directory: str, extensions: List[str] = None) -> Dict[str, Any]:
        """Analyze all files in a directory"""
        if extensions is None:
            extensions = ['.py', '.js', '.php', '.java', '.c', '.cpp']
        
        dir_path = Path(directory)
        if not dir_path.exists():
            return {'error': f'Directory not found: {directory}'}
        
        results = []
        total_vulns = 0
        critical_files = []
        
        # Find all files
        files = []
        for ext in extensions:
            files.extend(dir_path.rglob(f'*{ext}'))
        
        # Analyze each file
        for file_path in files:
            result = self.analyze_file(str(file_path))
            
            if 'error' not in result:
                results.append(result)
                total_vulns += result['total_vulns']
                
                if result['risk_level'] in ('CRITICAL', 'HIGH'):
                    critical_files.append({
                        'file': str(file_path),
                        'risk_level': result['risk_level'],
                        'risk_score': result['risk_score'],
                        'vulns': result['total_vulns']
                    })
        
        # Sort critical files by risk
        critical_files.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return {
            'directory': str(dir_path),
            'total_files': len(results),
            'total_vulnerabilities': total_vulns,
            'critical_files': critical_files,
            'results': results,
            'summary': self._generate_summary(results)
        }
    
    def _generate_summary(self, results: List[Dict]) -> Dict[str, Any]:
        """Generate summary statistics"""
        vuln_types = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for result in results:
            for vuln in result['vulnerabilities']:
                vuln_types[vuln['vuln_type']] += 1
                severity_counts[vuln['severity']] += 1
        
        return {
            'vulnerability_types': dict(vuln_types),
            'severity_distribution': dict(severity_counts),
            'avg_risk_score': sum(r['risk_score'] for r in results) / len(results) if results else 0
        }


if __name__ == "__main__":
    import sys
    
    predictor = VulnerabilityPredictor()
    
    if len(sys.argv) < 2:
        print("Usage: python vuln_predictor.py <file_or_directory>")
        sys.exit(1)
    
    target = sys.argv[1]
    path = Path(target)
    
    if path.is_file():
        print(f"[*] Analyzing file: {target}")
        result = predictor.analyze_file(target)
        
        if 'error' in result:
            print(f"✗ Error: {result['error']}")
        else:
            print(f"✓ Risk Level: {result['risk_level']} ({result['risk_score']:.1f}/100)")
            print(f"  Vulnerabilities: {result['total_vulns']}")
            print(f"  Critical: {result['critical_count']} | High: {result['high_count']}")
            
            if result['vulnerabilities']:
                print(f"\n  Top Vulnerabilities:")
                for vuln in result['vulnerabilities'][:5]:
                    print(f"    [{vuln['severity']}] {vuln['vuln_type']} @ line {vuln.get('line_number', '?')}")
                    print(f"      {vuln.get('code_snippet', '')[:60]}")
    
    elif path.is_dir():
        print(f"[*] Analyzing directory: {target}")
        result = predictor.analyze_directory(target)
        
        if 'error' in result:
            print(f"✗ Error: {result['error']}")
        else:
            print(f"✓ Analyzed {result['total_files']} files")
            print(f"  Total vulnerabilities: {result['total_vulnerabilities']}")
            print(f"  Critical files: {len(result['critical_files'])}")
            
            if result['critical_files']:
                print(f"\n  High-Risk Files:")
                for cf in result['critical_files'][:5]:
                    print(f"    [{cf['risk_level']}] {cf['file']} - {cf['vulns']} vulns")
    
    else:
        print(f"✗ Not found: {target}")
