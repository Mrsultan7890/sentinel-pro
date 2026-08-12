"""
Dark Web Report Builder
Professional reporting for dark web investigations
"""

import json
import os
from datetime import datetime
from pathlib import Path
from modules.report_signature import sign_json, get_html_footer

class DarkWebReport:
    def __init__(self, output_dir='reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def save(self, target, data):
        """Save dark web investigation report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = target.replace('@', '').replace('.', '_').replace('/', '_')
        base_path = self.output_dir / f'darkweb_{safe_target}_{timestamp}'
        
        # Calculate risk
        risk_level = self._calculate_risk(data)
        
        # Build report
        report = {
            'target': target,
            'timestamp': data.get('timestamp'),
            'risk_level': risk_level,
            'summary': self._generate_summary(data),
            'onion_sites': data.get('onion_results', []),
            'encrypted_content': data.get('decrypted_data', []),
            'paste_results': data.get('paste_results', []),
            'forum_mentions': data.get('forum_mentions', []),
            'statistics': self._generate_statistics(data),
            'risk_flags': self._generate_risk_flags(data)
        }
        
        # Save JSON
        json_path = f'{base_path}.json'
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(sign_json(report), f, indent=2, ensure_ascii=False)
        
        # Save summary
        summary_path = f'{base_path}_summary.txt'
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(self._generate_text_summary(report))
        
        # Save HTML
        html_path = self._generate_html(report, base_path)
        
        return {
            'json': json_path,
            'summary': summary_path,
            'html': html_path
        }
    
    def _calculate_risk(self, data):
        """Calculate risk level based on findings"""
        score = 0
        
        onion_results = data.get('onion_results', [])
        paste_results = data.get('paste_results', [])
        forum_mentions = data.get('forum_mentions', [])
        
        # Scoring
        score += len(onion_results) * 10
        score += len(paste_results) * 15
        score += len(forum_mentions) * 20
        
        # Check for sensitive keywords
        sensitive_keywords = ['leak', 'breach', 'hack', 'dump', 'database', 'password', 'credential']
        for result in onion_results:
            content = result.get('content', '').lower()
            for keyword in sensitive_keywords:
                if keyword in content:
                    score += 25
        
        if score >= 100:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_summary(self, data):
        """Generate executive summary"""
        onion_count = len(data.get('onion_results', []))
        paste_count = len(data.get('paste_results', []))
        forum_count = len(data.get('forum_mentions', []))
        encrypted_count = len(data.get('decrypted_data', []))
        
        return [
            f"Found {onion_count} .onion site references",
            f"Discovered {paste_count} paste site mentions",
            f"Identified {forum_count} forum discussions",
            f"Analyzed {encrypted_count} encrypted content samples"
        ]
    
    def _generate_statistics(self, data):
        """Generate statistics"""
        return {
            'total_onion_sites': len(data.get('onion_results', [])),
            'successful_crawls': len([r for r in data.get('onion_results', []) if r.get('status') == 'success']),
            'failed_crawls': len([r for r in data.get('onion_results', []) if 'error' in r.get('status', '')]),
            'paste_sites_found': len(data.get('paste_results', [])),
            'forum_mentions': len(data.get('forum_mentions', [])),
            'encrypted_samples': len(data.get('decrypted_data', []))
        }
    
    def _generate_risk_flags(self, data):
        """Generate risk flags"""
        flags = []
        
        if len(data.get('onion_results', [])) > 5:
            flags.append({
                'severity': 'HIGH',
                'flag': 'High Dark Web Presence',
                'detail': f"Target mentioned in {len(data.get('onion_results', []))} .onion sites"
            })
        
        if len(data.get('paste_results', [])) > 0:
            flags.append({
                'severity': 'CRITICAL',
                'flag': 'Paste Site Exposure',
                'detail': f"Found {len(data.get('paste_results', []))} paste site mentions"
            })
        
        if len(data.get('forum_mentions', [])) > 0:
            flags.append({
                'severity': 'HIGH',
                'flag': 'Forum Discussion',
                'detail': f"Target discussed in {len(data.get('forum_mentions', []))} dark web forums"
            })
        
        sensitive_found = False
        for result in data.get('onion_results', []):
            content = result.get('content', '').lower()
            if any(word in content for word in ['leak', 'breach', 'hack', 'dump']):
                sensitive_found = True
                break
        
        if sensitive_found:
            flags.append({
                'severity': 'CRITICAL',
                'flag': 'Sensitive Content Detected',
                'detail': 'Found references to leaks, breaches, or hacks'
            })
        
        return flags
    
    def _generate_text_summary(self, report):
        """Generate text summary"""
        lines = [
            "=" * 80,
            "DARK WEB INVESTIGATION REPORT",
            "=" * 80,
            f"Target       : {report['target']}",
            f"Timestamp    : {report['timestamp']}",
            f"Risk Level   : {report['risk_level']}",
            "",
            "SUMMARY:",
        ]
        
        for item in report['summary']:
            lines.append(f"  • {item}")
        
        lines.append("")
        lines.append("STATISTICS:")
        for key, value in report['statistics'].items():
            lines.append(f"  {key:<25}: {value}")
        
        if report['risk_flags']:
            lines.append("")
            lines.append("RISK FLAGS:")
            for flag in report['risk_flags']:
                lines.append(f"  [{flag['severity']}] {flag['flag']}")
                lines.append(f"      {flag['detail']}")
        
        lines.append("")
        lines.append("ONION SITES:")
        for i, site in enumerate(report['onion_sites'][:10], 1):
            lines.append(f"  {i}. {site.get('title', 'N/A')}")
            lines.append(f"     URL: {site.get('site', 'N/A')}")
            lines.append(f"     Status: {site.get('status', 'N/A')}")
            lines.append("")
        
        lines.append("=" * 80)
        return '\n'.join(lines)
    
    def _generate_html(self, report, base_path):
        """Generate HTML report"""
        risk_colors = {
            'CRITICAL': '#e74c3c',
            'HIGH': '#e67e22',
            'MEDIUM': '#f39c12',
            'LOW': '#27ae60'
        }
        
        risk_color = risk_colors.get(report['risk_level'], '#888')
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dark Web Investigation - {report['target']}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', sans-serif; padding: 24px; }}
  .header {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 20px; }}
  .header h1 {{ color: #58a6ff; font-size: 22px; }}
  .risk-badge {{ display: inline-block; padding: 6px 16px; border-radius: 20px;
                 background: {risk_color}; color: white; font-weight: bold; font-size: 16px; margin-top: 10px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }}
  .card h3 {{ color: #58a6ff; margin-bottom: 12px; font-size: 15px; }}
  .site {{ background: #0d1117; border-radius: 6px; padding: 12px; margin-bottom: 10px; border-left: 4px solid #8b949e; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #21262d; padding: 8px; text-align: left; }}
  td {{ padding: 8px; border-bottom: 1px solid #21262d; }}
</style>
</head>
<body>
<div class="header">
  <h1>🕵️ Dark Web Investigation</h1>
  <h2>Target: {report['target']}</h2>
  <div class="risk-badge">Risk: {report['risk_level']}</div>
</div>
<div class="card">
  <h3>Summary</h3>
  <ul>{''.join(f'<li>{item}</li>' for item in report['summary'])}</ul>
</div>
{get_html_footer()}
</body>
</html>"""
        
        html_path = f'{base_path}.html'
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return html_path
