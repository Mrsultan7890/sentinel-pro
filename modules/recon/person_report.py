"""
Person OSINT Report Generator
"""

import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class PersonReport:

    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(self, query: str, person_result: dict, graph: dict = None) -> dict:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = query.replace('@', '_at_').replace('.', '_').replace(' ', '_').replace('+', '')[:40]
        base = self.output_dir / f"person_{safe_name}_{timestamp}"

        paths = {}

        # JSON
        full_data = {'person': person_result, 'graph': graph}
        json_path = Path(str(base) + '.json')
        json_path.write_text(json.dumps(full_data, indent=2, ensure_ascii=False), encoding='utf-8')
        paths['json'] = str(json_path)

        # Summary text
        summary_path = Path(str(base) + '_summary.txt')
        summary_path.write_text(self._build_summary(query, person_result, graph), encoding='utf-8')
        paths['summary'] = str(summary_path)

        # HTML
        html_path = Path(str(base) + '.html')
        html_path.write_text(self._build_html(query, person_result, graph), encoding='utf-8')
        paths['html'] = str(html_path)

        return paths

    def _build_summary(self, query: str, result: dict, graph: dict) -> str:
        lines = [
            f"PERSON OSINT REPORT",
            f"Query      : {query}",
            f"Type       : {result.get('query_type', 'unknown')}",
            f"Risk Level : {result.get('risk_level', 'UNKNOWN')}",
            f"Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"SOCIAL PROFILES FOUND: {len(result.get('social_profiles', []))}",
        ]
        for p in result.get('social_profiles', []):
            lines.append(f"  [{p['platform'].upper()}] @{p['username']} - {p['url']}")

        lines += ["", f"EMAILS FOUND: {len(result.get('emails_found', []))}"]
        for e in result.get('emails_found', []):
            lines.append(f"  {e}")

        lines += ["", f"PHONES FOUND: {len(result.get('phones_found', []))}"]
        for p in result.get('phones_found', []):
            lines.append(f"  {p}")

        lines += ["", f"ADDRESSES FOUND: {len(result.get('addresses', []))}"]
        for a in result.get('addresses', []):
            lines.append(f"  {a}")

        if graph:
            summary = graph.get('summary', {})
            lines += [
                "",
                "RELATION GRAPH:",
                f"  Nodes      : {summary.get('total_nodes', 0)}",
                f"  Relations  : {summary.get('total_edges', 0)}",
                f"  Confidence : {summary.get('confidence_score', 0)}%",
            ]

        lines += ["", "RISK FLAGS:"]
        for flag in result.get('risk_flags', []):
            lines.append(f"  [{flag['severity']}] {flag['flag']}: {flag['detail']}")

        return '\n'.join(lines)

    def _build_html(self, query: str, result: dict, graph: dict) -> str:
        risk = result.get('risk_level', 'LOW')
        risk_color = {'CRITICAL': '#dc2626', 'HIGH': '#ea580c', 'MEDIUM': '#d97706', 'LOW': '#16a34a'}.get(risk, '#6b7280')

        profiles_html = ''
        for p in result.get('social_profiles', []):
            profiles_html += f'<tr><td>{p["platform"].upper()}</td><td>@{p["username"]}</td><td><a href="{p["url"]}" target="_blank">{p["url"]}</a></td></tr>'

        relations_html = ''
        if graph:
            for edge in graph.get('edges', []):
                conf = int(edge.get('confidence', 0) * 100)
                relations_html += f'<tr><td>{edge["from"]}</td><td>{edge["relation"]}</td><td>{edge["to"]}</td><td>{conf}%</td></tr>'

        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Person OSINT: {query}</title>
<style>
  body {{ font-family: monospace; background: #0f172a; color: #e2e8f0; padding: 20px; }}
  h1 {{ color: #38bdf8; }} h2 {{ color: #7dd3fc; border-bottom: 1px solid #334155; padding-bottom: 5px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
  th {{ background: #1e293b; color: #94a3b8; padding: 8px; text-align: left; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #1e293b; }}
  .risk {{ color: {risk_color}; font-weight: bold; font-size: 1.2em; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>🔍 Person OSINT Report</h1>
<p>Query: <strong>{query}</strong> | Type: {result.get('query_type')} | Risk: <span class="risk">{risk}</span></p>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<h2>Social Profiles ({len(result.get('social_profiles', []))} found)</h2>
<table><tr><th>Platform</th><th>Username</th><th>URL</th></tr>{profiles_html}</table>

<h2>Emails Found</h2>
<ul>{''.join(f'<li>{e}</li>' for e in result.get('emails_found', []))}</ul>

<h2>Phones Found</h2>
<ul>{''.join(f'<li>{p}</li>' for p in result.get('phones_found', []))}</ul>

<h2>Addresses Found</h2>
<ul>{''.join(f'<li>{a}</li>' for a in result.get('addresses', []))}</ul>

<h2>Relation Graph ({graph.get('summary', {}).get('total_edges', 0) if graph else 0} relations)</h2>
<table><tr><th>From</th><th>Relation</th><th>To</th><th>Confidence</th></tr>{relations_html}</table>

<h2>Risk Flags</h2>
<ul>{''.join(f'<li>[{f["severity"]}] {f["flag"]}: {f["detail"]}</li>' for f in result.get('risk_flags', []))}</ul>
</body></html>"""
