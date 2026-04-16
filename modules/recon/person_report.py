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

        # ML Engine Results
        nlp = result.get('ml_nlp', {})
        if nlp:
            lines += ["", "ML NLP ANALYSIS:"]
            lines.append(f"  Risk Level       : {nlp.get('risk_level','LOW')}")
            mt = nlp.get('ml_threat', {})
            if mt.get('label'):
                lines.append(f"  ThreatClassifier : {mt['label']} ({mt.get('confidence',0):.0%} confidence)")
            if nlp.get('professions'):
                lines.append(f"  Professions      : {', '.join(p['profession'] for p in nlp['professions'][:3])}")
            if nlp.get('interests'):
                lines.append(f"  Interests        : {', '.join(i['interest'] for i in nlp['interests'][:5])}")
            if nlp.get('personality'):
                lines.append(f"  Personality      : {', '.join(p['trait'] for p in nlp['personality'][:3])}")
            if nlp.get('languages', {}).get('likely_language'):
                lines.append(f"  Language         : {nlp['languages']['likely_language']}")
            ws = nlp.get('writing_style', {})
            if ws.get('style_label'):
                lines.append(f"  Writing Style    : {ws['style_label']} | formality: {ws.get('formality_score',0):.0%}")

        fake_scores = result.get('ml_fake_scores', [])
        if fake_scores:
            lines += ["", f"ML FAKE DETECTION (avg: {result.get('ml_fake_avg',0):.0%}):"]
            for s in fake_scores:
                flag = 'FAKE' if s['is_fake'] else 'REAL'
                lines.append(f"  [{flag}] {s['platform']:12} @{s['username']:20} {s['fake_probability']:.0%}")

        clusters = result.get('ml_username_clusters', {})
        if clusters and clusters.get('total_clusters', 0) > 0:
            lines += ["", f"ML USERNAME CLUSTERS ({clusters['total_clusters']}):"]
            for cl in clusters.get('clusters', []):
                lines.append(f"  [{cl['confidence']:.0%}] {', '.join(cl['usernames'])} -> {cl['canonical']}")

        identity = result.get('ml_identity', {})
        if identity and identity.get('evidence_count', 0) > 0:
            lines += ["", "ML IDENTITY SCORE:"]
            lines.append(f"  Label      : {identity.get('label','N/A')}")
            lines.append(f"  Confidence : {identity.get('confidence_pct',0)}%")
            lines.append(f"  Evidence   : {identity.get('evidence_count',0)} pieces")
            for ev in identity.get('strongest_evidence', [])[:3]:
                lines.append(f"  - {ev.get('type','')} : {ev.get('details','')}")

        return '\n'.join(lines)

    def _build_ml_html(self, result: dict) -> str:
        html = ''

        # NLP
        nlp = result.get('ml_nlp', {})
        if nlp:
            mt = nlp.get('ml_threat', {})
            risk_c = {'CRITICAL':'#dc2626','HIGH':'#ea580c','MEDIUM':'#d97706','LOW':'#16a34a'}.get(nlp.get('risk_level','LOW'),'#6b7280')
            html += f'<h3 style="color:#7dd3fc">NLP Analysis</h3>'
            html += f'<table><tr><th>Field</th><th>Value</th></tr>'
            html += f'<tr><td>Risk Level</td><td style="color:{risk_c}">{nlp.get("risk_level","LOW")}</td></tr>'
            if mt.get('label'):
                tc = '#dc2626' if mt['label'] in ('CRITICAL','HIGH') else '#d97706'
                html += f'<tr><td>ThreatClassifier</td><td style="color:{tc}">{mt["label"]} ({mt.get("confidence",0):.0%})</td></tr>'
            if nlp.get('professions'):
                html += f'<tr><td>Professions</td><td>{", ".join(p["profession"] for p in nlp["professions"][:3])}</td></tr>'
            if nlp.get('interests'):
                html += f'<tr><td>Interests</td><td>{", ".join(i["interest"] for i in nlp["interests"][:5])}</td></tr>'
            if nlp.get('personality'):
                html += f'<tr><td>Personality</td><td>{", ".join(p["trait"] for p in nlp["personality"][:3])}</td></tr>'
            if nlp.get('languages', {}).get('likely_language'):
                html += f'<tr><td>Language</td><td>{nlp["languages"]["likely_language"]}</td></tr>'
            ws = nlp.get('writing_style', {})
            if ws.get('style_label'):
                html += f'<tr><td>Writing Style</td><td>{ws["style_label"]} | formality: {ws.get("formality_score",0):.0%} | vocab: {ws.get("vocabulary_richness",0):.0%}</td></tr>'
            html += '</table>'

            if nlp.get('osint_flags'):
                html += '<h4>NLP OSINT Flags</h4><ul>'
                for flag in nlp['osint_flags'][:5]:
                    fc = '#dc2626' if flag['severity'] in ('CRITICAL','HIGH') else '#d97706'
                    html += f'<li style="color:{fc}">[{flag["severity"]}] {flag["flag"]}: {flag["detail"]}</li>'
                html += '</ul>'

        # Fake Detection
        fake_scores = result.get('ml_fake_scores', [])
        if fake_scores:
            avg = result.get('ml_fake_avg', 0)
            avg_c = '#dc2626' if avg >= 0.6 else '#d97706' if avg >= 0.4 else '#16a34a'
            html += f'<h3 style="color:#7dd3fc">🤖 Fake Profile Detection (avg: <span style="color:{avg_c}">{avg:.0%}</span>)</h3>'
            html += '<table><tr><th>Platform</th><th>Username</th><th>Fake Score</th><th>Verdict</th></tr>'
            for s in fake_scores:
                sc = '#dc2626' if s['fake_probability'] >= 0.6 else '#d97706' if s['fake_probability'] >= 0.4 else '#16a34a'
                verdict = '🔴 FAKE' if s['is_fake'] else '🟢 REAL'
                html += f'<tr><td>{s["platform"]}</td><td>@{s["username"]}</td><td style="color:{sc}">{s["fake_probability"]:.0%}</td><td>{verdict}</td></tr>'
            html += '</table>'

        # Username Clusters
        clusters = result.get('ml_username_clusters', {})
        if clusters and clusters.get('total_clusters', 0) > 0:
            html += f'<h3 style="color:#7dd3fc">🔗 Username Clusters ({clusters["total_clusters"]})</h3>'
            html += '<table><tr><th>Usernames</th><th>Canonical</th><th>Confidence</th><th>Reason</th></tr>'
            for cl in clusters.get('clusters', []):
                html += f'<tr><td>{", ".join(cl["usernames"])}</td><td><strong>{cl["canonical"]}</strong></td><td>{cl["confidence"]:.0%}</td><td>{cl.get("reason","")}</td></tr>'
            html += '</table>'

        # Identity Score
        identity = result.get('ml_identity', {})
        if identity and identity.get('evidence_count', 0) > 0:
            ic = '#dc2626' if identity.get('confidence',0) >= 0.75 else '#d97706' if identity.get('confidence',0) >= 0.5 else '#16a34a'
            html += f'<h3 style="color:#7dd3fc">🧬 Identity Score</h3>'
            html += f'<p>Label: <strong style="color:{ic}">{identity.get("label","N/A")}</strong> | Confidence: {identity.get("confidence_pct",0)}% | Evidence: {identity.get("evidence_count",0)} pieces</p>'
            if identity.get('strongest_evidence'):
                html += '<ul>'
                for ev in identity['strongest_evidence'][:3]:
                    html += f'<li><strong>{ev.get("type","")}</strong>: {ev.get("details","")}</li>'
                html += '</ul>'

        return html if html else '<p style="color:#6b7280">No ML analysis available (insufficient bio data)</p>'

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

<h2>🧠 ML Engine Analysis</h2>
{self._build_ml_html(result)}

</body></html>"""
