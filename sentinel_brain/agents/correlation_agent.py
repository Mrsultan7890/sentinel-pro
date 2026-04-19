"""
Correlation Agent — Multi-Scan Pattern Detection
=================================================
- Multiple scan results correlate karo
- "Pichle scan se kya naya mila?"
- Cross-target patterns dhundo
- GNN entity graph banao
- Anomaly detection (Isolation Forest)
- DBSCAN clustering

Author: @who_is_the_black_hat
"""

import logging
from datetime import datetime
from sentinel_brain.memory import Memory

logger = logging.getLogger(__name__)

_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


class CorrelationAgent:
    NAME = 'correlation_agent'

    def __init__(self, memory: Memory, sentinel=None):
        self.memory   = memory
        self.sentinel = sentinel
        self._adv_ml  = self._load_adv_ml()

    def _load_adv_ml(self):
        try:
            from sentinel_brain.advanced_ml import AdvancedMLEngine
            return AdvancedMLEngine()
        except Exception:
            return None

    # ── Main Entry ────────────────────────────────────────────────────────────

    def run(self, target: str = None, targets: list = None) -> dict:
        """
        Single target ya multiple targets correlate karo.
        target  = single target diff analysis
        targets = cross-target pattern analysis
        """
        if targets:
            return self._cross_target_analysis(targets)
        return self._single_target_diff(target)

    # ── Single Target: Diff Analysis ─────────────────────────────────────────

    def _single_target_diff(self, target: str) -> dict:
        """Pichle scan se kya naya mila?"""
        logger.info(f"[CorrelationAgent] Diff analysis: {target}")

        # Memory se sab scans lo
        scans    = self.memory.recall_target(target)
        findings = self.memory.recall_findings(target)

        # Findings ko time se sort karo
        new_findings  = []
        seen_titles   = set()

        for f in findings:
            key = f"{f['severity']}:{f['title']}"
            if key not in seen_titles:
                seen_titles.add(key)
                new_findings.append(f)

        # Risk trend
        risk_trend = self._calculate_risk_trend(target)

        # Anomaly detection
        anomalies = self._detect_anomalies(target, findings)

        # GNN entity graph
        graph = self._build_entity_graph(target)

        result = {
            'target':      target,
            'total_scans': len(scans) if isinstance(scans, list) else (len(scans.split('\n')) if scans else 0),
            'findings':    new_findings,
            'risk_trend':  risk_trend,
            'anomalies':   anomalies,
            'entity_graph': graph,
            'summary':     self._build_summary(target, new_findings, risk_trend, anomalies),
        }

        self.memory.remember_decision(
            target, self.NAME, 'correlation',
            'Correlation Analysis', result['summary']
        )
        return result

    # ── Cross-Target Analysis ─────────────────────────────────────────────────

    def _cross_target_analysis(self, targets: list) -> dict:
        """Multiple targets mein common patterns dhundo."""
        logger.info(f"[CorrelationAgent] Cross-target: {targets}")

        all_findings = {}
        for t in targets:
            all_findings[t] = self.memory.recall_findings(t)

        # Common vulnerabilities
        common_vulns = self._find_common_vulns(all_findings)

        # IP clustering
        ip_clusters = self._cluster_ips(targets)

        # Tech stack correlation
        tech_correlation = self._correlate_tech_stacks(targets)

        result = {
            'targets':          targets,
            'common_vulns':     common_vulns,
            'ip_clusters':      ip_clusters,
            'tech_correlation': tech_correlation,
            'high_risk_targets': [
                t for t in targets
                if any(f['severity'] in ('CRITICAL','HIGH')
                       for f in all_findings.get(t, []))
            ],
        }

        summary = (
            f"{len(targets)} targets | "
            f"{len(common_vulns)} common vulns | "
            f"{len(result['high_risk_targets'])} high risk"
        )
        result['summary'] = summary
        result['_agent_summary'] = summary
        return result

    # ── Risk Trend ────────────────────────────────────────────────────────────

    def _calculate_risk_trend(self, target: str) -> dict:
        """Risk level time ke saath kaise change hua."""
        try:
            import sqlite3, config
            conn = sqlite3.connect(str(config.BASE_DIR / 'data' / 'sentinel.db'))
            rows = conn.execute(
                "SELECT risk_level, timestamp FROM scans WHERE target=? ORDER BY timestamp",
                (target,)
            ).fetchall()
            conn.close()

            if not rows:
                return {'trend': 'unknown', 'history': []}

            history = [{'risk': r[0], 'time': r[1]} for r in rows]
            sev_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

            if len(history) >= 2:
                first = sev_map.get(history[0]['risk'], 1)
                last  = sev_map.get(history[-1]['risk'], 1)
                if last > first:
                    trend = 'WORSENING'
                elif last < first:
                    trend = 'IMPROVING'
                else:
                    trend = 'STABLE'
            else:
                trend = 'FIRST_SCAN'

            return {'trend': trend, 'history': history[-5:],
                    'current': history[-1]['risk'] if history else 'UNKNOWN'}
        except Exception as e:
            logger.debug(f"Risk trend error: {e}")
            return {'trend': 'unknown', 'history': []}

    # ── Anomaly Detection ─────────────────────────────────────────────────────

    def _detect_anomalies(self, target: str, findings: list) -> list:
        """Unusual patterns detect karo."""
        anomalies = []

        if not self._adv_ml:
            return anomalies

        try:
            # Findings se features banao
            if len(findings) >= 3:
                features = [
                    [
                        _SEV_ORDER.get(f.get('severity', 'LOW'), 3),
                        len(f.get('title', '')),
                        len(f.get('detail', '')),
                    ]
                    for f in findings
                ]
                result = self._adv_ml.detect_anomalies(features)
                for i, is_anomaly in enumerate(result.get('anomalies', [])):
                    if is_anomaly and i < len(findings):
                        anomalies.append({
                            'finding': findings[i].get('title', ''),
                            'reason':  'Unusual pattern detected by Isolation Forest',
                        })
        except Exception as e:
            logger.debug(f"Anomaly detection error: {e}")

        return anomalies

    # ── Entity Graph ──────────────────────────────────────────────────────────

    def _build_entity_graph(self, target: str) -> dict:
        """GNN entity graph banao — domain→IP→subdomain→email."""
        graph = {'nodes': [], 'edges': []}

        if not self._adv_ml:
            return graph

        try:
            # IOCs from DB
            import sqlite3, config
            conn = sqlite3.connect(str(config.BASE_DIR / 'data' / 'sentinel.db'))
            iocs = conn.execute(
                "SELECT ioc_type, ioc_value FROM iocs WHERE target=?",
                (target,)
            ).fetchall()
            conn.close()

            # Nodes
            graph['nodes'].append({'id': target, 'type': 'domain'})
            for ioc_type, ioc_value in iocs:
                graph['nodes'].append({'id': ioc_value, 'type': ioc_type})
                graph['edges'].append({'from': target, 'to': ioc_value,
                                       'relation': ioc_type})

            # GNN analysis
            if len(graph['nodes']) >= 3:
                gnn_result = self._adv_ml.analyze_entity_graph(
                    graph['nodes'], graph['edges']
                )
                graph['gnn_analysis'] = gnn_result
        except Exception as e:
            logger.debug(f"Entity graph error: {e}")

        return graph

    # ── Common Vulns ──────────────────────────────────────────────────────────

    def _find_common_vulns(self, all_findings: dict) -> list:
        """Multiple targets mein same vulnerability dhundo."""
        from collections import Counter
        vuln_counter = Counter()

        for target, findings in all_findings.items():
            for f in findings:
                vuln_counter[f.get('title', '')] += 1

        return [
            {'vuln': vuln, 'count': count, 'targets': count}
            for vuln, count in vuln_counter.most_common(10)
            if count >= 2
        ]

    def _cluster_ips(self, targets: list) -> list:
        """Same IP range pe targets cluster karo."""
        clusters = {}
        for t in targets:
            try:
                import socket
                ip = socket.gethostbyname(t)
                # /24 subnet
                subnet = '.'.join(ip.split('.')[:3])
                clusters.setdefault(subnet, []).append({'target': t, 'ip': ip})
            except Exception:
                pass
        return [
            {'subnet': f"{k}.0/24", 'targets': v}
            for k, v in clusters.items()
            if len(v) >= 2
        ]

    def _correlate_tech_stacks(self, targets: list) -> list:
        """Same technology use karne wale targets dhundo."""
        tech_map = {}
        for t in targets:
            findings = self.memory.recall_findings(t)
            for f in findings:
                detail = f.get('detail', '').lower()
                for tech in ['wordpress', 'nginx', 'apache', 'php',
                             'cloudflare', 'react', 'django', 'laravel']:
                    if tech in detail:
                        tech_map.setdefault(tech, []).append(t)

        return [
            {'technology': tech, 'targets': list(set(tgts))}
            for tech, tgts in tech_map.items()
            if len(set(tgts)) >= 2
        ]

    # ── Summary ───────────────────────────────────────────────────────────────

    def _build_summary(self, target: str, findings: list,
                       risk_trend: dict, anomalies: list) -> str:
        parts = [
            f"Target: {target}",
            f"Findings: {len(findings)}",
            f"Risk trend: {risk_trend.get('trend', 'unknown')}",
        ]
        if anomalies:
            parts.append(f"Anomalies: {len(anomalies)}")
        critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        if critical:
            parts.append(f"CRITICAL: {critical}")
        return ' | '.join(parts)
