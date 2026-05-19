"""
Sentinel ML Engines — Advanced Algorithms
GNN + Isolation Forest + DBSCAN + LightGBM + Genetic Algorithm
Author: @who_is_the_black_hat
"""

import json
import logging
import random
import numpy as np
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

# ── 1. GNN — Graph Neural Network (entity relationships) ─────────────────────

class SentinelGNN:
    """
    Target ke entities ka graph banao aur relationships find karo.
    Domain → IP → Subdomain → Email → Person
    """

    def __init__(self):
        self.nodes = {}   # id → {type, value, features}
        self.edges = []   # {from, to, relation, weight}

    def build_graph(self, scan_data: dict) -> dict:
        target = scan_data.get('target', '')
        self._add_node(target, 'domain', {'risk': scan_data.get('risk_level', 'LOW')})

        # Subdomains
        for s in scan_data.get('subdomains', {}).get('subdomains', [])[:20]:
            sub = s.get('subdomain', s) if isinstance(s, dict) else s
            self._add_node(sub, 'subdomain')
            self._add_edge(target, sub, 'has_subdomain', 0.8)

        # IPs
        for s in scan_data.get('subdomains', {}).get('subdomains', [])[:20]:
            ip = s.get('ip', '') if isinstance(s, dict) else ''
            if ip:
                self._add_node(ip, 'ip')
                sub = s.get('subdomain', '')
                if sub:
                    self._add_edge(sub, ip, 'resolves_to', 1.0)

        # Emails
        emails = scan_data.get('go_scraper', {}).get('emails', [])
        for email in emails[:10]:
            self._add_node(email, 'email')
            self._add_edge(target, email, 'has_email', 0.9)

        # Ports
        for p in scan_data.get('ports', {}).get('high_risk_ports', [])[:10]:
            port_id = f"{target}:{p.get('port')}"
            self._add_node(port_id, 'port', {'service': p.get('service', '')})
            self._add_edge(target, port_id, 'has_port', 0.7)

        # Cloud assets
        for f in scan_data.get('cloud_assets', {}).get('findings', [])[:5]:
            asset = f.get('name', '')
            if asset:
                self._add_node(asset, 'cloud_asset', {'public': f.get('public', False)})
                self._add_edge(target, asset, 'has_cloud_asset', 0.9)

        return self._analyze()

    def _add_node(self, node_id: str, node_type: str, features: dict = None):
        if node_id and node_id not in self.nodes:
            self.nodes[node_id] = {'type': node_type, 'features': features or {}, 'degree': 0}

    def _add_edge(self, src: str, dst: str, relation: str, weight: float):
        if src in self.nodes and dst in self.nodes:
            self.edges.append({'from': src, 'to': dst, 'relation': relation, 'weight': weight})
            self.nodes[src]['degree'] = self.nodes[src].get('degree', 0) + 1
            self.nodes[dst]['degree'] = self.nodes[dst].get('degree', 0) + 1

    def _analyze(self) -> dict:
        # High degree nodes = important targets
        high_degree = sorted(self.nodes.items(), key=lambda x: x[1].get('degree', 0), reverse=True)[:5]

        # Public cloud assets = critical
        critical_nodes = [n for n, d in self.nodes.items()
                         if d.get('features', {}).get('public')]

        # Email nodes = OSINT targets
        email_nodes = [n for n, d in self.nodes.items() if d['type'] == 'email']

        return {
            'total_nodes':    len(self.nodes),
            'total_edges':    len(self.edges),
            'high_value':     [n for n, _ in high_degree],
            'critical_nodes': critical_nodes,
            'email_targets':  email_nodes,
            'attack_surface': len(self.nodes),
            'graph':          {'nodes': list(self.nodes.keys())[:20], 'edges': self.edges[:30]},
        }


# ── 2. Isolation Forest — Anomaly Detection ───────────────────────────────────

class SentinelIsolationForest:
    """
    Unusual patterns detect karo — weird ports, suspicious responses, anomalies.
    """

    def __init__(self, contamination=0.1, n_trees=100):
        self.contamination = contamination
        self.n_trees       = n_trees
        self._model        = None

    def fit(self, data: list):
        try:
            from sklearn.ensemble import IsolationForest
            X = self._to_matrix(data)
            if len(X) < 5:
                return
            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_trees,
                random_state=42
            )
            self._model.fit(X)
        except Exception as e:
            logger.error(f"IsolationForest fit error: {e}")

    def detect(self, scan_data: dict) -> dict:
        """Scan data mein anomalies dhundo"""
        anomalies = []

        # Port anomalies
        ports = scan_data.get('ports', {}).get('high_risk_ports', [])
        unusual_ports = [p for p in ports if p.get('port') not in
                        (80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 8443)]
        if unusual_ports:
            anomalies.append({
                'type':     'unusual_port',
                'severity': 'HIGH',
                'detail':   f"Unusual ports: {[p['port'] for p in unusual_ports]}",
            })

        # SSL anomaly
        ssl = scan_data.get('ssl', {})
        if ssl.get('grade') in ('F', 'T'):
            anomalies.append({
                'type':     'ssl_anomaly',
                'severity': 'HIGH',
                'detail':   f"SSL grade {ssl.get('grade')} — critical misconfiguration",
            })

        # Header anomaly
        hdrs = scan_data.get('headers', {})
        if hdrs.get('score', 100) < 20:
            anomalies.append({
                'type':     'headers_anomaly',
                'severity': 'MEDIUM',
                'detail':   f"Security headers score {hdrs.get('score')}/100 — very low",
            })

        # Subdomain count anomaly
        sub_count = scan_data.get('subdomains', {}).get('total_found', 0)
        if sub_count > 100:
            anomalies.append({
                'type':     'large_attack_surface',
                'severity': 'MEDIUM',
                'detail':   f"{sub_count} subdomains — large attack surface",
            })

        # ML-based anomaly agar model trained hai
        if self._model:
            try:
                X = self._to_matrix([scan_data])
                if len(X) > 0:
                    score = self._model.decision_function(X)[0]
                    if score < -0.3:
                        anomalies.append({
                            'type':     'ml_anomaly',
                            'severity': 'HIGH',
                            'detail':   f"ML anomaly score: {score:.3f} — highly unusual pattern",
                        })
            except Exception as e:
                logger.debug(f"IsolationForest ML anomaly detection error: {e}")

        return {
            'anomalies': anomalies,
            'total':     len(anomalies),
            'risk':      'CRITICAL' if any(a['severity'] == 'CRITICAL' for a in anomalies)
                         else 'HIGH' if any(a['severity'] == 'HIGH' for a in anomalies)
                         else 'MEDIUM' if anomalies else 'LOW',
        }

    def _to_matrix(self, data_list: list) -> np.ndarray:
        rows = []
        for d in data_list:
            row = [
                d.get('ports', {}).get('total_open', 0),
                d.get('ports', {}).get('total_high_risk', 0),
                d.get('subdomains', {}).get('total_found', 0),
                d.get('headers', {}).get('score', 100),
                len(d.get('vulns', {}).get('sqli', [])),
                len(d.get('vulns', {}).get('xss', [])),
                d.get('cloud_assets', {}).get('total', 0),
                d.get('github_dorks', {}).get('total_secrets', 0),
            ]
            rows.append(row)
        return np.array(rows, dtype=float) if rows else np.array([]).reshape(0, 8)


# ── 3. DBSCAN — Username/IP Clustering ───────────────────────────────────────

class SentinelDBSCAN:
    """
    Usernames aur IPs cluster karo — same person ke alag accounts dhundo.
    """

    def cluster_usernames(self, usernames: list) -> dict:
        if len(usernames) < 2:
            return {'clusters': [], 'noise': usernames}

        try:
            from sklearn.cluster import DBSCAN
            from sklearn.feature_extraction.text import TfidfVectorizer

            vec = TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4))
            X   = vec.fit_transform(usernames).toarray()

            db  = DBSCAN(eps=0.5, min_samples=2, metric='cosine')
            labels = db.fit_predict(X)

            clusters = defaultdict(list)
            noise    = []
            for i, label in enumerate(labels):
                if label == -1:
                    noise.append(usernames[i])
                else:
                    clusters[int(label)].append(usernames[i])

            result = []
            for cid, members in clusters.items():
                result.append({
                    'cluster_id': cid,
                    'members':    members,
                    'size':       len(members),
                    'likely_same_person': len(members) >= 2,
                })

            return {'clusters': result, 'noise': noise, 'total_clusters': len(result)}

        except Exception as e:
            logger.error(f"DBSCAN error: {e}")
            return {'clusters': [], 'noise': usernames, 'error': str(e)}

    def cluster_ips(self, ips: list) -> dict:
        """IP addresses ko subnet ke hisaab se cluster karo"""
        if not ips:
            return {'clusters': {}}

        clusters = defaultdict(list)
        for ip in ips:
            parts = ip.split('.')
            if len(parts) == 4:
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                clusters[subnet].append(ip)

        return {
            'clusters': dict(clusters),
            'total':    len(clusters),
            'same_subnet': [ips for ips in clusters.values() if len(ips) > 1],
        }


# ── 4. LightGBM — Log Analysis ───────────────────────────────────────────────

class SentinelLightGBM:
    """
    Scan logs se attack patterns predict karo.
    """

    MODEL_PATH = Path('/home/kali/osints/models/ml_engine/lgbm_log_model.pkl')

    def __init__(self):
        self._model = None
        self._load()

    def _load(self):
        if self.MODEL_PATH.exists():
            try:
                import joblib
                self._model = joblib.load(self.MODEL_PATH)
                logger.info("LightGBM model loaded")
            except Exception as e:
                logger.debug(f"Failed to load LightGBM model: {e}")

    def train(self, log_entries: list) -> dict:
        """Log entries se model train karo"""
        if len(log_entries) < 20:
            return {'error': 'Need 20+ log entries'}

        try:
            import lightgbm as lgb
            import joblib
            from sklearn.model_selection import train_test_split

            X = np.array([self._log_to_features(e) for e in log_entries])
            y = np.array([1 if e.get('is_attack', False) else 0 for e in log_entries])

            X_tr, X_val, y_tr, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

            self._model = lgb.LGBMClassifier(
                n_estimators=100,
                learning_rate=0.1,
                num_leaves=31,
                class_weight='balanced',
                random_state=42,
                verbose=-1,
            )
            self._model.fit(X_tr, y_tr, eval_set=[(X_val, y_val)])

            acc = self._model.score(X_val, y_val)
            joblib.dump(self._model, self.MODEL_PATH)
            logger.info(f"LightGBM trained: acc={acc:.3f}")
            return {'accuracy': round(acc, 4), 'samples': len(log_entries)}

        except ImportError:
            return {'error': 'pip install lightgbm'}
        except Exception as e:
            return {'error': str(e)}

    def predict_log(self, log_entry: dict) -> dict:
        """Single log entry ka threat predict karo"""
        if not self._model:
            return self._rule_based(log_entry)

        try:
            X = np.array([self._log_to_features(log_entry)])
            prob = self._model.predict_proba(X)[0][1]
            return {
                'is_attack':   prob >= 0.5,
                'probability': round(float(prob), 4),
                'severity':    'HIGH' if prob >= 0.8 else 'MEDIUM' if prob >= 0.5 else 'LOW',
                'source':      'lgbm',
            }
        except Exception:
            return self._rule_based(log_entry)

    def analyze_logs(self, logs: list) -> dict:
        """Batch log analysis"""
        results   = [self.predict_log(l) for l in logs]
        attacks   = [r for r in results if r.get('is_attack')]
        return {
            'total':        len(logs),
            'attacks':      len(attacks),
            'attack_rate':  round(len(attacks) / len(logs), 3) if logs else 0,
            'high_risk':    [l for l, r in zip(logs, results) if r.get('severity') == 'HIGH'],
            'risk':         'CRITICAL' if len(attacks) > len(logs) * 0.5 else
                            'HIGH'     if attacks else 'LOW',
        }

    def _log_to_features(self, log: dict) -> list:
        text = str(log.get('message', log.get('text', ''))).lower()
        return [
            len(text),
            int('error' in text),
            int('fail' in text),
            int('attack' in text or 'exploit' in text),
            int('sql' in text or 'injection' in text),
            int('xss' in text or 'script' in text),
            int('scan' in text or 'nmap' in text),
            int('brute' in text or 'hydra' in text),
            int('unauthorized' in text or '401' in text),
            int('forbidden' in text or '403' in text),
            log.get('status_code', 200),
            log.get('response_time', 0),
        ]

    def _rule_based(self, log: dict) -> dict:
        text = str(log.get('message', '')).lower()
        is_attack = any(k in text for k in
                       ['exploit', 'injection', 'xss', 'attack', 'brute', 'scan', 'malware'])
        return {
            'is_attack':   is_attack,
            'probability': 0.8 if is_attack else 0.1,
            'severity':    'HIGH' if is_attack else 'LOW',
            'source':      'rule_based',
        }


# ── 5. Genetic Algorithm — Tool Sequence Optimizer ───────────────────────────

class SentinelGeneticOptimizer:
    """
    Best tool sequence evolve karo — kaunsa tool kab chalana hai.
    Chromosome = tool sequence
    Fitness    = findings / time
    """

    TOOLS = ['nmap', 'subfinder', 'nikto', 'gobuster', 'nuclei',
             'sqlmap', 'breach', 'osint', 'searchsploit']

    def __init__(self, pop_size=20, generations=30, mutation_rate=0.2):
        self.pop_size      = pop_size
        self.generations   = generations
        self.mutation_rate = mutation_rate
        self.best_sequence = None
        self.best_fitness  = 0.0

    def evolve(self, fitness_scores: dict = None) -> list:
        """
        fitness_scores = {'nmap': 0.8, 'nikto': 0.6, ...}
        Best tool sequence evolve karo.
        """
        if fitness_scores is None:
            fitness_scores = self._default_fitness()

        # Initial population — random sequences
        population = [self._random_sequence() for _ in range(self.pop_size)]

        for gen in range(self.generations):
            # Fitness evaluate karo
            scored = [(seq, self._evaluate(seq, fitness_scores)) for seq in population]
            scored.sort(key=lambda x: x[1], reverse=True)

            # Best track karo
            if scored[0][1] > self.best_fitness:
                self.best_fitness  = scored[0][1]
                self.best_sequence = scored[0][0]

            # Selection — top 50% survive
            survivors = [s[0] for s in scored[:self.pop_size // 2]]

            # Crossover + mutation
            new_pop = list(survivors)
            while len(new_pop) < self.pop_size:
                p1 = random.choice(survivors)
                p2 = random.choice(survivors)
                child = self._crossover(p1, p2)
                child = self._mutate(child)
                new_pop.append(child)

            population = new_pop

        return self.best_sequence or self._default_sequence()

    def _evaluate(self, sequence: list, fitness_scores: dict) -> float:
        """Sequence ka fitness score calculate karo"""
        score = 0.0
        for i, tool in enumerate(sequence):
            tool_score = fitness_scores.get(tool, 0.5)
            # Earlier position = higher weight (fast tools pehle)
            position_weight = 1.0 / (i + 1)
            score += tool_score * position_weight
        return score

    def _random_sequence(self) -> list:
        import random as _r
        seq = list(self.TOOLS)
        _r.shuffle(seq)
        return seq[:6]  # 6 tools per sequence

    def _crossover(self, p1: list, p2: list) -> list:
        """Single-point crossover"""
        import random as _r
        point = _r.randint(1, min(len(p1), len(p2)) - 1)
        child = p1[:point]
        for t in p2:
            if t not in child:
                child.append(t)
            if len(child) >= 6:
                break
        return child

    def _mutate(self, sequence: list) -> list:
        import random as _r
        if _r.random() < self.mutation_rate:
            i, j = _r.sample(range(len(sequence)), 2)
            sequence[i], sequence[j] = sequence[j], sequence[i]
        return sequence

    def _default_fitness(self) -> dict:
        return {
            'nmap':        0.9,
            'subfinder':   0.7,
            'nikto':       0.8,
            'gobuster':    0.7,
            'nuclei':      0.9,
            'sqlmap':      0.8,
            'breach':      0.6,
            'osint':       0.5,
            'searchsploit':0.7,
        }

    def _default_sequence(self) -> list:
        return ['nmap', 'subfinder', 'nuclei', 'nikto', 'gobuster', 'sqlmap']

    def update_fitness(self, tool: str, found_something: bool, time_taken: float) -> dict:
        """Real scan results se fitness update karo"""
        path = Path('/home/kali/osints/models/ml_engine/ga_fitness.json')
        fitness = {}
        if path.exists():
            fitness = json.loads(path.read_text())

        current = fitness.get(tool, {'score': 0.5, 'runs': 0})
        reward  = 1.0 if found_something else 0.0
        # Time penalty — zyada time = lower score
        time_penalty = min(0.3, time_taken / 300)
        new_score = (current['score'] * current['runs'] + reward - time_penalty) / (current['runs'] + 1)

        fitness[tool] = {
            'score': round(max(0.1, min(1.0, new_score)), 4),
            'runs':  current['runs'] + 1,
        }
        path.write_text(json.dumps(fitness, indent=2))
        return fitness


# ── Unified Interface ─────────────────────────────────────────────────────────

class AdvancedMLEngine:
    """Sab algorithms ek jagah"""

    def __init__(self):
        self.gnn       = SentinelGNN()
        self.iso_forest = SentinelIsolationForest()
        self.dbscan    = SentinelDBSCAN()
        self.lgbm      = SentinelLightGBM()
        self.genetic   = SentinelGeneticOptimizer()

    def full_analysis(self, scan_data: dict) -> dict:
        """Ek scan data pe sab algorithms chalao"""
        results = {}

        # GNN — entity graph
        try:
            results['gnn'] = self.gnn.build_graph(scan_data)
        except Exception as e:
            results['gnn'] = {'error': str(e)}

        # Isolation Forest — anomalies
        try:
            results['anomalies'] = self.iso_forest.detect(scan_data)
        except Exception as e:
            results['anomalies'] = {'error': str(e)}

        # DBSCAN — username clustering
        try:
            usernames = scan_data.get('possible_usernames', [])
            if usernames:
                results['clusters'] = self.dbscan.cluster_usernames(usernames)
        except Exception as e:
            results['clusters'] = {'error': str(e)}

        # Genetic — best tool sequence
        try:
            results['optimal_sequence'] = self.genetic.evolve()
        except Exception as e:
            results['optimal_sequence'] = ['nmap', 'nuclei', 'nikto', 'gobuster', 'sqlmap']

        return results

    def get_optimal_scan_order(self) -> list:
        """Genetic algorithm se best tool order lo — real DB stats use karo"""
        try:
            from modules.database import SentinelDB
            stats = SentinelDB.get_tool_stats()
            if stats:
                fitness = {s['tool']: s['effectiveness'] for s in stats}
                return self.genetic.evolve(fitness)
        except Exception as e:
            logger.debug(f"Failed to get tool stats from DB for genetic optimizer: {e}")
        return self.genetic.evolve()
