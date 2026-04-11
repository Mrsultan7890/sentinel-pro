"""
Relation Mapper - ML-Powered Entity Relation Graph
OSINT Intelligence Grade

Ab ye sirf rules nahi, real ML use karta hai:
- EntityMatcher (TF-IDF + Cosine Similarity) → profile matching
- UsernameClusterer (DBSCAN) → username grouping
- IdentityScorer (Bayesian log-odds) → confidence scoring
"""

import logging
from collections import defaultdict
from modules.ml_engine.entity_matcher import EntityMatcher
from modules.ml_engine.username_clusterer import UsernameClusterer
from modules.ml_engine.identity_scorer import IdentityScorer

logger = logging.getLogger(__name__)


class RelationMapper:
    """
    Person OSINT results ko leke ML-powered relation graph banata hai.

    Nodes = entities (name, email, phone, profile, address, image)
    Edges = ML-scored relations
    """

    def __init__(self):
        self.matcher   = EntityMatcher()
        self.clusterer = UsernameClusterer(eps=0.35, min_samples=2)
        self.scorer    = IdentityScorer()

    def build_graph(self, person_result: dict, extra_results: dict = None) -> dict:
        graph = {
            'nodes':            [],
            'edges':            [],
            'clusters':         [],
            'ml_matches':       [],
            'username_clusters': [],
            'central_identity': None,
            'confidence_score': 0.0,
            'identity_score':   {},
            'summary':          {},
        }

        # ── Step 1: Seed node ─────────────────────────────────────────────────
        seed_node = {
            'id':      f"seed_{person_result['query']}",
            'label':   person_result['query'],
            'type':    person_result['query_type'],
            'is_seed': True,
        }
        graph['nodes'].append(seed_node)

        # ── Step 2: Social profile nodes ──────────────────────────────────────
        for profile in person_result.get('social_profiles', []):
            node_id = f"{profile['platform']}_{profile['username']}"
            graph['nodes'].append({
                'id':           node_id,
                'label':        f"@{profile['username']}",
                'type':         'social_profile',
                'platform':     profile['platform'],
                'url':          profile.get('url', ''),
                'display_name': profile.get('display_name', ''),
                'username':     profile['username'],
            })
            # Seed → profile edge (base confidence)
            graph['edges'].append({
                'from':       seed_node['id'],
                'to':         node_id,
                'relation':   'has_profile',
                'confidence': 0.80,
                'method':     'direct_discovery',
            })

        # ── Step 3: Email nodes ───────────────────────────────────────────────
        for email in person_result.get('emails_found', []):
            node_id = f"email_{email}"
            graph['nodes'].append({'id': node_id, 'label': email, 'type': 'email'})
            graph['edges'].append({
                'from': seed_node['id'], 'to': node_id,
                'relation': 'has_email', 'confidence': 0.75, 'method': 'page_extraction',
            })

        # ── Step 4: Phone nodes ───────────────────────────────────────────────
        for phone in person_result.get('phones_found', []):
            node_id = f"phone_{phone}"
            graph['nodes'].append({'id': node_id, 'label': phone, 'type': 'phone'})
            graph['edges'].append({
                'from': seed_node['id'], 'to': node_id,
                'relation': 'has_phone', 'confidence': 0.70, 'method': 'page_extraction',
            })

        # ── Step 5: Address nodes ─────────────────────────────────────────────
        for addr in person_result.get('addresses', []):
            node_id = f"addr_{addr[:20]}"
            graph['nodes'].append({'id': node_id, 'label': addr, 'type': 'address'})
            graph['edges'].append({
                'from': seed_node['id'], 'to': node_id,
                'relation': 'has_address', 'confidence': 0.65, 'method': 'people_search',
            })

        # ── Step 6: Image nodes ───────────────────────────────────────────────
        for img in person_result.get('images_found', []):
            node_id = f"img_{img['source']}"
            graph['nodes'].append({
                'id': node_id, 'label': f"Image ({img['source']})",
                'type': 'image', 'url': img.get('url', ''), 'source': img['source'],
            })
            graph['edges'].append({
                'from': seed_node['id'], 'to': node_id,
                'relation': 'has_image', 'confidence': 0.70, 'method': 'gravatar_lookup',
            })

        # ── Step 7: ML - Entity Matching (TF-IDF + Cosine Similarity) ─────────
        profiles = person_result.get('social_profiles', [])
        if len(profiles) >= 2:
            ml_matches = self.matcher.match_profiles(profiles)
            graph['ml_matches'] = ml_matches

            for match in ml_matches:
                pa = match['profile_a']
                pb = match['profile_b']
                node_a = f"{pa['platform']}_{pa['username']}"
                node_b = f"{pb['platform']}_{pb['username']}"

                graph['edges'].append({
                    'from':       node_a,
                    'to':         node_b,
                    'relation':   match['label'],
                    'confidence': match['confidence'],
                    'method':     'ml_entity_matching',
                    'evidence':   match.get('evidence', ''),
                    'text_sim':   match.get('text_sim', 0),
                    'struct_sim': match.get('struct_sim', 0),
                })

        # ── Step 8: ML - Username Clustering (DBSCAN) ─────────────────────────
        all_usernames = person_result.get('possible_usernames', [])
        # Found profile usernames bhi add karo
        all_usernames += [p['username'] for p in profiles]
        all_usernames = list(set(all_usernames))

        if len(all_usernames) >= 2:
            cluster_result = self.clusterer.cluster_cross_platform(profiles) if profiles else \
                             self.clusterer.cluster(all_usernames)
            graph['username_clusters'] = cluster_result.get('clusters', [])

            # Cluster edges add karo
            for cluster in cluster_result.get('clusters', []):
                members = cluster.get('usernames', [])
                canonical = cluster.get('canonical', members[0] if members else '')
                conf = cluster.get('confidence', 0.7)

                for uname in members:
                    if uname != canonical:
                        # Canonical node dhundho
                        canonical_node = next(
                            (n['id'] for n in graph['nodes']
                             if n.get('username') == canonical or canonical in n.get('id', '')),
                            f"username_{canonical}"
                        )
                        current_node = next(
                            (n['id'] for n in graph['nodes']
                             if n.get('username') == uname or uname in n.get('id', '')),
                            f"username_{uname}"
                        )
                        graph['edges'].append({
                            'from':       current_node,
                            'to':         canonical_node,
                            'relation':   'username_variant',
                            'confidence': conf,
                            'method':     'dbscan_clustering',
                            'evidence':   cluster.get('reason', ''),
                        })

        # ── Step 9: ML - Identity Scoring (Bayesian) ──────────────────────────
        identity_score = self.scorer.score_from_osint_result(
            person_result,
            match_results=graph['ml_matches'],
        )
        graph['identity_score'] = identity_score

        # ── Step 10: Extra results merge ──────────────────────────────────────
        if extra_results:
            self._merge_extra_results(graph, seed_node['id'], extra_results)

        # ── Step 11: Graph analytics ──────────────────────────────────────────
        graph['clusters']         = self._find_connected_components(graph)
        graph['confidence_score'] = self._calc_graph_confidence(graph)
        graph['central_identity'] = self._find_central_node(graph)

        # ── Step 12: Summary ──────────────────────────────────────────────────
        graph['summary'] = {
            'total_nodes':          len(graph['nodes']),
            'total_edges':          len(graph['edges']),
            'total_clusters':       len(graph['clusters']),
            'ml_matches_found':     len(graph['ml_matches']),
            'username_clusters':    len(graph['username_clusters']),
            'platforms_found':      list(set(n['platform'] for n in graph['nodes'] if n.get('platform'))),
            'emails_found':         [n['label'] for n in graph['nodes'] if n['type'] == 'email'],
            'phones_found':         [n['label'] for n in graph['nodes'] if n['type'] == 'phone'],
            'addresses_found':      [n['label'] for n in graph['nodes'] if n['type'] == 'address'],
            'confidence_score':     graph['confidence_score'],
            'identity_confidence':  identity_score.get('confidence_pct', 0),
            'identity_label':       identity_score.get('label', 'NO_EVIDENCE'),
        }

        return graph

    # ── Extra Results Merge ────────────────────────────────────────────────────

    def _merge_extra_results(self, graph: dict, seed_id: str, extra_results: dict):
        email_result = extra_results.get('email', {})
        if email_result and not email_result.get('error'):
            for hint in email_result.get('social_hints', []):
                if hint['status'] == 'found':
                    node_id = f"email_social_{hint['platform']}"
                    graph['nodes'].append({
                        'id': node_id, 'label': f"{hint['platform']} (via email)",
                        'type': 'social_profile', 'platform': hint['platform'], 'url': hint['url'],
                    })
                    # ML score nikalo
                    conf = self.scorer.score_relation_edge('email_local_username_match')
                    graph['edges'].append({
                        'from': seed_id, 'to': node_id,
                        'relation': 'email_linked_profile',
                        'confidence': conf, 'method': 'ml_identity_scorer',
                    })

        phone_result = extra_results.get('phone', {})
        if phone_result and not phone_result.get('error'):
            if phone_result.get('carrier'):
                node_id = f"carrier_{phone_result['carrier']}"
                graph['nodes'].append({'id': node_id, 'label': phone_result['carrier'], 'type': 'carrier'})
                graph['edges'].append({
                    'from': seed_id, 'to': node_id,
                    'relation': 'uses_carrier', 'confidence': 0.90, 'method': 'phone_osint',
                })
            if phone_result.get('location'):
                node_id = f"location_{phone_result['location']}"
                graph['nodes'].append({'id': node_id, 'label': phone_result['location'], 'type': 'location'})
                graph['edges'].append({
                    'from': seed_id, 'to': node_id,
                    'relation': 'located_in', 'confidence': 0.70, 'method': 'phone_osint',
                })

    # ── Graph Analytics ────────────────────────────────────────────────────────

    def _find_connected_components(self, graph: dict) -> list:
        """BFS se connected components dhundho"""
        adjacency = defaultdict(set)
        for edge in graph['edges']:
            adjacency[edge['from']].add(edge['to'])
            adjacency[edge['to']].add(edge['from'])

        visited = set()
        components = []
        for node in graph['nodes']:
            nid = node['id']
            if nid not in visited:
                component = []
                stack = [nid]
                while stack:
                    curr = stack.pop()
                    if curr not in visited:
                        visited.add(curr)
                        component.append(curr)
                        stack.extend(adjacency[curr] - visited)
                if len(component) > 1:
                    components.append(component)
        return components

    def _calc_graph_confidence(self, graph: dict) -> float:
        """
        Graph-level confidence score:
        - Average edge confidence (weighted by method quality)
        - ML methods ko higher weight
        """
        if not graph['edges']:
            return 0.0

        method_weights = {
            'ml_entity_matching':   1.5,
            'dbscan_clustering':    1.4,
            'ml_identity_scorer':   1.3,
            'direct_discovery':     1.0,
            'phone_osint':          1.0,
            'page_extraction':      0.9,
            'people_search':        0.8,
            'gravatar_lookup':      0.9,
        }

        weighted_sum = 0.0
        weight_total = 0.0
        for edge in graph['edges']:
            method = edge.get('method', 'direct_discovery')
            mw = method_weights.get(method, 1.0)
            conf = edge.get('confidence', 0.5)
            weighted_sum += conf * mw
            weight_total += mw

        avg = weighted_sum / weight_total if weight_total > 0 else 0.0
        node_bonus = min(len(graph['nodes']) * 1.5, 15)
        ml_bonus   = min(len(graph['ml_matches']) * 3, 15)

        return round(min((avg * 70) + node_bonus + ml_bonus, 100), 1)

    def _find_central_node(self, graph: dict) -> dict:
        """Sabse zyada connections wala node = central identity"""
        if not graph['nodes']:
            return {}

        conn_count = defaultdict(int)
        for edge in graph['edges']:
            conn_count[edge['from']] += 1
            conn_count[edge['to']]   += 1

        if not conn_count:
            return graph['nodes'][0]

        central_id   = max(conn_count, key=conn_count.get)
        central_node = next((n for n in graph['nodes'] if n['id'] == central_id), {})
        if central_node:
            central_node = dict(central_node)
            central_node['connection_count'] = conn_count[central_id]
        return central_node

    def export_as_text(self, graph: dict) -> str:
        lines = ['=' * 65, 'ML-POWERED RELATION MAP', '=' * 65]
        s = graph.get('summary', {})
        lines += [
            f"Nodes            : {s.get('total_nodes', 0)}",
            f"Relations        : {s.get('total_edges', 0)}",
            f"ML Matches       : {s.get('ml_matches_found', 0)}",
            f"Username Clusters: {s.get('username_clusters', 0)}",
            f"Graph Confidence : {s.get('confidence_score', 0)}%",
            f"Identity Score   : {s.get('identity_confidence', 0)}% ({s.get('identity_label', 'N/A')})",
            '',
        ]
        if s.get('platforms_found'):
            lines.append(f"Platforms : {', '.join(s['platforms_found'])}")
        if s.get('emails_found'):
            lines.append(f"Emails    : {', '.join(s['emails_found'])}")
        if s.get('phones_found'):
            lines.append(f"Phones    : {', '.join(s['phones_found'])}")

        lines += ['', 'ML MATCHES (Entity Matcher):']
        for m in graph.get('ml_matches', []):
            pa = m['profile_a']
            pb = m['profile_b']
            lines.append(
                f"  [{m['label'].upper()}] {pa['platform']}:@{pa['username']} ↔ "
                f"{pb['platform']}:@{pb['username']} "
                f"(conf={m['confidence']:.0%}, text={m.get('text_sim',0):.0%}, struct={m.get('struct_sim',0):.0%})"
            )
            if m.get('evidence'):
                lines.append(f"    Evidence: {m['evidence']}")

        lines += ['', 'USERNAME CLUSTERS (DBSCAN):']
        for c in graph.get('username_clusters', []):
            lines.append(
                f"  Cluster #{c['id']} [{c['confidence']:.0%}] "
                f"canonical='{c['canonical']}' → {c['usernames']}"
            )
            lines.append(f"    Reason: {c.get('reason', 'N/A')}")

        lines += ['', 'ALL RELATIONS:']
        for edge in sorted(graph.get('edges', []), key=lambda x: x.get('confidence', 0), reverse=True):
            conf = int(edge.get('confidence', 0) * 100)
            method = edge.get('method', '')
            lines.append(f"  [{conf}%][{method}] {edge['from']} --[{edge['relation']}]--> {edge['to']}")
            if edge.get('evidence'):
                lines.append(f"    Evidence: {edge['evidence']}")

        return '\n'.join(lines)
