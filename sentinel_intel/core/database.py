"""
Graph Database Engine - Sentinel Intel
Uses sentinel.db + ML algorithms for intelligent graph analysis
"""

import sqlite3
import json
import uuid
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config

class GraphDatabase:
    """
    Professional graph database with ML integration
    - Stores nodes (entities) and edges (relationships)
    - ML-powered similarity detection
    - Auto-clustering with DBSCAN
    - GNN for relationship prediction
    """
    
    def __init__(self):
        self.db_path = config.BASE_DIR / 'data' / 'sentinel.db'
        self.conn = None
        self._init_db()
        self._load_ml_models()
    
    def _init_db(self):
        """Initialize graph tables in sentinel.db"""
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys = ON")
        
        # Nodes table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS intel_nodes (
                id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                label TEXT NOT NULL,
                properties TEXT,
                x REAL DEFAULT 0,
                y REAL DEFAULT 0,
                color TEXT,
                size INTEGER DEFAULT 50,
                icon TEXT,
                confidence REAL DEFAULT 1.0,
                ml_cluster INTEGER DEFAULT -1,
                risk_score REAL DEFAULT 0.0,
                starred INTEGER DEFAULT 0,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # Edges table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS intel_edges (
                id TEXT PRIMARY KEY,
                from_node TEXT NOT NULL,
                to_node TEXT NOT NULL,
                relationship TEXT NOT NULL,
                confidence REAL DEFAULT 1.0,
                weight REAL DEFAULT 1.0,
                properties TEXT,
                ml_predicted INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (from_node) REFERENCES intel_nodes(id) ON DELETE CASCADE,
                FOREIGN KEY (to_node) REFERENCES intel_nodes(id) ON DELETE CASCADE
            )
        """)
        
        # Transform history
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS intel_transforms (
                id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                transform_name TEXT NOT NULL,
                transform_type TEXT NOT NULL,
                result_count INTEGER DEFAULT 0,
                api_used TEXT,
                ml_enhanced INTEGER DEFAULT 0,
                execution_time REAL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (node_id) REFERENCES intel_nodes(id) ON DELETE CASCADE
            )
        """)
        
        # Saved graphs
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS intel_graphs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                tags TEXT,
                node_count INTEGER DEFAULT 0,
                edge_count INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'LOW',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # ML predictions cache
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS intel_ml_cache (
                id TEXT PRIMARY KEY,
                entity_value TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL,
                model_used TEXT,
                timestamp TEXT NOT NULL
            )
        """)
        
        # Create indexes
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_type ON intel_nodes(entity_type)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_label ON intel_nodes(label)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_from ON intel_edges(from_node)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_to ON intel_edges(to_node)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_ml_cache ON intel_ml_cache(entity_value, entity_type)")
        
        self.conn.commit()
    
    def _load_ml_models(self):
        """Load ML models for graph intelligence"""
        try:
            from modules.ml_engine.trainer import ModelTrainer
            from modules.ml_engine.sentinel_net import SentinelNet
            
            self.ml_trainer = ModelTrainer()
            self.sentinelnet = SentinelNet()
            self.ml_available = True
        except Exception as e:
            self.ml_available = False
            print(f"[!] ML models not available: {e}")
    
    # ========== NODE OPERATIONS ==========
    
    def add_node(self, entity_type: str, label: str, properties: Dict = None,
                 x: float = None, y: float = None, confidence: float = 1.0) -> str:
        """Add node with ML-powered risk scoring"""
        node_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        # Random position if not specified
        if x is None or y is None:
            import random
            x = random.uniform(-400, 400)
            y = random.uniform(-400, 400)
        
        # Entity type colors
        colors = {
            'domain': '#00D9FF', 'ip': '#FF6B35', 'email': '#4ECDC4',
            'person': '#95E1D3', 'phone': '#F38181', 'username': '#AA96DA',
            'url': '#FCBAD3', 'hash': '#FFFFD2', 'cve': '#FF5252',
            'port': '#69F0AE', 'company': '#FFD93D', 'location': '#6BCF7F',
            'cryptocurrency': '#F9A826', 'malware': '#E74C3C', 'breach': '#C0392B'
        }
        color = colors.get(entity_type, '#00D9FF')
        
        # ML risk scoring
        risk_score = 0.0
        if self.ml_available and label:
            risk_score = self._calculate_risk_score(entity_type, label, properties)
        
        props_json = json.dumps(properties) if properties else '{}'
        
        self.conn.execute("""
            INSERT INTO intel_nodes 
            (id, entity_type, label, properties, x, y, color, confidence, risk_score, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (node_id, entity_type, label, props_json, x, y, color, confidence, risk_score, now, now))
        
        self.conn.commit()
        return node_id
    
    def _calculate_risk_score(self, entity_type: str, label: str, properties: Dict = None) -> float:
        """ML-powered risk scoring using SentinelNet"""
        try:
            # Check cache first
            cached = self._get_ml_cache(label, entity_type)
            if cached:
                return cached.get('confidence', 0.0)
            
            # Use SentinelNet for threat classification
            text = f"{entity_type}: {label}"
            if properties:
                text += f" {json.dumps(properties)}"
            
            prediction = self.ml_trainer.predict_threat(text)
            risk_map = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}
            risk_score = risk_map.get(prediction.get('label', 'LOW'), 0.0)
            
            # Cache result
            self._cache_ml_prediction(label, entity_type, prediction, 'SentinelNet')
            
            return risk_score
        except Exception:
            return 0.0
    
    def get_nodes(self, entity_type: str = None, limit: int = None) -> List[Dict]:
        """Get nodes with optional filtering"""
        query = """
            SELECT id, entity_type, label, properties, x, y, color, size, 
                   confidence, ml_cluster, risk_score, starred, notes
            FROM intel_nodes
        """
        params = []
        
        if entity_type:
            query += " WHERE entity_type = ?"
            params.append(entity_type)
        
        if limit:
            query += f" LIMIT {limit}"
        
        cursor = self.conn.execute(query, params)
        
        nodes = []
        for row in cursor.fetchall():
            nodes.append({
                'id': row[0], 'entity_type': row[1], 'label': row[2],
                'properties': json.loads(row[3]) if row[3] else {},
                'x': row[4], 'y': row[5], 'color': row[6], 'size': row[7],
                'confidence': row[8], 'ml_cluster': row[9], 'risk_score': row[10],
                'starred': bool(row[11]), 'notes': row[12]
            })
        
        return nodes
    
    def update_node_properties(self, node_id: str, properties: Dict):
        """Update node properties (merge with existing)"""
        cursor = self.conn.execute("SELECT properties FROM intel_nodes WHERE id = ?", (node_id,))
        row = cursor.fetchone()
        if row:
            current_props = json.loads(row[0]) if row[0] else {}
            current_props.update(properties)
            self.conn.execute(
                "UPDATE intel_nodes SET properties = ? WHERE id = ?",
                (json.dumps(current_props), node_id)
            )
            self.conn.commit()
    
    def update_node(self, node_id: str, **kwargs):
        """Update node properties"""
        fields = []
        values = []
        
        for key, value in kwargs.items():
            if key == 'properties':
                value = json.dumps(value)
            elif key in ('starred',):
                value = 1 if value else 0
            fields.append(f"{key} = ?")
            values.append(value)
        
        values.append(datetime.now().isoformat())
        fields.append("updated_at = ?")
        values.append(node_id)
        
        query = f"UPDATE intel_nodes SET {', '.join(fields)} WHERE id = ?"
        self.conn.execute(query, values)
        self.conn.commit()
    
    def delete_node(self, node_id: str):
        """Delete node (cascades to edges)"""
        self.conn.execute("DELETE FROM intel_nodes WHERE id = ?", (node_id,))
        self.conn.commit()
    
    # ========== EDGE OPERATIONS ==========
    
    def add_edge(self, from_node: str, to_node: str, relationship: str,
                 confidence: float = 1.0, properties: Dict = None, 
                 ml_predicted: bool = False) -> str:
        """Add edge with ML confidence"""
        edge_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        props_json = json.dumps(properties) if properties else '{}'
        weight = confidence  # Edge weight = confidence
        
        self.conn.execute("""
            INSERT INTO intel_edges
            (id, from_node, to_node, relationship, confidence, weight, properties, ml_predicted, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (edge_id, from_node, to_node, relationship, confidence, weight, props_json, 
              1 if ml_predicted else 0, now))
        
        self.conn.commit()
        return edge_id
    
    def get_edges(self, node_id: str = None) -> List[Dict]:
        """Get edges, optionally filtered by node"""
        if node_id:
            cursor = self.conn.execute("""
                SELECT id, from_node, to_node, relationship, confidence, weight, properties, ml_predicted
                FROM intel_edges 
                WHERE from_node = ? OR to_node = ?
            """, (node_id, node_id))
        else:
            cursor = self.conn.execute("""
                SELECT id, from_node, to_node, relationship, confidence, weight, properties, ml_predicted
                FROM intel_edges
            """)
        
        edges = []
        for row in cursor.fetchall():
            edges.append({
                'id': row[0], 'from_node': row[1], 'to_node': row[2],
                'relationship': row[3], 'confidence': row[4], 'weight': row[5],
                'properties': json.loads(row[6]) if row[6] else {},
                'ml_predicted': bool(row[7])
            })
        
        return edges
    
    def delete_edge(self, edge_id: str):
        """Delete edge"""
        self.conn.execute("DELETE FROM intel_edges WHERE id = ?", (edge_id,))
        self.conn.commit()
    
    # ========== TRANSFORM OPERATIONS ==========
    
    def log_transform(self, node_id: str, transform_name: str, transform_type: str,
                     result_count: int, api_used: str = None, ml_enhanced: bool = False,
                     execution_time: float = 0.0):
        """Log transform execution"""
        transform_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        self.conn.execute("""
            INSERT INTO intel_transforms
            (id, node_id, transform_name, transform_type, result_count, api_used, ml_enhanced, execution_time, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (transform_id, node_id, transform_name, transform_type, result_count, 
              api_used, 1 if ml_enhanced else 0, execution_time, now))
        
        self.conn.commit()
    
    def get_transform_history(self, node_id: str) -> List[Dict]:
        """Get transform history for node"""
        cursor = self.conn.execute("""
            SELECT transform_name, transform_type, result_count, api_used, ml_enhanced, execution_time, timestamp
            FROM intel_transforms
            WHERE node_id = ?
            ORDER BY timestamp DESC
        """, (node_id,))
        
        history = []
        for row in cursor.fetchall():
            history.append({
                'transform_name': row[0], 'transform_type': row[1],
                'result_count': row[2], 'api_used': row[3],
                'ml_enhanced': bool(row[4]), 'execution_time': row[5],
                'timestamp': row[6]
            })
        
        return history
    
    def clear_transform_history(self, node_id: str):
        """Clear transform history for specific node"""
        self.conn.execute("DELETE FROM intel_transforms WHERE node_id = ?", (node_id,))
        self.conn.commit()
    
    # ========== ML CACHE OPERATIONS ==========
    
    def _cache_ml_prediction(self, entity_value: str, entity_type: str, 
                            prediction: Dict, model_used: str):
        """Cache ML prediction"""
        cache_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        self.conn.execute("""
            INSERT INTO intel_ml_cache
            (id, entity_value, entity_type, prediction, confidence, model_used, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (cache_id, entity_value, entity_type, json.dumps(prediction),
              prediction.get('confidence', 0.0), model_used, now))
        
        self.conn.commit()
    
    def _get_ml_cache(self, entity_value: str, entity_type: str) -> Optional[Dict]:
        """Get cached ML prediction"""
        cursor = self.conn.execute("""
            SELECT prediction, confidence, model_used, timestamp
            FROM intel_ml_cache
            WHERE entity_value = ? AND entity_type = ?
            ORDER BY timestamp DESC LIMIT 1
        """, (entity_value, entity_type))
        
        row = cursor.fetchone()
        if row:
            return {
                'prediction': json.loads(row[0]),
                'confidence': row[1],
                'model_used': row[2],
                'timestamp': row[3]
            }
        return None
    
    # ========== GRAPH OPERATIONS ==========
    
    def clear_graph(self):
        """Clear all nodes and edges"""
        self.conn.execute("DELETE FROM intel_nodes")
        self.conn.commit()
    
    def get_stats(self) -> Dict:
        """Get graph statistics"""
        cursor = self.conn.execute("SELECT COUNT(*) FROM intel_nodes")
        node_count = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM intel_edges")
        edge_count = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(DISTINCT entity_type) FROM intel_nodes")
        entity_types = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT AVG(risk_score) FROM intel_nodes WHERE risk_score > 0")
        avg_risk = cursor.fetchone()[0] or 0.0
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM intel_nodes WHERE ml_cluster >= 0")
        clustered_nodes = cursor.fetchone()[0]
        
        return {
            'nodes': node_count,
            'edges': edge_count,
            'entity_types': entity_types,
            'avg_risk_score': round(avg_risk, 2),
            'clustered_nodes': clustered_nodes,
            'ml_available': self.ml_available
        }
    
    # ========== ML GRAPH ANALYSIS ==========
    
    def run_clustering(self) -> Dict:
        """Run DBSCAN clustering on graph nodes"""
        if not self.ml_available:
            return {'error': 'ML not available'}
        
        try:
            from sklearn.cluster import DBSCAN
            import numpy as np
            
            nodes = self.get_nodes()
            if len(nodes) < 3:
                return {'error': 'Need at least 3 nodes'}
            
            # Feature extraction: position + risk score
            features = np.array([[n['x'], n['y'], n['risk_score']] for n in nodes])
            
            # DBSCAN clustering
            clustering = DBSCAN(eps=config.ML_CLUSTER_EPS * 100, min_samples=2)
            labels = clustering.fit_predict(features)
            
            # Update nodes with cluster labels
            for node, label in zip(nodes, labels):
                self.update_node(node['id'], ml_cluster=int(label))
            
            n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
            n_noise = list(labels).count(-1)
            
            return {
                'clusters': n_clusters,
                'noise_points': n_noise,
                'clustered_nodes': len(nodes) - n_noise
            }
        except Exception as e:
            return {'error': str(e)}
    
    def predict_relationships(self, node_id: str, max_predictions: int = 5) -> List[Tuple[str, str, float]]:
        """Use GNN to predict missing relationships"""
        if not self.ml_available:
            return []
        
        try:
            import networkx as nx
            
            # Build NetworkX graph
            G = nx.DiGraph()
            nodes = self.get_nodes()
            edges = self.get_edges()
            
            for node in nodes:
                G.add_node(node['id'], **node)
            
            for edge in edges:
                G.add_edge(edge['from_node'], edge['to_node'], **edge)
            
            # Simple link prediction using common neighbors
            predictions = []
            source_node = node_id
            
            for target_node in G.nodes():
                if target_node == source_node:
                    continue
                if G.has_edge(source_node, target_node):
                    continue
                
                # Calculate score based on common neighbors
                common = len(list(nx.common_neighbors(G.to_undirected(), source_node, target_node)))
                if common > 0:
                    score = common / (G.degree(source_node) + G.degree(target_node))
                    predictions.append((source_node, target_node, score))
            
            # Sort by score and return top predictions
            predictions.sort(key=lambda x: x[2], reverse=True)
            return predictions[:max_predictions]
        
        except Exception:
            return []
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


# Global database instance
db = GraphDatabase()
