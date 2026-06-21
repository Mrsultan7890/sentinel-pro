"""
Database Engine - Unified Intelligence Storage
Query and cross-reference entities across all investigations
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from sentinel_intel.core.database import db

class DatabaseEngine:
    """
    Database Engine for Sentinel Intel
    
    Capabilities:
    - Query historical intelligence
    - Cross-reference entities
    - Find relationships across investigations
    - Track entity evolution over time
    - Search by properties
    """
    
    def __init__(self):
        self.name = "Database"
    
    def investigate(self, query: str) -> Dict:
        """
        Search database for matching entities
        
        Args:
            query: Search query (entity label or property)
        
        Returns:
            Dict with matching entities and relationships
        """
        result = {
            'query': query,
            'timestamp': datetime.now().isoformat(),
            'entities': [],
            'relationships': [],
            'timeline': [],
            'sources': ['sentinel_intel_db']
        }
        
        # Search all nodes
        all_nodes = db.get_nodes()
        matching_nodes = []
        
        for node in all_nodes:
            # Match by label
            if query.lower() in node['label'].lower():
                matching_nodes.append(node)
                continue
            
            # Match by properties
            props = node.get('properties', {})
            for key, value in props.items():
                if isinstance(value, str) and query.lower() in value.lower():
                    matching_nodes.append(node)
                    break
        
        # Add matching entities
        for node in matching_nodes[:50]:  # Limit to 50 results
            result['entities'].append({
                'id': node['id'],
                'type': node['entity_type'],
                'label': node['label'],
                'confidence': node.get('confidence', 0.5),
                'risk_score': node.get('risk_score', 0),
                'properties': node.get('properties', {}),
                'created_at': node.get('created_at')
            })
        
        # Find relationships
        all_edges = db.get_edges()
        for edge in all_edges:
            if edge['from'] in [n['id'] for n in matching_nodes] or \
               edge['to'] in [n['id'] for n in matching_nodes]:
                result['relationships'].append({
                    'from': edge['from'],
                    'to': edge['to'],
                    'relationship': edge['relationship'],
                    'confidence': edge.get('confidence', 0.5)
                })
        
        # Build timeline
        result['timeline'] = self._build_timeline(matching_nodes)
        
        # Stats
        result['total_matches'] = len(matching_nodes)
        result['total_relationships'] = len(result['relationships'])
        result['entity_types'] = list(set(n['type'] for n in result['entities']))
        
        return result
    
    def _build_timeline(self, nodes: List[Dict]) -> List[Dict]:
        """Build timeline of entity appearances"""
        timeline = []
        
        for node in nodes:
            if node.get('created_at'):
                timeline.append({
                    'timestamp': node['created_at'],
                    'event': 'entity_discovered',
                    'entity_id': node['id'],
                    'entity_type': node['entity_type'],
                    'label': node['label']
                })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return timeline[:20]  # Return last 20 events
    
    def query_by_type(self, entity_type: str) -> List[Dict]:
        """Get all entities of a specific type"""
        all_nodes = db.get_nodes()
        return [n for n in all_nodes if n['entity_type'] == entity_type]
    
    def query_by_property(self, property_key: str, property_value: str) -> List[Dict]:
        """Find entities with specific property value"""
        all_nodes = db.get_nodes()
        matches = []
        
        for node in all_nodes:
            props = node.get('properties', {})
            if props.get(property_key) == property_value:
                matches.append(node)
        
        return matches
    
    def get_entity_history(self, entity_id: str) -> Dict:
        """Get complete history of an entity"""
        nodes = [n for n in db.get_nodes() if n['id'] == entity_id]
        if not nodes:
            return {'error': 'Entity not found'}
        
        node = nodes[0]
        
        # Get all transforms executed on this entity
        history = db.get_transform_history()
        entity_transforms = [h for h in history if h['node_id'] == entity_id]
        
        # Get all relationships
        edges = db.get_edges()
        incoming = [e for e in edges if e['to'] == entity_id]
        outgoing = [e for e in edges if e['from'] == entity_id]
        
        return {
            'entity': node,
            'transforms_executed': len(entity_transforms),
            'transform_details': entity_transforms,
            'incoming_relationships': len(incoming),
            'outgoing_relationships': len(outgoing),
            'total_connections': len(incoming) + len(outgoing)
        }
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        all_nodes = db.get_nodes()
        all_edges = db.get_edges()
        history = db.get_transform_history()
        
        # Entity type breakdown
        entity_types = {}
        for node in all_nodes:
            etype = node['entity_type']
            entity_types[etype] = entity_types.get(etype, 0) + 1
        
        # Risk distribution
        risk_high = len([n for n in all_nodes if n.get('risk_score', 0) > 0.7])
        risk_medium = len([n for n in all_nodes if 0.4 <= n.get('risk_score', 0) <= 0.7])
        risk_low = len([n for n in all_nodes if n.get('risk_score', 0) < 0.4])
        
        # Most active entities (by connection count)
        connection_counts = {}
        for edge in all_edges:
            connection_counts[edge['from']] = connection_counts.get(edge['from'], 0) + 1
            connection_counts[edge['to']] = connection_counts.get(edge['to'], 0) + 1
        
        top_entities = sorted(connection_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_entities': len(all_nodes),
            'total_relationships': len(all_edges),
            'total_transforms': len(history),
            'entity_types': entity_types,
            'risk_distribution': {
                'high': risk_high,
                'medium': risk_medium,
                'low': risk_low
            },
            'most_connected_entities': [
                {
                    'entity_id': eid,
                    'connections': count,
                    'label': next((n['label'] for n in all_nodes if n['id'] == eid), 'Unknown')
                }
                for eid, count in top_entities
            ]
        }
    
    def find_paths(self, from_entity: str, to_entity: str, max_depth: int = 3) -> List[List[str]]:
        """
        Find paths between two entities
        
        Args:
            from_entity: Starting entity ID
            to_entity: Target entity ID
            max_depth: Maximum path length
        
        Returns:
            List of paths (each path is a list of entity IDs)
        """
        all_edges = db.get_edges()
        
        # Build adjacency list
        graph = {}
        for edge in all_edges:
            if edge['from'] not in graph:
                graph[edge['from']] = []
            graph[edge['from']].append(edge['to'])
        
        # BFS to find paths
        paths = []
        queue = [([from_entity], from_entity)]
        visited = set()
        
        while queue:
            path, current = queue.pop(0)
            
            if len(path) > max_depth:
                continue
            
            if current == to_entity:
                paths.append(path)
                continue
            
            if current in visited:
                continue
            
            visited.add(current)
            
            for neighbor in graph.get(current, []):
                if neighbor not in path:  # Avoid cycles
                    queue.append((path + [neighbor], neighbor))
        
        return paths[:10]  # Return top 10 paths
    
    def get_related_entities(self, entity_id: str, relationship_type: Optional[str] = None, depth: int = 1) -> List[Dict]:
        """
        Get entities related to given entity
        
        Args:
            entity_id: Starting entity
            relationship_type: Filter by relationship type (optional)
            depth: How many hops (1-3)
        
        Returns:
            List of related entities
        """
        all_edges = db.get_edges()
        all_nodes = db.get_nodes()
        
        related_ids = set()
        current_level = {entity_id}
        
        for _ in range(depth):
            next_level = set()
            for edge in all_edges:
                if relationship_type and edge['relationship'] != relationship_type:
                    continue
                
                if edge['from'] in current_level:
                    next_level.add(edge['to'])
                    related_ids.add(edge['to'])
                elif edge['to'] in current_level:
                    next_level.add(edge['from'])
                    related_ids.add(edge['from'])
            
            current_level = next_level
        
        # Get node details
        related_entities = [
            n for n in all_nodes if n['id'] in related_ids
        ]
        
        return related_entities
