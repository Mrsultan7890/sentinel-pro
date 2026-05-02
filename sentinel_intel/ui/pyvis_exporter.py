"""PyVis Interactive Graph Exporter v1.0 - HTML Interactive Visualization"""
from pyvis.network import Network
from pathlib import Path

class PyVisExporter:
    def __init__(self):
        self.output_dir = Path(__file__).resolve().parents[2] / 'reports'
        self.output_dir.mkdir(exist_ok=True)
    
    def export_graph(self, nodes_data, edges_data, filename='sentinel_graph.html'):
        """Export graph to interactive HTML using PyVis"""
        
        # Create network with dark theme
        net = Network(
            height='900px',
            width='100%',
            bgcolor='#0a0e27',
            font_color='#ffffff',
            directed=True
        )
        
        # Physics settings for better layout
        net.set_options("""
        {
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -30000,
              "centralGravity": 0.3,
              "springLength": 200,
              "springConstant": 0.04,
              "damping": 0.09,
              "avoidOverlap": 0.5
            },
            "stabilization": {
              "enabled": true,
              "iterations": 1000
            }
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "navigationButtons": true,
            "keyboard": {
              "enabled": true
            }
          },
          "nodes": {
            "font": {
              "size": 14,
              "face": "Segoe UI"
            },
            "borderWidth": 2,
            "shadow": true
          },
          "edges": {
            "smooth": {
              "type": "continuous"
            },
            "arrows": {
              "to": {
                "enabled": true,
                "scaleFactor": 0.5
              }
            },
            "font": {
              "size": 10,
              "align": "middle"
            }
          }
        }
        """)
        
        # Entity type colors and emojis
        colors = {
            'email': '#4ECDC4', 'phone': '#F38181', 'ip': '#FF6B35',
            'person': '#95E1D3', 'domain': '#00D9FF', 'username': '#AA96DA',
            'url': '#FCBAD3', 'hash': '#FFFFD2', 'cve': '#FF5252',
            'port': '#69F0AE', 'company': '#FFD93D', 'location': '#6BCF7F',
            'cryptocurrency': '#F9A826', 'malware': '#E74C3C', 'breach': '#C0392B',
            'certificate': '#9B59B6', 'threat': '#E67E22', 'technology': '#3498DB',
            'transaction': '#1ABC9C'
        }
        
        icons = {
            'email': 'E', 'phone': 'P', 'ip': 'IP', 'person': 'U',
            'domain': 'D', 'username': 'UN', 'url': 'URL', 'hash': 'H',
            'cve': 'CVE', 'port': 'PT', 'company': 'C', 'location': 'L',
            'cryptocurrency': '$', 'malware': 'M', 'breach': 'B',
            'certificate': 'CT', 'threat': 'T', 'technology': 'TK',
            'transaction': '💸'
        }
        
        # Add nodes
        for node in nodes_data:
            node_id = node['id']
            entity_type = node['entity_type']
            label = node['label']
            props = node.get('properties', {})
            risk_score = props.get('risk_score', 0.0)
            
            # Risk-based color
            if risk_score > 0.7:
                color = '#FF4444'
                border_color = '#FF0000'
                size = 35
            elif risk_score > 0.5:
                color = '#FF8844'
                border_color = '#FF6600'
                size = 30
            elif risk_score > 0.3:
                color = colors.get(entity_type, '#00D9FF')
                border_color = '#FFAA00'
                size = 25
            else:
                color = colors.get(entity_type, '#00D9FF')
                border_color = '#FFFFFF'
                size = 20
            
            # Build tooltip
            icon = icons.get(entity_type, '🔹')
            tooltip = f"{icon} {label}\n\nType: {entity_type}\nRisk: {risk_score:.2f}"
            
            if props:
                tooltip += "\n\nProperties:"
                for k, v in list(props.items())[:10]:  # Limit to 10 props
                    if k != 'risk_score':
                        tooltip += f"\n• {k}: {v}"
            
            net.add_node(
                node_id,
                label=f"{icon} {label[:30]}",
                title=tooltip,
                color={'background': color, 'border': border_color},
                size=size,
                borderWidth=3 if risk_score > 0.5 else 2
            )
        
        # Add edges
        for edge in edges_data:
            from_id = edge['from_node']
            to_id = edge['to_node']
            relationship = edge['relationship']
            confidence = edge.get('confidence', 1.0)
            
            # Edge color based on confidence
            if confidence > 0.8:
                edge_color = '#00D9FF'
                width = 3
            elif confidence > 0.6:
                edge_color = '#4ECDC4'
                width = 2
            else:
                edge_color = '#AA96DA'
                width = 1
            
            net.add_edge(
                from_id,
                to_id,
                label=relationship,
                title=f"{relationship} (confidence: {confidence:.2f})",
                color=edge_color,
                width=width,
                dashes=False if confidence > 0.7 else True
            )
        
        # Save to file
        output_path = self.output_dir / filename
        net.save_graph(str(output_path))
        
        return str(output_path)
