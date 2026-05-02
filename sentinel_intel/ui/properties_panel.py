"""Properties Panel - Show Node Details & History"""
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import QIcon
import sys
import re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from sentinel_intel.core.database import db

class PropertiesPanel(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        
        self.properties_text = QTextEdit()
        self.properties_text.setReadOnly(True)
        self.properties_text.setPlaceholderText("Select a node to view properties...")
        
        self.history_list = QListWidget()
        
        # Groq Analysis Tab
        self.groq_analysis_text = QTextEdit()
        self.groq_analysis_text.setReadOnly(True)
        self.groq_analysis_text.setPlaceholderText("🤖 Groq AI Analysis will appear here...\n\nRun a transform to see AI-powered insights.")
        self.groq_analysis_text.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a2e;
                color: #E0E0E0;
                border: 1px solid #00D9FF;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11pt;
            }
        """)
        
        tabs = QTabWidget()
        tabs.addTab(self.properties_text, "📋 Properties")
        tabs.addTab(self.history_list, "📜 History")
        tabs.addTab(self.groq_analysis_text, "🤖 Groq AI")
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Clear History")
        self.clear_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_TrashIcon))
        self.clear_btn.clicked.connect(self.clear_history)
        self.export_btn = QPushButton("Export")
        self.export_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))
        self.export_btn.clicked.connect(self.export_properties)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addStretch()
        
        layout.addWidget(tabs)
        layout.addLayout(btn_layout)
    
    def update_properties(self, node_id: str):
        nodes = [n for n in db.get_nodes() if n['id'] == node_id]
        if not nodes:
            return
        
        node = nodes[0]
        
        # Format properties with colors
        text = f"<h3 style='color: #00D9FF;'>{node['label']}</h3>"
        text += f"<p><b>Type:</b> <span style='color: #4ECDC4;'>{node['entity_type']}</span></p>"
        text += f"<p><b>ID:</b> <span style='color: #888;'>{node['id'][:16]}...</span></p>"
        text += f"<p><b>Confidence:</b> {node['confidence']:.0%}</p>"
        
        # Risk score with color
        risk_color = 'red' if node['risk_score'] > 0.7 else 'yellow' if node['risk_score'] > 0.4 else 'green'
        text += f"<p><b>Risk Score:</b> <span style='color: {risk_color}; font-weight: bold;'>{node['risk_score']:.0%}</span></p>"
        
        # ML Cluster
        if node['ml_cluster'] >= 0:
            text += f"<p><b>ML Cluster:</b> <span style='color: #AA96DA;'>#{node['ml_cluster']}</span></p>"
        
        # Properties
        if node['properties']:
            text += "<h4 style='color: #00D9FF;'>Properties:</h4><ul>"
            for key, value in node['properties'].items():
                text += f"<li><b>{key}:</b> {value}</li>"
            text += "</ul>"
        
        # Notes
        if node.get('notes'):
            text += f"<h4 style='color: #00D9FF;'>Notes:</h4><p>{node['notes']}</p>"
        
        self.properties_text.setHtml(text)
        
        # Update Groq Analysis if available
        self.update_groq_analysis(node)
        
        # Update history
        self.history_list.clear()
        self.current_node_id = node_id
        history = db.get_transform_history(node_id)
        for item in history:
            ml_badge = "[ML]" if item['ml_enhanced'] else ""
            self.history_list.addItem(
                f"{item['transform_name']} → {item['result_count']} results | "
                f"{item['api_used'] or 'N/A'} | {item['execution_time']:.2f}s {ml_badge}"
            )
    
    def clear_history(self):
        """Clear transform history for current node"""
        if not hasattr(self, 'current_node_id'):
            return
        
        reply = QMessageBox.question(self, 'Clear History',
                                    'Clear all transform history for this node?',
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            db.clear_transform_history(self.current_node_id)
            self.history_list.clear()
            QMessageBox.information(self, 'Success', 'History cleared!')
    
    def export_properties(self):
        """Export node properties to JSON"""
        if not hasattr(self, 'current_node_id'):
            return
        
        from PyQt6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Properties',
                                                 f'node_{self.current_node_id[:8]}.json',
                                                 'JSON Files (*.json)')
        if filename:
            nodes = [n for n in db.get_nodes() if n['id'] == self.current_node_id]
            if nodes:
                with open(filename, 'w') as f:
                    json.dump(nodes[0], f, indent=2, default=str)
                QMessageBox.information(self, 'Success', f'Exported to {filename}')
    
    def update_groq_analysis(self, node: dict):
        """Update Groq AI Analysis tab with node's Groq data"""
        groq_data = node.get('properties', {}).get('groq_analysis')
        
        if not groq_data:
            self.groq_analysis_text.setHtml("""
                <div style='text-align: center; padding: 50px;'>
                    <h2 style='color: #00D9FF;'>🤖 Groq AI Analysis</h2>
                    <p style='color: #888; font-size: 12pt;'>No AI analysis available for this node yet.</p>
                    <p style='color: #666; font-size: 10pt;'>Run a transform to generate AI-powered insights.</p>
                </div>
            """)
            return
        
        # Format Groq analysis with rich HTML
        html = "<div style='padding: 10px;'>"
        html += "<h2 style='color: #00D9FF; border-bottom: 2px solid #00D9FF; padding-bottom: 5px;'>🤖 Groq AI Analysis</h2>"
        
        # Timestamp
        if groq_data.get('timestamp'):
            import datetime
            ts = datetime.datetime.fromtimestamp(groq_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            html += f"<p style='color: #888; font-size: 9pt;'>Generated: {ts}</p>"
        
        # Main assessment
        assessment = groq_data.get('assessment', '')
        if assessment:
            # Parse and format the assessment
            lines = assessment.split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Headers (numbered or with colons)
                if re.match(r'^\d+\.', line) or line.endswith(':'):
                    html += f"<h3 style='color: #4ECDC4; margin-top: 15px;'>{line}</h3>"
                # Risk levels
                elif 'CRITICAL' in line.upper():
                    html += f"<p style='color: #FF4444; font-weight: bold;'>🔴 {line}</p>"
                elif 'HIGH' in line.upper():
                    html += f"<p style='color: #FF8844; font-weight: bold;'>🟠 {line}</p>"
                elif 'MEDIUM' in line.upper():
                    html += f"<p style='color: #FFAA00; font-weight: bold;'>🟡 {line}</p>"
                elif 'LOW' in line.upper():
                    html += f"<p style='color: #4ECDC4;'>🟢 {line}</p>"
                # Bullet points
                elif line.startswith('-') or line.startswith('•'):
                    html += f"<p style='margin-left: 20px; color: #E0E0E0;'>• {line[1:].strip()}</p>"
                # Regular text
                else:
                    html += f"<p style='color: #E0E0E0;'>{line}</p>"
        
        # Additional fields
        for key in ['threat_analysis', 'security_analysis', 'identity_analysis', 
                    'pattern_analysis', 'malware_analysis', 'crypto_forensics']:
            if key in groq_data:
                title = key.replace('_', ' ').title()
                html += f"<h3 style='color: #AA96DA; margin-top: 20px; border-top: 1px solid #444; padding-top: 10px;'>{title}</h3>"
                html += f"<p style='color: #E0E0E0;'>{groq_data[key]}</p>"
        
        html += "</div>"
        self.groq_analysis_text.setHtml(html)
