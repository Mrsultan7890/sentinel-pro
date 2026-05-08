"""Properties Panel - Show Node Details & History"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QTabWidget, QListWidget, QListWidgetItem, QTableWidget, QTableWidgetItem,
    QStyle, QMessageBox, QFileDialog
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QRunnable, QThreadPool
from PyQt6.QtGui import QIcon
import sys
import re
import html
import json
import logging
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from sentinel_intel.core.database import db

logger = logging.getLogger(__name__)

class PropertiesPanel(QWidget):
    # Signals for thread updates
    history_updated = pyqtSignal(list)
    groq_data_updated = pyqtSignal(dict)
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.current_node_id = None
        self.thread_pool = QThreadPool()
        
        # Connect signals
        self.history_updated.connect(self._on_history_updated)
        self.groq_data_updated.connect(self._on_groq_updated)
        
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
    
    def _on_history_updated(self, history: list):
        """Handle history update signal"""
        self.history_list.clear()
        for item in history:
            self.history_list.addItem(f"{item.get('timestamp', 'N/A')}: {item.get('transform', 'Unknown')}")
    
    def _on_groq_updated(self, groq_data: dict):
        """Handle Groq data update signal"""
        self._update_groq_analysis_safe({'properties': {'groq_analysis': groq_data}})
    
    def _get_node_safe(self, node_id: str):
        """Safely get node from database"""
        try:
            nodes = db.get_nodes()
            for node in nodes:
                if node.get('id') == node_id:
                    return node
            return None
        except Exception as e:
            logger.error(f"Error getting node: {e}")
            return None
    
    def _load_history_async(self, node_id: str):
        """Load history asynchronously"""
        try:
            if hasattr(db, 'get_transform_history'):
                history = db.get_transform_history(node_id)
                self.history_updated.emit(history if history else [])
        except Exception as e:
            logger.error(f"Error loading history: {e}")
    
    def _update_groq_analysis_safe(self, node: dict):
        """Safely update Groq analysis"""
        try:
            groq_data = node.get('properties', {}).get('groq_analysis')
            if not groq_data:
                self.groq_analysis_text.setHtml("""
                    <div style='text-align: center; padding: 50px;'>
                        <h2 style='color: #00D9FF;'>🤖 Groq AI Analysis</h2>
                        <p style='color: #888;'>No AI analysis available yet.</p>
                    </div>
                """)
                return
            
            html_content = "<div style='padding: 10px;'>"
            html_content += "<h2 style='color: #00D9FF;'>🤖 Groq AI Analysis</h2>"
            
            assessment = groq_data.get('assessment', '')
            if assessment:
                html_content += f"<p style='color: #E0E0E0;'>{html.escape(assessment)}</p>"
            
            html_content += "</div>"
            self.groq_analysis_text.setHtml(html_content)
        except Exception as e:
            logger.error(f"Error updating Groq analysis: {e}")
    
    def update_properties(self, node_id: str):
        """Update properties panel for node (with error handling)"""
        try:
            # Direct query instead of filter all nodes
            node = self._get_node_safe(node_id)
            if not node:
                self.properties_text.setHtml("<p style='color: red;'>Node not found</p>")
                return
            
            self.current_node_id = node_id
        
            # Format properties with HTML escaping for safety
            text = f"<h3 style='color: #00D9FF;'>{html.escape(str(node.get('label', 'Unknown')))}</h3>"
            text += f"<p><b>Type:</b> <span style='color: #4ECDC4;'>{html.escape(str(node.get('entity_type', 'N/A')))}</span></p>"
            node_id_display = html.escape(node.get('id', '')[:16] + '...')
            text += f"<p><b>ID:</b> <span style='color: #888;'>{node_id_display}</span></p>"
            
            confidence = node.get('confidence', 0)
            text += f"<p><b>Confidence:</b> {float(confidence):.0%}</p>"
            
            # Risk score with color
            risk_score = float(node.get('risk_score', 0))
            risk_color = 'red' if risk_score > 0.7 else 'yellow' if risk_score > 0.4 else 'green'
            text += f"<p><b>Risk Score:</b> <span style='color: {risk_color}; font-weight: bold;'>{risk_score:.0%}</span></p>"
            
            # ML Cluster
            ml_cluster = node.get('ml_cluster', -1)
            if ml_cluster >= 0:
                text += f"<p><b>ML Cluster:</b> <span style='color: #AA96DA;'>#{int(ml_cluster)}</span></p>"
            
            # Properties (safely escaped)
            props = node.get('properties', {})
            if props and isinstance(props, dict):
                text += "<h4 style='color: #00D9FF;'>Properties:</h4><ul>"
                for key, value in props.items():
                    safe_key = html.escape(str(key))
                    safe_value = html.escape(str(value))
                    text += f"<li><b>{safe_key}:</b> {safe_value}</li>"
                text += "</ul>"
            
            # Notes (safely escaped)
            notes = node.get('notes')
            if notes:
                safe_notes = html.escape(str(notes))
                text += f"<h4 style='color: #00D9FF;'>Notes:</h4><p>{safe_notes}</p>"
            
            self.properties_text.setHtml(text)
            
            # Update Groq Analysis if available
            self._update_groq_analysis_safe(node)
            
            # Load history asynchronously (don't block UI)
            self._load_history_async(node_id)
        
        except Exception as e:
            logger.error(f"Error updating properties for node {node_id}: {e}", exc_info=True)
            self.properties_text.setHtml(f"<p style='color: red;'>Error: {html.escape(str(e))}</p>")
    
    
    def clear_history(self):
        """Clear transform history for current node"""
        if not self.current_node_id:
            QMessageBox.warning(self, 'Warning', 'No node selected')
            return
        
        reply = QMessageBox.question(self, 'Clear History',
                                    'Clear all transform history for this node?',
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                if hasattr(db, 'clear_transform_history'):
                    db.clear_transform_history(self.current_node_id)
                    self.history_list.clear()
                    QMessageBox.information(self, 'Success', 'History cleared!')
                else:
                    QMessageBox.warning(self, 'Error', 'Database does not support history clearing')
            except Exception as e:
                logger.error(f"Error clearing history: {e}", exc_info=True)
                QMessageBox.critical(self, 'Error', f"Failed to clear history: {e}")
    
    
    def export_properties(self):
        """Export node properties to JSON"""
        if not self.current_node_id:
            QMessageBox.warning(self, 'Warning', 'No node selected')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, 'Export Properties',
                                                 f'node_{self.current_node_id[:8]}.json',
                                                 'JSON Files (*.json)')
        if filename:
            try:
                node = self._get_node_safe(self.current_node_id)
                if node:
                    with open(filename, 'w') as f:
                        json.dump(node, f, indent=2, default=str)
                    QMessageBox.information(self, 'Success', f'Exported to {filename}')
                else:
                    QMessageBox.warning(self, 'Error', 'Node not found')
            except Exception as e:
                logger.error(f"Error exporting properties: {e}", exc_info=True)
                QMessageBox.critical(self, 'Error', f"Failed to export: {e}")
    
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
        
    def update_groq_analysis(self, node: dict):
        """Update Groq AI Analysis tab with node's Groq data"""
        self._update_groq_analysis_safe(node)


class HistorySignals:
    """Signals for history worker thread"""
    result = pyqtSignal(list)
    error = pyqtSignal(str)


class HistoryWorker(QRunnable):
    """Worker to load transform history asynchronously"""
    def __init__(self, node_id: str, database):
        super().__init__()
        self.node_id = node_id
        self.db = database
        self.signals = HistorySignals()
    
    def run(self):
        try:
            if hasattr(self.db, 'get_transform_history'):
                history = self.db.get_transform_history(self.node_id)
                self.signals.result.emit(history if history else [])
            else:
                self.signals.result.emit([])
        except Exception as e:
            logger.error(f"Error loading history: {e}", exc_info=True)
            self.signals.error.emit(str(e))
