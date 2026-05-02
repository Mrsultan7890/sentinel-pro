"""Entity Palette v2.0 - 15+ Entity Types"""
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from sentinel_intel.core.database import db

class EntityPalette(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        
        # Search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search entities...")
        layout.addWidget(self.search_box)
        
        # Entity types (15+)
        entities = [
            ('Email', 'email'),
            ('Phone', 'phone'),
            ('IP Address', 'ip'),
            ('Person', 'person'),
            ('Domain', 'domain'),
            ('Username', 'username'),
            ('Hash', 'hash'),
            ('Cryptocurrency', 'cryptocurrency'),
            ('Company', 'company'),
            ('Location', 'location'),
            ('URL', 'url'),
            ('CVE', 'cve'),
            ('Malware', 'malware'),
            ('Breach', 'breach'),
            ('🔌 Port', 'port')
        ]
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        for label, entity_type in entities:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, t=entity_type: self._add_entity(t))
            btn.setToolTip(f"Add {entity_type} entity to graph")
            scroll_layout.addWidget(btn)
        
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)
        
        # Quick add section
        layout.addWidget(QLabel("Quick Add:"))
        self.quick_input = QLineEdit()
        self.quick_input.setPlaceholderText("Enter value...")
        self.quick_input.returnPressed.connect(self._quick_add)
        layout.addWidget(self.quick_input)
        
        quick_btn = QPushButton("➕ Auto-Detect & Add")
        quick_btn.clicked.connect(self._quick_add)
        layout.addWidget(quick_btn)
    
    def _add_entity(self, entity_type: str):
        value, ok = QInputDialog.getText(self, f'Add {entity_type}', f'Enter {entity_type} value:')
        if ok and value:
            node_id = db.add_node(entity_type, value, {})
            self.main_window.canvas.add_node(node_id, entity_type, value)
            self.main_window.statusbar.showMessage(f"Added {entity_type}: {value}", 3000)
    
    def _quick_add(self):
        value = self.quick_input.text().strip()
        if not value:
            return
        
        # Auto-detect entity type
        entity_type = self._detect_entity_type(value)
        
        node_id = db.add_node(entity_type, value, {})
        self.main_window.canvas.add_node(node_id, entity_type, value)
        self.main_window.statusbar.showMessage(f"Added {entity_type}: {value}", 3000)
        self.quick_input.clear()
    
    def _detect_entity_type(self, value: str) -> str:
        """Auto-detect entity type from value"""
        import re
        
        # Email
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return 'email'
        
        # Phone
        if re.match(r'^\+?[0-9\s\-\(\)]{10,}$', value):
            return 'phone'
        
        # IP Address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return 'ip'
        
        # Domain
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value) and '@' not in value:
            return 'domain'
        
        # Hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'hash'  # MD5
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return 'hash'  # SHA1
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return 'hash'  # SHA256
        
        # Cryptocurrency
        if value.startswith('0x') and len(value) == 42:
            return 'cryptocurrency'  # Ethereum
        if value.startswith(('1', '3', 'bc1')):
            return 'cryptocurrency'  # Bitcoin
        
        # URL
        if value.startswith(('http://', 'https://', 'ftp://')):
            return 'url'
        
        # CVE
        if re.match(r'^CVE-\d{4}-\d{4,}$', value, re.IGNORECASE):
            return 'cve'
        
        # Default to username
        return 'username'
