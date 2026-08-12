"""Graph Canvas v2.0 - Interactive Node/Edge Visualization with Risk-Based Styling"""
from PyQt6.QtWidgets import (
    QGraphicsScene, QGraphicsView, QGraphicsEllipseItem, QGraphicsLineItem,
    QGraphicsTextItem, QApplication, QMainWindow, QVBoxLayout, QWidget,
    QGraphicsDropShadowEffect, QGraphicsRectItem
)
from PyQt6.QtCore import Qt, QTimer, QPointF, QEvent, pyqtSignal, QRect
from PyQt6.QtGui import QPen, QBrush, QColor, QFont, QPainter
import math

class NodeItem(QGraphicsEllipseItem):
    def __init__(self, node_id, entity_type, label, x, y, risk_score=0.0, size=50):
        super().__init__(-size/2, -size/2, size, size)
        self.node_id = node_id
        self.entity_type = entity_type
        self.label_text = label
        self.risk_score = risk_score
        
        # 19+ Entity type colors (vibrant palette)
        colors = {
            'email': '#4ECDC4',      # Cyan
            'phone': '#F38181',      # Pink
            'ip': '#FF6B35',         # Orange
            'person': '#95E1D3',     # Mint
            'domain': '#00D9FF',     # Sky Blue
            'username': '#AA96DA',   # Purple
            'url': '#FCBAD3',        # Light Pink
            'hash': '#FFFFD2',       # Light Yellow
            'cve': '#FF5252',        # Red
            'port': '#69F0AE',       # Green
            'company': '#FFD93D',    # Yellow
            'location': '#6BCF7F',   # Light Green
            'cryptocurrency': '#F9A826',  # Gold
            'malware': '#E74C3C',    # Dark Red
            'breach': '#C0392B',     # Crimson
            'certificate': '#9B59B6', # Violet
            'threat': '#E67E22',     # Dark Orange
            'technology': '#3498DB', # Blue
            'transaction': '#1ABC9C', # Turquoise
            # NEW SUB-ENTITY TYPES
            'social_profile': '#E91E63',  # Pink
            'social_platform': '#FF6090',  # Rose
            'paste': '#9C27B0',      # Deep Purple
            'paste_site': '#BA68C8', # Light Purple
            'data_leak': '#F44336',  # Red
            'data_class': '#EF5350', # Light Red
            'phone_property': '#EC407A', # Pink
            'timezone': '#42A5F5',   # Blue
            'asn': '#66BB6A',        # Green
            'network_range': '#26A69A', # Teal
            'service': '#FFA726',    # Orange
            'file': '#8D6E63',       # Brown
            'file_type': '#A1887F', # Light Brown
            'file_size': '#BCAAA4', # Gray Brown
            'exploit': '#D32F2F',    # Dark Red
            'campaign': '#C62828',   # Darker Red
            'threat_actor': '#B71C1C', # Darkest Red
            'patch': '#689F38',      # Light Green
            'version': '#7CB342',    # Green
            'cwe': '#FF5722',        # Deep Orange
            'registry_key': '#795548', # Brown
            'mutex': '#8D6E63',      # Brown
            'behavior': '#FFC107',   # Amber
            'capability': '#FFB300', # Amber
            'yara_rule': '#FF6F00',  # Dark Orange
            'job': '#03A9F4',        # Light Blue
            'education': '#0288D1',  # Blue
            'institution': '#01579B', # Dark Blue
            'image': '#E1BEE7',      # Purple
            'social_post': '#F48FB1', # Pink
            'identity_cluster': '#AB47BC', # Purple
            'nameserver': '#00ACC1', # Cyan
            'mail_server': '#0097A7', # Dark Cyan
            'certificate_authority': '#7B1FA2', # Purple
            'threat_report': '#D84315', # Red Orange
            'balance': '#FDD835',    # Yellow
            'currency': '#F9A825',   # Dark Yellow
            'abuse_report': '#BF360C', # Dark Orange
            'amount': '#FFD600',     # Bright Yellow
            'timestamp': '#00BCD4',  # Cyan
            'indicator': '#FF9800',  # Orange
            'tag': '#9E9E9E',        # Gray
            'report': '#607D8B',      # Blue Gray
            'payment_profile': '#00b894',  # Green
        }
        
        base_color = colors.get(entity_type, '#00D9FF')
        
        # Risk-based color intensity
        if risk_score > 0.7:
            # Critical - Red tint
            self.setBrush(QBrush(QColor('#FF4444')))
            border_color = '#FF0000'
            border_width = 4
        elif risk_score > 0.5:
            # High - Orange tint
            self.setBrush(QBrush(QColor('#FF8844')))
            border_color = '#FF6600'
            border_width = 3
        elif risk_score > 0.3:
            # Medium - Yellow tint
            self.setBrush(QBrush(QColor(base_color)))
            border_color = '#FFAA00'
            border_width = 2
        else:
            # Low - Normal color
            self.setBrush(QBrush(QColor(base_color)))
            border_color = '#FFFFFF'
            border_width = 2
        
        self.setPen(QPen(QColor(border_color), border_width))
        self.setPos(x, y)
        
        # Make interactive
        self.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        
        # Add glow effect for high-risk nodes
        if risk_score > 0.7:
            glow = QGraphicsDropShadowEffect()
            glow.setBlurRadius(20)
            glow.setColor(QColor('#FF0000'))
            glow.setOffset(0, 0)
            self.setGraphicsEffect(glow)
        
        # Label with entity icon
        icon_map = {
            'email': 'E', 'phone': 'P', 'ip': 'IP', 'person': 'U',
            'domain': 'D', 'username': 'UN', 'url': 'URL', 'hash': 'H',
            'cve': 'CVE', 'port': 'PT', 'company': 'C', 'location': 'L',
            'cryptocurrency': '$', 'malware': 'M', 'breach': 'B',
            'certificate': 'CT', 'threat': 'T', 'technology': 'TK',
            'transaction': '💸',
            # NEW SUB-ENTITY ICONS
            'social_profile': 'SP', 'social_platform': 'PF', 'paste': 'PS',
            'paste_site': 'PST', 'data_leak': 'DL', 'data_class': 'DC',
            'phone_property': 'PP', 'timezone': 'TZ', 'asn': 'AS',
            'network_range': 'NR', 'service': 'SV', 'file': 'F',
            'file_type': 'FT', 'file_size': 'SZ', 'exploit': 'EX',
            'campaign': 'CM', 'threat_actor': 'TA', 'patch': 'PX',
            'version': 'V', 'cwe': 'CW', 'registry_key': 'RK',
            'mutex': 'MX', 'behavior': 'BH', 'capability': 'CP',
            'yara_rule': 'YR', 'job': 'JB', 'education': 'ED',
            'institution': 'IN', 'image': 'IM', 'social_post': 'SO',
            'identity_cluster': 'IC', 'nameserver': 'NS', 'mail_server': 'MX',
            'certificate_authority': 'CA', 'threat_report': 'TR',
            'balance': 'BL', 'currency': 'CR', 'abuse_report': 'AR',
            'amount': 'AM', 'timestamp': 'TS', 'indicator': 'ID',
            'tag': 'TG', 'report': 'RP', 'cloud_provider': 'CL',
            'malware_type': 'MT', 'payment_profile': '💳'
        }
        
        icon = icon_map.get(entity_type, '🔹')
        display_label = f"{icon} {label[:30]}"  # Truncate long labels
        
        self.label = QGraphicsTextItem(display_label, self)
        self.label.setDefaultTextColor(QColor('#FFFFFF'))
        self.label.setFont(QFont('Segoe UI', 9, QFont.Weight.Bold))
        
        # Add shadow to label for better readability
        label_shadow = QGraphicsDropShadowEffect()
        label_shadow.setBlurRadius(5)
        label_shadow.setColor(QColor('#000000'))
        label_shadow.setOffset(1, 1)
        self.label.setGraphicsEffect(label_shadow)
        
        label_rect = self.label.boundingRect()
        self.label.setPos(-label_rect.width()/2, size/2 + 5)
        
        self.edges = []
    
    def add_edge(self, edge):
        self.edges.append(edge)
    
    def itemChange(self, change, value):
        if change == QGraphicsEllipseItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self.edges:
                edge.update_position()
            from sentinel_intel.core.database import db
            db.update_node(self.node_id, x=self.scenePos().x(), y=self.scenePos().y())
        return super().itemChange(change, value)
    
    def hoverEnterEvent(self, event):
        """Highlight on hover"""
        self.setPen(QPen(QColor('#00FFFF'), 4))
        super().hoverEnterEvent(event)
    
    def hoverLeaveEvent(self, event):
        """Remove highlight"""
        border_color = '#FF0000' if self.risk_score > 0.7 else '#FF6600' if self.risk_score > 0.5 else '#FFAA00' if self.risk_score > 0.3 else '#FFFFFF'
        border_width = 4 if self.risk_score > 0.7 else 3 if self.risk_score > 0.5 else 2
        self.setPen(QPen(QColor(border_color), border_width))
        super().hoverLeaveEvent(event)

class EdgeItem(QGraphicsLineItem):
    def __init__(self, from_node, to_node, relationship, confidence=1.0):
        super().__init__()
        self.from_node = from_node
        self.to_node = to_node
        self.relationship = relationship
        self.confidence = confidence
        
        # Edge styling based on confidence
        width = max(1, int(confidence * 3))
        alpha = int(confidence * 200)
        
        # Color based on confidence
        if confidence > 0.8:
            color = QColor(0, 217, 255, alpha)  # Cyan - High confidence
        elif confidence > 0.6:
            color = QColor(78, 205, 196, alpha)  # Teal - Medium confidence
        else:
            color = QColor(170, 150, 218, alpha)  # Purple - Low confidence
        
        pen = QPen(color, width)
        pen.setStyle(Qt.PenStyle.SolidLine if confidence > 0.7 else Qt.PenStyle.DashLine)
        self.setPen(pen)
        self.setZValue(-1)
        
        # Relationship label
        self.label = QGraphicsTextItem(relationship)
        self.label.setDefaultTextColor(QColor('#CCCCCC'))
        self.label.setFont(QFont('Segoe UI', 7))
        
        # Label background for readability
        label_bg = QGraphicsRectItem(self.label.boundingRect(), self.label)
        label_bg.setBrush(QBrush(QColor(22, 33, 62, 180)))
        label_bg.setPen(QPen(Qt.PenStyle.NoPen))
        label_bg.setZValue(-1)
        
        from_node.add_edge(self)
        to_node.add_edge(self)
        self.update_position()
    
    def update_position(self):
        from_pos = self.from_node.scenePos()
        to_pos = self.to_node.scenePos()
        
        self.setLine(from_pos.x(), from_pos.y(), to_pos.x(), to_pos.y())
        
        # Position label at midpoint
        mid_x = (from_pos.x() + to_pos.x()) / 2
        mid_y = (from_pos.y() + to_pos.y()) / 2
        label_rect = self.label.boundingRect()
        self.label.setPos(mid_x - label_rect.width()/2, mid_y - label_rect.height()/2)

class GraphCanvas(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        
        # Modern dark background with gradient
        self.setStyleSheet("""
            QGraphicsView {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0e27, stop:1 #16213e);
                border: 2px solid #00D9FF;
                border-radius: 8px;
            }
        """)
        
        self.scene.setBackgroundBrush(QBrush(QColor('#0a0e27')))
        
        # Enable antialiasing for smooth graphics
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        
        # Enable drag mode
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        
        self.nodes = {}
        self.edges = {}
        self.zoom_level = 1.0
    
    def add_node(self, node_id, entity_type, label, properties=None, x=0, y=0):
        if node_id in self.nodes:
            return
        
        # Random position if not specified
        if x == 0 and y == 0:
            import random
            x = random.randint(-400, 400)
            y = random.randint(-400, 400)
        
        # Get risk score from properties
        risk_score = properties.get('risk_score', 0.0) if properties else 0.0
        
        # Create node with risk-based styling
        node = NodeItem(node_id, entity_type, label, x, y, risk_score)
        self.scene.addItem(node)
        self.nodes[node_id] = node
    
    def add_edge(self, from_id, to_id, relationship, confidence=1.0):
        if from_id not in self.nodes or to_id not in self.nodes:
            return
        
        edge_id = f"{from_id}_{to_id}_{relationship}"
        if edge_id in self.edges:
            return
        
        edge = EdgeItem(self.nodes[from_id], self.nodes[to_id], relationship, confidence)
        self.scene.addItem(edge)
        self.edges[edge_id] = edge
    
    def clear(self):
        for edge in list(self.edges.values()):
            try:
                if edge.scene():
                    self.scene.removeItem(edge)
            except Exception:
                pass
        for node in list(self.nodes.values()):
            try:
                if node.scene():
                    self.scene.removeItem(node)
            except Exception:
                pass
        self.nodes.clear()
        self.edges.clear()
        self.scene.clear()
    
    def auto_layout(self):
        """Circular layout algorithm"""
        if not self.nodes:
            return
        
        nodes = list(self.nodes.values())
        n = len(nodes)
        radius = max(300, n * 40)
        
        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / n
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)
            node.setPos(x, y)
        
        self.center_view()
    
    def center_view(self):
        """Center and fit view to graph"""
        if self.nodes:
            self.fitInView(self.scene.itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)
            self.zoom_level = 1.0
    
    def zoom_in(self):
        """Zoom in"""
        self.zoom_level *= 1.2
        self.scale(1.2, 1.2)
    
    def zoom_out(self):
        """Zoom out"""
        self.zoom_level /= 1.2
        self.scale(1/1.2, 1/1.2)
    
    def wheelEvent(self, event):
        """Mouse wheel zoom"""
        if event.angleDelta().y() > 0:
            self.zoom_in()
        else:
            self.zoom_out()
    
    def mousePressEvent(self, event):
        """Handle node selection"""
        super().mousePressEvent(event)
        item = self.itemAt(event.pos())
        
        if isinstance(item, NodeItem):
            self.main_window.properties_panel.update_properties(item.node_id)
        elif isinstance(item, QGraphicsTextItem) and hasattr(item.parentItem(), 'node_id'):
            self.main_window.properties_panel.update_properties(item.parentItem().node_id)
    
    def get_selected_node(self):
        """Get currently selected node ID"""
        for item in self.scene.selectedItems():
            if isinstance(item, NodeItem):
                return item.node_id
        return None

    def highlight_path(self, node_ids: list):
        """Shortest path nodes highlight karo."""
        path_set = set(node_ids)
        for nid, node in self.nodes.items():
            if nid in path_set:
                node.setPen(QPen(QColor('#FFD700'), 4))
            else:
                node.setPen(QPen(QColor('#FFFFFF'), 2))

    def highlight_diff(self, added: list, removed: list):
        """Diff nodes highlight karo — green=added, red=removed."""
        added_ids   = {n['id'] for n in added}
        removed_ids = {n['id'] for n in removed}
        for nid, node in self.nodes.items():
            if nid in added_ids:
                node.setPen(QPen(QColor('#00FF88'), 4))
            elif nid in removed_ids:
                node.setPen(QPen(QColor('#FF4444'), 4))
            else:
                node.setPen(QPen(QColor('#FFFFFF'), 2))
    
    def select_node(self, node_id: str):
        """Programmatically select a node by ID"""
        for item in self.scene.items():
            if isinstance(item, NodeItem) and item.node_id == node_id:
                item.setSelected(True)
                # Trigger properties update
                self.main_window.properties_panel.update_properties(node_id)
                break
    
    def reload_graph(self):
        """Reload graph from database"""
        self.clear()
        from sentinel_intel.core.database import db
        
        nodes = db.get_nodes()
        edges = db.get_edges()
        
        for node in nodes:
            self.add_node(node['id'], node['entity_type'], node['label'], 
                         node['properties'], node['x'], node['y'])
        
        for edge in edges:
            self.add_edge(edge['from_node'], edge['to_node'], 
                         edge['relationship'], edge['confidence'])
    
    def export_png(self):
        """Export graph as PNG image"""
        filename, _ = QFileDialog.getSaveFileName(
            self.main_window, "Export PNG", "", "PNG Files (*.png)"
        )
        
        if filename:
            # Get scene bounding rect
            rect = self.scene.itemsBoundingRect()
            
            # Create high-resolution image
            image = QImage(rect.size().toSize() * 2, QImage.Format.Format_ARGB32)
            image.fill(QColor('#0a0e27'))
            
            # Render scene to image
            painter = QPainter(image)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            self.scene.render(painter, QRectF(image.rect()), rect)
            painter.end()
            
            # Save image
            image.save(filename)
            self.main_window.statusbar.showMessage(f"📤 Exported to {filename}", 3000)
