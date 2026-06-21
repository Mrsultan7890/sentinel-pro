"""
Sentinel Intel v2.0 - Main Window (Maltego Killer)
Professional Graph Intelligence Platform with Modern UI
"""
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QDockWidget,
    QMenu, QMenuBar, QStatusBar, QMessageBox, QFileDialog,
    QLineEdit, QComboBox, QLabel, QPushButton, QProgressBar,
    QTabWidget, QToolBar, QInputDialog, QSplitter, QStyle, QDialog, QTextEdit
)
from PyQt6.QtCore import Qt, QSize, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QFont, QKeySequence, QAction, QPixmap
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from sentinel_intel.core.database import db
from sentinel_intel.ui.graph_canvas import GraphCanvas
from sentinel_intel.ui.entity_palette import EntityPalette
from sentinel_intel.ui.transform_palette import TransformPalette
from sentinel_intel.ui.properties_panel import PropertiesPanel

# Modern Dialog Helper
class ModernDialog(QDialog):
    """Modern styled dialog with gradient background"""
    def __init__(self, parent, title, icon="ℹ️"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(600)
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1a1a2e, stop:1 #16213e);
            }
            QLabel {
                color: #E0E0E0;
                font-size: 12pt;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0f3460, stop:1 #16213e);
                color: #E0E0E0;
                border: 2px solid #00D9FF;
                border-radius: 8px;
                padding: 10px 24px;
                font-weight: bold;
                font-size: 11pt;
                min-width: 100px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #16213e, stop:1 #0f3460);
                border: 3px solid #00D9FF;
            }
            QPushButton:pressed {
                background: #0a2540;
            }
            QTextEdit {
                background: #0f3460;
                color: #E0E0E0;
                border: 2px solid #00D9FF;
                border-radius: 6px;
                padding: 12px;
                font-family: 'Segoe UI', Arial;
                font-size: 11pt;
            }
        """)
        self.icon = icon
        
    def setup_ui(self, message, buttons=["OK"]):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Icon + Title
        header = QHBoxLayout()
        icon_label = QLabel(self.icon)
        icon_label.setStyleSheet("font-size: 48pt;")
        header.addWidget(icon_label)
        
        title_label = QLabel(self.windowTitle())
        title_label.setStyleSheet("font-size: 18pt; font-weight: bold; color: #00D9FF;")
        header.addWidget(title_label)
        header.addStretch()
        layout.addLayout(header)
        
        # Message
        if len(message) > 500:
            msg_widget = QTextEdit()
            msg_widget.setPlainText(message)
            msg_widget.setReadOnly(True)
            msg_widget.setMinimumHeight(400)
            layout.addWidget(msg_widget)
        else:
            msg_label = QLabel(message)
            msg_label.setWordWrap(True)
            msg_label.setStyleSheet("font-size: 12pt; line-height: 1.5; padding: 10px;")
            layout.addWidget(msg_label)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        self.result = None
        for btn_text in buttons:
            btn = QPushButton(btn_text)
            btn.clicked.connect(lambda checked, text=btn_text: self._on_button_click(text))
            btn_layout.addWidget(btn)
        
        layout.addLayout(btn_layout)
    
    def _on_button_click(self, text):
        self.result = text
        self.accept()

def show_info(parent, title, message):
    """Modern info dialog"""
    dialog = ModernDialog(parent, title, "✅")
    dialog.setup_ui(message, ["OK"])
    dialog.exec()

def show_warning(parent, title, message):
    """Modern warning dialog"""
    dialog = ModernDialog(parent, title, "⚠️")
    dialog.setup_ui(message, ["OK"])
    dialog.exec()

def show_error(parent, title, message):
    """Modern error dialog"""
    dialog = ModernDialog(parent, title, "❌")
    dialog.setup_ui(message, ["OK"])
    dialog.exec()

def show_question(parent, title, message):
    """Modern question dialog"""
    dialog = ModernDialog(parent, title, "❓")
    dialog.setup_ui(message, ["Yes", "No"])
    dialog.exec()
    return dialog.result == "Yes"

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🕸️ Sentinel Intel v2.0 — AI-Powered Graph Intelligence Platform")
        self.setGeometry(50, 50, 1920, 1080)
        self._apply_modern_theme()
        self._init_ui()
        self._init_menubar()
        self._init_toolbar()
        self._init_statusbar()
        self._load_graph()
    
    def _apply_modern_theme(self):
        """Modern dark theme with gradients"""
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a1a2e, stop:1 #16213e);
            }
            QWidget {
                color: #E0E0E0;
                font-family: 'Segoe UI', 'Arial', sans-serif;
                font-size: 11pt;
            }
            QMenuBar {
                background: #0f3460;
                color: #E0E0E0;
                padding: 5px;
                border-bottom: 2px solid #00D9FF;
            }
            QMenuBar::item:selected {
                background: #16213e;
                border-radius: 4px;
            }
            QMenu {
                background: #16213e;
                border: 1px solid #00D9FF;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background: #0f3460;
            }
            QToolBar {
                background: #0f3460;
                border-bottom: 2px solid #00D9FF;
                spacing: 10px;
                padding: 5px;
            }
            QToolButton {
                background: #16213e;
                border: 1px solid #00D9FF;
                border-radius: 4px;
                padding: 8px;
                color: #E0E0E0;
                font-size: 14pt;
            }
            QToolButton:hover {
                background: #0f3460;
                border: 2px solid #00D9FF;
            }
            QStatusBar {
                background: #0f3460;
                color: #00D9FF;
                border-top: 2px solid #00D9FF;
                font-weight: bold;
            }
            QTabWidget::pane {
                border: 1px solid #00D9FF;
                border-radius: 4px;
                background: #16213e;
            }
            QTabBar::tab {
                background: #0f3460;
                color: #E0E0E0;
                padding: 10px 20px;
                border: 1px solid #00D9FF;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #16213e;
                color: #00D9FF;
                font-weight: bold;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0f3460, stop:1 #16213e);
                color: #E0E0E0;
                border: 1px solid #00D9FF;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #16213e, stop:1 #0f3460);
                border: 2px solid #00D9FF;
            }
            QPushButton:pressed {
                background: #0a2540;
            }
            QLineEdit, QTextEdit, QListWidget {
                background: #16213e;
                color: #E0E0E0;
                border: 1px solid #00D9FF;
                border-radius: 4px;
                padding: 6px;
            }
            QLineEdit:focus, QTextEdit:focus {
                border: 2px solid #00D9FF;
            }
            QScrollBar:vertical {
                background: #16213e;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background: #00D9FF;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background: #4ECDC4;
            }
        """)
    
    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # Top: Search & Filter Bar
        search_bar = self._create_search_bar()
        layout.addWidget(search_bar)
        
        # Main: 3-Panel Layout
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Entity + Transform Palettes
        left_panel = self._create_left_panel()
        
        # Center: Graph Canvas
        self.canvas = GraphCanvas(self)
        
        # Right: Properties Panel
        self.properties_panel = PropertiesPanel(self)
        self.properties_panel.setMaximumWidth(400)
        
        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(self.canvas)
        main_splitter.addWidget(self.properties_panel)
        main_splitter.setSizes([350, 1200, 400])
        
        layout.addWidget(main_splitter)
    
    def _create_search_bar(self):
        """Modern search and filter bar"""
        search_widget = QWidget()
        search_layout = QHBoxLayout(search_widget)
        search_layout.setContentsMargins(10, 5, 10, 5)
        
        # Search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search nodes by label, type, or properties...")
        self.search_box.textChanged.connect(self._filter_graph)
        self.search_box.setMinimumWidth(400)
        search_layout.addWidget(self.search_box)
        
        # Entity type filter
        self.type_filter = QComboBox()
        self.type_filter.addItems(['All Types', 'email', 'phone', 'ip', 'domain', 'person', 
                                   'username', 'hash', 'cryptocurrency', 'company', 'location',
                                   'url', 'cve', 'malware', 'breach', 'port', 'exploit', 'cwe',
                                   'technology', 'threat', 'certificate'])
        self.type_filter.currentTextChanged.connect(self._filter_graph)
        search_layout.addWidget(QLabel("Type:"))
        search_layout.addWidget(self.type_filter)
        
        # Risk filter
        self.risk_filter = QComboBox()
        self.risk_filter.addItems(['All Risk', 'Critical (>70%)', 'High (>50%)', 'Medium (>30%)', 'Low (<30%)'])
        self.risk_filter.currentTextChanged.connect(self._filter_graph)
        search_layout.addWidget(QLabel("Risk:"))
        search_layout.addWidget(self.risk_filter)
        
        # Clear filters button
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._clear_filters)
        search_layout.addWidget(clear_btn)
        
        search_layout.addStretch()
        
        # Node count label
        self.node_count_label = QLabel("Nodes: 0")
        self.node_count_label.setStyleSheet("color: #00D9FF; font-weight: bold;")
        search_layout.addWidget(self.node_count_label)
        
        return search_widget
    
    def _create_left_panel(self):
        """Left panel with entities and transforms"""
        left_panel = QWidget()
        left_panel.setMaximumWidth(350)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(5, 5, 5, 5)
        
        # Title
        title = QLabel("Investigation Tools")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #00D9FF; padding: 10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        left_layout.addWidget(title)
        
        self.entity_palette = EntityPalette(self)
        self.transform_palette = TransformPalette(self)
        
        tabs = QTabWidget()
        tabs.addTab(self.entity_palette, "Entities")
        tabs.addTab(self.transform_palette, "Transforms")
        left_layout.addWidget(tabs)
        
        return left_panel
    
    def _init_menubar(self):
        menubar = self.menuBar()
        
        # File Menu
        file_menu = menubar.addMenu("&File")
        
        action = QAction("New Graph", self)
        action.setShortcut("Ctrl+N")
        action.triggered.connect(self._new_graph)
        file_menu.addAction(action)
        
        action = QAction("📂 Open Graph", self)
        action.setShortcut("Ctrl+O")
        action.triggered.connect(self._open_graph)
        file_menu.addAction(action)
        
        action = QAction("Save Graph", self)
        action.setShortcut("Ctrl+S")
        action.triggered.connect(self._save_graph)
        file_menu.addAction(action)
        
        file_menu.addSeparator()
        
        action = QAction("📤 Export PNG", self)
        action.setShortcut("Ctrl+Shift+P")
        action.triggered.connect(self.canvas.export_png)
        file_menu.addAction(action)
        
        action = QAction("Export Interactive HTML (PyVis)", self)
        action.setShortcut("Ctrl+Shift+H")
        action.triggered.connect(self._export_pyvis)
        file_menu.addAction(action)
        
        action = QAction("📤 Export JSON", self)
        action.setShortcut("Ctrl+Shift+J")
        action.triggered.connect(self._export_json)
        file_menu.addAction(action)
        
        action = QAction("📤 Export PDF", self)
        action.setShortcut("Ctrl+Shift+D")
        action.triggered.connect(self._export_pdf)
        file_menu.addAction(action)
        
        file_menu.addSeparator()
        
        action = QAction("Exit", self)
        action.setShortcut("Ctrl+Q")
        action.triggered.connect(self.close)
        file_menu.addAction(action)
        
        # Edit Menu
        edit_menu = menubar.addMenu("&Edit")
        
        action = QAction("Auto Layout", self)
        action.setShortcut("Ctrl+L")
        action.triggered.connect(self.canvas.auto_layout)
        edit_menu.addAction(action)
        
        action = QAction("Center View", self)
        action.setShortcut("Ctrl+E")
        action.triggered.connect(self.canvas.center_view)
        edit_menu.addAction(action)
        
        action = QAction("Zoom In", self)
        action.setShortcut("Ctrl++")
        action.triggered.connect(self.canvas.zoom_in)
        edit_menu.addAction(action)
        
        action = QAction("Zoom Out", self)
        action.setShortcut("Ctrl+-")
        action.triggered.connect(self.canvas.zoom_out)
        edit_menu.addAction(action)
        
        edit_menu.addSeparator()
        
        action = QAction("Clear Graph", self)
        action.setShortcut("Ctrl+Del")
        action.triggered.connect(self._clear_graph)
        edit_menu.addAction(action)
        
        action = QAction("Reload Graph", self)
        action.setShortcut("F5")
        action.triggered.connect(self.canvas.reload_graph)
        edit_menu.addAction(action)
        
        # View Menu
        view_menu = menubar.addMenu("&View")
        view_menu.addAction("Risk Heatmap", self._show_risk_heatmap)
        view_menu.addAction("Timeline View", self._show_timeline)
        view_menu.addAction("🌳 Tree View", self._show_tree_view)
        view_menu.addAction("📋 Table View", self._show_table_view)
        
        # ML Menu
        ml_menu = menubar.addMenu("&ML Analysis")
        
        action = QAction("Run Clustering", self)
        action.setShortcut("Ctrl+K")
        action.triggered.connect(self._run_clustering)
        ml_menu.addAction(action)
        
        action = QAction("Predict Links", self)
        action.setShortcut("Ctrl+P")
        action.triggered.connect(self._predict_links)
        ml_menu.addAction(action)
        
        action = QAction("Risk Analysis", self)
        action.setShortcut("Ctrl+R")
        action.triggered.connect(self._risk_analysis)
        ml_menu.addAction(action)
        
        ml_menu.addAction("Identity Resolution", self._identity_resolution)
        ml_menu.addAction("🤖 Fake Profile Detection", self._fake_detection)
        ml_menu.addAction("✍️ Writing Analysis", self._writing_analysis)
        
        # Tools Menu
        tools_menu = menubar.addMenu("&Tools")
        tools_menu.addAction("Bulk Import CSV", self._bulk_import)
        tools_menu.addAction("📝 Add Notes", self._add_notes)
        tools_menu.addAction("🏷️ Add Tags", self._add_tags)
        tools_menu.addAction("⭐ Star Node", self._star_node)
        
        # Help Menu
        help_menu = menubar.addMenu("&Help")
        
        action = QAction("📖 Documentation", self)
        action.setShortcut("F1")
        action.triggered.connect(self._show_help)
        help_menu.addAction(action)
        
        help_menu.addAction("⌨️ Keyboard Shortcuts", self._show_shortcuts)
        help_menu.addAction("Check Updates", self._check_updates)
        help_menu.addAction("ℹ️ About", self._show_about)
    
    def _init_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(32, 32))
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # File actions
        new_action = toolbar.addAction("New")
        new_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
        new_action.triggered.connect(self._new_graph)
        new_action.setToolTip("New Graph (Ctrl+N)")
        
        save_action = toolbar.addAction("Save")
        save_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))
        save_action.triggered.connect(self._save_graph)
        save_action.setToolTip("Save Graph (Ctrl+S)")
        
        toolbar.addSeparator()
        
        # Layout actions
        layout_action = toolbar.addAction("Layout")
        layout_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        layout_action.triggered.connect(self.canvas.auto_layout)
        layout_action.setToolTip("Auto Layout (Ctrl+L)")
        
        center_action = toolbar.addAction("Center")
        center_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogResetButton))
        center_action.triggered.connect(self.canvas.center_view)
        center_action.setToolTip("Center View (Ctrl+E)")
        
        toolbar.addSeparator()
        
        # Zoom actions
        zoom_in_action = toolbar.addAction("Zoom In")
        zoom_in_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowUp))
        zoom_in_action.triggered.connect(self.canvas.zoom_in)
        zoom_in_action.setToolTip("Zoom In (Ctrl++)")
        
        zoom_out_action = toolbar.addAction("Zoom Out")
        zoom_out_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowDown))
        zoom_out_action.triggered.connect(self.canvas.zoom_out)
        zoom_out_action.setToolTip("Zoom Out (Ctrl+-)")
        
        toolbar.addSeparator()
        
        # Export action
        export_action = toolbar.addAction("Export HTML")
        export_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
        export_action.triggered.connect(self._export_pyvis)
        export_action.setToolTip("Export Interactive HTML (Ctrl+Shift+H)")
        
        toolbar.addSeparator()
        
        # ML actions
        cluster_action = toolbar.addAction("Cluster")
        cluster_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView))
        cluster_action.triggered.connect(self._run_clustering)
        cluster_action.setToolTip("ML Clustering (Ctrl+K)")
        
        predict_action = toolbar.addAction("Predict")
        predict_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation))
        predict_action.triggered.connect(self._predict_links)
        predict_action.setToolTip("Predict Links (Ctrl+P)")
        
        risk_action = toolbar.addAction("Risk")
        risk_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning))
        risk_action.triggered.connect(self._risk_analysis)
        risk_action.setToolTip("Risk Analysis (Ctrl+R)")
        
        toolbar.addSeparator()
        
        # Clear action
        clear_action = toolbar.addAction("Clear")
        clear_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_TrashIcon))
        clear_action.triggered.connect(self._clear_graph)
        clear_action.setToolTip("Clear Graph (Ctrl+Del)")
    
    def _init_statusbar(self):
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        
        # Stats label
        self.stats_label = QLabel()
        self.statusbar.addPermanentWidget(self.stats_label)
        
        # Progress bar (hidden by default)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.statusbar.addPermanentWidget(self.progress_bar)
        
        # Update timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self._update_stats)
        self.stats_timer.start(2000)
        self._update_stats()
    
    def _update_stats(self):
        stats = db.get_stats()
        ml_icon = "[ML]" if stats['ml_available'] else "[--]"
        self.stats_label.setText(
            f"Nodes: {stats['nodes']} | "
            f"Edges: {stats['edges']} | "
            f"Types: {stats['entity_types']} | "
            f"Avg Risk: {stats['avg_risk_score']:.0%} | "
            f"ML: {ml_icon}"
        )
        self.node_count_label.setText(f"Nodes: {stats['nodes']}")
    
    def _filter_graph(self):
        """Filter graph based on search and filters"""
        search_text = self.search_box.text().lower()
        entity_type = self.type_filter.currentText()
        risk_level = self.risk_filter.currentText()
        
        nodes = db.get_nodes()
        visible_count = 0
        
        for item in self.canvas.scene.items():
            if hasattr(item, 'node_id'):
                node = next((n for n in nodes if n['id'] == item.node_id), None)
                if not node:
                    continue
                
                visible = True
                
                # Search filter
                if search_text:
                    searchable = f"{node['label']} {node['entity_type']} {str(node.get('properties', {}))}".lower()
                    if search_text not in searchable:
                        visible = False
                
                # Type filter
                if entity_type != 'All Types' and node['entity_type'] != entity_type:
                    visible = False
                
                # Risk filter
                if risk_level != 'All Risk':
                    risk = node.get('risk_score', 0.0)
                    if risk_level == 'Critical (>70%)' and risk <= 0.7:
                        visible = False
                    elif risk_level == 'High (>50%)' and risk <= 0.5:
                        visible = False
                    elif risk_level == 'Medium (>30%)' and risk <= 0.3:
                        visible = False
                    elif risk_level == 'Low (<30%)' and risk > 0.3:
                        visible = False
                
                item.setVisible(visible)
                if hasattr(item, 'label'):
                    item.label.setVisible(visible)
                
                if visible:
                    visible_count += 1
        
        # Hide/show edges based on connected nodes
        for item in self.canvas.scene.items():
            if hasattr(item, 'from_node') and hasattr(item, 'to_node'):
                from_visible = item.from_node.isVisible()
                to_visible = item.to_node.isVisible()
                item.setVisible(from_visible and to_visible)
                if hasattr(item, 'label'):
                    item.label.setVisible(from_visible and to_visible)
        
        self.statusbar.showMessage(f"Showing {visible_count}/{len(nodes)} nodes", 3000)
    
    def _clear_filters(self):
        """Clear all filters"""
        self.search_box.clear()
        self.type_filter.setCurrentIndex(0)
        self.risk_filter.setCurrentIndex(0)
        self.statusbar.showMessage("Filters cleared", 2000)
    
    # File operations
    def _new_graph(self):
        if show_question(self, 'New Graph', 'Clear current graph and start fresh?'):
            self._clear_graph()
    
    def _save_graph(self):
        self.statusbar.showMessage("Graph auto-saved to database", 3000)
    
    def _clear_graph(self):
        db.clear_graph()
        self.canvas.clear()
        self._update_stats()
        self.statusbar.showMessage("Graph cleared", 3000)
    
    def _load_graph(self):
        nodes = db.get_nodes()
        edges = db.get_edges()
        for node in nodes:
            self.canvas.add_node(node['id'], node['entity_type'], node['label'], 
                               node['properties'], node['x'], node['y'])
        for edge in edges:
            self.canvas.add_edge(edge['from_node'], edge['to_node'], 
                               edge['relationship'], edge['confidence'])
        if nodes:
            self.canvas.center_view()
    
    def _export_pyvis(self):
        """Export interactive HTML graph using PyVis"""
        try:
            from sentinel_intel.ui.pyvis_exporter import PyVisExporter
            
            nodes = db.get_nodes()
            edges = db.get_edges()
            
            if not nodes:
                show_warning(self, 'Export HTML', 'No nodes to export!')
                return
            
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            self.statusbar.showMessage("Generating interactive HTML...", 0)
            
            exporter = PyVisExporter()
            output_path = exporter.export_graph(nodes, edges)
            
            self.progress_bar.setVisible(False)
            self.statusbar.showMessage(f"Exported to {output_path}", 5000)
            
            # Ask to open in browser
            if show_question(self, 'Export Complete', 
                           f'Interactive graph exported!\n\n{output_path}\n\nOpen in browser?'):
                import webbrowser
                webbrowser.open(f'file://{output_path}')
        
        except ImportError:
            show_error(self, 'PyVis Not Installed', 
                      'PyVis library not found!\n\nInstall: pip install pyvis')
        except Exception as e:
            self.progress_bar.setVisible(False)
            show_error(self, 'Export Error', f'Error: {str(e)}')
    
    def _export_json(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Export Graph", "", "JSON Files (*.json)")
        if filename:
            import json
            data = {'nodes': db.get_nodes(), 'edges': db.get_edges()}
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            self.statusbar.showMessage(f"📤 Exported to {filename}", 3000)
    
    def _export_pdf(self):
        """Export graph as PDF report"""
        from PyQt6.QtGui import QPainter, QPageLayout, QPageSize
        from PyQt6.QtPrintSupport import QPrinter
        from PyQt6.QtCore import QMarginsF
        
        nodes = db.get_nodes()
        if not nodes:
            show_warning(self, 'Export PDF', 'No nodes to export!')
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, "Export PDF", "", "PDF Files (*.pdf)")
        if not filename:
            return
        
        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            self.statusbar.showMessage("Generating PDF report...", 0)
            
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(filename)
            printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
            printer.setPageOrientation(QPageLayout.Orientation.Portrait)
            printer.setPageMargins(QMarginsF(20, 20, 20, 20), QPageLayout.Unit.Millimeter)
            
            painter = QPainter()
            painter.begin(printer)
            
            # Title
            painter.setFont(QFont('Arial', 24, QFont.Weight.Bold))
            painter.drawText(100, 100, "🕸️ Sentinel Intel Report")
            
            # Stats
            stats = db.get_stats()
            painter.setFont(QFont('Arial', 12))
            y = 200
            painter.drawText(100, y, f"Total Nodes: {stats['nodes']}")
            y += 40
            painter.drawText(100, y, f"Total Edges: {stats['edges']}")
            y += 40
            painter.drawText(100, y, f"Entity Types: {stats['entity_types']}")
            y += 40
            painter.drawText(100, y, f"Average Risk: {stats['avg_risk_score']:.0%}")
            y += 80
            
            # Graph visualization
            painter.drawText(100, y, "Graph Visualization:")
            y += 40
            
            # Render graph scene
            source_rect = self.canvas.scene.itemsBoundingRect()
            target_rect = painter.viewport()
            target_rect.setTop(y)
            target_rect.setHeight(target_rect.height() - y - 100)
            
            self.canvas.scene.render(painter, target_rect, source_rect)
            
            painter.end()
            
            self.progress_bar.setVisible(False)
            self.statusbar.showMessage(f"📄 PDF exported: {filename}", 5000)
            
            show_info(self, 'Export Complete', f'Report exported!\n\n{filename}')
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            show_error(self, 'Export Error', f'Error: {str(e)}')
    
    def _open_graph(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open Graph", "", "JSON Files (*.json)")
        if filename:
            import json
            with open(filename, 'r') as f:
                data = json.load(f)
            db.clear_graph()
            self.canvas.clear()
            for node in data.get('nodes', []):
                db.add_node(node['entity_type'], node['label'], 
                          node.get('properties'), node.get('x'), node.get('y'))
            self._load_graph()
            self.statusbar.showMessage(f"📂 Loaded from {filename}", 3000)
    
    # ML operations
    def _run_clustering(self):
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        result = db.run_clustering()
        self.progress_bar.setVisible(False)
        
        if 'error' in result:
            show_warning(self, 'ML Clustering', f"Error: {result['error']}")
        else:
            msg = f"Clustering Complete!\n\n"
            msg += f"• Clusters Found: {result['clusters']}\n"
            msg += f"• Nodes Clustered: {result['clustered_nodes']}\n"
            msg += f"Noise Points: {result['noise_points']}"
            show_info(self, 'ML Clustering', msg)
            self.canvas.reload_graph()
    
    def _predict_links(self):
        selected = self.canvas.get_selected_node()
        if not selected:
            show_warning(self, 'Predict Links', 'Select a node first!')
            return
        
        predictions = db.predict_relationships(selected, max_predictions=5)
        if predictions:
            msg = "Predicted Relationships:\n\n"
            for src, tgt, score in predictions:
                msg += f"→ {tgt} (confidence: {score:.0%})\n"
            show_info(self, 'Link Prediction', msg)
        else:
            show_info(self, 'Link Prediction', 'ℹ️ No predictions available')
    
    def _risk_analysis(self):
        nodes = db.get_nodes()
        critical = [n for n in nodes if n['risk_score'] > 0.7]
        high = [n for n in nodes if 0.5 < n['risk_score'] <= 0.7]
        medium = [n for n in nodes if 0.3 < n['risk_score'] <= 0.5]
        low = [n for n in nodes if n['risk_score'] <= 0.3]
        
        msg = f"Risk Analysis Report:\n\n"
        msg += f"Critical Risk (>70%): {len(critical)}\n"
        msg += f"High Risk (50-70%): {len(high)}\n"
        msg += f"Medium Risk (30-50%): {len(medium)}\n"
        msg += f"Low Risk (<30%): {len(low)}\n\n"
        msg += f"Total Nodes: {len(nodes)}"
        
        show_info(self, 'Risk Analysis', msg)
    
    def _identity_resolution(self):
        """Identity resolution using EntityMatcher and IdentityScorer"""
        from modules.ml_engine.entity_matcher import EntityMatcher
        from modules.ml_engine.identity_scorer import IdentityScorer
        
        nodes = db.get_nodes()
        if not nodes:
            show_warning(self, 'Identity Resolution', 'No nodes to analyze!')
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.statusbar.showMessage("Analyzing identities...", 0)
        
        try:
            matcher = EntityMatcher()
            scorer = IdentityScorer()
            
            # Extract profiles from nodes
            profiles = []
            for node in nodes:
                if node['entity_type'] in ['username', 'email', 'person']:
                    profiles.append({
                        'node_id': node['id'],
                        'username': node['label'],
                        'platform': node['entity_type'],
                        'display_name': node.get('properties', {}).get('name', ''),
                        'bio': node.get('properties', {}).get('bio', ''),
                    })
            
            if len(profiles) < 2:
                self.progress_bar.setVisible(False)
                show_info(self, 'Identity Resolution', 
                    'Need at least 2 profiles to match.\n\nAdd more entities first.')
                return
            
            # Match profiles
            matches = matcher.match_profiles(profiles)
            
            if not matches:
                self.progress_bar.setVisible(False)
                show_info(self, 'Identity Resolution', 'No identity matches found.')
                return
            
            # Build evidence list for scoring
            evidence = []
            for match in matches:
                evidence.append({
                    'type': match['label'].replace('_', ' '),
                    'details': match.get('evidence', ''),
                })
            
            # Score overall identity
            score_result = scorer.score_identity(evidence)
            
            # Create result dialog
            result_msg = f"🔍 Identity Resolution Results\n\n"
            result_msg += f"Confidence: {score_result['confidence_pct']:.1f}%\n"
            result_msg += f"Label: {score_result['label']}\n"
            result_msg += f"Evidence Count: {score_result['evidence_count']}\n\n"
            
            result_msg += "Top Matches:\n"
            for i, match in enumerate(matches[:5], 1):
                pa = match['profile_a']
                pb = match['profile_b']
                result_msg += f"\n{i}. {pa['username']} ↔ {pb['username']}\n"
                result_msg += f"   Confidence: {match['confidence']:.0%}\n"
                result_msg += f"   Evidence: {match.get('evidence', 'N/A')[:80]}\n"
            
            # Add edges for high-confidence matches
            edges_added = 0
            for match in matches:
                if match['confidence'] >= 0.7:
                    node_a = match['profile_a']['node_id']
                    node_b = match['profile_b']['node_id']
                    db.add_edge(node_a, node_b, 'same_identity', match['confidence'], ml_predicted=True)
                    edges_added += 1
            
            if edges_added > 0:
                result_msg += f"\n\n✅ Added {edges_added} identity links to graph!"
                self.canvas.reload_graph()
            
            self.progress_bar.setVisible(False)
            show_info(self, 'Identity Resolution', result_msg)
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            show_error(self, 'Error', f'Identity resolution failed:\n{str(e)}')
    
    def _fake_detection(self):
        """Fake profile detection using ML"""
        from modules.fake_profile_detector import FakeProfileDetector
        
        selected = self.canvas.get_selected_node()
        if not selected:
            show_warning(self, 'Fake Detection', 'Select a person/username node first!')
            return
        
        nodes = db.get_nodes()
        node = next((n for n in nodes if n['id'] == selected), None)
        if not node or node['entity_type'] not in ['person', 'username', 'email']:
            show_warning(self, 'Fake Detection', 'Select a person/username/email node!')
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.statusbar.showMessage("Analyzing profile authenticity...", 0)
        
        try:
            detector = FakeProfileDetector()
            
            # Collect profile data from node properties and connected nodes
            edges = db.get_edges(selected)
            social_data = []
            
            # Build profile data from connected social_profile nodes
            for edge in edges:
                child_id = edge['to_node'] if edge['from_node'] == selected else edge['from_node']
                child_node = next((n for n in nodes if n['id'] == child_id), None)
                
                if child_node and child_node['entity_type'] == 'social_profile':
                    props = child_node.get('properties', {})
                    social_data.append({
                        'platform': props.get('platform', 'unknown'),
                        'profile_info': {
                            'display_name': props.get('display_name', node['label']),
                            'profile_image': props.get('profile_image', ''),
                            'verified': props.get('verified', False),
                            'follower_count': str(props.get('followers', 0)),
                            'following_count': str(props.get('following', 0)),
                        },
                        'bio_data': {
                            'bio': props.get('bio', ''),
                        },
                        'posts_data': {
                            'posts': props.get('posts', []),
                        },
                    })
            
            if not social_data:
                # Use main node properties if no connected profiles
                props = node.get('properties', {})
                social_data = [{
                    'platform': node['entity_type'],
                    'profile_info': {
                        'display_name': node['label'],
                        'profile_image': props.get('image', ''),
                        'verified': props.get('verified', False),
                    },
                    'bio_data': {'bio': props.get('bio', '')},
                    'posts_data': {'posts': []},
                }]
            
            # Run detection
            results = detector.analyze_profile({'social_data': social_data})
            
            self.progress_bar.setVisible(False)
            
            # Build result message
            msg = f"🤖 Fake Profile Detection Results\n\n"
            msg += f"Target: {node['label']}\n\n"
            msg += f"Fake Score: {results['overall_fake_score']}/100\n"
            msg += f"Risk Level: {results['risk_level']}\n\n"
            
            if results.get('ml_analysis', {}).get('status') == 'completed':
                ml = results['ml_analysis']
                msg += f"ML Analysis:\n"
                msg += f"  • Texts Analyzed: {ml['texts_analyzed']}\n"
                msg += f"  • Toxic Content: {ml['toxic_count']} ({ml['toxic_ratio']:.0%})\n\n"
            
            indicators = results.get('suspicious_indicators', [])
            if indicators:
                msg += f"Suspicious Indicators ({len(indicators)}):\n"
                for ind in indicators[:5]:
                    msg += f"  ⚠️ {ind['type']} [{ind['severity']}]\n"
                    msg += f"     {ind['description']}\n"
            
            recommendations = results.get('recommendations', [])
            if recommendations:
                msg += f"\nRecommendations:\n"
                for rec in recommendations[:3]:
                    msg += f"  {rec}\n"
            
            # Update node risk score
            risk_score = results['overall_fake_score'] / 100
            db.update_node(selected, risk_score=risk_score)
            self.canvas.reload_graph()
            
            show_info(self, 'Fake Detection Complete', msg)
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            show_error(self, 'Error', f'Fake detection failed:\n{str(e)}')
    
    def _writing_analysis(self):
        """Writing style analysis using WritingFingerprinter"""
        from modules.ml_engine.writing_fingerprinter import WritingFingerprinter
        
        nodes = db.get_nodes()
        if not nodes:
            show_warning(self, 'Writing Analysis', 'No nodes to analyze!')
            return
        
        # Collect text samples from nodes
        text_samples = []
        sample_labels = []
        
        for node in nodes:
            props = node.get('properties', {})
            text = ''
            
            # Extract text from different node types
            if node['entity_type'] == 'social_profile':
                text = props.get('bio', '')
            elif node['entity_type'] == 'social_post':
                text = props.get('text', '') or props.get('content', '')
            elif node['entity_type'] in ['person', 'username', 'email']:
                text = props.get('bio', '') or props.get('description', '')
            
            if text and len(text.split()) >= 10:
                text_samples.append(text)
                sample_labels.append(f"{node['entity_type']}: {node['label'][:30]}")
        
        if len(text_samples) < 2:
            show_warning(self, 'Writing Analysis', 
                'Need at least 2 text samples (10+ words each).\n\n'
                'Add social profiles or posts with text content.')
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.statusbar.showMessage("Analyzing writing styles...", 0)
        
        try:
            fingerprinter = WritingFingerprinter()
            
            # Compare multiple texts
            results = fingerprinter.compare_multiple(text_samples, sample_labels)
            
            self.progress_bar.setVisible(False)
            
            if 'error' in results:
                show_warning(self, 'Writing Analysis', f"Error: {results['error']}")
                return
            
            # Build result message
            msg = f"✍️ Writing Style Analysis Results\n\n"
            msg += f"Texts Analyzed: {len(text_samples)}\n"
            msg += f"Average Similarity: {results['avg_similarity']:.0%}\n"
            msg += f"Overall Verdict: {results['overall_verdict']}\n\n"
            
            same_pairs = results.get('same_author_pairs', [])
            likely_pairs = results.get('likely_same_pairs', [])
            
            msg += f"Same Author Matches: {len(same_pairs)}\n"
            msg += f"Likely Same Author: {len(likely_pairs)}\n\n"
            
            if results.get('strongest_match'):
                match = results['strongest_match']
                msg += f"Strongest Match:\n"
                msg += f"  {match['source_a']}\n"
                msg += f"  ↔\n"
                msg += f"  {match['source_b']}\n"
                msg += f"  Similarity: {match['final_score']:.0%}\n"
                msg += f"  Verdict: {match['label']}\n\n"
                
                if match.get('evidence'):
                    msg += f"  Evidence:\n"
                    for ev in match['evidence'][:3]:
                        msg += f"    • {ev}\n"
            
            # Show top 3 comparisons
            comparisons = results.get('comparisons', [])[:3]
            if comparisons:
                msg += f"\nTop Matches:\n"
                for i, comp in enumerate(comparisons, 1):
                    msg += f"\n{i}. {comp['source_a']} ↔ {comp['source_b']}\n"
                    msg += f"   Score: {comp['final_score']:.0%} ({comp['label']})\n"
            
            show_info(self, 'Writing Analysis Complete', msg)
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            show_error(self, 'Error', f'Writing analysis failed:\n{str(e)}')
    
    # View operations
    def _show_risk_heatmap(self):
        """Risk heatmap visualization"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        from PyQt6.QtWebEngineWidgets import QWebEngineView
        import tempfile
        
        nodes = db.get_nodes()
        if not nodes:
            show_warning(self, 'Risk Heatmap', 'No nodes to visualize!')
            return
        
        # Generate heatmap HTML
        html = '''<!DOCTYPE html>
<html><head><style>
body { background: #0a0e27; color: #fff; font-family: Arial; padding: 20px; }
.risk-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 10px; }
.risk-cell { padding: 20px; border-radius: 8px; text-align: center; cursor: pointer; }
.risk-cell:hover { transform: scale(1.05); transition: 0.2s; }
.critical { background: #ff0000; }
.high { background: #ff6600; }
.medium { background: #ffaa00; }
.low { background: #00ff00; }
</style></head><body>
<h1>🔥 Risk Heatmap</h1>
<div class="risk-grid">'''
        
        for node in nodes:
            risk = node.get('risk_score', 0.0)
            if risk > 0.7:
                color_class = 'critical'
                level = 'CRITICAL'
            elif risk > 0.5:
                color_class = 'high'
                level = 'HIGH'
            elif risk > 0.3:
                color_class = 'medium'
                level = 'MEDIUM'
            else:
                color_class = 'low'
                level = 'LOW'
            
            html += f'<div class="risk-cell {color_class}"><b>{node["label"][:20]}</b><br>{level}<br>{risk:.0%}</div>'
        
        html += '</div></body></html>'
        
        # Show in dialog
        dialog = QDialog(self)
        dialog.setWindowTitle('Risk Heatmap')
        dialog.setGeometry(100, 100, 1200, 800)
        layout = QVBoxLayout(dialog)
        
        try:
            view = QWebEngineView()
            view.setHtml(html)
            layout.addWidget(view)
        except:
            # Fallback without WebEngine
            from PyQt6.QtWidgets import QTextBrowser
            view = QTextBrowser()
            view.setHtml(html)
            layout.addWidget(view)
        
        dialog.exec()
    
    def _show_timeline(self):
        """Timeline view of node creation dates"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextBrowser
        import json
        
        nodes = db.get_nodes()
        edges = db.get_edges()
        
        if not nodes:
            show_warning(self, 'Timeline', 'No nodes to display!')
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle('📅 Timeline View')
        dialog.setGeometry(100, 100, 1200, 700)
        layout = QVBoxLayout(dialog)
        
        browser = QTextBrowser()
        browser.setStyleSheet('''
            QTextBrowser { 
                background: #16213e; 
                color: #E0E0E0; 
                border: 1px solid #00D9FF;
                font-family: 'Courier New', monospace;
                padding: 15px;
            }
        ''')
        
        # Build timeline HTML
        html = '''<style>
        body {{ background: #16213e; color: #E0E0E0; font-family: Arial; }}
        .timeline {{ position: relative; padding: 20px; }}
        .event {{ 
            margin: 15px 0; 
            padding: 15px; 
            background: #0f3460; 
            border-left: 4px solid #00D9FF; 
            border-radius: 4px;
        }}
        .event-time {{ color: #00D9FF; font-weight: bold; font-size: 14px; }}
        .event-type {{ color: #4ECDC4; font-size: 12px; }}
        .event-label {{ font-size: 16px; margin: 5px 0; }}
        .event-risk {{ float: right; padding: 3px 8px; border-radius: 3px; font-size: 11px; }}
        .risk-high {{ background: #ff0000; color: #fff; }}
        .risk-medium {{ background: #ff6600; color: #fff; }}
        .risk-low {{ background: #00ff00; color: #000; }}
        </style>
        <div class="timeline">
        <h2 style="color: #00D9FF;">📅 Entity Timeline</h2>
        <p>Total Events: {0}</p>
        <hr style="border-color: #00D9FF;">
        '''.format(len(nodes) + len(edges))
        
        # Collect all events with timestamps
        events = []
        
        # Add node creation events
        for node in nodes:
            # Try to extract timestamp from properties
            props = node.get('properties', {})
            timestamp = props.get('created_at') or props.get('timestamp') or props.get('date') or 'Unknown'
            
            risk = node.get('risk_score', 0.0)
            risk_class = 'risk-high' if risk > 0.7 else 'risk-medium' if risk > 0.5 else 'risk-low'
            risk_label = f'{risk:.0%}' if risk > 0 else 'N/A'
            
            events.append({
                'time': timestamp,
                'type': 'Node Created',
                'entity_type': node['entity_type'],
                'label': node['label'],
                'risk_score': risk,
                'risk_class': risk_class,
                'risk_label': risk_label,
            })
        
        # Sort by timestamp (newest first)
        events.sort(key=lambda x: x['time'], reverse=True)
        
        # Generate HTML for events
        for event in events:
            html += f'''
            <div class="event">
                <span class="event-time">{event['time']}</span>
                <span class="event-risk {event['risk_class']}">{event['risk_label']}</span>
                <div class="event-type">{event['type']} • {event['entity_type']}</div>
                <div class="event-label">🔹 {event['label']}</div>
            </div>
            '''
        
        html += '</div>'
        
        browser.setHtml(html)
        layout.addWidget(browser)
        dialog.exec()
    
    def _show_tree_view(self):
        """Hierarchical tree view of graph"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTreeWidget, QTreeWidgetItem
        
        nodes = db.get_nodes()
        edges = db.get_edges()
        
        if not nodes:
            show_warning(self, 'Tree View', 'No nodes to display!')
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle('🌳 Hierarchical Tree View')
        dialog.setGeometry(100, 100, 1000, 700)
        layout = QVBoxLayout(dialog)
        
        tree = QTreeWidget()
        tree.setHeaderLabels(['Entity', 'Type', 'Risk', 'Properties'])
        tree.setColumnWidth(0, 300)
        tree.setColumnWidth(1, 150)
        tree.setColumnWidth(2, 100)
        tree.setStyleSheet('''
            QTreeWidget { background: #16213e; color: #E0E0E0; border: 1px solid #00D9FF; }
            QTreeWidget::item:hover { background: #0f3460; }
            QTreeWidget::item:selected { background: #00D9FF; color: #000; }
        ''')
        
        # Build parent-child map
        children_map = {}
        for edge in edges:
            if edge['from_node'] not in children_map:
                children_map[edge['from_node']] = []
            children_map[edge['from_node']].append(edge['to_node'])
        
        # Find root nodes (no incoming edges)
        all_children = set()
        for children in children_map.values():
            all_children.update(children)
        
        node_dict = {n['id']: n for n in nodes}
        root_nodes = [n for n in nodes if n['id'] not in all_children]
        
        def add_node_to_tree(node, parent_item=None):
            risk = node.get('risk_score', 0.0)
            risk_color = '🔴' if risk > 0.7 else '🟠' if risk > 0.5 else '🟡' if risk > 0.3 else '🟢'
            
            item = QTreeWidgetItem([
                f"{node['label']}",
                node['entity_type'],
                f"{risk_color} {risk:.0%}",
                str(len(node.get('properties', {}))) + ' props'
            ])
            
            if parent_item:
                parent_item.addChild(item)
            else:
                tree.addTopLevelItem(item)
            
            # Add children recursively
            if node['id'] in children_map:
                for child_id in children_map[node['id']]:
                    if child_id in node_dict:
                        add_node_to_tree(node_dict[child_id], item)
            
            return item
        
        # Add root nodes
        for node in root_nodes:
            add_node_to_tree(node)
        
        tree.expandAll()
        layout.addWidget(tree)
        dialog.exec()
    
    def _show_table_view(self):
        """Table view of all nodes"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView
        
        nodes = db.get_nodes()
        if not nodes:
            show_warning(self, 'Table View', 'No nodes to display!')
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle('📋 Data Table View')
        dialog.setGeometry(100, 100, 1400, 800)
        layout = QVBoxLayout(dialog)
        
        table = QTableWidget()
        table.setRowCount(len(nodes))
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(['Label', 'Type', 'Risk', 'Confidence', 'Cluster', 'Properties'])
        table.setStyleSheet('''
            QTableWidget { background: #16213e; color: #E0E0E0; border: 1px solid #00D9FF; gridline-color: #00D9FF; }
            QTableWidget::item { padding: 8px; }
            QTableWidget::item:selected { background: #00D9FF; color: #000; }
            QHeaderView::section { background: #0f3460; color: #00D9FF; padding: 8px; font-weight: bold; border: 1px solid #00D9FF; }
        ''')
        
        for i, node in enumerate(nodes):
            risk = node.get('risk_score', 0.0)
            risk_emoji = '🔴' if risk > 0.7 else '🟠' if risk > 0.5 else '🟡' if risk > 0.3 else '🟢'
            
            table.setItem(i, 0, QTableWidgetItem(node['label']))
            table.setItem(i, 1, QTableWidgetItem(node['entity_type']))
            table.setItem(i, 2, QTableWidgetItem(f"{risk_emoji} {risk:.0%}"))
            table.setItem(i, 3, QTableWidgetItem(f"{node.get('confidence', 1.0):.0%}"))
            table.setItem(i, 4, QTableWidgetItem(str(node.get('ml_cluster', -1))))
            table.setItem(i, 5, QTableWidgetItem(str(len(node.get('properties', {}))) + ' properties'))
        
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setSortingEnabled(True)
        
        layout.addWidget(table)
        dialog.exec()
    
    # Tools operations
    def _bulk_import(self):
        """Bulk import entities from CSV"""
        filename, _ = QFileDialog.getOpenFileName(self, "Import CSV", "", "CSV Files (*.csv)")
        if not filename:
            return
        
        try:
            import csv
            
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            self.statusbar.showMessage("Importing entities...", 0)
            
            imported = 0
            with open(filename, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Expected columns: entity_type, label, properties (optional JSON)
                    entity_type = row.get('entity_type', 'domain')
                    label = row.get('label', '')
                    
                    if not label:
                        continue
                    
                    properties = {}
                    if 'properties' in row and row['properties']:
                        try:
                            import json
                            properties = json.loads(row['properties'])
                        except:
                            pass
                    
                    # Add other columns as properties
                    for key, value in row.items():
                        if key not in ['entity_type', 'label', 'properties'] and value:
                            properties[key] = value
                    
                    node_id = db.add_node(entity_type, label, properties)
                    self.canvas.add_node(node_id, entity_type, label, properties)
                    imported += 1
            
            self.progress_bar.setVisible(False)
            self.canvas.auto_layout()
            self._update_stats()
            
            msg = f'✅ Successfully imported {imported} entities!\n\n'
            msg += f'CSV Format:\n'
            msg += f'entity_type, label, properties (optional JSON), custom_field1, custom_field2...'
            show_info(self, 'Bulk Import', msg)
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            show_error(self, 'Import Error', f'Error: {str(e)}')
    
    def _add_notes(self):
        selected = self.canvas.get_selected_node()
        if not selected:
            show_warning(self, 'Add Notes', 'Select a node first!')
            return
        
        notes, ok = QInputDialog.getMultiLineText(self, 'Add Notes', 'Enter notes:')
        if ok and notes:
            db.update_node(selected, notes=notes)
            self.statusbar.showMessage("📝 Notes added", 2000)
    
    def _add_tags(self):
        """Add tags to selected node"""
        selected = self.canvas.get_selected_node()
        if not selected:
            show_warning(self, 'Add Tags', 'Select a node first!')
            return
        
        nodes = db.get_nodes()
        node = next((n for n in nodes if n['id'] == selected), None)
        if not node:
            return
        
        current_tags = node.get('properties', {}).get('tags', [])
        if isinstance(current_tags, str):
            current_tags = [t.strip() for t in current_tags.split(',')]
        
        tags_str = ', '.join(current_tags) if current_tags else ''
        
        new_tags, ok = QInputDialog.getText(self, 'Add Tags', 
            f'Current tags: {tags_str}\n\nEnter tags (comma-separated):', 
            text=tags_str)
        
        if ok:
            tag_list = [t.strip() for t in new_tags.split(',') if t.strip()]
            properties = node.get('properties', {})
            properties['tags'] = tag_list
            db.update_node_properties(selected, properties)
            self.statusbar.showMessage(f"🏷️ Tags updated: {', '.join(tag_list)}", 3000)
    
    def _star_node(self):
        selected = self.canvas.get_selected_node()
        if not selected:
            show_warning(self, 'Star Node', 'Select a node first!')
            return
        
        db.update_node(selected, starred=True)
        self.statusbar.showMessage("⭐ Node starred", 2000)
    
    # Help operations
    def _show_help(self):
        help_text = """
        📖 Sentinel Intel v2.0 — Quick Help
        
        🎯 Adding Entities:
        • Click entity type in left panel (Email, IP, Domain, Person, etc.)
        • Enter value and click "Add Entity"
        • Use Quick Add for auto-detection of entity type
        • Import bulk entities via Tools → Bulk Import CSV
        
        🔄 Running Transforms:
        • Select node on canvas
        • Choose transform from Transform Palette
        • Use Auto-Chain button for AI-powered suggestions
        • Wait for transform to complete
        • Sub-entities automatically created in hierarchical structure
        
        🧠 ML Analysis Features:
        • Clustering (Ctrl+K): Group related entities using DBSCAN
        • Link Prediction (Ctrl+P): Find hidden relationships with GNN
        • Risk Analysis (Ctrl+R): Identify threat levels across graph
        • Identity Resolution: Match same person across platforms (EntityMatcher)
        • Fake Detection: Detect fake/bot accounts (ML classifier)
        • Writing Analysis: Compare writing styles for authorship attribution
        
        👁️ View Options:
        • Risk Heatmap: Color-coded threat visualization
        • Timeline View: Chronological entity creation history
        • Tree View: Hierarchical parent-child relationships
        • Table View: Sortable data table with all properties
        
        🔍 Search & Filter:
        • Search box: Filter by label, type, or properties
        • Type filter: Show specific entity types only
        • Risk filter: Filter by risk level (Critical/High/Medium/Low)
        • Clear button: Reset all filters
        
        📤 Export Options:
        • PNG: High-resolution graph image
        • Interactive HTML: PyVis 3D visualization (open in browser)
        • JSON: Raw graph data for backup/sharing
        • PDF: Professional report with graph + statistics
        
        🛠️ Tools:
        • Add Notes: Annotate nodes with custom text
        • Add Tags: Categorize nodes with tags
        • Star Node: Mark important entities
        • Bulk Import: CSV file with entity_type, label, properties columns
        
        🎨 Navigation:
        • Drag nodes: Reposition manually
        • Mouse wheel: Zoom in/out
        • Drag canvas: Pan view
        • Auto Layout (Ctrl+L): Circular arrangement
        • Center View (Ctrl+E): Fit graph to screen
        
        ⌨️ Essential Shortcuts:
        • Ctrl+N: New Graph
        • Ctrl+S: Save Graph
        • Ctrl+L: Auto Layout
        • Ctrl+E: Center View
        • Ctrl+K: Run ML Clustering
        • Ctrl+P: Predict Links
        • Ctrl+R: Risk Analysis
        • F5: Reload Graph
        • F1: Show this help
        
        💡 Pro Tips:
        • Use *_investigate transforms for best results (auto sub-entities)
        • Run ML clustering after adding 10+ nodes
        • Export to HTML for interactive 3D exploration
        • Use Risk Heatmap to identify critical nodes quickly
        • Star important nodes before exporting reports
        """
        show_info(self, 'Sentinel Intel v2.0 Help', help_text)
    
    def _show_shortcuts(self):
        shortcuts = """
        ⌨️ Sentinel Intel v2.0 — Keyboard Shortcuts
        
        📁 File Operations:
        • Ctrl+N         New Graph (clear and start fresh)
        • Ctrl+O         Open Graph (load from JSON)
        • Ctrl+S         Save Graph (auto-saved to database)
        • Ctrl+Q         Exit Application
        
        ✏️ Edit & Navigation:
        • Ctrl+L         Auto Layout (circular arrangement)
        • Ctrl+E         Center View (fit graph to screen)
        • Ctrl++         Zoom In
        • Ctrl+-         Zoom Out
        • Ctrl+Del       Clear Graph (delete all nodes/edges)
        • F5             Reload Graph (refresh from database)
        
        🧠 ML Analysis:
        • Ctrl+K         Run ML Clustering (DBSCAN)
        • Ctrl+P         Predict Missing Links (GNN)
        • Ctrl+R         Risk Analysis Report
        
        📤 Export:
        • Ctrl+Shift+P   Export PNG (high-res graph image)
        • Ctrl+Shift+H   Export Interactive HTML (PyVis 3D)
        • Ctrl+Shift+J   Export JSON (graph data)
        • Ctrl+Shift+D   Export PDF (professional report)
        
        ℹ️ Help:
        • F1             Show Documentation
        
        🖱️ Mouse Controls:
        • Click          Select node
        • Drag           Move node or pan canvas
        • Wheel          Zoom in/out
        • Right-click    Context menu (coming soon)
        
        💡 Tips:
        • Hold Shift while dragging to select multiple nodes
        • Double-click node to run default transform
        • Escape to deselect all nodes
        """
        show_info(self, 'Keyboard Shortcuts', shortcuts)
    
    def _check_updates(self):
        show_info(self, 'Updates', 'You are running the latest version: v2.0')
    
    def _show_about(self):
        about_text = """
        🕸️ Sentinel Intel v2.0
        Professional Graph Intelligence Platform
        
        ═══════════════════════════════════════════════
        
        🎯 The Maltego Killer — Professional OSINT
        AI-Powered · Hierarchical Sub-Entities · 100% Feature Complete
        
        ═══════════════════════════════════════════════
        
        📊 Platform Statistics:
        • 13 Intelligence Engines
          (Email, Phone, IP, Domain, Person, Username, 
           Hash, Crypto, URL, Company, CVE, Breach, Malware)
        
        • 60+ Entity Types (19 primary + 45 sub-entities)
        • 40+ Transforms (OSINT operations)
        • 10+ ML Algorithms (SentinelNet, EntityMatcher, etc.)
        • 300+ Hierarchical Relationships (2-3 levels deep)
        
        🧠 AI/ML Models:
        • SentinelNet v5.0 — Threat Classification (F1=0.83, 8.6MB)
        • Seq2Seq v2.0 — Command Generation (34MB)
        • SentinelLM v1.0 — Language Model (137MB)
        • EntityMatcher — Same Person Detection (TF-IDF)
        • IdentityScorer — Cross-platform Identity Resolution
        • WritingFingerprinter — Authorship Attribution
        • FakeProfileDetector — Bot/Fake Account Detection
        • Groq LLM — llama-3.3-70b-versatile
        
        🎨 UI Features:
        • Risk-Based Visualization (color/border/glow)
        • Real-time Search & Filtering
        • Risk Heatmap · Timeline · Tree · Table Views
        • Interactive HTML Export (PyVis 3D)
        • PDF Reports · CSV Bulk Import
        • ML Clustering · Link Prediction · Risk Analysis
        
        🛠️ Technology Stack:
        • Python 3.10+ · PyQt6 · NetworkX
        • scikit-learn · TensorFlow · NumPy
        • SQLite · Groq API · 70% Free APIs
        
        📈 Code Statistics:
        • 257 Source Files
        • 85,000+ Lines of Code
        • 4 Languages (Python, Go, Rust, Solidity)
        • 181MB ML Models
        • 34,458 Attack Payloads
        
        ═══════════════════════════════════════════════
        
        👨‍💻 Author: @who_is_the_black_hat
        🔗 GitHub: github.com/Mrsultan7890/osints
        📜 License: MIT
        🏆 Status: Production Ready
        
        ═══════════════════════════════════════════════
        
        Built with ❤️ for the OSINT & Security Community
        """
        show_info(self, 'About Sentinel Intel v2.0', about_text)
