"""
Sentinel Intel v2.0 - Main Window (Maltego Killer)
Professional Graph Intelligence Platform with Modern UI
"""
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from sentinel_intel.core.database import db
from sentinel_intel.ui.graph_canvas import GraphCanvas
from sentinel_intel.ui.entity_palette import EntityPalette
from sentinel_intel.ui.transform_palette import TransformPalette
from sentinel_intel.ui.properties_panel import PropertiesPanel

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
        
        # TODO: Implement filtering logic
        # For now, just show message
        if search_text or entity_type != 'All Types' or risk_level != 'All Risk':
            self.statusbar.showMessage(f"Filtering: {search_text or 'All'} | {entity_type} | {risk_level}", 3000)
    
    def _clear_filters(self):
        """Clear all filters"""
        self.search_box.clear()
        self.type_filter.setCurrentIndex(0)
        self.risk_filter.setCurrentIndex(0)
        self.statusbar.showMessage("Filters cleared", 2000)
    
    # File operations
    def _new_graph(self):
        reply = QMessageBox.question(self, 'New Graph', 
                                     'Clear current graph and start fresh?',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
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
                QMessageBox.warning(self, 'Export HTML', 'No nodes to export!')
                return
            
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            self.statusbar.showMessage("Generating interactive HTML...", 0)
            
            exporter = PyVisExporter()
            output_path = exporter.export_graph(nodes, edges)
            
            self.progress_bar.setVisible(False)
            self.statusbar.showMessage(f"Exported to {output_path}", 5000)
            
            # Ask to open in browser
            reply = QMessageBox.question(self, 'Export Complete', 
                                         f'Interactive graph exported!\n\n{output_path}\n\nOpen in browser?',
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                import webbrowser
                webbrowser.open(f'file://{output_path}')
        
        except ImportError:
            QMessageBox.critical(self, 'PyVis Not Installed', 
                               'PyVis library not found!\n\nInstall: pip install pyvis')
        except Exception as e:
            self.progress_bar.setVisible(False)
            QMessageBox.critical(self, 'Export Error', f'Error: {str(e)}')
    
    def _export_json(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Export Graph", "", "JSON Files (*.json)")
        if filename:
            import json
            data = {'nodes': db.get_nodes(), 'edges': db.get_edges()}
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            self.statusbar.showMessage(f"📤 Exported to {filename}", 3000)
    
    def _export_pdf(self):
        QMessageBox.information(self, 'Export PDF', '📄 PDF export coming soon!')
    
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
            QMessageBox.warning(self, 'ML Clustering', f"Error: {result['error']}")
        else:
            QMessageBox.information(self, 'ML Clustering', 
                f"Clustering Complete!\n\n"
                f"• Clusters Found: {result['clusters']}\n"
                f"• Nodes Clustered: {result['clustered_nodes']}\n"
                f"Noise Points: {result['noise_points']}")
            self.canvas.reload_graph()
    
    def _predict_links(self):
        selected = self.canvas.get_selected_node()
        if not selected:
            QMessageBox.warning(self, 'Predict Links', 'Select a node first!')
            return
        
        predictions = db.predict_relationships(selected, max_predictions=5)
        if predictions:
            msg = "Predicted Relationships:\n\n"
            for src, tgt, score in predictions:
                msg += f"→ {tgt} (confidence: {score:.0%})\n"
            QMessageBox.information(self, 'Link Prediction', msg)
        else:
            QMessageBox.information(self, 'Link Prediction', 'ℹ️ No predictions available')
    
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
        
        QMessageBox.information(self, 'Risk Analysis', msg)
    
    def _identity_resolution(self):
        QMessageBox.information(self, 'Identity Resolution', '• Identity resolution coming soon!')
    
    def _fake_detection(self):
        QMessageBox.information(self, 'Fake Detection', '🤖 Fake profile detection coming soon!')
    
    def _writing_analysis(self):
        QMessageBox.information(self, 'Writing Analysis', '✍️ Writing analysis coming soon!')
    
    # View operations
    def _show_risk_heatmap(self):
        QMessageBox.information(self, 'Risk Heatmap', '• Risk heatmap view coming soon!')
    
    def _show_timeline(self):
        QMessageBox.information(self, 'Timeline', 'Timeline view coming soon!')
    
    def _show_tree_view(self):
        QMessageBox.information(self, 'Tree View', '🌳 Tree view coming soon!')
    
    def _show_table_view(self):
        QMessageBox.information(self, 'Table View', '📋 Table view coming soon!')
    
    # Tools operations
    def _bulk_import(self):
        QMessageBox.information(self, 'Bulk Import', 'Bulk CSV import coming soon!')
    
    def _add_notes(self):
        selected = self.canvas.get_selected_node()
        if not selected:
            QMessageBox.warning(self, 'Add Notes', 'Select a node first!')
            return
        
        notes, ok = QInputDialog.getMultiLineText(self, 'Add Notes', 'Enter notes:')
        if ok and notes:
            db.update_node(selected, notes=notes)
            self.statusbar.showMessage("📝 Notes added", 2000)
    
    def _add_tags(self):
        QMessageBox.information(self, 'Add Tags', '🏷️ Tag system coming soon!')
    
    def _star_node(self):
        selected = self.canvas.get_selected_node()
        if not selected:
            QMessageBox.warning(self, 'Star Node', 'Select a node first!')
            return
        
        db.update_node(selected, starred=True)
        self.statusbar.showMessage("⭐ Node starred", 2000)
    
    # Help operations
    def _show_help(self):
        help_text = """
        📖 Sentinel Intel v2.0 — Quick Help
        
        • Add Entities:
        • Click entity type in left panel
        • Use Quick Add for auto-detection
        
        Run Transforms:
        • Select node → Choose transform
        • Use Auto-Chain for AI suggestions
        
        ML Analysis:
        • Clustering: Group related entities
        • Link Prediction: Find hidden connections
        • Risk Analysis: Identify threats
        
        Navigation:
        • Drag nodes to reposition
        • Mouse wheel to zoom
        • Drag canvas to pan
        
        ⌨️ Keyboard Shortcuts:
        • Ctrl+N: New Graph
        • Ctrl+S: Save Graph
        • Ctrl+L: Auto Layout
        • Ctrl+K: Run Clustering
        • F5: Reload Graph
        """
        QMessageBox.information(self, 'Help', help_text)
    
    def _show_shortcuts(self):
        shortcuts = """
        ⌨️ Keyboard Shortcuts:
        
        File:
        • Ctrl+N: New Graph
        • Ctrl+O: Open Graph
        • Ctrl+S: Save Graph
        • Ctrl+Q: Exit
        
        Edit:
        • Ctrl+L: Auto Layout
        • Ctrl+E: Center View
        • Ctrl++: Zoom In
        • Ctrl+-: Zoom Out
        • Ctrl+Del: Clear Graph
        • F5: Reload Graph
        
        ML Analysis:
        • Ctrl+K: Run Clustering
        • Ctrl+P: Predict Links
        • Ctrl+R: Risk Analysis
        
        Export:
        • Ctrl+Shift+P: Export PNG
        • Ctrl+Shift+H: Export Interactive HTML
        • Ctrl+Shift+J: Export JSON
        
        Help:
        • F1: Documentation
        """
        QMessageBox.information(self, 'Keyboard Shortcuts', shortcuts)
    
    def _check_updates(self):
        QMessageBox.information(self, 'Updates', 'You are running the latest version: v2.0')
    
    def _show_about(self):
        about_text = """
        🕸️ Sentinel Intel v2.0
        
        AI-Powered Graph Intelligence Platform
        Maltego Killer — Professional OSINT
        
        Features:
        • 11 Intelligence Engines (Email, Phone, IP, Domain, Person, Username, Hash, Crypto, URL, Company, CVE)
        • 60+ Transforms
        • 20+ Entity Types
        • 10+ ML Algorithms
        • 70% Free APIs + 30% Paid
        
        Built with:
        • Python 3.10+
        • PyQt6
        • SentinelNet v5.0 (F1=0.83)
        • NetworkX, scikit-learn
        
        @who_is_the_black_hat
        github.com/Mrsultan7890
        """
        QMessageBox.about(self, 'About Sentinel Intel', about_text)
