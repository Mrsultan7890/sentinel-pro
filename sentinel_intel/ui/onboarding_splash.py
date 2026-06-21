"""
Sentinel Intel v2.0 — Professional Onboarding Splash Screen
Maltego-style OSINT with AI/ML Power
"""
from PyQt6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout, 
    QPushButton, QFrame, QApplication
)
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QPixmap, QPainter, QColor, QPen


class OnboardingSplash(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('')
        self.setFixedSize(1100, 700)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        
        self._dot_frame = 0
        self._setup_ui()
        self._start_animations()
        
        # Center on screen
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)
        
        # Auto-close timer (8 seconds)
        self.auto_timer = QTimer()
        self.auto_timer.timeout.connect(self.accept)
        self.auto_timer.start(8000)
    
    def _setup_ui(self):
        # Main container with neon border
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(3, 3, 3, 3)
        
        # Outer neon frame
        outer_frame = QFrame()
        outer_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #00e5c0, stop:0.5 #00b89a, stop:1 #00e5c0);
                border-radius: 12px;
            }
        """)
        outer_layout = QVBoxLayout(outer_frame)
        outer_layout.setContentsMargins(2, 2, 2, 2)
        
        # Inner container
        inner_frame = QFrame()
        inner_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #080c0e, stop:1 #0d1214);
                border-radius: 10px;
            }
        """)
        inner_layout = QVBoxLayout(inner_frame)
        inner_layout.setContentsMargins(0, 0, 0, 0)
        inner_layout.setSpacing(0)
        
        # Top bar
        top_bar = self._create_top_bar()
        inner_layout.addWidget(top_bar)
        
        # Main content - 2 columns
        content = QWidget()
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        
        # Left panel - Graph art
        left_panel = self._create_left_panel()
        content_layout.addWidget(left_panel)
        
        # Vertical separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setStyleSheet("background: qlineargradient(y1:0, y2:1, stop:0 #003d35, stop:0.5 #00e5c0, stop:1 #003d35); min-width: 2px;")
        content_layout.addWidget(sep)
        
        # Right panel - Features
        right_panel = self._create_right_panel()
        content_layout.addWidget(right_panel)
        
        inner_layout.addWidget(content)
        
        # Bottom bar
        bottom_bar = self._create_bottom_bar()
        inner_layout.addWidget(bottom_bar)
        
        outer_layout.addWidget(inner_frame)
        main_layout.addWidget(outer_frame)
    
    def _create_top_bar(self):
        bar = QFrame()
        bar.setFixedHeight(40)
        bar.setStyleSheet("background: #0d1214; border-bottom: 1px solid #00e5c0;")
        
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(15, 0, 15, 0)
        
        # Left - Logo + Title
        title_label = QLabel("  🕸  SENTINEL INTEL  —  LOADING")
        title_label.setFont(QFont("Fira Code", 9, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #00e5c0; background: transparent;")
        layout.addWidget(title_label)
        
        layout.addStretch()
        
        # Right - Version
        version_label = QLabel("v2.0  ·  @who_is_the_black_hat  ")
        version_label.setFont(QFont("Fira Code", 8))
        version_label.setStyleSheet("color: #2a4a45; background: transparent;")
        layout.addWidget(version_label)
        
        return bar
    
    def _create_left_panel(self):
        panel = QFrame()
        panel.setFixedWidth(380)
        panel.setStyleSheet("background: #0d1214; border: none;")
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        
        # Icon placeholder (using text for now)
        icon_label = QLabel("🕸️")
        icon_label.setFont(QFont("Segoe UI Emoji", 48))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("color: #00e5c0; background: transparent;")
        layout.addWidget(icon_label)
        
        # ASCII Art Title - INTEL
        try:
            import pyfiglet
            intel_art = pyfiglet.figlet_format('INTEL', font='slant')
            art_label = QLabel(intel_art)
            art_label.setFont(QFont("Fira Code", 8, QFont.Weight.Bold))
            art_label.setStyleSheet("color: #00b89a; background: transparent;")
            art_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(art_label)
        except:
            fallback_label = QLabel("I N T E L")
            fallback_label.setFont(QFont("Fira Code", 20, QFont.Weight.Bold))
            fallback_label.setStyleSheet("color: #00b89a; background: transparent;")
            fallback_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(fallback_label)
        
        # Graph Network ASCII Art
        graph_art = """
           ●─────●
          ╱ ╲   ╱ ╲
         ●───●───●───●
          ╲ ╱   ╲ ╱
           ●─────●
            ╲   ╱
             ● ●
        """
        graph_label = QLabel(graph_art)
        graph_label.setFont(QFont("Fira Code", 11))
        graph_label.setStyleSheet("color: #00e5c0; background: transparent;")
        graph_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(graph_label)
        
        # Subtitle
        subtitle = QLabel("GRAPH INTELLIGENCE")
        subtitle.setFont(QFont("Fira Code", 10, QFont.Weight.Bold))
        subtitle.setStyleSheet("color: #00e5c0; background: transparent;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)
        
        subtitle2 = QLabel("Connect the dots. Reveal the truth.")
        subtitle2.setFont(QFont("Fira Code", 8))
        subtitle2.setStyleSheet("color: #2a4a45; background: transparent;")
        subtitle2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle2)
        
        layout.addSpacing(10)
        
        # Animated loading dots
        self.dots_label = QLabel("◉ ○ ○")
        self.dots_label.setFont(QFont("Fira Code", 13))
        self.dots_label.setStyleSheet("color: #00e5c0; background: transparent;")
        self.dots_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.dots_label)
        
        layout.addStretch()
        
        return panel
    
    def _create_right_panel(self):
        panel = QFrame()
        panel.setStyleSheet("background: #080c0e; border: none;")
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(8)
        
        # Main title - SENTINEL with figlet
        try:
            import pyfiglet
            sentinel_art = pyfiglet.figlet_format('SENTINEL', font='slant')
            title_label = QLabel(sentinel_art)
            title_label.setFont(QFont("Fira Code", 9, QFont.Weight.Bold))
            title_label.setStyleSheet("color: #00e5c0; background: transparent;")
            layout.addWidget(title_label)
        except:
            title_label = QLabel("SENTINEL")
            title_label.setFont(QFont("Fira Code", 28, QFont.Weight.Bold))
            title_label.setStyleSheet("color: #00e5c0; background: transparent;")
            layout.addWidget(title_label)
        
        # Tagline
        tagline = QLabel("  AI-Powered Graph Intelligence  ·  Maltego Killer")
        tagline.setFont(QFont("Fira Code", 9))
        tagline.setStyleSheet("color: #5a8a80; background: transparent;")
        layout.addWidget(tagline)
        
        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background: #0f4a52; max-height: 1px;")
        layout.addWidget(sep)
        
        layout.addSpacing(5)
        
        # Features list
        features = [
            ("🎯", "14 Intelligence Engines", "Email · Phone · IP · Domain · Person · More"),
            ("🔗", "60+ OSINT Transforms", "Deep investigation across 40+ platforms"),
            ("🤖", "AI-Powered Analysis", "SentinelNet v5.0 · Groq llama-3.3-70b"),
            ("📊", "10+ ML Algorithms", "Clustering · Link prediction · Risk analysis"),
            ("🕸️", "Interactive Graph", "NetworkX · PyQt6 · Real-time visualization"),
            ("🔍", "20+ Entity Types", "People · Companies · Infrastructure · Threats"),
            ("⚡", "Auto-Chain Intelligence", "AI suggests next investigation steps"),
            ("📈", "Risk Visualization", "Color-coded threat levels · Heatmaps"),
        ]
        
        for icon, title, desc in features:
            feat_widget = QWidget()
            feat_layout = QHBoxLayout(feat_widget)
            feat_layout.setContentsMargins(0, 4, 0, 4)
            feat_layout.setSpacing(8)
            
            # Icon
            icon_label = QLabel(icon)
            icon_label.setFont(QFont("Segoe UI Emoji", 11))
            icon_label.setFixedWidth(30)
            icon_label.setStyleSheet("color: #00e5c0; background: transparent;")
            feat_layout.addWidget(icon_label)
            
            # Text container
            text_container = QWidget()
            text_layout = QVBoxLayout(text_container)
            text_layout.setContentsMargins(0, 0, 0, 0)
            text_layout.setSpacing(2)
            
            title_label = QLabel(title)
            title_label.setFont(QFont("Fira Code", 9, QFont.Weight.Bold))
            title_label.setStyleSheet("color: #cde8e0; background: transparent;")
            text_layout.addWidget(title_label)
            
            desc_label = QLabel(desc)
            desc_label.setFont(QFont("Fira Code", 8))
            desc_label.setStyleSheet("color: #2a4a45; background: transparent;")
            text_layout.addWidget(desc_label)
            
            feat_layout.addWidget(text_container)
            feat_layout.addStretch()
            
            layout.addWidget(feat_widget)
        
        # Separator
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet("background: #0f4a52; max-height: 1px;")
        layout.addWidget(sep2)
        
        layout.addSpacing(5)
        
        # AI Status Pills
        pills_container = QWidget()
        pills_layout = QHBoxLayout(pills_container)
        pills_layout.setContentsMargins(0, 0, 0, 0)
        pills_layout.setSpacing(10)
        
        # Try to check if ML is available
        ml_available = True
        groq_available = True
        
        try:
            from sentinel_intel.engines.ai_engine import AIEngine
            ai = AIEngine()
            ml_available = ai.sentinelnet is not None
            groq_available = ai.groq is not None
        except:
            pass
        
        for label, available in [("SentinelNet v5.0", ml_available), ("Groq llama-3.3-70b", groq_available)]:
            pill = QFrame()
            pill.setStyleSheet(f"""
                background: {'#003d35' if available else '#0d1214'};
                border: 1px solid {'#00e5c0' if available else '#1e3035'};
                border-radius: 4px;
                padding: 6px 12px;
            """)
            
            pill_layout = QHBoxLayout(pill)
            pill_layout.setContentsMargins(8, 4, 8, 4)
            
            dot = QLabel("◉" if available else "◎")
            dot.setFont(QFont("Fira Code", 9))
            dot.setStyleSheet(f"color: {'#00e5c0' if available else '#2a4a45'}; background: transparent;")
            pill_layout.addWidget(dot)
            
            text = QLabel(label)
            text.setFont(QFont("Fira Code", 8))
            text.setStyleSheet(f"color: {'#00e5c0' if available else '#2a4a45'}; background: transparent;")
            pill_layout.addWidget(text)
            
            pills_layout.addWidget(pill)
        
        pills_layout.addStretch()
        layout.addWidget(pills_container)
        
        layout.addStretch()
        
        return panel
    
    def _create_bottom_bar(self):
        bar = QFrame()
        bar.setFixedHeight(70)
        bar.setStyleSheet("background: #0d1214; border-top: 1px solid #00e5c0;")
        
        layout = QVBoxLayout(bar)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(8)
        
        # Info text
        info = QLabel("  Press  ENTER  or click to launch  ·  Auto-launch in 8s")
        info.setFont(QFont("Fira Code", 8))
        info.setStyleSheet("color: #2a4a45; background: transparent;")
        layout.addWidget(info)
        
        # Enter button
        self.enter_btn = QPushButton("  ▶   ENTER SENTINEL INTEL  ")
        self.enter_btn.setFont(QFont("Fira Code", 11, QFont.Weight.Bold))
        self.enter_btn.setFixedHeight(40)
        self.enter_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.enter_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #003d35, stop:0.5 #00e5c0, stop:1 #003d35);
                color: #080c0e;
                border: 2px solid #00e5c0;
                border-radius: 8px;
                padding: 10px 30px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00e5c0, stop:0.5 #39ff6e, stop:1 #00e5c0);
                border: 2px solid #39ff6e;
            }
            QPushButton:pressed {
                background: #005a4e;
            }
        """)
        self.enter_btn.clicked.connect(self.accept)
        layout.addWidget(self.enter_btn, alignment=Qt.AlignmentFlag.AlignRight)
        
        return bar
    
    def _start_animations(self):
        # Dot animation
        self.dot_timer = QTimer()
        self.dot_timer.timeout.connect(self._animate_dots)
        self.dot_timer.start(300)
    
    def _animate_dots(self):
        frames = ['◉ ○ ○', '◉ ◉ ○', '◉ ◉ ◉', '○ ◉ ◉', '○ ○ ◉', '○ ○ ○']
        self.dots_label.setText(frames[self._dot_frame % len(frames)])
        self._dot_frame += 1
    
    def accept(self):
        """Called when user clicks Enter or timer expires"""
        self.auto_timer.stop()
        self.dot_timer.stop()
        self.close()
        
        # Launch main window
        if hasattr(self, '_callback') and self._callback:
            self._callback()
    
    def keyPressEvent(self, event):
        """Handle keyboard events"""
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Escape):
            self.accept()
        else:
            super().keyPressEvent(event)
    
    def set_launch_callback(self, callback):
        """Set callback to launch main window"""
        self._callback = callback


def show_onboarding(callback=None):
    """Show onboarding splash and return when ready"""
    splash = OnboardingSplash()
    if callback:
        splash.set_launch_callback(callback)
    splash.show()
    return splash
