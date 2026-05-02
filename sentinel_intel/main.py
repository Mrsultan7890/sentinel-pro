#!/usr/bin/env python3
"""
Sentinel Intel v1.0 - Professional Graph Intelligence Platform
Maltego-style OSINT with AI/ML Power
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

def main():
    try:
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
        from sentinel_intel.ui.main_window import MainWindow
        
        QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
        
        app = QApplication(sys.argv)
        app.setApplicationName("Sentinel Intel")
        app.setOrganizationName("Sentinel Pro")
        
        window = MainWindow()
        window.show()
        
        sys.exit(app.exec())
        
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("\n📦 Install: pip install PyQt6 networkx matplotlib")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
