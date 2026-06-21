#!/usr/bin/env python3
"""
Sentinel Intel Onboarding Splash — Standalone Demo
Test the onboarding screen without launching the full app
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from PyQt6.QtWidgets import QApplication, QMessageBox
from sentinel_intel.ui.onboarding_splash import OnboardingSplash


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Sentinel Intel - Onboarding Demo")
    
    splash = OnboardingSplash()
    
    # Override the accept callback to show a message instead of launching main window
    original_accept = splash.accept
    
    def demo_accept():
        splash.auto_timer.stop()
        splash.dot_timer.stop()
        splash.close()
        
        # Show demo message
        msg = QMessageBox()
        msg.setWindowTitle("Demo Complete")
        msg.setText("🎉 Onboarding Splash Demo Complete!")
        msg.setInformativeText(
            "In production, this would launch the main Sentinel Intel window.\n\n"
            "Features tested:\n"
            "✓ Professional dark theme\n"
            "✓ Animated loading dots\n"
            "✓ 8-second auto-launch timer\n"
            "✓ Keyboard shortcuts (ENTER/ESCAPE)\n"
            "✓ AI status indicators\n"
            "✓ Feature showcase\n"
            "✓ Gradient button effects\n\n"
            "Press OK to exit demo."
        )
        msg.setIcon(QMessageBox.Icon.Information)
        msg.exec()
        app.quit()
    
    splash.accept = demo_accept
    splash.show()
    
    print("\n" + "="*60)
    print("  SENTINEL INTEL ONBOARDING SPLASH — DEMO MODE")
    print("="*60)
    print("\n📋 Instructions:")
    print("  • Wait 8 seconds for auto-launch")
    print("  • OR press ENTER to launch immediately")
    print("  • OR press ESCAPE to launch immediately")
    print("  • OR click the 'ENTER SENTINEL INTEL' button")
    print("\n🎨 Features:")
    print("  • Professional PyQt6 design")
    print("  • Animated loading dots (6 frames)")
    print("  • Neon teal theme (#00e5c0)")
    print("  • AI status indicators")
    print("  • Figlet ASCII art")
    print("  • Gradient hover effects")
    print("\n🔧 Status:")
    print("  • Window Size: 1100x700px")
    print("  • Position: Centered on screen")
    print("  • Theme: Dark gradient background")
    print("  • Auto-timer: 8 seconds")
    print("\n⏳ Launching splash screen...")
    print("="*60 + "\n")
    
    sys.exit(app.exec())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✋ Demo interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
