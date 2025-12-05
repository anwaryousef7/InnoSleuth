#!/usr/bin/env python3
"""
InnoSleuth - InnoDB Forensic Analysis Tool
Main Entry Point

Version: 2.0
Author: Digital Forensics Student
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from gui.main_window import IBDInvestigatorApp
from utils.helpers import exception_hook

def main():
    """Main application entry point"""
    # Set exception hook
    sys.excepthook = exception_hook

    # Enable High DPI
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("InnoSleuth")
    app.setApplicationVersion("2.0")
    app.setStyle('Fusion')

    # Create and show main window
    window = IBDInvestigatorApp()
    window.show()

    # Start event loop
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
