# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
#
# Unauthorized copying, distribution, or modification of this software,
# via any medium, is strictly prohibited without written permission.
#
# Licensed users may use this software under the terms of their license.
# For licensing: https://github.com/Mrsultan7890/osints
# ============================================================================

"""
PyInstaller runtime hook — NLTK data path
Binary mein NLTK data _MEIPASS ke andar hoti hai
"""
import sys
import os

# Binary ke andar nltk_data folder ka path set karo
if hasattr(sys, '_MEIPASS'):
    nltk_data_path = os.path.join(sys._MEIPASS, 'nltk_data')
    import nltk
    if nltk_data_path not in nltk.data.path:
        nltk.data.path.insert(0, nltk_data_path)
