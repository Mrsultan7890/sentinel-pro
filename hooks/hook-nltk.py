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
