import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import requests
import pandas as pd
import os
import subprocess
import logging
import time

# File paths
LOG_FILE = 'gui_app_debug.log'
FEEDBACK_FILE = 'feedback.csv'
FLASK_API_URL = 'http://127.0.0.1:5000/analyze'  # Update with your Flask API URL

def ensure_feedback_file():
    if not os.path.exists(FEEDBACK_FILE):
        empty_df = pd.DataFrame(columns=['url', 'is_phishing', 'is_actual_phishing'])
        empty_df.to_csv(FEEDBACK_FILE, index=False)
        logging.info("Created new feedback file: %s", FEEDBACK_FILE)

# Ensure the feedback file exists
ensure_feedback_file()