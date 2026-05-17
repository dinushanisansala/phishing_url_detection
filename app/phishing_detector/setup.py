from setuptools import setup

APP = ['gui_app.py']
DATA_FILES = []
OPTIONS = {
    'argv_emulation': True,
    'packages': ['requests', 'flask', 'joblib', 'pandas'],
    'iconfile': 'icon.icns',  # Optional, specify the path to your .icns file if you have one
    'plist': {
        'CFBundleName': 'URL Phishing Detector',  # Name of your application
        'CFBundleShortVersionString': '1.0',
        'CFBundleVersion': '1.0',
        'CFBundleIdentifier': 'com.yourdomain.urlphishingdetector',  # Unique identifier for your app
    },
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
