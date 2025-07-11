# Configuration settings for the application

import os

# Mappls API Key - Get from https://mappls.com/
MAPPLS_API_KEY = os.getenv('MAPPLS_API_KEY', 'your-mappls-api-key-here')

# Google Maps API Key
GOOGLE_MAPS_API_KEY = 'AIzaSyBaqd94Q2sk7d3c3WHZD4wTT2yhztBk_08'

# Other configuration settings
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
SQLALCHEMY_DATABASE_URI = 'sqlite:///bus_tracker.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
WTF_CSRF_ENABLED = True

# Base URL configuration
BASE_URL = os.getenv('BASE_URL', 'http://localhost:5000')