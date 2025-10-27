import os

class Config:
    # MobSF Configuration
    MOBSF_URL = os.getenv('MOBSF_URL', 'http://localhost:8000')
    MOBSF_API_KEY = os.getenv('MOBSF_API_KEY', '')
    
    # Your App Configuration
    APP_API_KEY = os.getenv('APP_API_KEY', 'your_app_api_key_here')
    
    # PDF Configuration
    WKHTMLTOPDF_PATH = os.getenv('WKHTMLTOPDF_PATH', '/usr/bin/wkhtmltopdf')
    
    # Font paths (project root contains templates/)
    PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
    FONT_DIR = os.path.join(PROJECT_ROOT, 'templates', 'fonts')
    OPENSANS_FONT = os.path.join(FONT_DIR, 'OpenSans-Regular.ttf')
    OSWALD_FONT = os.path.join(FONT_DIR, 'Oswald-Regular.ttf')
