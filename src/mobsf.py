"""MobSF API client and utilities.

This module provides a clean interface to MobSF's API endpoints and handles:
- API key generation from secret
- Session management and auto-login
- All API endpoint interactions
"""
import os
import re
import json
import time
import logging
import requests
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

class MobSFClient:
    """Client for interacting with MobSF API endpoints."""
    
    def __init__(
        self,
        base_url: str = None,
        api_key: str = None,
        secret_path: str = None,
        username: str = "mobsf",
        password: str = "mobsf",
        timeout: int = 30
    ):
        """Initialize MobSF client.
        
        Args:
            base_url: MobSF server URL (default: from MOBSF_URL env var or http://localhost:8001)
            api_key: API key (default: from MOBSF_API_KEY env var or generated from secret)
            secret_path: Path to MobSF secret file (default: ~/.MobSF/secret)
            username: MobSF web UI username (default: mobsf)
            password: MobSF web UI password (default: mobsf)
            timeout: Request timeout in seconds (default: 30)
        """
        self.base_url = (base_url or os.getenv("MOBSF_URL", "http://localhost:8001")).rstrip('/')
        self.timeout = timeout
        self.username = username
        self.password = password
        
        # API key: from param > env > secret file
        self.api_key = api_key or os.getenv("MOBSF_API_KEY")
        if not self.api_key:
            secret_path = secret_path or os.path.expanduser("~/.MobSF/secret")
            self.api_key = self._generate_api_key(secret_path)
        
        # Session for web UI interactions
        self.session = requests.Session()
        self._ensure_login()
    
    def _generate_api_key(self, secret_path: str) -> str:
        """Generate API key from MobSF secret file."""
        try:
            if not os.path.isfile(secret_path):
                raise FileNotFoundError(
                    f"MobSF secret not found at {secret_path}. "
                    "Please run MobSF at least once or set MOBSF_API_KEY env var."
                )
            
            with open(secret_path, 'r') as f:
                secret = f.read().strip()
            
            # Same algorithm as MobSF uses
            import hashlib
            api_key = hashlib.sha256(secret.encode()).hexdigest()
            
            if not re.match(r'^[a-f0-9]{64}$', api_key):
                raise ValueError("Generated API key doesn't match expected format")
            
            return api_key
            
        except Exception as e:
            logger.error("Failed to generate API key: %s", e)
            raise
    
    def _ensure_login(self) -> None:
        """Ensure we're logged into the MobSF web UI."""
        try:
            login_url = f"{self.base_url}/login"
            
            # Get CSRF token
            response = self.session.get(login_url, timeout=self.timeout)
            response.raise_for_status()
            
            # Extract CSRF token (adjust pattern if needed)
            csrf_match = re.search(
                r'name="csrfmiddlewaretoken"\s+value="([^"]+)"',
                response.text
            )
            if not csrf_match:
                raise ValueError("Could not find CSRF token in login page")
            
            csrf_token = csrf_match.group(1)
            
            # Perform login
            login_data = {
                "username": self.username,
                "password": self.password,
                "csrfmiddlewaretoken": csrf_token
            }
            response = self.session.post(
                login_url,
                data=login_data,
                headers={"Referer": login_url},
                timeout=self.timeout
            )
            response.raise_for_status()
            
            if "login" in response.url.lower():
                raise ValueError("Login failed - check credentials")
            
        except Exception as e:
            logger.error("Login failed: %s", e)
            raise
    
    def wait_for_server(self, max_attempts: int = 15, delay: int = 2) -> None:
        """Wait for MobSF server to be ready."""
        for attempt in range(max_attempts):
            try:
                response = requests.get(
                    self.base_url,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                if response.status_code == 200:
                    return
            except requests.RequestException:
                pass
            
            if attempt < max_attempts - 1:
                time.sleep(delay)
        
        raise TimeoutError(f"MobSF server not responding at {self.base_url}")
    
    def upload_file(self, file_path: str) -> Tuple[str, Dict[str, Any]]:
        """Upload a file to MobSF.
        
        Args:
            file_path: Path to APK/IPA file to upload
            
        Returns:
            Tuple of (file hash, full response data)
        """
        try:
            with open(file_path, 'rb') as f:
                response = requests.post(
                    f"{self.base_url}/api/v1/upload",
                    files={"file": f},
                    headers={"Authorization": self.api_key},
                    timeout=self.timeout
                )
            response.raise_for_status()
            data = response.json()
            
            file_hash = data.get('hash')
            if not file_hash:
                raise ValueError("Upload succeeded but no hash in response")
                
            return file_hash, data
            
        except Exception as e:
            logger.error("Upload failed: %s", e)
            raise
    
    def start_scan(self, file_hash: str) -> Dict[str, Any]:
        """Start scanning an uploaded file.
        
        Args:
            file_hash: Hash from upload_file()
            
        Returns:
            Scan response data
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/scan",
                data={"hash": file_hash},
                headers={"Authorization": self.api_key},
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('error'):
                raise ValueError(f"Scan failed: {data['error']}")
            
            return data
            
        except Exception as e:
            logger.error("Scan failed: %s", e)
            raise
    
    def get_report_json(self, file_hash: str) -> Dict[str, Any]:
        """Get JSON report for a scanned file.
        
        Args:
            file_hash: Hash from upload_file()
            
        Returns:
            Report data as dict
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/report_json",
                data={"hash": file_hash},
                headers={"Authorization": self.api_key},
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error("Failed to get JSON report: %s", e)
            raise
    
    def download_pdf(
        self,
        file_hash: str,
        output_path: str,
        scan_type: str = "apk"
    ) -> str:
        """Download PDF report for a scanned file.
        
        Args:
            file_hash: Hash from upload_file()
            output_path: Where to save the PDF
            scan_type: Type of scan (apk/ipa)
            
        Returns:
            Path to saved PDF
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/download_pdf",
                data={"hash": file_hash, "scan_type": scan_type},
                headers={"Authorization": self.api_key},
                timeout=self.timeout
            )
            response.raise_for_status()
            
            # Save PDF
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(response.content)
            
            return output_path
            
        except Exception as e:
            logger.error("Failed to download PDF: %s", e)
            raise
    
    def get_report_url(self, file_hash: str) -> str:
        """Get web UI URL for a report.
        
        Args:
            file_hash: Hash from upload_file()
            
        Returns:
            Full URL to report
        """
        return f"{self.base_url}/report/{file_hash}"