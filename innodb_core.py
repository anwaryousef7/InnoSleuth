import sys
import os
import re
import math
import hashlib
import base64
import struct
import zlib
import binascii
import concurrent.futures
import pickle
import gzip

import ctypes
from PyQt6.QtGui import QIcon  # Ensure this is imported



def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
    
from datetime import datetime
from collections import Counter, defaultdict

# External Libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from fpdf import FPDF
import networkx as nx 

# Optional GPU Support
try:
    import cupy as cp
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

# Try importing YARA
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject, QByteArray, QMutex, QWaitCondition, QDate
from PyQt6.QtGui import QPixmap, QColor, QFont, QAction, QImage
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QTableWidget, QTableWidgetItem,
    QLineEdit, QComboBox, QSplitter, QMessageBox, QProgressBar,
    QTabWidget, QTextEdit, QGroupBox, QHeaderView, QMenu, QFrame,
    QInputDialog, QProgressDialog, QListWidget, QListWidgetItem,
    QScrollArea, QCheckBox, QDialog, QTextEdit, QFormLayout, QDateEdit
)

import sqlite3
import json
# TDE Decryption Support
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    TDE_AVAILABLE = True
except ImportError:
    TDE_AVAILABLE = False


# ---------------------------
# GLOBAL CRASH HANDLER
# ---------------------------
def exception_hook(exctype, value, traceback):
    if exctype == KeyboardInterrupt:
        sys.__excepthook__(exctype, value, traceback)
        return
    print(f"CRITICAL ERROR: {value}")
    try:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setText("Critical Error")
        msg.setInformativeText(str(value))
        msg.exec()
    except: pass
    sys.__excepthook__(exctype, value, traceback)

sys.excepthook = exception_hook



# ============================================================================
# IOC THREAT INTELLIGENCE MODULE - Complete Backend
# ============================================================================
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any
import requests
import time
import logging

@dataclass
class IOCResult:
    ioc: str
    ioc_type: str
    source: str
    malicious: Optional[bool]
    score: Optional[float]
    detections: Optional[int]
    total_engines: Optional[int]
    tags: List[str]
    threat_types: List[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    country: Optional[str]
    asn: Optional[str]
    additional_info: Dict[str, Any]
    error: Optional[str]
    timestamp: str
    def to_dict(self): return asdict(self)

class CTIProvider(ABC):
    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.rate_limit_delay = 0
    @abstractmethod
    def check_hash(self, h: str) -> IOCResult: pass
    @abstractmethod
    def check_ip(self, ip: str) -> IOCResult: pass
    @abstractmethod
    def check_domain(self, d: str) -> IOCResult: pass
    @abstractmethod
    def check_url(self, u: str) -> IOCResult: pass
    def _handle_rate_limit(self):
        if self.rate_limit_delay > 0: time.sleep(self.rate_limit_delay)
    def _create_error_result(self, ioc: str, ioc_type: str, source: str, error: str):
        return IOCResult(ioc=ioc, ioc_type=ioc_type, source=source, malicious=None, 
                        score=None, detections=None, total_engines=None, tags=[], 
                        threat_types=[], first_seen=None, last_seen=None, country=None, 
                        asn=None, additional_info={}, error=error, timestamp=datetime.now().isoformat())

class VirusTotalProvider(CTIProvider):
    def __init__(self, api_key: str, timeout: int = 10):
        super().__init__(api_key, timeout)
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session.headers.update({'x-apikey': self.api_key})
        self.rate_limit_delay = 15
    def check_hash(self, h: str):
        try:
            self._handle_rate_limit()
            r = self.session.get(f"{self.base_url}/files/{h}", timeout=self.timeout)
            if r.status_code == 404: return self._create_error_result(h, "hash", "VirusTotal", "Not found")
            r.raise_for_status()
            d = r.json()['data']['attributes']
            s = d.get('last_analysis_stats', {})
            m = s.get('malicious', 0)
            t = sum(s.values())
            return IOCResult(ioc=h, ioc_type="hash", source="VirusTotal", malicious=m>0,
                           score=(m/t*100) if t>0 else 0, detections=m, total_engines=t,
                           tags=d.get('tags',[])[:5], threat_types=[], 
                           first_seen=str(d.get('first_submission_date',''))[:10],
                           last_seen=str(d.get('last_analysis_date',''))[:10], 
                           country=None, asn=None, additional_info={'sha256':d.get('sha256','')[:16]},
                           error=None, timestamp=datetime.now().isoformat())
        except Exception as e: return self._create_error_result(h, "hash", "VirusTotal", str(e))
    def check_ip(self, ip: str):
        try:
            self._handle_rate_limit()
            r = self.session.get(f"{self.base_url}/ip_addresses/{ip}", timeout=self.timeout)
            r.raise_for_status()
            d = r.json()['data']['attributes']
            s = d.get('last_analysis_stats', {})
            m = s.get('malicious', 0)
            t = sum(s.values())
            return IOCResult(ioc=ip, ioc_type="ip", source="VirusTotal", malicious=m>0,
                           score=(m/t*100) if t>0 else 0, detections=m, total_engines=t,
                           tags=d.get('tags',[])[:5], threat_types=[], first_seen=None,
                           last_seen=str(d.get('last_analysis_date',''))[:10], 
                           country=d.get('country',''), asn=str(d.get('asn','')),
                           additional_info={'owner':d.get('as_owner','')[:30]},
                           error=None, timestamp=datetime.now().isoformat())
        except Exception as e: return self._create_error_result(ip, "ip", "VirusTotal", str(e))
    def check_domain(self, dom: str):
        try:
            self._handle_rate_limit()
            r = self.session.get(f"{self.base_url}/domains/{dom}", timeout=self.timeout)
            r.raise_for_status()
            d = r.json()['data']['attributes']
            s = d.get('last_analysis_stats', {})
            m = s.get('malicious', 0)
            t = sum(s.values())
            return IOCResult(ioc=dom, ioc_type="domain", source="VirusTotal", malicious=m>0,
                           score=(m/t*100) if t>0 else 0, detections=m, total_engines=t,
                           tags=d.get('tags',[])[:5], threat_types=[], first_seen=None,
                           last_seen=str(d.get('last_analysis_date',''))[:10],
                           country=None, asn=None, additional_info={},
                           error=None, timestamp=datetime.now().isoformat())
        except Exception as e: return self._create_error_result(dom, "domain", "VirusTotal", str(e))
    def check_url(self, url: str):
        try:
            self._handle_rate_limit()
            import base64
            uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            r = self.session.get(f"{self.base_url}/urls/{uid}", timeout=self.timeout)
            if r.status_code == 404: return self._create_error_result(url, "url", "VirusTotal", "Not found")
            r.raise_for_status()
            d = r.json()['data']['attributes']
            s = d.get('last_analysis_stats', {})
            m = s.get('malicious', 0)
            t = sum(s.values())
            return IOCResult(ioc=url[:50], ioc_type="url", source="VirusTotal", malicious=m>0,
                           score=(m/t*100) if t>0 else 0, detections=m, total_engines=t,
                           tags=d.get('tags',[])[:5], threat_types=[], 
                           first_seen=str(d.get('first_submission_date',''))[:10],
                           last_seen=str(d.get('last_analysis_date',''))[:10],
                           country=None, asn=None, additional_info={},
                           error=None, timestamp=datetime.now().isoformat())
        except Exception as e: return self._create_error_result(url, "url", "VirusTotal", str(e))

class AlienVaultOTXProvider(CTIProvider):
    def __init__(self, api_key: str, timeout: int = 10):
        super().__init__(api_key, timeout)
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.session.headers.update({'X-OTX-API-KEY': self.api_key})
    def check_hash(self, h: str):
        try:
            r = self.session.get(f"{self.base_url}/indicators/file/{h}/general", timeout=self.timeout)
            r.raise_for_status()
            p = r.json().get('pulse_info',{}).get('count',0)
            return IOCResult(ioc=h, ioc_type="hash", source="AlienVault OTX", malicious=p>0,
                           score=min(p*10,100), detections=p, total_engines=None,
                           tags=[], threat_types=[], first_seen=None, last_seen=None,
                           country=None, asn=None, additional_info={'pulses':p},
                           error=None, timestamp=datetime.now().isoformat())
        except Exception as e: return self._create_error_result(h, "hash", "AlienVault OTX", str(e))
    def check_ip(self, ip: str):
        try:
            r = self.session.get(f"{self.base_url}/indicators/IPv4/{ip}/general", timeout=self.timeout)
            r.raise_for_status()
            d = r.json()
            p = d.get('pulse_info',{}).get('count',0)
            return IOCResult(ioc=ip, ioc_type="ip", source="AlienVault OTX", malicious=p>0,
                           score=min(p*10,100), detections=p, total_engines=None,
                           tags=[], threat_types=[], first_seen=None, last_seen=None,
                           country=d.get('country_name',''), asn=d.get('asn',''),
                           additional_info={'pulses':p,'city':d.get('city','')},
                           error=None, timestamp=datetime.now().isoformat())
        except Exception as e: return self._create_error_result(ip, "ip", "AlienVault OTX", str(e))
    def check_domain(self, dom: str):
        try:
            r = self.session.get(f"{self.base_url}/indicators/domain/{dom}/general", timeout=self.timeout)
            r.raise_for_status()
            p = r.json().get('pulse_info',{}).get('count',0)
            return IOCResult(ioc=dom, ioc_type="domain", source="AlienVault OTX", malicious=p>0,
                           score=min(p*10,100), detections=p, total_engines=None,
                           tags=[], threat_types=[], first_seen=None, last_seen=None,
                           country=None, asn=None, additional_info={'pulses':p},
                           error=None, timestamp=datetime.now().isoformat())
        except Exception as e: return self._create_error_result(dom, "domain", "AlienVault OTX", str(e))
    def check_url(self, url: str):
        try:
            r = self.session.get(f"{self.base_url}/indicators/url/{quote(url,safe='')}/general", timeout=self.timeout)
            r.raise_for_status()
            p = r.json().get('pulse_info',{}).get('count',0)
            return IOCResult(ioc=url[:50], ioc_type="url", source="AlienVault OTX", malicious=p>0,
                           score=min(p*10,100), detections=p, total_engines=None,
                           tags=[], threat_types=[], first_seen=None, last_seen=None,
                           country=None, asn=None, additional_info={'pulses':p},
                           error=None, timestamp=datetime.now().isoformat())
        except Exception as e: return self._create_error_result(url, "url", "AlienVault OTX", str(e))

class AbuseIPDBProvider(CTIProvider):
    def __init__(self, api_key: str, timeout: int = 10):
        super().__init__(api_key, timeout)
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.session.headers.update({'Key': self.api_key, 'Accept': 'application/json'})
    def check_hash(self, h: str):
        return self._create_error_result(h, "hash", "AbuseIPDB", "Not supported")
    def check_ip(self, ip: str):
        try:
            r = self.session.get(f"{self.base_url}/check", 
                params={'ipAddress':ip,'maxAgeInDays':90}, timeout=self.timeout)
            r.raise_for_status()
            d = r.json()['data']
            sc = d.get('abuseConfidenceScore',0)
            return IOCResult(ioc=ip, ioc_type="ip", source="AbuseIPDB", malicious=sc>25,
                           score=float(sc), detections=d.get('totalReports',0), total_engines=None,
                           tags=[], threat_types=[], first_seen=None, 
                           last_seen=d.get('lastReportedAt','')[:10],
                           country=d.get('countryCode',''), asn=None,
                           additional_info={'isp':d.get('isp','')[:30]},
                           error=None, timestamp=datetime.now().isoformat())
        except Exception as e: return self._create_error_result(ip, "ip", "AbuseIPDB", str(e))
    def check_domain(self, d: str):
        return self._create_error_result(d, "domain", "AbuseIPDB", "Not supported")
    def check_url(self, u: str):
        return self._create_error_result(u, "url", "AbuseIPDB", "Not supported")

class ThreatIntelAggregator:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.providers = {}
        self._initialize_providers()
    def _initialize_providers(self):
        if 'virustotal' in self.config:
            try: self.providers['virustotal'] = VirusTotalProvider(self.config['virustotal']['api_key'])
            except Exception as e: logging.error(f"VT: {e}")
        if 'alienvault_otx' in self.config:
            try: self.providers['alienvault_otx'] = AlienVaultOTXProvider(self.config['alienvault_otx']['api_key'])
            except Exception as e: logging.error(f"OTX: {e}")
        if 'abuseipdb' in self.config:
            try: self.providers['abuseipdb'] = AbuseIPDBProvider(self.config['abuseipdb']['api_key'])
            except Exception as e: logging.error(f"AbuseIPDB: {e}")
    def check_ioc(self, ioc_value: str, ioc_type: str, providers: Optional[List[str]] = None):
        if not self.providers: return []
        providers_to_check = providers or list(self.providers.keys())
        results = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            for pname in providers_to_check:
                if pname not in self.providers: continue
                provider = self.providers[pname]
                if ioc_type == 'hash': future = executor.submit(provider.check_hash, ioc_value)
                elif ioc_type == 'ip': future = executor.submit(provider.check_ip, ioc_value)
                elif ioc_type == 'domain': future = executor.submit(provider.check_domain, ioc_value)
                elif ioc_type == 'url': future = executor.submit(provider.check_url, ioc_value)
                else: continue
                futures[future] = pname
            for future in as_completed(futures):
                try: results.append(future.result(timeout=30))
                except Exception as e: logging.error(f"Error: {e}")
        return results
    def export_results_json(self, results, filepath):
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)

# End of IOC TI Module
# ============================================================================

# ---------------------------
# 1. CONFIG & PATTERNS
# ---------------------------

SUSPICIOUS_KEYWORDS = [
    "crime", "criminal", "illegal", "illicit", "unlawful", "contraband",
    "felony", "misdemeanor", "offender", "fugitive", "arrest", "warrant",
    "trafficking", "smuggling", "cartel", "mafia", "gang", "terror",
    "homicide", "murder", "assassin", "kidnap", "hostage", "corpse",
    "victim", "suspect", "confession", "testimony", "guilty", "verdict",
    "money laundering", "laundering", "geldwäsche", "schwarzgeld", "smurfing",
    "structuring", "tax evasion", "offshore", "shell company", "tax haven",
    "bribe", "bribery", "corruption", "kickback", "bestechung", "embezzle",
    "fraud", "scam", "ponzi", "pyramid scheme", "defraud", "fake invoice",
    "bank drop", "mule", "wire transfer", "western union", "moneygram",
    "launder", "wash money", "dirty money", "frozen account", "seize",
    "drug", "narcotic", "cocaine", "heroin", "meth", "amphetamine",
    "marijuana", "cannabis", "weed", "hash", "fentanyl", "opioid",
    "mdma", "ecstasy", "lsd", "dealer", "supplier", "dose", "overdose",
    "cartel", "pills", "prescription", "pharmacy", "substance",
    "weapon", "firearm", "gun", "pistol", "rifle", "ak47", "ar15",
    "ammo", "ammunition", "munition", "explosive", "bomb", "grenade",
    "c4", "detonator", "ied", "nuclear", "radioactive", "biohazard",
    "silencer", "suppressor", "caliber", "ballistics",
    "hack", "hacked", "hacker", "breach", "compromise", "intrusion",
    "malware", "ransomware", "spyware", "adware", "rootkit", "trojan",
    "worm", "virus", "backdoor", "keylogger", "botnet", "ddos", "dos attack",
    "phishing", "spear phishing", "social engineering", "whaling",
    "exploit", "payload", "shellcode", "buffer overflow", "injection",
    "sql injection", "sqli", "xss", "cross-site", "csrf", "rce",
    "zero-day", "0day", "vulnerability", "patch", "bypass", "crack",
    "brute force", "rainbow table", "hashcat", "john the ripper",
    "metasploit", "cobalt strike", "empire", "mimikatz", "wireshark",
    "nmap", "burp suite", "owasp", "cve", "pwned", "defacement",
    "cmd.exe", "powershell", "/bin/sh", "/bin/bash", "whoami", "net user",
    "eval(", "exec(", "base64_decode", "system(", "popen", "passthru",
    "alert(", "onload=", "onerror=", "javascript:", "vbscript:",
    "union select", "waitfor delay", "or 1=1", "drop table", "truncate",
    "127.0.0.1", "localhost", "admin", "root", "superuser", "passwd",
    "shadow", "htpasswd", "ssh-rsa", "private key",
    "tor browser", "onion", "darkweb", "deepweb", "silk road",
    "bitcoin", "btc", "monero", "xmr", "ethereum", "eth", "wallet",
    "private key", "seed phrase", "vpn", "proxy", "socks5", "tunnel",
    "protonmail", "tutanota", "signal", "telegram", "wickr", "pgp", "gpg"
]

REGEX_PATTERNS = {
    "Email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "IP_v4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "IBAN": re.compile(r'\b[A-Z]{2}[0-9A-Z]{10,30}\b'),
    "Crypto": re.compile(r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59}|0x[a-fA-F0-9]{40})\b'),
    "Credit_Card": re.compile(r'\b(?:\d[ -]*?){13,19}\b'),
    "Date_Text": re.compile(r'(\d{4}-\d{2}-\d{2})|(\d{2}/\d{2}/\d{4})'),
    "Unix_Time": re.compile(r'\b1[5-7]\d{8}\b'),
    "Base64_Suspect": re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:={0,2})'),
    "Hex_Suspect": re.compile(r'\b[0-9a-fA-F]{16,}\b')
}

INNODB_PAGE_TYPES = {
    0x45BF: "INDEX (B-Tree)", 0x0002: "UNDO LOG", 0x0003: "INODE",
    0x0004: "IBUF FREE LIST", 0x000A: "BLOB (Binary)", 0x0000: "ALLOCATED",
    0x0005: "IBUF BITMAP", 0x0006: "SYS", 0x0007: "TRX SYS",
    0x0008: "FSP HDR", 0x0009: "XDES", 0x000B: "ZBLOB",
    0x000C: "BLOB2", 0x000D: "INDEX (Comp)", 0x000E: "INDEX (Comp2)"
}

CARVING_SIGNATURES = {
    b'\x89\x50\x4E\x47': {'ext': 'png', 'type': 'PNG Image', 'head_len': 4},
    b'\xFF\xD8\xFF':     {'ext': 'jpg', 'type': 'JPEG Image', 'head_len': 3},
    b'%PDF-':            {'ext': 'pdf', 'type': 'PDF Document', 'head_len': 5},
    b'PK\x03\x04':       {'ext': 'zip', 'type': 'ZIP Archive', 'head_len': 4}
}

APP_ICON_SVG = r'''<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48">
  <defs>
    <linearGradient id="mainGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#00d4ff;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#0099cc;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="accentGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#00ffff;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#00bcd4;stop-opacity:1" />
    </linearGradient>
  </defs>

  <!-- Shield shape (forensics/security) -->
  <path d="M 24 4 L 8 10 L 8 22 Q 8 32 24 44 Q 40 32 40 22 L 40 10 Z" 
        fill="none" stroke="url(#mainGrad)" stroke-width="2.5"/>

  <!-- Database symbol inside shield -->
  <ellipse cx="24" cy="18" rx="10" ry="3.5" fill="none" stroke="url(#accentGrad)" stroke-width="2"/>
  <line x1="14" y1="18" x2="14" y2="26" stroke="url(#accentGrad)" stroke-width="2"/>
  <line x1="34" y1="18" x2="34" y2="26" stroke="url(#accentGrad)" stroke-width="2"/>
  <ellipse cx="24" cy="26" rx="10" ry="3.5" fill="none" stroke="url(#accentGrad)" stroke-width="2"/>

  <!-- Magnifying glass overlay -->
  <circle cx="28" cy="30" r="5.5" fill="none" stroke="#00ffff" stroke-width="2"/>
  <line x1="32" y1="34" x2="36" y2="38" stroke="#00ffff" stroke-width="2.5" stroke-linecap="round"/>

  <!-- Binary code dots -->
  <circle cx="20" cy="21" r="1" fill="#00bcd4"/>
  <circle cx="24" cy="21" r="1" fill="#00bcd4"/>
  <circle cx="28" cy="21" r="1" fill="#00bcd4"/>
</svg>'''

# ---------------------------
# 2. HELPER FUNCTIONS & ENGINES
# ---------------------------

class FastEntropy:
    """ High Performance Entropy Calculator using Numpy or CuPy (GPU) """
    @staticmethod
    def calculate(data_bytes):
        if not data_bytes: return 0.0
        
        # GPU Acceleration Check
        if GPU_AVAILABLE:
            try:
                # Move to GPU memory
                arr_gpu = cp.frombuffer(data_bytes, dtype=cp.uint8)
                # Compute bincount on GPU
                counts = cp.bincount(arr_gpu, minlength=256)
                # Normalize
                probs = counts[counts > 0] / len(data_bytes)
                # Compute Entropy
                entropy = -cp.sum(probs * cp.log2(probs))
                return float(entropy)
            except:
                pass # Fallback to CPU if GPU memory fails
        
        # CPU Vectorized (Numpy) - Much faster than pure Python loop
        arr = np.frombuffer(data_bytes, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256)
        probs = counts[counts > 0] / len(data_bytes)
        return -np.sum(probs * np.log2(probs))

def classify_entropy(val):
    if val < 0.1: return "Empty / Null"
    if val < 3.0: return "Low (Sparse/Text)"
    if val < 5.0: return "Medium (Code/Mixed)"
    if val < 7.5: return "High (Compressed)"
    return "Very High (Encrypted/Random)"

def get_page_type_str(page_bytes):
    try:
        if len(page_bytes) < 26: return "Unknown"
        p_type = struct.unpack('>H', page_bytes[24:26])[0]
        return INNODB_PAGE_TYPES.get(p_type, f"Unknown (0x{p_type:04X})")
    except: return "Error"

def luhn_check(n):
    try:
        d = [int(x) for x in str(n) if x.isdigit()]
        return sum(d[-1::-2] + [sum(divmod(2*i, 10)) for i in d[-2::-2]]) % 10 == 0
    except: return False

def calculate_file_hashes(path):
    m, s = hashlib.md5(), hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while c := f.read(65536): m.update(c); s.update(c)
        return m.hexdigest(), s.hexdigest()
    except: return "Err", "Err"

def convert_unix_time(ts):
    try: return datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except: return None



# ═══════════════════════════════════════════════════════════════════
# TDE DECRYPTION ENGINE - Thread-Safe Implementation
# ═══════════════════════════════════════════════════════════════════
class TDEDecryptor:
    """InnoDB Transparent Data Encryption Decryptor"""
    def __init__(self, master_key=None):
        self.master_key = master_key
        self.tablespace_keys = {}

    def detect_encrypted(self, page_data):
        try:
            if len(page_data) < 38:
                return False
            enc_flag = struct.unpack('>H', page_data[26:28])[0]
            if enc_flag == 0x0001:
                return True
            ent = FastEntropy.calculate(page_data)
            return ent > 7.8
        except:
            return False

    def decrypt_page(self, page_data, page_id):
        if not self.master_key or not TDE_AVAILABLE:
            return page_data
        try:
            page_size = len(page_data)
            if page_id == 0 and 0 not in self.tablespace_keys:
                iv = page_data[38:54]
                enc_ts_key = page_data[54:86]
                cipher = Cipher(algorithms.AES(self.master_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                ts_key = decryptor.update(enc_ts_key) + decryptor.finalize()
                self.tablespace_keys[0] = ts_key[:32]
            if 0 in self.tablespace_keys:
                iv = page_data[38:54]
                encrypted_data = page_data[54:]
                cipher = Cipher(algorithms.AES(self.tablespace_keys[0]), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                return page_data[:54] + decrypted_data[:page_size-54]
        except Exception:
            pass
        return page_data


# ---------------------------
# ENHANCED: MESSAGE RECONSTRUCTOR WITH TELEGRAM/WHATSAPP SUPPORT
# ---------------------------
class MessageReconstructor:
    """
    Enhanced Reconstructor with Telegram/WhatsApp BLOB support
    Improved heuristics for fragmented message reconstruction
    """
    def __init__(self, artifacts_df):
        self.df = artifacts_df

    def reconstruct(self):
        if self.df.empty:
            return []

        # Broaden filter to include blobs and base64 suspects
        mask = self.df['Type'].str.contains('Record|Blob|Deleted|Raw Carve', case=False, na=False) | \
               self.df['Data'].astype(str).str.contains(REGEX_PATTERNS.get('Base64_Suspect', ''), na=False)
        text_df = self.df[mask].sort_values(by=['PageID','RawOff'])

        reconstructed = []

        # Stronger telegram/whatsapp detection patterns
        telegram_seg = re.compile(rb'[\x00-\x1f][A-Za-z0-9_\-]{6,}')
        b64_re = re.compile(r'(?:[A-Za-z0-9+/]{4}){6,}(?:={0,2})')

        def norm(s):
            try:
                return str(s)
            except:
                return ''

        prev_row = None
        current_chain = None

        for _, row in text_df.iterrows():
            data = norm(row['Data'])
            pid = int(row.get('PageID', -1) or -1)

            # Base64 detection heuristic
            is_b64 = bool(b64_re.search(data))

            # Clustering: if page difference small -> append
            if prev_row is not None and (pid - int(prev_row.get('PageID', pid))) <= 2:
                if current_chain is None:
                    current_chain = [prev_row, row]
                else:
                    current_chain.append(row)
            else:
                # Flush old chain
                if current_chain and len(current_chain) > 1:
                    assembled = ' '.join([norm(r['Data']) for r in current_chain])
                    if len(assembled) > 120:
                        reconstructed.append({
                            'Type': 'Reconstructed Msg',
                            'Data': assembled,
                            'PageStart': int(current_chain[0].get('PageID',0)),
                            'PageEnd': int(current_chain[-1].get('PageID',0))
                        })
                current_chain = None

            prev_row = row

            # Special: telegram-like segments - greedy merge
            if telegram_seg.search(data.encode('latin-1', errors='ignore')) or is_b64:
                cluster = [row]
                idx = row.name
                try:
                    idx_pos = list(text_df.index).index(idx)
                    for k in range(1,4):
                        if idx_pos+k < len(text_df):
                            cluster.append(text_df.iloc[idx_pos+k])
                        if idx_pos-k >= 0:
                            cluster.insert(0, text_df.iloc[idx_pos-k])
                except Exception:
                    pass

                assembled = ' '.join([norm(r['Data']) for r in cluster])
                if len(assembled) > 120:
                    reconstructed.append({
                        'Type': 'Reconstructed Msg',
                        'Data': assembled,
                        'PageStart': int(cluster[0].get('PageID',0)),
                        'PageEnd': int(cluster[-1].get('PageID',0))
                    })

        # Final flush
        if current_chain and len(current_chain) > 1:
            assembled = ' '.join([norm(r['Data']) for r in current_chain])
            if len(assembled) > 120:
                reconstructed.append({
                    'Type': 'Reconstructed Msg',
                    'Data': assembled,
                    'PageStart': int(current_chain[0].get('PageID',0)),
                    'PageEnd': int(current_chain[-1].get('PageID',0))
                })

        # Deduplicate by content hash
        seen = set()
        final = []
        for r in reconstructed:
            h = hash(r['Data'])
            if h in seen:
                continue
            seen.add(h)
            final.append(r)

        return final

# ---------------------------
# SCHEMA & STRUCTURED PARSING
# ---------------------------
class TableSchema:
    def __init__(self, create_sql):
        self.columns = []
        self.nullable_count = 0
        self.variable_count = 0
        self.parse_sql(create_sql)
        
    def parse_sql(self, sql):
        match = re.search(r'\((.*)\)', sql.replace('\n', ' '), re.DOTALL)
        if not match: return
        
        defs = match.group(1).split(',')
        for d in defs:
            d = d.strip()
            if not d or d.upper().startswith(('PRIMARY', 'KEY', 'INDEX', 'CONSTRAINT', 'UNIQUE')):
                continue
            
            parts = d.split()
            if len(parts) < 2: continue
            
            col_name = parts[0].strip('`"')
            col_type_raw = parts[1].upper()
            
            is_nullable = "NOT NULL" not in d.upper()
            if is_nullable: self.nullable_count += 1
            
            col_len = 0
            is_var = False
            
            len_match = re.search(r'\((\d+)\)', d)
            if len_match:
                col_len = int(len_match.group(1))
            
            base_type = col_type_raw.split('(')[0]
            
            if 'VARCHAR' in base_type or 'TEXT' in base_type or 'BLOB' in base_type:
                is_var = True
                self.variable_count += 1
            elif 'INT' in base_type:
                col_len = 4
                if 'BIGINT' in base_type: col_len = 8
                elif 'SMALLINT' in base_type: col_len = 2
                elif 'TINYINT' in base_type: col_len = 1
            elif 'DATE' in base_type:
                col_len = 3
            elif 'TIMESTAMP' in base_type:
                col_len = 4
            elif 'CHAR' in base_type:
                pass 
                
            self.columns.append({
                'name': col_name,
                'type': base_type,
                'len': col_len,
                'nullable': is_nullable,
                'is_variable': is_var
            })

# ---------------------------
# 3. FORENSIC AI ENGINE (Lite)
# ---------------------------
# ═══════════════════════════════════════════════════════════════════
# ENHANCED - ibdNinja Features | By: Anwar Yousef
# ═══════════════════════════════════════════════════════════════════
class SDIParser:
    def __init__(self): self.tables = {}
    def parse_sdi(self, fp):
        try:
            with open(fp, 'rb') as f:
                for p in range(3, 8):
                    f.seek(p * 16384)
                    d = f.read(16384)
                    if b'"dd_object"' in d:
                        import json
                        s = d.find(b'{')
                        if s != -1:
                            try: return json.loads(d[s:d.rfind(b'}')+1].decode('utf-8', errors='ignore'))
                            except: pass
        except: pass
        return None

class InstantColumnsDetector:
    def detect(self, rd):
        try:
            if len(rd) > 5 and rd[5] & 0x20: return {'instant': True, 'waste': len(rd)//10}
        except: pass
        return {'instant': False, 'waste': 0}

class AdvancedSpaceAnalyzer:
    def analyze(self, pd, recs):
        v = sum(r.get('size', 0) for r in recs if not r.get('del'))
        d = sum(r.get('size', 0) for r in recs if r.get('del'))
        return {'valid': v, 'deleted': d, 'free': max(0, 16384-v-d-100)}

class MultiVersionRecordAnalyzer:
    def analyze(self, rd):
        try:
            if len(rd) >= 12:
                t = int.from_bytes(rd[6:12], 'big')
                return {'ver': 1 if t<1e6 else (2 if t<1e7 else 3), 'age': 'old' if t<1e6 else ('med' if t<1e7 else 'new')}
        except: pass
        return {'ver': 0, 'age': 'cur'}

class ForensicAI:
    def __init__(self):
        self.vocab = {}
        self.spam_probs = {}
        self.ham_probs = {}
        self.p_spam = 0.5
        self.p_ham = 0.5
        self.alpha = 1.0
        self._train_internal_model()

    def _tokenize(self, text):
        return re.findall(r'\b[a-z]{3,}\b', text.lower())

    def _train_internal_model(self):
        training_data = [
            ("delete the logs immediately cover tracks", 1), ("transfer funds to offshore account now", 1),
            ("bypass firewall with shellcode injection", 1), ("upload the malware payload to server", 1),
            ("encrypt the files and demand ransom", 1), ("buy bitcoin using tor browser", 1),
            ("meeting at the drop point tonight", 1), ("hide the body in the trunk", 1),
            ("unauthorized access root privilege", 1), ("sql injection vulnerability found", 1),
            ("credit card dump for sale", 1), ("clean the money through shell company", 1),
            ("disable antivirus before execution", 1), ("keylogger captured password", 1),
            ("brute force attack successful", 1), ("dump the database and leak it", 1),
            ("create fake invoice for tax evasion", 1),
            ("system update completed successfully", 0), ("select * from users where id = 1", 0),
            ("meeting scheduled for monday morning", 0), ("database connection established", 0),
            ("please reset my password thanks", 0), ("invoice paid via bank transfer", 0),
            ("check the server logs for errors", 0), ("installing new printer driver", 0),
            ("weather is nice today", 0), ("project deadline is extended", 0),
            ("backup restored from tape", 0), ("network latency is high", 0),
            ("html css javascript tutorial", 0), ("user logged out session ended", 0)
        ]

        spam_counts = defaultdict(int); ham_counts = defaultdict(int)
        spam_total = 0; ham_total = 0; vocab = set()

        for text, label in training_data:
            tokens = self._tokenize(text)
            for t in tokens:
                vocab.add(t)
                if label == 1: spam_counts[t] += 1; spam_total += 1
                else: ham_counts[t] += 1; ham_total += 1
        
        self.vocab = vocab; vocab_size = len(vocab)
        for w in vocab:
            self.spam_probs[w] = (spam_counts[w] + self.alpha) / (spam_total + self.alpha * vocab_size)
            self.ham_probs[w] = (ham_counts[w] + self.alpha) / (ham_total + self.alpha * vocab_size)

    def predict_score(self, text):
        if not text or len(text) < 15: return 0.0
        tokens = self._tokenize(text)
        if len(tokens) < 3: return 0.0
        log_prob_spam = math.log(self.p_spam); log_prob_ham = math.log(self.p_ham)
        relevant_tokens = 0
        for t in tokens:
            if t in self.vocab:
                relevant_tokens += 1
                log_prob_spam += math.log(self.spam_probs[t])
                log_prob_ham += math.log(self.ham_probs[t])
        if relevant_tokens < 2: return 0.0
        if log_prob_spam > log_prob_ham:
            diff = log_prob_spam - log_prob_ham
            return min(0.99, 0.5 + (diff / 10.0))
        return 0.01

# ---------------------------
# 4. REDO LOG PARSER
# ---------------------------
class RedoLogParser:
    BLOCK_SIZE = 512
    HEADER_SIZE = 12
    TRAILER_SIZE = 4
    
    def __init__(self):
        pass

    def parse_block(self, block_data, block_index):
        if len(block_data) != self.BLOCK_SIZE: return []
        
        hdr_blk_no = struct.unpack('>I', block_data[0:4])[0]
        hdr_data_len = struct.unpack('>H', block_data[4:6])[0]
        
        if hdr_data_len > 512 or hdr_data_len < 12:
            return []
            
        payload = block_data[self.HEADER_SIZE : hdr_data_len]
        results = []
        txt_hits = self.extract_strings(payload)
        for txt in txt_hits:
            results.append({
                "Type": "REDO LOG", "Data": txt, 
                "State": "Pending/History", 
                "Offset": (block_index * self.BLOCK_SIZE) + self.HEADER_SIZE,
                "Note": f"Block: {hdr_blk_no}"
            })
        return results

    def extract_strings(self, raw_bytes):
        results = []
        matches = re.findall(rb'[\x20-\x7E]{4,}', raw_bytes)
        results.extend([m.decode('latin-1') for m in matches])
        return list(set(results))

# ---------------------------
# 5. INNODB PARSER ENGINE
# ---------------------------
class InnoDBParser:
    FIL_PAGE_OFFSET = 4
    FIL_PAGE_LSN = 16    
    FIL_PAGE_TYPE = 24
    
    PAGE_N_HEAP = 4
    PAGE_FREE = 6
    PAGE_GARBAGE = 8
    INFIMUM = 99
    SUPREMUM = 112
    
    def __init__(self, page_size=16384, schema=None):
        self.page_size = page_size
        self.schema = schema

    def decompress_if_needed(self, page_data):
        try:
            if not page_data: return None
            # Check Page Header for Compressed Types
            try:
                p_type = self.read_uint16(page_data, self.FIL_PAGE_TYPE)
            except: p_type = 0
            
            # 0x000D: INDEX (Comp), 0x000E: INDEX (Comp2), 0x001F: Compressed
            if p_type in [0x000D, 0x000E, 0x001F]:
                try:
                    return zlib.decompress(page_data[38:])
                except:
                    pass

            # Fallback: Check for Zlib magic bytes at offset 38
            if len(page_data) > 38:
                if page_data[38:40] in [b'\x78\x9c', b'\x78\x01', b'\x78\xda']:
                    try: return zlib.decompress(page_data[38:])
                    except: pass
            
            # Check for Zlib magic bytes at offset 0
            if page_data.startswith(b'\x78\x9c') or page_data.startswith(b'\x78\x01') or page_data.startswith(b'\x78\xda'):
                try: return zlib.decompress(page_data)
                except: pass
                
            return None
        except:
            return None

    def read_uint16(self, data, offset):
        if offset + 2 > len(data): return 0
        return struct.unpack('>H', data[offset:offset+2])[0]

    def read_uint64(self, data, offset):
        if offset + 8 > len(data): return 0
        return struct.unpack('>Q', data[offset:offset+8])[0]

    def get_page_lsn(self, page_data):
        try: return self.read_uint64(page_data, self.FIL_PAGE_LSN)
        except: return 0

    def get_record_header(self, page, offset):
        try:
            header_start = offset - 5
            if header_start < 0: return None
            next_relative = struct.unpack('>h', page[header_start+3:header_start+5])[0]
            next_off = (offset + next_relative) & 0xFFFF
            flags = page[header_start]
            is_deleted = True if (flags & 0x20) else False
            return next_off, is_deleted
        except:
            return None

    def extract_advanced_strings(self, raw_bytes):
        results = []
        matches = re.findall(rb'[\x20-\x7E]{4,}', raw_bytes)
        results.extend([m.decode('latin-1') for m in matches])
        matches_utf16 = re.findall(rb'(?:[\x20-\x7E]\x00){4,}', raw_bytes)
        for m in matches_utf16:
            try: results.append(m.decode('utf-16le'))
            except: pass
        return list(set(results))

    def parse_blob_page(self, page_data, page_id):
        try:
            blob_content = page_data[38 : -8]
            is_zblob = (self.read_uint16(page_data, self.FIL_PAGE_TYPE) == 0x000B)
            results = []
            
            if is_zblob:
                 try:
                     decompressed = zlib.decompress(blob_content)
                     results.append({
                         "Type": "ZBLOB Payload", "Data": f"[Compressed Content Decompressed: {len(decompressed)} bytes]",
                         "State": "Active", "Offset": page_id * self.page_size,
                         "RawBytes": decompressed
                     })
                     strs = self.extract_advanced_strings(decompressed)
                     for s in strs:
                         results.append({"Type": "ZBLOB String", "Data": s, "State": "Active", "Offset": page_id * self.page_size})
                 except:
                     results.append({"Type": "ZBLOB (Corrupt)", "Data": "[Decompression Failed]", "State": "Err", "Offset": page_id * self.page_size})
            else:
                strs = self.extract_advanced_strings(blob_content)
                for s in strs:
                     results.append({"Type": "BLOB String", "Data": s, "State": "Active", "Offset": page_id * self.page_size})
                
                results.append({
                    "Type": "BLOB RAW", "Data": f"[Binary Blob Segment: {len(blob_content)} bytes]",
                    "State": "Active", "Offset": page_id * self.page_size,
                    "RawBytes": blob_content
                })
                
            return results
        except: return []

    def parse_undo_page(self, page_data, page_id):
        results = []
        try:
            undo_page_type = self.read_uint16(page_data, 38)
            label = "Undo Insert" if undo_page_type == 1 else "Undo Update"
            txt_hits = self.extract_advanced_strings(page_data)
            for txt in txt_hits:
                results.append({
                    "Type": f"{label} Record", "Data": txt, 
                    "State": "MVCC History",
                    "Offset": (page_id * self.page_size) 
                })
            return results
        except: return []

    def parse_structured_row(self, page, offset, is_deleted):
        cursor = offset
        result_text = []
        try:
            cursor += 19 
            for col in self.schema.columns:
                if cursor >= len(page): break
                val = ""
                if col['is_variable']:
                    try:
                        raw_str = ""
                        sub_cursor = cursor
                        while sub_cursor < len(page) and 32 <= page[sub_cursor] <= 126:
                            raw_str += chr(page[sub_cursor])
                            sub_cursor += 1
                        if len(raw_str) > 0:
                            val = raw_str
                            cursor = sub_cursor
                            if cursor < len(page) and page[cursor] == 0: cursor += 1
                        else:
                            cursor += 1
                    except: pass
                elif 'INT' in col['type']:
                    try:
                        if col['len'] == 4:
                            val = str(struct.unpack('>I', page[cursor:cursor+4])[0] & 0x7FFFFFFF) 
                        elif col['len'] == 8:
                            val = str(struct.unpack('>Q', page[cursor:cursor+8])[0])
                        cursor += col['len']
                    except: pass
                elif 'CHAR' in col['type']:
                     val = page[cursor:cursor+col['len']].decode('latin-1', errors='ignore').strip()
                     cursor += col['len']
                if val:
                    result_text.append(f"{col['name']}={val}")
            return ", ".join(result_text)
        except:
            return None

    def parse_page(self, page_data, page_id):
        results = []
        try:
            page_type = self.read_uint16(page_data, self.FIL_PAGE_TYPE)
        except: return []
        
        if page_type == 0x000A or page_type == 0x000B:
            return self.parse_blob_page(page_data, page_id)
        
        if page_type == 0x0002:
            return self.parse_undo_page(page_data, page_id)

        if page_type != 0x45BF and page_type != 0x0000:
            return None 

        base_type_label = "Record"
        page_header = page_data[38:94]
        try: free_list_start = self.read_uint16(page_header, self.PAGE_FREE)
        except: free_list_start = 0

        curr = self.INFIMUM
        loops = 0
        while curr != self.SUPREMUM and loops < 2000: 
            meta = self.get_record_header(page_data, curr)
            if not meta: break
            next_rec, is_deleted = meta
            if next_rec > curr:
                extracted = False
                if self.schema:
                    struct_data = self.parse_structured_row(page_data, curr, is_deleted)
                    if struct_data:
                        results.append({
                            "Type": "Schema Record", "Data": struct_data,
                            "State": "Deleted" if is_deleted else "Active",
                            "Offset": (page_id * self.page_size) + curr
                        })
                        extracted = True
                
                if not extracted:
                    txt_hits = self.extract_advanced_strings(page_data[curr : next_rec])
                    for txt in txt_hits:
                        results.append({
                            "Type": base_type_label, "Data": txt, 
                            "State": "Deleted" if is_deleted else "Active",
                            "Offset": (page_id * self.page_size) + curr
                        })
            if next_rec == 0 or next_rec == curr: break 
            curr = next_rec
            loops += 1

        curr = free_list_start
        loops = 0
        while curr != 0 and loops < 2000:
            meta = self.get_record_header(page_data, curr)
            if not meta: break
            next_rec, _ = meta 
            scan_len = next_rec - curr if next_rec > curr else 200
            
            extracted = False
            if self.schema:
                struct_data = self.parse_structured_row(page_data, curr, True)
                if struct_data:
                    results.append({
                        "Type": "Schema Recovered", "Data": struct_data,
                        "State": "Recovered",
                        "Offset": (page_id * self.page_size) + curr
                    })
                    extracted = True

            if not extracted:
                txt_hits = self.extract_advanced_strings(page_data[curr : curr + scan_len])
                for txt in txt_hits:
                    results.append({
                        "Type": "Deleted/Purged", "Data": txt, "State": "Recovered",
                        "Offset": (page_id * self.page_size) + curr
                    })
            if next_rec == 0 or next_rec == curr: break
            curr = next_rec
            loops += 1
        return results

# ---------------------------
# 6. MULTI-THREADED TASK
# ---------------------------

def analyze_chunk_task(filepath, start_page, end_page, page_size, active_keywords, schema_obj=None, is_redo_log=False, tde_master_key=None):
    extracted_data = []
    timeline_data = []
    carved_files = []
    keyword_stats = Counter()
    
    num_pages = end_page - start_page
    entropy_partial = [0.0] * num_pages
    page_types_partial = [""] * num_pages
    
    if is_redo_log:
        parser = RedoLogParser()
    else:
        parser = InnoDBParser(page_size, schema=schema_obj)
        
    ai_engine = ForensicAI()
    filename = os.path.basename(filepath)
    
    def get_match(text):
        if not text: return None
        t = text.lower()
        for k in active_keywords:
            if k in t: return k
        return None

    def analyze_text(text, base_type, offset, pid, p_type, lsn, raw_bytes=None):
        det_type = base_type
        is_susp = "No"
        kw = get_match(text)
        note = ""
        
        if kw:
            is_susp = "Yes"
            keyword_stats[kw] += 1
        
        if is_susp == "No" and " " in text and len(text) > 20:
            ai_score = ai_engine.predict_score(text)
            if ai_score > 0.8:
                is_susp = "Yes"
                det_type = "AI Detected"
                note = f"AI Confidence: {int(ai_score*100)}%"
                keyword_stats["AI_HIT"] += 1

        if REGEX_PATTERNS["Email"].search(text): det_type = "Email"
        elif REGEX_PATTERNS["Credit_Card"].search(text):
            if luhn_check(text.replace("-","")): det_type = "Credit Card"
        elif REGEX_PATTERNS["IP_v4"].search(text): det_type = "IP"
        elif REGEX_PATTERNS["Crypto"].search(text): det_type = "Crypto"
        elif REGEX_PATTERNS["IBAN"].search(text): det_type = "IBAN"
        
        # ENHANCED: Instant Columns Detection
        if raw_bytes and len(raw_bytes) > 10:
            try:
                if raw_bytes[5] & 0x20:
                    det_type = "Instant Column Record"
                    note += f" | Instant: {len(raw_bytes)//10}B wasted"
                if len(raw_bytes) >= 12:
                    trx = int.from_bytes(raw_bytes[6:12], 'big')
                    if trx > 0:
                        v = 1 if trx < 1e6 else (2 if trx < 1e7 else 3)
                        a = 'old' if trx < 1e6 else ('med' if trx < 1e7 else 'new')
                        note += f" | Ver:{v} Age:{a}"
            except:
                pass

        extracted_data.append({
            "HexOffset": f"0x{offset:08X}", "PageID": pid, "PageType": p_type,
            "Type": det_type, "Data": text, "Suspicious": is_susp,
            "Decoded": "", "Source": filename, "RawOff": offset, 
            "Keyword": kw if kw else ("AI" if det_type == "AI Detected" else ""), 
            "Bookmark": False, "Note": note, "LSN": lsn,
            "RawBytes": raw_bytes 
        })

    try:
        with open(filepath, 'rb') as f:
            f.seek(start_page * page_size)
            
            for i in range(num_pages):
                pid = start_page + i
                page_data = f.read(page_size)
                if not page_data or len(page_data) < 12: 
                    break
                
                start_offset = pid * page_size
                
                # UPDATED: Use High Performance Entropy Engine
                ent = FastEntropy.calculate(page_data)
                entropy_partial[i] = ent
                
                if is_redo_log:
                    p_type_str = "REDO BLOCK"
                    page_types_partial[i] = p_type_str
                    records = parser.parse_block(page_data, pid)
                    for rec in records:
                        analyze_text(rec['Data'], rec['Type'], rec['Offset'], pid, p_type_str, 0)
                    continue

                p_type_str = get_page_type_str(page_data)
                page_types_partial[i] = p_type_str
                
                page_lsn = parser.get_page_lsn(page_data)
                if page_lsn > 0:
                     timeline_data.append({
                        "Date": "N/A", "Data": f"Page {pid} Write ({p_type_str})", 
                        "HexOffset": f"0x{start_offset:08X}", "Source": filename, 
                        "RawDate": "", "LSN": page_lsn, "Type": "Page Write", "Year": 0
                    })

                # Enhanced Decompression (Zlib / Compressed Pages)
                try:
                    decompressed = parser.decompress_if_needed(page_data)
                    if decompressed:
                        adv_strings = parser.extract_advanced_strings(decompressed)
                        for s in adv_strings:
                            analyze_text(s, "Decompressed (Zlib)", start_offset, pid, p_type_str, page_lsn)
                except: pass

                for sig, meta in CARVING_SIGNATURES.items():
                    sig_offset = page_data.find(sig)
                    if sig_offset != -1:
                        abs_off = start_offset + sig_offset
                        carved_files.append({
                            "Type": meta['type'], "Ext": meta['ext'], "Offset": abs_off,
                            "Preview": f"{meta['type']} found at {abs_off:08X}", "Source": filename, "PageID": pid
                        })
                        extracted_data.append({
                            "HexOffset": f"0x{abs_off:08X}", "PageID": pid, "PageType": p_type_str,
                            "Type": "Carved File", "Data": f"Embedded {meta['type']}", "Suspicious": "Yes",
                            "Decoded": "", "Source": filename, "RawOff": abs_off, 
                            "Keyword": "FILE_HEADER", "Bookmark": False, "Note": f"Carved {meta['ext']}", "LSN": page_lsn
                        })

                records = parser.parse_page(page_data, pid)
                if records is None:
                    raw_strings = parser.extract_advanced_strings(page_data)
                    records = []
                    for s in raw_strings:
                        records.append({"Type": "Raw Carve", "Data": s, "State": "Unknown", "Offset": (pid*page_size)})

                for rec in records:
                    r_bytes = rec.get("RawBytes", None)
                    analyze_text(rec['Data'], rec['Type'], rec['Offset'], pid, p_type_str, page_lsn, r_bytes)
                    
                    text_val = rec['Data']
                    ts_text = REGEX_PATTERNS["Date_Text"].search(text_val)
                    if ts_text:
                        date_str = ts_text.group(0)
                        try:
                            if '-' in date_str: year_val = int(date_str.split('-')[0])
                            elif '/' in date_str: year_val = int(date_str.split('/')[-1])
                            else: year_val = 0
                        except: year_val = 0
                        
                        timeline_data.append({
                            "Date": date_str, "Data": text_val, 
                            "HexOffset": f"0x{rec['Offset']:08X}", "Source": filename, 
                            "RawDate": date_str, "LSN": page_lsn, "Type": "Text Date", "Year": year_val
                        })
                    
                    unix_ts = REGEX_PATTERNS["Unix_Time"].findall(text_val)
                    for uts in unix_ts:
                        readable = convert_unix_time(uts)
                        if readable:
                            try: year_val = int(readable[:4])
                            except: year_val = 0
                            
                            timeline_data.append({
                                "Date": readable, "Data": f"Unix: {uts} in {text_val[:30]}...", 
                                "HexOffset": f"0x{rec['Offset']:08X}", "Source": filename, 
                                "RawDate": readable, "LSN": page_lsn, "Type": "Unix Time", "Year": year_val
                            })

    except Exception as e:
        print(f"Error in chunk {start_page}: {e}")

    return (extracted_data, dict(keyword_stats), timeline_data, carved_files, entropy_partial, page_types_partial, num_pages, start_page)


class ForensicLoaderThread(QThread):
    data_ready = pyqtSignal(list, dict, list, dict, list, list, list, list, list, list)
    progress_update = pyqtSignal(str, int)
    error_occurred = pyqtSignal(str)

    def __init__(self, paths, yara_rules=None, custom_keywords=None, schema=None, tde_master_key=None):
        super().__init__()
        self.paths = paths
        self.yara_rules = yara_rules
        self.schema = schema
        self.tde_master_key = tde_master_key
        self.active_keywords = set(SUSPICIOUS_KEYWORDS)
        if custom_keywords:
            self.active_keywords.update(custom_keywords)
        self.active_keywords = list(self.active_keywords)

    def detect_high_entropy_clusters(self, entropy_list, page_types):
        """ Identifies sequential blocks of high entropy pages (encrypted blobs) """
        clusters = []
        cluster_start = -1
        threshold = 7.0
        
        for i, val in enumerate(entropy_list):
            if val > threshold:
                if cluster_start == -1: cluster_start = i
            else:
                if cluster_start != -1:
                    length = i - cluster_start
                    if length >= 3: # Ignore singletons
                         clusters.append((cluster_start, i-1, length))
                    cluster_start = -1
        return clusters

    def run(self):
        try:
            for filepath in self.paths:
                filename = os.path.basename(filepath)
                self.progress_update.emit(f"Analyzing {filename}...", 0)
                
                md5, sha256 = calculate_file_hashes(filepath)
                file_size = os.path.getsize(filepath)
                file_info = {"Filename": filename, "Path": filepath, "Size": file_size, "MD5": md5, "SHA256": sha256}
                
                is_redo = False
                page_size = 16384
                if "ib_logfile" in filename.lower():
                    is_redo = True
                    page_size = 512
                
                if file_size < page_size:
                    self.error_occurred.emit("File is too small.")
                    continue

                total_pages = math.ceil(file_size / page_size)
                
                merged_extracted = []
                merged_stats = Counter()
                merged_timeline = []
                merged_carved = []
                merged_heatmap = [0] * total_pages
                merged_entropy = [0.0] * total_pages
                merged_page_types = [""] * total_pages
                
                cpu_count = os.cpu_count() or 4
                num_workers = min(max(1, cpu_count), 8)
                if total_pages < 500: num_workers = 1 
                
                chunk_size = math.ceil(total_pages / num_workers)
                
                futures = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
                    for i in range(num_workers):
                        start_pg = i * chunk_size
                        end_pg = min((i + 1) * chunk_size, total_pages)
                        if start_pg >= total_pages: break
                        
                        futures.append(executor.submit(
                            analyze_chunk_task, 
                            filepath, start_pg, end_pg, page_size, self.active_keywords, self.schema, is_redo
                        ))
                    
                    processed_pages = 0
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            res = future.result()
                            (ext_data, stats, time_data, carved, ent_part, pt_part, pg_cnt, start_idx) = res
                            
                            merged_extracted.extend(ext_data)
                            merged_timeline.extend(time_data)
                            merged_carved.extend(carved)
                            for k, v in stats.items(): merged_stats[k] += v
                            
                            for j, val in enumerate(ent_part):
                                if start_idx + j < len(merged_entropy): merged_entropy[start_idx+j] = val
                            
                            for j, val in enumerate(pt_part):
                                if start_idx + j < len(merged_page_types):
                                    merged_page_types[start_idx+j] = val
                                    if "INDEX" in val or "UNDO" in val: merged_heatmap[start_idx+j] = 1

                            processed_pages += pg_cnt
                            prog = int((processed_pages / total_pages) * 80)
                            self.progress_update.emit(f"Processed {processed_pages}/{total_pages} pages...", prog)
                            
                        except Exception as e:
                            print(f"Chunk processing failed: {e}")

                # YARA Scanning
                if self.yara_rules:
                    self.progress_update.emit("Running YARA...", 85)
                    try:
                        matches = self.yara_rules.match(filepath=filepath)
                        for m in matches:
                            for instance in m.strings:
                                off = instance[0]
                                pid = off // page_size
                                if pid < len(merged_heatmap): merged_heatmap[pid] = 2
                                merged_extracted.append({
                                    "HexOffset": f"0x{off:08X}", "PageID": pid, "PageType": "YARA Hit",
                                    "Type": "YARA Hit", "Data": f"{m.rule} match", "Suspicious": "Yes",
                                    "Decoded": "", "Source": filename, "RawOff": off, "Keyword": m.rule, 
                                    "Bookmark": False, "Note": "YARA Rule", "LSN": 0
                                })
                                merged_stats[f"YARA:{m.rule}"] += 1
                    except: pass
                
                # --- NEW: CLUSTER DETECTION ---
                self.progress_update.emit("Detecting Entropy Clusters...", 90)
                clusters = self.detect_high_entropy_clusters(merged_entropy, merged_page_types)
                for start, end, length in clusters:
                    for k in range(start, end+1):
                         merged_heatmap[k] = 3 # Mark as Cluster
                    merged_extracted.append({
                        "HexOffset": f"0x{start*page_size:08X}", "PageID": start, "PageType": "Entropy Cluster",
                        "Type": "Encrypted Blob", "Data": f"High Entropy Cluster (Length: {length} Pages)", "Suspicious": "Yes",
                        "Decoded": "", "Source": filename, "RawOff": start*page_size, "Keyword": "CLUSTER", 
                        "Bookmark": False, "Note": "Potential Encrypted Container", "LSN": 0
                    })

                # --- NEW: MESSAGE RECONSTRUCTION ---
                self.progress_update.emit("Reconstructing Fragmented Messages...", 95)
                temp_df = pd.DataFrame(merged_extracted)
                reconstructor = MessageReconstructor(temp_df)
                reconstructed_msgs = reconstructor.reconstruct()
                
                # Final Data Assembly
                for item in merged_extracted:
                    pid = item['PageID']
                    if pid < len(merged_heatmap) and merged_heatmap[pid] == 0:
                        if item['Suspicious'] == 'Yes': merged_heatmap[pid] = 2
                        elif "Email" in item['Type'] or "Credit" in item['Type']: merged_heatmap[pid] = 1

                self.data_ready.emit(
                    merged_extracted, file_info, [], dict(merged_stats), 
                    merged_timeline, merged_heatmap, merged_entropy, 
                    merged_page_types, merged_carved, reconstructed_msgs
                )

        except Exception as e:
            self.error_occurred.emit(f"Loader Error: {str(e)}")
            import traceback
            traceback.print_exc()

class PDFExportThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, df, metadata, save_path, case_info=None):
        super().__init__()
        self.df = df
        self.metadata = metadata
        self.save_path = save_path
        self.case_info = case_info if case_info else {}
        self._is_running = True

    def stop(self):
        self._is_running = False

    def run(self):
        try:
            pdf = FPDF()
            pdf.add_page()
            
            pdf.set_fill_color(30, 30, 30); pdf.rect(0, 0, 210, 35, 'F')
            pdf.set_font("Arial", 'B', 22); pdf.set_text_color(0, 190, 212); pdf.cell(0, 15, "InnoSleuth", 0, 1, 'C')
            pdf.set_font("Arial", 'I', 10); pdf.set_text_color(200); pdf.cell(0, 5, "INNODB Forensic PARSER", 0, 1, 'C'); pdf.ln(15)
            
            # --- CASE INFO SECTION ---
            pdf.set_fill_color(240); pdf.set_text_color(0); pdf.set_font("Arial",'B',12)
            pdf.cell(0,10," 1. Case Investigation Details",1,1,'L',True); pdf.ln(2)
            
            if self.case_info:
                pdf.set_font("Arial",'',10)
                # Case Info
                pdf.set_font("Arial",'B',10); pdf.cell(40,6,"Case ID:",0,0); pdf.set_font("Arial",'',10); pdf.cell(0,6, self.case_info.get("Case ID","N/A"),0,1)
                pdf.set_font("Arial",'B',10); pdf.cell(40,6,"Case Name:",0,0); pdf.set_font("Arial",'',10); pdf.cell(0,6, self.case_info.get("Case Name","N/A"),0,1)
                pdf.set_font("Arial",'B',10); pdf.cell(40,6,"Type:",0,0); pdf.set_font("Arial",'',10); pdf.cell(0,6, self.case_info.get("Type","N/A"),0,1)
                pdf.ln(2)
                # Investigator
                pdf.set_font("Arial",'B',10); pdf.cell(40,6,"Investigator:",0,0); pdf.set_font("Arial",'',10); pdf.cell(0,6, f"{self.case_info.get('Investigator Name','')} ({self.case_info.get('Investigator ID','')})",0,1)
                # Incident
                pdf.set_font("Arial",'B',10); pdf.cell(40,6,"Incident Date:",0,0); pdf.set_font("Arial",'',10); pdf.cell(0,6, self.case_info.get("Incident Date","N/A"),0,1)
                pdf.set_font("Arial",'B',10); pdf.cell(40,6,"Affected System:",0,0); pdf.set_font("Arial",'',10); pdf.cell(0,6, self.case_info.get("Affected System","N/A"),0,1)
                
                pdf.ln(2)
                pdf.set_font("Arial",'B',10); pdf.cell(0,6,"Investigation Notes:",0,1)
                pdf.set_font("Arial",'',9); pdf.multi_cell(0,5, self.case_info.get("Notes",""))
                pdf.ln(5)

            pdf.set_fill_color(240); pdf.set_text_color(0); pdf.set_font("Arial",'B',12)
            pdf.cell(0,10," 2. File Metadata",1,1,'L',True); pdf.ln(2)
            
            pdf.set_font("Courier",'',9)
            if self.metadata:
                for f, m in self.metadata.items():
                    pdf.set_font("Courier",'B',9)
                    pdf.cell(0,5,f"File: {f}",0,1)
                    pdf.set_font("Courier",'',9)
                    pdf.cell(20,5,"Path:",0,0); pdf.cell(0,5,f"{m.get('Path','N/A')}",0,1)
                    pdf.cell(20,5,"Size:",0,0); pdf.cell(0,5,f"{m.get('Size',0):,} bytes",0,1)
                    pdf.cell(20,5,"MD5:",0,0); pdf.cell(0,5,f"{m.get('MD5','N/A')}",0,1)
                    pdf.ln(3)

            pdf.ln(5); pdf.set_font("Arial",'B',12); pdf.set_text_color(0); pdf.cell(0,10," 3. Executive Summary",1,1,'L',True); pdf.ln(5)
            
            tot = len(self.df)
            susp = len(self.df[self.df['Suspicious']=='Yes'])
            ai_hits = len(self.df[self.df['Type']=='AI Detected'])
            deleted_count = len(self.df[self.df['Type'].str.contains("Deleted|Recovered", na=False)])

            pdf.set_font("Arial",'B',10)
            pdf.set_text_color(0,150,0); pdf.cell(0,8,f"Total Artifacts Analyzed: {tot}",0,1)
            pdf.set_text_color(200,0,0); pdf.cell(0,8,f"Suspicious / High Risk Items: {susp}",0,1)
            pdf.set_text_color(128,0,128); pdf.cell(0,8,f"AI / ML Detected Items: {ai_hits}",0,1)
            pdf.set_text_color(255,100,0); pdf.cell(0,8,f"Recovered (Deleted) Records: {deleted_count}",0,1)
            pdf.set_text_color(0)

            bk = self.df[self.df['Bookmark']==True]
            if not bk.empty:
                pdf.ln(5); pdf.set_fill_color(255,255,200)
                pdf.cell(0,10,f" 4. Bookmarked Evidence ({len(bk)})",1,1,'L',True)
                pdf.set_font("Arial",'',8)
                for i, r in bk.iterrows():
                    pdf.cell(0,6, f"[{r['HexOffset']}] {r['Type']}: {str(r['Data'])[:60]} -- Note: {r['Note']}",0,1)

            pdf.add_page() 
            pdf.set_font("Arial",'B',12); pdf.set_fill_color(220)
            pdf.cell(0,10," 5. Detailed Artifact List (Full Export)",1,1,'L',True); pdf.ln(2)
            
            pdf.set_font("Arial",'B',8); pdf.set_fill_color(50); pdf.set_text_color(255)
            pdf.cell(30, 6, "Offset", 1, 0, 'C', True)
            pdf.cell(30, 6, "Type", 1, 0, 'C', True)
            pdf.cell(100, 6, "Content", 1, 0, 'C', True)
            pdf.cell(30, 6, "Suspicious", 1, 1, 'C', True)
            
            pdf.set_font("Arial",'',8)
            
            count = 0
            for i, r in self.df.iterrows():
                if not self._is_running: break
                if count % 100 == 0: self.progress.emit(count)
                count += 1
                
                is_deleted = "Deleted" in str(r['Type']) or "Recovered" in str(r['Type'])
                
                if is_deleted: pdf.set_text_color(255, 100, 0) 
                elif r['Type'] == 'AI Detected': pdf.set_text_color(128, 0, 128)
                elif r['Suspicious'] == 'Yes': pdf.set_text_color(200, 0, 0)
                else: pdf.set_text_color(0, 0, 0)
                
                offset_txt = str(r['HexOffset'])
                type_txt = str(r['Type'])[:15]
                data_txt = str(r['Data']).replace('\n', ' ')[:65]
                susp_txt = r['Suspicious']
                
                pdf.cell(30, 6, offset_txt, 1, 0, 'L')
                pdf.cell(30, 6, type_txt, 1, 0, 'L')
                pdf.cell(100, 6, data_txt, 1, 0, 'L')
                pdf.cell(30, 6, susp_txt, 1, 1, 'C')

            if self._is_running:
                pdf.output(self.save_path)
                self.finished.emit(f"PDF Saved with {count} rows.")
            
        except Exception as e:
            self.error.emit(str(e))

# ---------------------------
# 6. GUI COMPONENTS
# ---------------------------

# --- NEW: CASE INVESTIGATION FORM ---
class NewCaseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Case Investigation")
        self.resize(600, 500)
        self.setStyleSheet("""
            QDialog { background-color: #1a1e24; color: #e0e0e0; }
            QLabel { color: #00bcd4; font-weight: bold; }
            QLineEdit, QDateEdit, QTextEdit, QComboBox { 
                background-color: #0d1014; border: 1px solid #333; padding: 5px; color: white; border-radius: 3px; 
            }
            QGroupBox { border: 1px solid #444; margin-top: 10px; padding-top: 10px; font-weight: bold; color: #fff; }
            QPushButton { background-color: #252a33; border: 1px solid #444; padding: 8px; color: white; border-radius: 4px; }
            QPushButton:hover { border: 1px solid #00bcd4; color: #00bcd4; }
        """)

        layout = QVBoxLayout(self)

        # 1. Case Info
        gb_case = QGroupBox("Case Info")
        form_case = QFormLayout()
        self.txt_case_id = QLineEdit(); self.txt_case_id.setPlaceholderText("e.g., CASE-2025-001")
        self.txt_case_name = QLineEdit()
        self.combo_type = QComboBox()
        self.combo_type.addItems(["Fraud", "Data Breach", "Insider Threat", "Malware Analysis", "Intellectual Property Theft", "Other"])
        
        form_case.addRow("Unique Case ID:", self.txt_case_id)
        form_case.addRow("Case Name:", self.txt_case_name)
        form_case.addRow("Type of Case:", self.combo_type)
        gb_case.setLayout(form_case)
        layout.addWidget(gb_case)

        # 2. Investigator Info
        gb_inv = QGroupBox("Investigator Info")
        form_inv = QFormLayout()
        self.txt_inv_id = QLineEdit()
        self.txt_inv_name = QLineEdit()
        form_inv.addRow("Investigator ID:", self.txt_inv_id)
        form_inv.addRow("Investigator Name:", self.txt_inv_name)
        gb_inv.setLayout(form_inv)
        layout.addWidget(gb_inv)

        # 3. Incident Info
        gb_inc = QGroupBox("Incident / Evidence")
        form_inc = QFormLayout()
        self.date_incident = QDateEdit(); self.date_incident.setCalendarPopup(True); self.date_incident.setDate(QDate.currentDate())
        self.txt_system = QLineEdit()
        self.txt_evidence = QLineEdit()
        form_inc.addRow("Date of Incident:", self.date_incident)
        form_inc.addRow("Affected System:", self.txt_system)
        form_inc.addRow("Evidence Description:", self.txt_evidence)
        gb_inc.setLayout(form_inc)
        layout.addWidget(gb_inc)

        # 4. Notes
        gb_notes = QGroupBox("Investigation Notes / Findings")
        l_notes = QVBoxLayout()
        self.txt_notes = QTextEdit()
        l_notes.addWidget(self.txt_notes)
        gb_notes.setLayout(l_notes)
        layout.addWidget(gb_notes)

        # Buttons
        btn_box = QHBoxLayout()
        btn_create = QPushButton("Create Case")
        btn_create.clicked.connect(self.validate_and_accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        
        btn_box.addStretch()
        btn_box.addWidget(btn_create)
        btn_box.addWidget(btn_cancel)
        layout.addLayout(btn_box)

    def validate_and_accept(self):
        if not self.txt_case_id.text().strip():
            QMessageBox.warning(self, "Required", "Case ID is required.")
            return
        self.accept()

    def get_data(self):
        return {
            "Case ID": self.txt_case_id.text(),
            "Case Name": self.txt_case_name.text(),
            "Type": self.combo_type.currentText(),
            "Investigator ID": self.txt_inv_id.text(),
            "Investigator Name": self.txt_inv_name.text(),
            "Incident Date": self.date_incident.date().toString("yyyy-MM-dd"),
            "Affected System": self.txt_system.text(),
            "Evidence Desc": self.txt_evidence.text(),
            "Notes": self.txt_notes.toPlainText()
        }

class SchemaDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Load Schema (CREATE TABLE)")
        self.resize(500, 400)
        self.schema_sql = None
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Paste 'CREATE TABLE' SQL statement to enable 100% accurate column decoding:"))
        
        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText("CREATE TABLE `users` (\n  `id` int(11) NOT NULL,\n  `username` varchar(255),\n  ...\n) ENGINE=InnoDB;")
        layout.addWidget(self.text_edit)
        
        btn_layout = QHBoxLayout()
        btn_load = QPushButton("Load & Parse")
        btn_load.clicked.connect(self.parse_and_accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        
        btn_layout.addWidget(btn_load)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)
        
    def parse_and_accept(self):
        sql = self.text_edit.toPlainText()
        if not sql:
            QMessageBox.warning(self, "Error", "Please paste SQL.")
            return
        
        if "CREATE TABLE" not in sql.upper():
            QMessageBox.warning(self, "Error", "Does not look like a CREATE TABLE statement.")
            return
            
        self.schema_sql = sql
        self.accept()

class EnhancedGraphWidget(FigureCanvas):
    def __init__(self, parent=None):
        self.fig = Figure(figsize=(5, 4), dpi=100)
        self.fig.patch.set_facecolor('#1a1e24')
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor('#1a1e24')
        super().__init__(self.fig)
        self.G = None

    def build_graph(self, df):
        self.G = nx.Graph()
        mask = (df['Type'].str.contains('Email|IP|Credit|Crypto|IBAN|YARA|Deleted|AI', na=False)) | (df['Suspicious'] == 'Yes')
        entities = df[mask].head(500)
        
        if entities.empty: return False

        for _, row in entities.iterrows():
            src = row['Source']
            data = str(row['Data'])[:30]
            etype = row['Type']
            is_susp = row['Suspicious']
            
            self.G.add_node(src, type='file', color='#888', size=1)
            
            node_color = '#00bcd4'
            if 'Email' in etype: node_color = '#4caf50'
            elif 'IP' in etype: node_color = '#ff9800'
            elif 'Credit' in etype or 'IBAN' in etype: node_color = '#e91e63'
            elif 'Deleted' in etype: node_color = '#ff5252'
            elif 'AI' in etype: node_color = '#9c27b0'
            elif 'YARA' in etype or is_susp == 'Yes': node_color = '#ff0000'

            self.G.add_node(data, type='data', color=node_color, size=1, susp=is_susp)
            
            edge_color = '#ff0000' if (is_susp == 'Yes' or 'YARA' in etype) else '#555555'
            weight = 2 if (is_susp == 'Yes') else 1
            self.G.add_edge(src, data, color=edge_color, weight=weight)
            
        return True

    def calculate_centrality(self):
        if not self.G or len(self.G) == 0: return
        deg = nx.degree_centrality(self.G)
        nx.set_node_attributes(self.G, deg, 'degree_centrality')
        
        if len(self.G) < 200:
            bet = nx.betweenness_centrality(self.G)
            nx.set_node_attributes(self.G, bet, 'betweenness_centrality')
        else:
            nx.set_node_attributes(self.G, 0, 'betweenness_centrality')

    def plot_graph(self, df, layout_type='Spring', use_centrality=True):
        self.ax.clear()
        self.ax.axis('off')
        
        if df.empty:
            self.ax.text(0.5, 0.5, "No Data Loaded", color='#555', ha='center'); self.draw(); return

        if not self.build_graph(df):
            self.ax.text(0.5, 0.5, "No actionable entities found.", color='#888', ha='center'); self.draw(); return

        if use_centrality: self.calculate_centrality()

        if layout_type == 'Circular': pos = nx.circular_layout(self.G)
        elif layout_type == 'Kamada-Kawai':
            try: pos = nx.kamada_kawai_layout(self.G)
            except: pos = nx.spring_layout(self.G, k=0.5)
        else: pos = nx.spring_layout(self.G, k=0.5, iterations=50)

        colors = [self.G.nodes[n].get('color', '#00bcd4') for n in self.G.nodes()]
        
        base_size = 100
        if use_centrality:
            sizes = []
            degrees = nx.get_node_attributes(self.G, 'degree_centrality')
            for n in self.G.nodes():
                s = degrees.get(n, 0.1) * 3000 
                sizes.append(max(base_size, s))
        else:
            sizes = [base_size] * len(self.G.nodes())

        edge_colors = [self.G.edges[u, v]['color'] for u, v in self.G.edges()]
        widths = [self.G.edges[u, v]['weight'] for u, v in self.G.edges()]

        nx.draw_networkx_nodes(self.G, pos, ax=self.ax, node_color=colors, node_size=sizes, edgecolors='#fff', linewidths=0.5)
        nx.draw_networkx_edges(self.G, pos, ax=self.ax, edge_color=edge_colors, width=widths, alpha=0.6)
        
        labels = {}
        for n in self.G.nodes():
            if self.G.nodes[n].get('susp') == 'Yes' or self.G.degree[n] > 1: labels[n] = n
        
        nx.draw_networkx_labels(self.G, pos, labels, ax=self.ax, font_size=8, font_color='white', font_family='sans-serif')
        
        title = f"Professional Link Analysis ({len(self.G.nodes)} Nodes)"
        if use_centrality: title += " - Centrality Weighted"
        self.ax.set_title(title, color='white')
        self.draw()

    def export_gexf(self, path):
        if self.G:
            try: nx.write_gexf(self.G, path); return True
            except: return False
        return False

class HeatmapWidget(FigureCanvas):
    def __init__(self, parent=None):
        fig = Figure(figsize=(5, 4), dpi=100)
        fig.patch.set_facecolor('#1a1e24')
        self.ax = fig.add_subplot(111)
        self.ax.set_facecolor('#1a1e24')
        super().__init__(fig)
    
    def plot_heatmap(self, data_list, mode='Structure'):
        self.ax.clear()
        self.ax.axis('off')
        if not data_list: return
        
        total = len(data_list)
        cols = int(math.ceil(math.sqrt(total)))
        rows = int(math.ceil(total / cols))
        padded = data_list + [-1] * (rows * cols - total)
        grid = [padded[r*cols : (r+1)*cols] for r in range(rows)]
        
        if mode == 'Structure':
            from matplotlib.colors import ListedColormap
            # 0=Empty, 1=Data, 2=Suspicious, 3=Cluster
            cmap = ListedColormap(['#111', '#005f99', '#0f3018', '#8a1c1c', '#ffd700'])
            self.ax.imshow(grid, cmap=cmap, interpolation='nearest', aspect='auto', vmin=-1, vmax=3)
            legend_patches = [
                mpatches.Patch(color='#005f99', label='Allocated'),
                mpatches.Patch(color='#0f3018', label='Potential Data'),
                mpatches.Patch(color='#8a1c1c', label='Suspicious / Deleted'),
                mpatches.Patch(color='#ffd700', label='High Entropy Cluster (Encrypted)')
            ]
            self.ax.legend(handles=legend_patches, loc='upper right', facecolor='#1a1e24', labelcolor='white', fontsize=8)
            self.ax.set_title(f"Structure Heatmap ({total} Pages)", color='white', fontsize=10)

        elif mode == 'Entropy':
            grid_np = np.array(grid, dtype=float)
            masked_grid = np.ma.masked_where(grid_np == -1, grid_np)
            im = self.ax.imshow(masked_grid, cmap='plasma', interpolation='nearest', aspect='auto', vmin=0, vmax=8)
            cbar = self.figure.colorbar(im, ax=self.ax, orientation='vertical', fraction=0.046, pad=0.04)
            cbar.ax.tick_params(colors='white')
            cbar.set_label('Shannon Entropy (bits)', color='white')
            self.ax.set_title(f"Entropy Complexity Map (0=Empty, 8=Encrypted)", color='white', fontsize=10)
        
        self.draw()

class EntropyAnalyticsWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        self.fig = Figure(figsize=(5, 4), dpi=100)
        self.fig.patch.set_facecolor('#1a1e24')
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor('#1a1e24')
        self.canvas = FigureCanvas(self.fig)
        layout.addWidget(self.canvas)
        
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Page ID", "Page Type", "Entropy", "Classification"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)
    
    def load_data(self, entropy_list, page_types):
        self.ax.clear()
        if not entropy_list: return
        
        counts, bins, patches = self.ax.hist(entropy_list, bins=20, range=(0,8), color='#00bcd4', edgecolor='#1a1e24')
        self.ax.set_title("Entropy Distribution (Histogram)", color='white', fontsize=10, pad=10)
        
        self.ax.set_xlabel("Entropy Value (0-8)", color='white', fontsize=9, labelpad=5)
        self.ax.set_ylabel("Page Count", color='white', fontsize=9)
        self.ax.tick_params(axis='x', colors='white', labelsize=8)
        self.ax.tick_params(axis='y', colors='white', labelsize=8)
        
        self.fig.tight_layout()
        self.canvas.draw()
        
        data_rows = []
        for i, val in enumerate(entropy_list):
            data_rows.append((i, page_types[i], val, classify_entropy(val)))
        
        data_rows.sort(key=lambda x: x[2], reverse=True)
        
        self.table.setRowCount(len(data_rows))
        for row_idx, (pid, ptype, val, cls) in enumerate(data_rows):
            self.table.setItem(row_idx, 0, QTableWidgetItem(str(pid)))
            self.table.setItem(row_idx, 1, QTableWidgetItem(str(ptype)))
            
            ent_item = QTableWidgetItem(f"{val:.4f}")
            if val > 7.5: ent_item.setForeground(QColor("#ff5252"))
            elif val > 5.0: ent_item.setForeground(QColor("#ff9800"))
            
            self.table.setItem(row_idx, 2, ent_item)
            self.table.setItem(row_idx, 3, QTableWidgetItem(cls))

class MediaPreviewWidget(QWidget):
    def __init__(self, metadata_ref):
        super().__init__()
        self.metadata_ref = metadata_ref
        self.layout = QHBoxLayout(self)
        
        self.list_widget = QListWidget()
        self.list_widget.setFixedWidth(300)
        self.list_widget.itemClicked.connect(self.preview_item)
        
        self.preview_area = QScrollArea()
        self.preview_area.setWidgetResizable(True)
        self.preview_content = QLabel("Select a file to preview")
        self.preview_content.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_area.setWidget(self.preview_content)
        
        self.layout.addWidget(self.list_widget)
        self.layout.addWidget(self.preview_area)
        
        self.carved_items = []

    def load_items(self, items):
        self.list_widget.clear()
        self.carved_items = items
        for i, item in enumerate(items):
            icon_str = "🖼️" if item['Ext'] in ['png', 'jpg'] else "📄"
            lbl = f"{icon_str} {item['Type']} (Offset: 0x{item['Offset']:X})"
            l_item = QListWidgetItem(lbl)
            l_item.setData(Qt.ItemDataRole.UserRole, i)
            self.list_widget.addItem(l_item)


    def _extract_complete_file(self, data, ext):
        """استخراج ملف كامل باستخدام end markers"""
        try:
            # البحث عن end marker من CARVING_SIGNATURES
            end_marker = None
            for sig, meta in CARVING_SIGNATURES.items():
                if meta['ext'] == ext and 'end_marker' in meta:
                    end_marker = meta['end_marker']
                    break

            if end_marker:
                if ext == 'png':
                    # PNG: البحث عن IEND chunk
                    end_pos = data.find(end_marker)
                    if end_pos != -1:
                        return data[:end_pos + len(end_marker)]
                    return data[:min(len(data), 10 * 1024 * 1024)]

                elif ext in ['jpg', 'jpeg']:
                    # JPEG: البحث عن آخر EOI marker
                    search_data = data[:min(len(data), 10 * 1024 * 1024)]
                    positions = []
                    pos = 0
                    while True:
                        pos = search_data.find(end_marker, pos)
                        if pos == -1:
                            break
                        positions.append(pos)
                        pos += len(end_marker)
                    if positions:
                        return data[:positions[-1] + len(end_marker)]
                    return data[:min(len(data), 5 * 1024 * 1024)]

                elif ext == 'gif':
                    # GIF: البحث عن trailer
                    end_pos = data.find(end_marker)
                    if end_pos != -1:
                        return data[:end_pos + len(end_marker)]
                    return data[:min(len(data), 10 * 1024 * 1024)]

                elif ext == 'pdf':
                    # PDF: البحث عن %%EOF
                    end_pos = data.find(end_marker)
                    if end_pos != -1:
                        return data[:end_pos + len(end_marker)]
                    return data[:min(len(data), 10 * 1024 * 1024)]

            # ملفات بدون end marker (BMP, TIFF, WebP, Videos)
            if ext == 'bmp':
                # BMP: قراءة الحجم من الهيدر
                if len(data) >= 10:
                    try:
                        import struct
                        file_size = struct.unpack('<I', data[2:6])[0]
                        return data[:min(file_size, len(data), 10 * 1024 * 1024)]
                    except:
                        pass
                return data[:min(len(data), 10 * 1024 * 1024)]

            elif ext in ['tif', 'tiff']:
                # TIFF: معقد، نأخذ حجم معقول
                return data[:min(len(data), 20 * 1024 * 1024)]

            elif ext == 'webp':
                # WebP: قراءة الحجم من RIFF header
                if len(data) >= 12 and data[:4] == b'RIFF':
                    try:
                        import struct
                        chunk_size = struct.unpack('<I', data[4:8])[0]
                        return data[:min(chunk_size + 8, len(data), 20 * 1024 * 1024)]
                    except:
                        pass
                return data[:min(len(data), 10 * 1024 * 1024)]

            elif ext in ['mp4', 'mov']:
                # MP4/MOV: البحث عن ftyp atom وحساب الحجم
                if len(data) >= 8:
                    try:
                        import struct
                        atom_size = struct.unpack('>I', data[0:4])[0]
                        return data[:min(len(data), 100 * 1024 * 1024)]
                    except:
                        pass
                return data[:min(len(data), 100 * 1024 * 1024)]

            elif ext == 'avi':
                # AVI: RIFF file، قراءة الحجم
                if len(data) >= 12 and data[:4] == b'RIFF':
                    try:
                        import struct
                        file_size = struct.unpack('<I', data[4:8])[0]
                        return data[:min(file_size + 8, len(data), 100 * 1024 * 1024)]
                    except:
                        pass
                return data[:min(len(data), 100 * 1024 * 1024)]

            elif ext == 'mkv':
                # MKV: EBML format، معقد
                return data[:min(len(data), 100 * 1024 * 1024)]

            # أنواع أخرى
            return data[:min(len(data), 10 * 1024 * 1024)]

        except Exception as e:
            return data[:min(len(data), 5 * 1024 * 1024)]

    def export_carved_file(self, list_item):
        """تصدير الملف المستخرج"""
        idx = list_item.data(Qt.ItemDataRole.UserRole)
        data = self.carved_items[idx]
        filename = data['Source']
        if filename not in self.metadata_ref:
            QMessageBox.warning(self, "Error", "Source file not found")
            return

        path = self.metadata_ref[filename]['Path']
        offset = data['Offset']

        try:
            # قراءة البيانات
            with open(path, 'rb') as f:
                f.seek(offset)
                chunk = f.read(20 * 1024 * 1024)  # 20MB

            # استخراج الملف الكامل
            extracted_data = self._extract_complete_file(chunk, data['Ext'])

            if not extracted_data or len(extracted_data) < 10:
                QMessageBox.warning(self, "Error", "Could not extract file data")
                return

            # طلب اسم الملف للحفظ
            default_name = f"carved_{data['PageID']}_offset_{offset:08X}.{data['Ext']}"
            save_path, _ = QFileDialog.getSaveFileName(
                self, "Export Carved File", default_name,
                f"{data['Ext'].upper()} Files (*.{data['Ext']});;All Files (*.*)"
            )

            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(extracted_data)
                QMessageBox.information(
                    self, "Success", 
                    f"File exported successfully!\n\nSize: {len(extracted_data):,} bytes\nPath: {save_path}"
                )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed:\n{str(e)}")

    def preview_item(self, list_item):
        idx = list_item.data(Qt.ItemDataRole.UserRole)
        data = self.carved_items[idx]
        
        filename = data['Source']
        if filename not in self.metadata_ref: return
        path = self.metadata_ref[filename]['Path']
        offset = data['Offset']
        
        try:
            with open(path, 'rb') as f:
                f.seek(offset)
                chunk = f.read(2 * 1024 * 1024)
            
            if data['Ext'] in ['png', 'jpg']:
                img = QImage()
                if img.loadFromData(chunk):
                    pix = QPixmap.fromImage(img)
                    if pix.width() > 800: pix = pix.scaledToWidth(800)
                    self.preview_content.setPixmap(pix)
                    self.preview_content.setText("")
                else:
                    self.preview_content.setText("❌ Could not render image.")
            elif data['Ext'] == 'pdf':
                self.preview_content.setPixmap(QPixmap())
                self.preview_content.setText(f"📄 PDF Document Detected.\nHeader: {chunk[:10]}\n\n(Internal viewer not supported.)")
            else:
                self.preview_content.setText("Unknown format.")
                
        except Exception as e:
            self.preview_content.setText(f"Error reading file: {str(e)}")


    def show_context_menu(self, position):
        """عرض قائمة النقر الأيمن للتصدير"""
        item = self.list_widget.itemAt(position)
        if not item:
            return

        menu = QMenu()
        menu.setStyleSheet("""
            QMenu {
                background-color: #252a33;
                color: white;
                border: 1px solid #444;
            }
            QMenu::item:selected {
                background-color: #00bcd4;
            }
        """)

        export_action = QAction("💾 Export File", self)
        export_action.triggered.connect(lambda: self.export_carved_file(item))
        menu.addAction(export_action)

        info_action = QAction("ℹ️ File Info", self)
        info_action.triggered.connect(lambda: self.show_file_info(item))
        menu.addAction(info_action)

        menu.exec(self.list_widget.mapToGlobal(position))

    def show_file_info(self, list_item):
        """عرض معلومات الملف"""
        idx = list_item.data(Qt.ItemDataRole.UserRole)
        data = self.carved_items[idx]
        filename = data['Source']

        if filename not in self.metadata_ref:
            QMessageBox.warning(self, "Error", "Source file not found")
            return

        path = self.metadata_ref[filename]['Path']
        offset = data['Offset']

        try:
            with open(path, 'rb') as f:
                f.seek(offset)
                chunk = f.read(20 * 1024 * 1024)

            extracted_data = self._extract_complete_file(chunk, data['Ext'])

            info_text = f"""File Information:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Type: {data['Type']}
Extension: {data['Ext'].upper()}
Source: {filename}
Page ID: {data['PageID']}
Offset: 0x{offset:08X} ({offset:,} bytes)

Extracted Size: {len(extracted_data):,} bytes
Header (hex): {extracted_data[:20].hex()}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

            QMessageBox.information(self, "File Information", info_text)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not read file info:\n{str(e)}")

    def export_selected_file(self):
        """تصدير الملف المحدد حاليًا"""
        if self.current_selected_idx is None:
            QMessageBox.warning(self, "No Selection", "Please select a file to export.")
            return

        items = self.list_widget.selectedItems()
        if not items:
            QMessageBox.warning(self, "No Selection", "Please select a file to export.")
            return

        self.export_carved_file(items[0])

class HexViewer(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 10))
        self.setStyleSheet("background-color: #1a1e24; color: #00ffcc; border: 1px solid #333; border-radius: 5px;")
    
    def load_context(self, filepath, offset):
        try:
            if not os.path.exists(filepath): self.setPlainText(f"Error: {filepath} not found."); return
            start = max(0, offset - 64)
            with open(filepath, 'rb') as f:
                f.seek(start)
                data = f.read(192)
            lines = [f"Offset    | Hex Matches                                     | ASCII", "="*70]
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]; curr = start + i
                mark = ">>" if (curr <= offset < curr+16) else "  "
                h = " ".join(f"{b:02X}" for b in chunk)
                a = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                lines.append(f"{mark} {curr:08X} | {h:<48} | {a}")
            self.setPlainText("\n".join(lines))
        except Exception as e: self.setPlainText(f"Hex View Error: {str(e)}")



# ═══════════════════════════════════════════════════════════════════
# ENHANCEMENT: QUICK SEARCH DIALOG (Real-time filtering)
# ═══════════════════════════════════════════════════════════════════
class QuickSearchDialog(QDialog):
    """Real-time search with filtered results table"""
    def __init__(self, parent, df):
        super().__init__(parent)
        self.df = df
        self.parent_app = parent
        self.setWindowTitle("Quick Search - InnoSleuth")
        self.resize(900, 600)

        self.setStyleSheet("""
            QDialog { background-color: #1a1e24; color: #e0e0e0; }
            QLabel { color: #00bcd4; font-weight: bold; }
            QLineEdit { background-color: #0d1014; border: 1px solid #00bcd4; 
                       padding: 8px; color: white; border-radius: 4px; }
            QTableWidget { background-color: #0d1014; color: white; 
                          gridline-color: #333; border: 1px solid #444; }
            QHeaderView::section { background-color: #252a33; color: #00bcd4; 
                                  font-weight: bold; padding: 5px; }
        """)

        layout = QVBoxLayout(self)

        lbl = QLabel("🔍 Type to search (Data / Type / Source / HexOffset):")
        layout.addWidget(lbl)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search text...")
        self.search_input.textChanged.connect(self.refresh_results)
        layout.addWidget(self.search_input)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(['Offset','Type','Data (preview)','Suspicious','Source'])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self.table_context_menu)
        layout.addWidget(self.results_table)

        self.refresh_results()

    def refresh_results(self):
        q = self.search_input.text().strip().lower()

        if q == '':
            filtered = self.df
        else:
            mask = self.df.apply(lambda row: (
                q in str(row.get('Data','')).lower() or
                q in str(row.get('Type','')).lower() or
                q in str(row.get('Source','')).lower() or
                q in str(row.get('HexOffset','')).lower()
            ), axis=1)
            filtered = self.df[mask]

        self.results_table.setRowCount(0)
        for i, r in filtered.head(1000).iterrows():
            rowpos = self.results_table.rowCount()
            self.results_table.insertRow(rowpos)
            self.results_table.setItem(rowpos, 0, QTableWidgetItem(str(r.get('HexOffset',''))))
            self.results_table.setItem(rowpos, 1, QTableWidgetItem(str(r.get('Type',''))))
            dpreview = str(r.get('Data',''))[:160]
            self.results_table.setItem(rowpos, 2, QTableWidgetItem(dpreview))
            self.results_table.setItem(rowpos, 3, QTableWidgetItem(str(r.get('Suspicious',''))))
            self.results_table.setItem(rowpos, 4, QTableWidgetItem(str(r.get('Source',''))))

    def table_context_menu(self, point):
        idx = self.results_table.indexAt(point)
        if not idx.isValid():
            return

        menu = QMenu()
        menu.setStyleSheet("QMenu{background:#252a33;color:white;}")
        action_hex = QAction('🔍 Open Hex Viewer', self)

        def open_hex():
            row = idx.row()
            off_item = self.results_table.item(row, 0)
            src_item = self.results_table.item(row, 4)
            try:
                off_text = off_item.text()
                off = int(off_text, 16)
            except:
                off = 0
            src = src_item.text() if src_item else ''

            if src in self.parent_app.file_metadata:
                filepath = self.parent_app.file_metadata[src]['Path']
                hv = HexViewer()
                hv.load_context(filepath, off)
                hv.setWindowTitle(f"Hex Viewer - {src} @ {off_text}")
                hv.resize(900, 400)
                hv.show()

                if not hasattr(self.parent_app, '_hex_viewers'):
                    self.parent_app._hex_viewers = []
                self.parent_app._hex_viewers.append(hv)

        action_hex.triggered.connect(open_hex)
        menu.addAction(action_hex)
        menu.exec(self.results_table.mapToGlobal(point))


# ═══════════════════════════════════════════════════════════════════
# ENHANCEMENT: TABLESPACE LAYOUT AUTO-DETECTOR
# ═══════════════════════════════════════════════════════════════════
def detect_tablespace_layout(filepath):
    """Lightweight detection of tablespace layout"""
    res = {
        'path': filepath,
        'exists': os.path.exists(filepath),
        'size_bytes': None,
        'page_size': None,
        'total_pages': None,
        'likely_type': 'Unknown',
        'has_sdi': False,
        'notes': []
    }

    if not os.path.exists(filepath):
        res['notes'].append('File not found')
        return res

    st = os.stat(filepath)
    res['size_bytes'] = st.st_size

    with open(filepath, 'rb') as f:
        try:
            header = f.read(16384 * 2)
        except:
            f.seek(0)
            header = f.read(4096)

    if b'innodb' in header[:128].lower():
        res['notes'].append('Contains "innodb" text near header')

    # Try detect page sizes
    for ps in (16384, 8192, 4096, 2048, 1024, 512):
        if len(header) >= ps:
            try:
                p_type = int.from_bytes(header[24:26], 'big')
                if p_type in INNODB_PAGE_TYPES:
                    res['page_size'] = ps
                    res['notes'].append(f'Page type 0x{p_type:04X} found at page size {ps}')
                    break
            except Exception:
                pass

    # Fallback
    if res['page_size'] is None:
        for ps in (16384, 8192, 4096, 2048, 1024, 512):
            if st.st_size % ps == 0:
                res['page_size'] = ps
                res['notes'].append(f'File size divisible by {ps} => probable page size')
                break

    if res['page_size']:
        res['total_pages'] = st.st_size // res['page_size']

    # Detect SDI
    try:
        with open(filepath, 'rb') as f:
            for i in range(2, 8):
                f.seek(i * (res['page_size'] or 16384))
                chunk = f.read(16384)
                if b'"dd_object"' in chunk or b'sdi' in chunk.lower():
                    res['has_sdi'] = True
                    res['notes'].append(f'SDI-like structure at page {i}')
                    break
    except Exception:
        pass

    # Guess type
    if 'ib_logfile' in os.path.basename(filepath).lower() or res.get('page_size') == 512:
        res['likely_type'] = 'InnoDB REDO/Log'
    else:
        res['likely_type'] = 'InnoDB Tablespace'

    return res


class TablespaceDetectorDialog(QDialog):
    """Dialog to show tablespace detection results"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Tablespace Layout Detector')
        self.resize(600, 450)

        self.setStyleSheet("""
            QDialog { background-color: #1a1e24; color: #e0e0e0; }
            QLabel { color: #00bcd4; padding: 3px; }
            QPushButton { background-color: #252a33; border: 1px solid #00bcd4;
                         padding: 8px; color: white; border-radius: 4px; }
            QPushButton:hover { background-color: #00bcd4; color: black; }
        """)

        p, _ = QFileDialog.getOpenFileName(self, 'Select File to Detect', '', 'All Files (*)')
        if not p:
            self.reject()
            return

        r = detect_tablespace_layout(p)

        ly = QVBoxLayout(self)
        ly.addWidget(QLabel(f"<b>Path:</b> {r['path']}"))
        ly.addWidget(QLabel(f"<b>Exists:</b> {r['exists']}"))
        ly.addWidget(QLabel(f"<b>Size:</b> {r['size_bytes']:,} bytes" if r['size_bytes'] else "N/A"))
        ly.addWidget(QLabel(f"<b>Page Size:</b> {r['page_size']} bytes" if r['page_size'] else "Unknown"))
        ly.addWidget(QLabel(f"<b>Total Pages:</b> {r.get('total_pages', 'N/A')}"))
        ly.addWidget(QLabel(f"<b>Likely Type:</b> {r['likely_type']}"))
        ly.addWidget(QLabel(f"<b>Has SDI:</b> {r['has_sdi']}"))

        ly.addWidget(QLabel("<br><b>Detection Notes:</b>"))
        for n in r['notes']:
            ly.addWidget(QLabel(f"  • {n}"))

        btn = QPushButton('✓ Close')
        btn.clicked.connect(self.accept)
        ly.addWidget(btn)




# ═══════════════════════════════════════════════════════════════════
# TDE KEYRING LOADER DIALOG
# ═══════════════════════════════════════════════════════════════════
class TDEKeyringDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("TDE Decryption - Load Keyring")
        self.resize(650, 350)
        self.keyring_path = None
        self.master_key_hex = None
        self.setStyleSheet("""
            QDialog { background-color: #1a1e24; color: #e0e0e0; }
            QLabel { color: #00bcd4; font-weight: bold; }
            QLineEdit, QTextEdit { background-color: #0d1014; border: 1px solid #333;
                padding: 8px; color: white; border-radius: 4px; }
            QPushButton { background-color: #252a33; border: 1px solid #00bcd4;
                padding: 10px; color: white; border-radius: 4px; }
            QPushButton:hover { background-color: #00bcd4; color: black; }
        """)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("🔐 TDE Decryption - Load Master Key"))
        layout.addWidget(QLabel("⚠️ Encrypted .ibd files require MySQL keyring or master key"))
        tabs = QTabWidget()
        tab_file = QWidget()
        tab_file_layout = QVBoxLayout(tab_file)
        tab_file_layout.addWidget(QLabel("Keyring File:"))
        file_row = QHBoxLayout()
        self.txt_keyring_path = QLineEdit()
        file_row.addWidget(self.txt_keyring_path)
        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self.browse_keyring)
        file_row.addWidget(btn_browse)
        tab_file_layout.addLayout(file_row)
        tab_file_layout.addStretch()
        tabs.addTab(tab_file, "From File")
        tab_manual = QWidget()
        tab_manual_layout = QVBoxLayout(tab_manual)
        tab_manual_layout.addWidget(QLabel("Master Key (64 hex chars):"))
        self.txt_master_key = QTextEdit()
        self.txt_master_key.setMaximumHeight(80)
        tab_manual_layout.addWidget(self.txt_master_key)
        tab_manual_layout.addStretch()
        tabs.addTab(tab_manual, "Manual Entry")
        layout.addWidget(tabs)
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_load = QPushButton("✓ Load")
        btn_load.clicked.connect(self.validate_and_accept)
        btn_layout.addWidget(btn_load)
        btn_cancel = QPushButton("✗ Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)

    def browse_keyring(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Keyring", "", "All Files (*)")
        if path:
            self.txt_keyring_path.setText(path)

    def validate_and_accept(self):
        keyring_file = self.txt_keyring_path.text().strip()
        manual_key = self.txt_master_key.toPlainText().strip()
        if keyring_file:
            if not os.path.exists(keyring_file):
                QMessageBox.warning(self, "Error", "File not found!")
                return
            self.keyring_path = keyring_file
            self.accept()
        elif manual_key:
            clean_key = manual_key.replace(" ", "").replace(":", "").replace("\n", "")
            if len(clean_key) != 64:
                QMessageBox.warning(self, "Invalid", f"Must be 64 hex chars. Got: {len(clean_key)}")
                return
            try:
                bytes.fromhex(clean_key)
                self.master_key_hex = clean_key
                self.accept()
            except ValueError:
                QMessageBox.warning(self, "Invalid Hex", "Invalid hex characters!")
        else:
            QMessageBox.warning(self, "No Input", "Provide keyring file or master key!")


class IBDInvestigatorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("InnoSleuth")
        self.resize(1500, 950)
        self.setAcceptDrops(True)

        self.df = pd.DataFrame()
        self.df_timeline = pd.DataFrame()
        self.df_reconstructed = pd.DataFrame()
        self.file_metadata = {}
        
        # IOC Threat Intelligence
        self.ti_aggregator = None
        self.ioc_api_keys = {}
        self.keyword_stats = Counter()
        self.all_carved_files = [] 
        
        self.heatmap_struct = []
        self.heatmap_entropy = []
        self.page_types_cache = [] 
        
        self.compiled_yara = None
        self.custom_wordlist = []
        self.active_schema = None
        self.pdf_thread = None
        self.tde_master_key = None

        # Case Information Storage
        self.case_info = {}

        root = QVBoxLayout(); root.setContentsMargins(15,15,15,15); root.setSpacing(10)

        head = QFrame(); hl = QHBoxLayout(head)
        icon = QLabel(); pm = QPixmap(); pm.loadFromData(APP_ICON_SVG.encode('utf-8'))
        icon.setPixmap(pm.scaled(50,50))
        hl.addWidget(icon)
        tbox = QVBoxLayout()
        self.lbl_title = QLabel("InnoSleuth v2.0"); self.lbl_title.setStyleSheet("font-size: 22px; font-weight: bold; color: white;")
        
        accel_status = "GPU Acceleration Active 🚀" if GPU_AVAILABLE else ""
        sub = QLabel(f"INNODB Forensic PARSER  {accel_status}"); sub.setStyleSheet("color: #00bcd4; font-size: 11px;")
        dev_label = QLabel("Developed By: Anwar Yousef"); dev_label.setStyleSheet("color: #00d4ff; font-size: 13px; font-weight: bold; margin-top: 2px;")
        tbox.addWidget(self.lbl_title); tbox.addWidget(sub); tbox.addWidget(dev_label); hl.addLayout(tbox); hl.addStretch()
        root.addWidget(head)

        tool = QFrame(); tool.setObjectName("ToolFrame"); tl = QHBoxLayout(tool)
        bst = "QPushButton{background:#252a33; border:1px solid #444; padding:6px 12px; color:white; border-radius:4px;} QPushButton:hover{border:1px solid #00bcd4; color:#00bcd4;}"
        
        # New Case Button
        b_new = QPushButton("📝 New Case"); b_new.clicked.connect(self.open_new_case_dialog); b_new.setStyleSheet(bst); tl.addWidget(b_new)
        
        tl.addSpacing(10)
        b1 = QPushButton("📂 Load Files"); b1.clicked.connect(self.load_file); b1.setStyleSheet(bst); tl.addWidget(b1)
        b_schema = QPushButton("⚙️ Load Schema"); b_schema.clicked.connect(self.load_schema_dialog); b_schema.setStyleSheet(bst); tl.addWidget(b_schema)
        
        tl.addSpacing(10)
        b_save_case = QPushButton("💾 Save Case"); b_save_case.clicked.connect(self.save_case_state); b_save_case.setStyleSheet(bst); tl.addWidget(b_save_case)
        b_load_case = QPushButton("📂 Open Case"); b_load_case.clicked.connect(self.load_case_state); b_load_case.setStyleSheet(bst); tl.addWidget(b_load_case)
        tl.addSpacing(10)

        b2 = QPushButton("📖 Indicators"); b2.clicked.connect(self.load_dict); b2.setStyleSheet(bst); tl.addWidget(b2)
        b3 = QPushButton("🛡️ YARA"); b3.clicked.connect(self.load_yara); b3.setStyleSheet(bst); tl.addWidget(b3)
        if not YARA_AVAILABLE: b3.setEnabled(False)
        b4 = QPushButton("📊 Excel"); b4.clicked.connect(self.export_excel); b4.setStyleSheet(bst); tl.addWidget(b4)
        b5 = QPushButton("📑 PDF Report"); b5.clicked.connect(self.export_report); b5.setStyleSheet(bst); tl.addWidget(b5)
        
        b_html = QPushButton("🌐 HTML"); b_html.clicked.connect(self.export_html_dashboard); b_html.setStyleSheet(bst); tl.addWidget(b_html)


        # ═══════════════════════════════════════════════════════════════════
        # ENHANCEMENT BUTTONS
        # ═══════════════════════════════════════════════════════════════════
        tl.addSpacing(15)

        b_sqlite = QPushButton("💾 SQLite Export")
        b_sqlite.setToolTip('Export current evidence to SQLite database')
        b_sqlite.clicked.connect(self.export_to_sqlite)
        b_sqlite.setStyleSheet(bst)
        tl.addWidget(b_sqlite)

        b_quick_search = QPushButton("🔎 Quick Search")
        b_quick_search.setToolTip('Open quick search dialog with live filtering')
        b_quick_search.clicked.connect(self.open_quick_search)
        b_quick_search.setStyleSheet(bst)
        tl.addWidget(b_quick_search)

        b_ts_detect = QPushButton("🔍 Detect Tablespace")
        b_ts_detect.setToolTip('Auto-detect tablespace layout and structure')
        b_ts_detect.clicked.connect(self.detect_tablespace_layout_ui)
        b_ts_detect.setStyleSheet(bst)
        tl.addWidget(b_ts_detect)

        tl.addSpacing(10)

        b_tde = QPushButton("🔐 TDE Key")
        b_tde.setToolTip('Load TDE Master Key for Encrypted .ibd Files')
        b_tde.clicked.connect(self.load_tde_keyring)
        b_tde.setStyleSheet(bst)
        tl.addWidget(b_tde)

        self.lbl_tde_status = QLabel("TDE: None")
        self.lbl_tde_status.setStyleSheet("color: #888; font-size: 9px;")
        tl.addWidget(self.lbl_tde_status)

        tl.addStretch()
        b6 = QPushButton("♻️ Reset"); b6.clicked.connect(self.reset); b6.setObjectName("ResetBtn"); tl.addWidget(b6)
        root.addWidget(tool)

        self.prog = QProgressBar(); self.prog.setVisible(False); root.addWidget(self.prog)

        split = QSplitter(Qt.Orientation.Vertical)
        self.tabs = QTabWidget()

        # Tab 1: Artifacts
        w_art = QWidget(); l_art = QVBoxLayout(w_art)
        l_search = QHBoxLayout()
        self.search = QLineEdit(); self.search.setPlaceholderText("Search data..."); self.search.textChanged.connect(self.filter_main)
        self.filter_combo = QComboBox(); 
        self.filter_combo.addItems(["All", "Suspicious", "AI Detected", "PII", "Bookmarks", "YARA", "Deleted Records", "Carved Files", "Redo Logs", "Undo History", "BLOBs"])
        self.filter_combo.currentIndexChanged.connect(self.filter_main)
        l_search.addWidget(self.search); l_search.addWidget(self.filter_combo)
        l_art.addLayout(l_search)
        
        self.table = QTableWidget(); self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels(["Offset", "ID", "Page", "Type", "Data", "Decoded", "Suspicious", "BM", "Note", "LSN (Seq)", "Src"])
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnHidden(10, True) 
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.ctx_menu)
        self.table.cellClicked.connect(self.on_click)
        l_art.addWidget(self.table)
        self.tabs.addTab(w_art, "🔍 Artifacts")
        
        # Tab 2: Reconstructed Messages (NEW)
        self.table_recon = QTableWidget(0, 3)
        self.table_recon.setHorizontalHeaderLabels(["Pages", "Type", "Reconstructed Message Content"])
        self.table_recon.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.table_recon, "🧩 Reconstructed")

        # Tab 3: Enhanced Link Graph
        w_graph = QWidget(); l_graph = QVBoxLayout(w_graph)
        gc_layout = QHBoxLayout()
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Spring Layout", "Circular Layout", "Kamada-Kawai"])
        gc_layout.addWidget(QLabel("Layout:"))
        gc_layout.addWidget(self.layout_combo)
        self.chk_centrality = QCheckBox("Size by Centrality")
        self.chk_centrality.setChecked(True)
        gc_layout.addWidget(self.chk_centrality)
        b_ref_graph = QPushButton("Refresh / Apply"); b_ref_graph.clicked.connect(self.refresh_graph); b_ref_graph.setStyleSheet(bst)
        gc_layout.addWidget(b_ref_graph)
        b_export_gexf = QPushButton("Export to Gephi (.gexf)"); b_export_gexf.clicked.connect(self.export_gexf); b_export_gexf.setStyleSheet(bst)
        b_export_gexf.setStyleSheet("color: #4caf50; border: 1px solid #4caf50;")
        gc_layout.addWidget(b_export_gexf)
        gc_layout.addStretch()
        l_graph.addLayout(gc_layout)
        self.graph_widget = EnhancedGraphWidget(); 
        l_graph.addWidget(self.graph_widget)
        self.tabs.addTab(w_graph, "🕸️ Link Analysis")

        # Tab 4: Timeline
        w_time = QWidget(); l_time = QVBoxLayout(w_time)
        t_ctrl = QHBoxLayout()
        self.time_sort_combo = QComboBox()
        self.time_sort_combo.addItems(["Newest First (Desc)", "Oldest First (Asc)"])
        self.time_sort_combo.currentIndexChanged.connect(self.populate_timeline)
        self.year_filter_combo = QComboBox()
        self.year_filter_combo.addItem("All Years")
        self.year_filter_combo.currentIndexChanged.connect(self.populate_timeline)
        t_ctrl.addWidget(QLabel("Sort:")); t_ctrl.addWidget(self.time_sort_combo)
        t_ctrl.addSpacing(20); t_ctrl.addWidget(QLabel("Year:")); t_ctrl.addWidget(self.year_filter_combo)
        t_ctrl.addStretch()
        l_time.addLayout(t_ctrl)

        self.table_time = QTableWidget(0, 5)
        self.table_time.setHorizontalHeaderLabels(["Relative Time (LSN)", "Event Type", "Timestamp (Text)", "Data Context", "Offset"])
        header = self.table_time.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_time.setColumnWidth(1, 150)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        l_time.addWidget(self.table_time)
        self.tabs.addTab(w_time, "📅 Hybrid Timeline")

        # Tab 5: Heatmap
        w_heat = QWidget(); l_heat = QVBoxLayout(w_heat)
        h_ctrl = QHBoxLayout()
        lbl_h = QLabel("Mode:"); lbl_h.setStyleSheet("color:#aaa;")
        self.heat_combo = QComboBox()
        self.heat_combo.addItems(["Structure / Suspicious / Clusters", "Entropy (Complexity)"])
        self.heat_combo.currentIndexChanged.connect(self.switch_heatmap_mode)
        h_ctrl.addWidget(lbl_h); h_ctrl.addWidget(self.heat_combo); h_ctrl.addStretch()
        l_heat.addLayout(h_ctrl)
        self.heatmap = HeatmapWidget(); l_heat.addWidget(self.heatmap)
        self.tabs.addTab(w_heat, "🔥 Disk Map")

        # Tab 6: Entropy
        self.entropy_stats = EntropyAnalyticsWidget()
        self.tabs.addTab(self.entropy_stats, "📊 Entropy")

        # Tab 7: Suspicious
        self.table_susp = QTableWidget(0, 4); self.table_susp.setHorizontalHeaderLabels(["Keyword", "Context", "Type", "Offset"])
        self.table_susp.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.table_susp, "⚠️ Suspicious")

        # Tab 8: Media
        self.media_widget = MediaPreviewWidget(self.file_metadata)
        self.tabs.addTab(self.media_widget, "📸 Media & Carving")

        # IOC Threat Intelligence Control Panel
        ioc_control_box = QGroupBox("🔒 IOC Threat Intelligence")
        ioc_control_box.setStyleSheet("""
            QGroupBox { 
                border: 2px solid #9c27b0; 
                border-radius: 5px; 
                margin-top: 10px; 
                padding: 10px;
                font-weight: bold;
                color: #9c27b0;
            }
        """)
        ioc_layout = QHBoxLayout()

        btn_ioc_config = QPushButton("⚙️ Configure API Keys")
        btn_ioc_config.clicked.connect(self.configure_ioc_threat_intel)
        btn_ioc_config.setStyleSheet("""
            QPushButton {
                background-color: #9c27b0;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #7b1fa2; }
        """)
        btn_ioc_config.setToolTip("Configure VirusTotal, AlienVault OTX, AbuseIPDB API Keys")
        ioc_layout.addWidget(btn_ioc_config)

        btn_batch_ioc = QPushButton("🔍 Batch Check All IOCs")
        btn_batch_ioc.clicked.connect(self.batch_check_artifacts_ioc)
        btn_batch_ioc.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #d32f2f; }
        """)
        btn_batch_ioc.setToolTip("Automatically check all hashes, IPs, domains, URLs in artifacts")
        ioc_layout.addWidget(btn_batch_ioc)

        self.ioc_status = QLabel("Status: ❌ Not Configured")
        self.ioc_status.setStyleSheet("color: #ff9800; font-weight: bold; font-size: 12px;")
        ioc_layout.addWidget(self.ioc_status)

        ioc_layout.addStretch()
        ioc_control_box.setLayout(ioc_layout)
        root.addWidget(ioc_control_box)

        split.addWidget(self.tabs)
        
        grp = QGroupBox("Hex Viewer"); l_grp = QVBoxLayout(grp)
        self.hex_view = HexViewer(); l_grp.addWidget(self.hex_view)
        split.addWidget(grp); split.setSizes([600, 250])
        
        root.addWidget(split)
        self.lbl_stat = QLabel("Ready."); self.lbl_stat.setStyleSheet("color:#888;")
        root.addWidget(self.lbl_stat)
        self.setLayout(root)
        self.apply_theme()

    def open_new_case_dialog(self):
        dlg = NewCaseDialog(self)
        if dlg.exec():
            self.case_info = dlg.get_data()
            cid = self.case_info.get('Case ID')
            self.lbl_title.setText(f"InnoSleuth - Case: {cid}")
            QMessageBox.information(self, "Case Created", f"Case {cid} started successfully.\nYou can now load files.")

    def load_schema_dialog(self):
        dlg = SchemaDialog(self)
        if dlg.exec():
            try:
                self.active_schema = TableSchema(dlg.schema_sql)
                QMessageBox.information(self, "Schema Loaded", f"Schema Parsed!\nColumns found: {len(self.active_schema.columns)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to parse SQL: {str(e)}")

    def load_dict(self):
        p, _ = QFileDialog.getOpenFileName(self, "Load Dictionary", "", "Txt (*.txt)")
        if p:
            with open(p,'r',encoding='utf-8',errors='ignore') as f: self.custom_wordlist = [l.strip() for l in f if len(l.strip())>3]
            QMessageBox.information(self,"OK", f"Loaded {len(self.custom_wordlist)} words.")

    def load_file(self):
        p, _ = QFileDialog.getOpenFileNames(self, "Load", "", "All (*.*)")
        if p:
            self.reset_ui(); self.prog.setVisible(True)
            self.loader = ForensicLoaderThread(p, self.compiled_yara, self.custom_wordlist, self.active_schema)
            self.loader.data_ready.connect(self.on_data)
            self.loader.progress_update.connect(lambda s,v: (self.lbl_stat.setText(s), self.prog.setValue(v)))
            self.loader.error_occurred.connect(self.on_error)
            self.loader.start()

    def on_error(self, msg): self.prog.setVisible(False); QMessageBox.critical(self, "Error", msg)
    
    def load_yara(self):
        p, _ = QFileDialog.getOpenFileName(self, "YARA", "", "Yar (*.yar)")
        if p: 
            try: self.compiled_yara = yara.compile(filepath=p); QMessageBox.information(self,"OK","Rules Loaded")
            except Exception as e: QMessageBox.critical(self,"Error",str(e))

    def on_data(self, data, info, logs, stats, timeline, heat_struct, heat_entropy, page_types, carved_files, reconstructed):
        self.prog.setVisible(False); self.lbl_stat.setText(f"Done. {len(data)} artifacts.")
        self.file_metadata[info['Filename']] = info
        self.heatmap_struct = heat_struct
        self.heatmap_entropy = heat_entropy
        self.keyword_stats = stats
        self.page_types_cache = page_types 
        
        if data:
            self.df = pd.concat([self.df, pd.DataFrame(data)], ignore_index=True)
            self.filter_main(); self.populate_susp(); self.refresh_graph()
        if timeline:
            self.df_timeline = pd.concat([self.df_timeline, pd.DataFrame(timeline)], ignore_index=True)
            self.year_filter_combo.blockSignals(True)
            self.year_filter_combo.clear()
            self.year_filter_combo.addItem("All Years")
            unique_years = sorted(self.df_timeline[self.df_timeline['Year'] > 1990]['Year'].unique(), reverse=True)
            for y in unique_years: self.year_filter_combo.addItem(str(y))
            self.year_filter_combo.blockSignals(False)
            self.populate_timeline() 
        
        if reconstructed:
            self.df_reconstructed = pd.DataFrame(reconstructed)
            self.populate_reconstructed()

        self.switch_heatmap_mode()
        self.entropy_stats.load_data(heat_entropy, page_types)

        if carved_files:
            self.all_carved_files.extend(carved_files)
            self.media_widget.load_items(self.all_carved_files)

    # ----------------------------------
    # SAVE / LOAD CASE FEATURES
    # ----------------------------------
    def save_case_state(self):
        if self.df.empty and not self.file_metadata:
            QMessageBox.warning(self, "Save Case", "No data to save.")
            return

        p, _ = QFileDialog.getSaveFileName(self, "Save Case", "Investigation.icase", "InnoSleuth Case (*.icase)")
        if not p: return

        try:
            # Prepare dictionary of data to preserve
            case_data = {
                'case_info': self.case_info, 
                'metadata': self.file_metadata,
                'df': self.df,
                'df_timeline': self.df_timeline,
                'df_reconstructed': self.df_reconstructed,
                'stats': self.keyword_stats,
                'heatmap_struct': self.heatmap_struct,
                'heatmap_entropy': self.heatmap_entropy,
                'carved_files': self.all_carved_files,
                'page_types': self.page_types_cache,
                'custom_wordlist': self.custom_wordlist,
                'timestamp': datetime.now().isoformat()
            }
            
            with gzip.open(p, 'wb') as f:
                pickle.dump(case_data, f)
            
            QMessageBox.information(self, "Success", f"Case saved successfully to {os.path.basename(p)}")
            
        except Exception as e:
            QMessageBox.critical(self, "Save Error", str(e))

    def load_case_state(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open Case", "", "InnoSleuth Case (*.icase)")
        if not p: return

        try:
            self.prog.setVisible(True)
            self.lbl_stat.setText("Loading Case File...")
            
            with gzip.open(p, 'rb') as f:
                case_data = pickle.load(f)
            
            # Restore variables
            self.reset() # Clear current state first
            
            self.case_info = case_data.get('case_info', {})
            if self.case_info.get("Case ID"):
                self.lbl_title.setText(f"InnoSleuth - Case: {self.case_info['Case ID']}")
                
            self.file_metadata = case_data.get('metadata', {})
            self.df = case_data.get('df', pd.DataFrame())
            self.df_timeline = case_data.get('df_timeline', pd.DataFrame())
            self.df_reconstructed = case_data.get('df_reconstructed', pd.DataFrame())
            self.keyword_stats = case_data.get('stats', Counter())
            self.heatmap_struct = case_data.get('heatmap_struct', [])
            self.heatmap_entropy = case_data.get('heatmap_entropy', [])
            self.all_carved_files = case_data.get('carved_files', [])
            self.page_types_cache = case_data.get('page_types', [])
            self.custom_wordlist = case_data.get('custom_wordlist', [])
            
            # Refresh UI components
            self.filter_main()
            self.populate_susp()
            self.populate_timeline()
            self.populate_reconstructed()
            self.refresh_graph()
            
            self.switch_heatmap_mode()
            self.entropy_stats.load_data(self.heatmap_entropy, self.page_types_cache)
            self.media_widget.load_items(self.all_carved_files)
            
            # Re-populate timeline combo box
            self.year_filter_combo.blockSignals(True)
            self.year_filter_combo.clear()
            self.year_filter_combo.addItem("All Years")
            if not self.df_timeline.empty and 'Year' in self.df_timeline.columns:
                unique_years = sorted(self.df_timeline[self.df_timeline['Year'] > 1990]['Year'].unique(), reverse=True)
                for y in unique_years: self.year_filter_combo.addItem(str(y))
            self.year_filter_combo.blockSignals(False)
            
            self.prog.setVisible(False)
            self.lbl_stat.setText(f"Case Loaded. {len(self.df)} artifacts restored.")
            QMessageBox.information(self, "Success", "Case restored successfully.")
            
        except Exception as e:
            self.prog.setVisible(False)
            self.lbl_stat.setText("Error loading case.")
            QMessageBox.critical(self, "Load Error", f"Could not load case file:\n{str(e)}")

    def switch_heatmap_mode(self):
        mode = self.heat_combo.currentText()
        if "Structure" in mode:
            self.heatmap.plot_heatmap(self.heatmap_struct, mode="Structure")
        else:
            self.heatmap.plot_heatmap(self.heatmap_entropy, mode="Entropy")

    def filter_main(self):
        if self.df.empty: return
        self.table.setSortingEnabled(False); self.table.setRowCount(0)
        txt = self.search.text().lower(); cat = self.filter_combo.currentText()
        
        mask = pd.Series([True]*len(self.df))
        if cat == "Suspicious": mask &= (self.df['Suspicious'] == "Yes")
        elif cat == "AI Detected": mask &= (self.df['Type'] == "AI Detected")
        elif cat == "PII": mask &= (self.df['Type'].str.contains("Email|IP|Credit|IBAN", na=False))
        elif cat == "Bookmarks": mask &= (self.df['Bookmark'] == True)
        elif cat == "YARA": mask &= (self.df['Type'] == "YARA Hit")
        elif cat == "Deleted Records": mask &= (self.df['Type'].str.contains("Deleted|Recovered", na=False))
        elif cat == "Carved Files": mask &= (self.df['Type'] == "Carved File")
        elif cat == "Redo Logs": mask &= (self.df['Type'].str.contains("REDO", na=False))
        elif cat == "Undo History": mask &= (self.df['Type'].str.contains("Undo|MVCC", na=False))
        elif cat == "BLOBs": mask &= (self.df['Type'].str.contains("BLOB", na=False))

        if txt: mask &= (self.df['Data'].str.lower().str.contains(txt, na=False))
        
        v = self.df[mask].head(2000)
        self.table.setRowCount(len(v))
        for i, r in enumerate(v.itertuples()):
            self.table.setItem(i, 0, QTableWidgetItem(r.HexOffset))
            self.table.setItem(i, 1, QTableWidgetItem(str(r.PageID)))
            pt = QTableWidgetItem(str(r.PageType))
            if "REDO" in r.PageType: pt.setForeground(QColor("#ffeb3b"))
            self.table.setItem(i, 2, pt)
            
            t_item = QTableWidgetItem(r.Type)
            if "Deleted" in r.Type or "Recovered" in r.Type: t_item.setForeground(QColor("#ff5252"))
            elif "Carved" in r.Type: t_item.setForeground(QColor("#e91e63"))
            elif "Undo" in r.Type: t_item.setForeground(QColor("#ffa726"))
            elif "BLOB" in r.Type: t_item.setForeground(QColor("#64b5f6"))
            elif "AI Detected" in r.Type: t_item.setForeground(QColor("#9c27b0"))
            self.table.setItem(i, 3, t_item)
            
            self.table.setItem(i, 4, QTableWidgetItem(str(r.Data)))
            self.table.setItem(i, 5, QTableWidgetItem(str(r.Decoded)))
            
            s = QTableWidgetItem(r.Suspicious)
            if r.Suspicious=="Yes": 
                s.setBackground(QColor("#4a0e16")); s.setForeground(QColor("#ff5252"))
                if r.Type == "AI Detected": s.setBackground(QColor("#2d0036")); s.setForeground(QColor("#d500f9"))
            self.table.setItem(i, 6, s)
            
            bm = QTableWidgetItem("★" if r.Bookmark else "")
            if r.Bookmark: bm.setForeground(QColor("yellow"))
            self.table.setItem(i, 7, bm)
            self.table.setItem(i, 8, QTableWidgetItem(str(r.Note)))
            lsn_val = getattr(r, 'LSN', 0)
            self.table.setItem(i, 9, QTableWidgetItem(str(lsn_val)))
            self.table.setItem(i, 10, QTableWidgetItem(r.Source))

        self.table.setSortingEnabled(True)

    def populate_susp(self):
        if self.df.empty: return
        v = self.df[self.df['Suspicious'] == 'Yes']
        self.table_susp.setRowCount(len(v))
        for i, r in enumerate(v.itertuples()):
            k = QTableWidgetItem(str(r.Keyword).upper()); k.setForeground(QColor("#ffdb4d"))
            self.table_susp.setItem(i, 0, k)
            self.table_susp.setItem(i, 1, QTableWidgetItem(str(r.Data)))
            self.table_susp.setItem(i, 2, QTableWidgetItem(str(r.Type)))
            self.table_susp.setItem(i, 3, QTableWidgetItem(str(r.HexOffset)))

    def populate_reconstructed(self):
        if self.df_reconstructed.empty: 
            self.table_recon.setRowCount(0)
            return
        
        self.table_recon.setRowCount(len(self.df_reconstructed))
        for i, r in enumerate(self.df_reconstructed.itertuples()):
            pg_range = f"{r.PageStart} -> {r.PageEnd}"
            self.table_recon.setItem(i, 0, QTableWidgetItem(pg_range))
            self.table_recon.setItem(i, 1, QTableWidgetItem(str(r.Type)))
            self.table_recon.setItem(i, 2, QTableWidgetItem(str(r.Data)))

    def populate_timeline(self):
        if self.df_timeline.empty: return
        self.table_time.setSortingEnabled(False)
        self.table_time.setUpdatesEnabled(False)
        self.table_time.setRowCount(0)
        
        selected_year_str = self.year_filter_combo.currentText()
        if selected_year_str != "All Years":
            try:
                sel_year = int(selected_year_str)
                df_view = self.df_timeline[self.df_timeline['Year'] == sel_year]
            except: df_view = self.df_timeline
        else: df_view = self.df_timeline

        sort_mode = self.time_sort_combo.currentText()
        is_asc = True if "Oldest" in sort_mode else False
        df_view['LSN'] = pd.to_numeric(df_view['LSN'], errors='coerce').fillna(0)
        df_view = df_view.sort_values(by=['LSN', 'RawDate'], ascending=[is_asc, is_asc])
        
        MAX_ROWS = 3000
        if len(df_view) > MAX_ROWS:
            self.lbl_stat.setText(f"Showing top {MAX_ROWS} events (Use filters to see more)")
            df_view = df_view.head(MAX_ROWS)
        
        self.table_time.setRowCount(len(df_view))
        for i, r in enumerate(df_view.itertuples()):
            lsn_item = QTableWidgetItem(str(int(r.LSN))); lsn_item.setForeground(QColor("#ffa726"))
            self.table_time.setItem(i, 0, lsn_item)
            type_item = QTableWidgetItem(str(r.Type))
            if "Page Write" in r.Type: type_item.setForeground(QColor("#aaa"))
            else: type_item.setForeground(QColor("#00bcd4"))
            self.table_time.setItem(i, 1, type_item)
            self.table_time.setItem(i, 2, QTableWidgetItem(str(r.Date)))
            self.table_time.setItem(i, 3, QTableWidgetItem(str(r.Data)))
            self.table_time.setItem(i, 4, QTableWidgetItem(str(r.HexOffset)))
            
        self.table_time.setUpdatesEnabled(True)
        self.table_time.setSortingEnabled(True)

    def refresh_graph(self):
        layout = self.layout_combo.currentText()
        if "Circular" in layout: l_type = 'Circular'
        elif "Kamada" in layout: l_type = 'Kamada-Kawai'
        else: l_type = 'Spring'
        self.graph_widget.plot_graph(self.df, layout_type=l_type, use_centrality=self.chk_centrality.isChecked())

    def export_gexf(self):
        p, _ = QFileDialog.getSaveFileName(self, "Export to Gephi", "Graph.gexf", "GEXF (*.gexf)")
        if p:
            if self.graph_widget.export_gexf(p): QMessageBox.information(self, "Success", "Graph exported successfully.")
            else: QMessageBox.warning(self, "Error", "Could not export graph.")

    def on_click(self, r, c):
        try:
            off = int(self.table.item(r, 0).text(), 16) 
            fn = self.table.item(r, 10).text()
            if fn in self.file_metadata:
                self.hex_view.load_context(self.file_metadata[fn]['Path'], off)
        except: pass

    def ctx_menu(self, pos):
        s = self.sender(); i = s.itemAt(pos)
        if not i: return
        row = i.row()
        if s == self.table:
            data_txt = s.item(row, 4).text()
            offset_str = s.item(row, 0).text()
            file_name = s.item(row, 10).text()
        elif s == self.table_susp:
            data_txt = s.item(row, 1).text()
            return 
        else: return

        m = QMenu(); m.setStyleSheet("QMenu{background:#252a33;color:white;}")
        act_bm = QAction("★ Toggle Bookmark", self); act_bm.triggered.connect(lambda: self.toggle_bookmark(offset_str)); m.addAction(act_bm)

        # ═══════════════════════════════════════════════════════════════════
        # ENHANCEMENT: Hex Viewer from Context Menu
        # ═══════════════════════════════════════════════════════════════════
        act_hex = QAction("🔍 Open Hex Viewer", self)
        def show_hex():
            if file_name in self.file_metadata:
                try:
                    offset = int(offset_str, 16)
                    filepath = self.file_metadata[file_name]['Path']

                    hv = HexViewer()
                    hv.load_context(filepath, offset)
                    hv.setWindowTitle(f"Hex Viewer - {file_name} @ {offset_str}")
                    hv.resize(900, 400)
                    hv.show()

                    if not hasattr(self, '_hex_viewers'):
                        self._hex_viewers = []
                    self._hex_viewers.append(hv)
                except Exception as e:
                    QMessageBox.warning(self, "Hex Viewer Error", str(e))

        act_hex.triggered.connect(show_hex)
        m.addAction(act_hex)
        m.addSeparator()

        act_note = QAction("✎ Add Note", self); act_note.triggered.connect(lambda: self.add_note(offset_str)); m.addAction(act_note)
        m.addSeparator()
        act_carve = QAction("💾 Carve Blob / File", self); act_carve.triggered.connect(lambda: self.carve_blob(offset_str, file_name)); m.addAction(act_carve)
        
        idx = self.df.index[self.df['HexOffset'] == offset_str]
        if not idx.empty and 'RawBytes' in self.df.columns:
            if isinstance(self.df.at[idx[0], 'RawBytes'], bytes):
                act_export_bin = QAction("📤 Export Raw Binary (BLOB)", self)
                act_export_bin.triggered.connect(lambda: self.export_raw_bytes(self.df.at[idx[0], 'RawBytes']))
                m.addAction(act_export_bin)
        
        act_xor = QAction("🔓 XOR Decode", self); act_xor.triggered.connect(lambda: self.xor_bruteforce(data_txt)); m.addAction(act_xor)
        

        # IOC Threat Intelligence
        if self.ti_aggregator:
            m.addSeparator()
            act_ioc = QAction("🔒 Check with Threat Intelligence", self)
            act_ioc.triggered.connect(lambda: self.check_ioc_from_table(data_txt))
            m.addAction(act_ioc)
        
        m.exec(s.viewport().mapToGlobal(pos))

    def toggle_bookmark(self, hex_offset):
        idx = self.df.index[self.df['HexOffset'] == hex_offset]
        if not idx.empty:
            val = not self.df.at[idx[0], 'Bookmark']
            self.df.at[idx[0], 'Bookmark'] = val
            self.filter_main()

    def add_note(self, hex_offset):
        text, ok = QInputDialog.getText(self, "Add Note", "Enter case note:")
        if ok:
            idx = self.df.index[self.df['HexOffset'] == hex_offset]
            if not idx.empty:
                self.df.at[idx[0], 'Note'] = text
                self.df.at[idx[0], 'Bookmark'] = True
                self.filter_main()

    def carve_blob(self, hex_offset, filename):
        if filename not in self.file_metadata: return
        path = self.file_metadata[filename]['Path']
        offset = int(hex_offset, 16)
        try:
            with open(path, 'rb') as f:
                f.seek(offset); chunk = f.read(50000)
            ext = "bin"
            if chunk.startswith(b'\xff\xd8\xff'): ext = "jpg"
            elif chunk.startswith(b'\x89PNG'): ext = "png"
            elif chunk.startswith(b'%PDF'): ext = "pdf"
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Carved", f"carved_{hex_offset}.{ext}", "All (*.*)")
            if save_path:
                with open(save_path, 'wb') as f_out: f_out.write(chunk)
                QMessageBox.information(self, "Success", f"Dumped 50KB to {save_path}")
        except Exception as e: QMessageBox.warning(self, "Error", str(e))

    def export_raw_bytes(self, data):
        save_path, _ = QFileDialog.getSaveFileName(self, "Save BLOB Data", "blob_export.bin", "Binary (*.bin)")
        if save_path:
            try:
                with open(save_path, 'wb') as f: f.write(data)
                QMessageBox.information(self, "Success", "Binary data exported.")
            except Exception as e: QMessageBox.critical(self, "Error", str(e))

    def xor_bruteforce(self, text):
        try:
            data = text.encode('latin-1')
            results = []
            for key in range(1, 256):
                decoded = bytes([b ^ key for b in data])
                try:
                    s = decoded.decode('utf-8')
                    if s.isprintable() and len(s) > 4: results.append(f"Key {key}: {s}")
                except: pass
            if results: QMessageBox.information(self, "XOR Results", "\n".join(results[:10]))
            else: QMessageBox.information(self, "XOR", "No readable strings.")
        except: pass

    def reset_ui(self):
        self.table.setRowCount(0); self.table_time.setRowCount(0); self.table_susp.setRowCount(0); self.table_recon.setRowCount(0)
        self.heatmap.ax.clear(); self.heatmap.draw()
        self.graph_widget.ax.clear(); self.graph_widget.draw()
        self.entropy_stats.table.setRowCount(0); self.entropy_stats.ax.clear(); self.entropy_stats.canvas.draw()
        self.media_widget.list_widget.clear(); self.media_widget.preview_content.setText("Select a file to preview")

    def reset(self):
        self.reset_ui(); self.df = pd.DataFrame(); self.df_timeline = pd.DataFrame(); self.df_reconstructed = pd.DataFrame()
        self.heatmap_struct = []
        self.heatmap_entropy = []
        self.all_carved_files = []
        self.page_types_cache = []
        self.active_schema = None
        self.case_info = {}
        self.lbl_title.setText("InnoSleuth v2.0")

    def export_excel(self):
        if self.df.empty: return
        p, _ = QFileDialog.getSaveFileName(self, "Export", "Report.xlsx", "Excel (*.xlsx)")
        if p:
            df_export = self.df.drop(columns=['RawBytes'], errors='ignore')
            with pd.ExcelWriter(p, engine='xlsxwriter') as w:
                df_export.to_excel(w, sheet_name='Artifacts', index=False)
                if not self.df_timeline.empty: self.df_timeline.to_excel(w, sheet_name='Timeline', index=False)
                if not self.df_reconstructed.empty: self.df_reconstructed.to_excel(w, sheet_name='Reconstructed', index=False)
                if self.case_info:
                    pd.DataFrame([self.case_info]).to_excel(w, sheet_name='Case Info', index=False)
            QMessageBox.information(self, "OK", "Exported.")


    # ═══════════════════════════════════════════════════════════════════
    # ENHANCEMENT: SQLite Evidence Export
    # ═══════════════════════════════════════════════════════════════════
    def export_to_sqlite(self):
        """Export current evidence to SQLite database"""
        try:
            if self.df is None or self.df.empty:
                QMessageBox.warning(self, "No Data", "No artifacts loaded to export.")
                return

            db_path, _ = QFileDialog.getSaveFileName(self, "Export Evidence (SQLite)", 
                                                      "inno_sleuth_evidence.db", 
                                                      "SQLite DB (*.db *.sqlite)")
            if not db_path:
                return

            conn = sqlite3.connect(db_path)
            cur = conn.cursor()

            # Create tables
            cur.execute('''CREATE TABLE IF NOT EXISTS artifacts(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            hexoffset TEXT, pageid INTEGER, pagetype TEXT,
                            type TEXT, data TEXT, suspicious TEXT, decoded TEXT,
                            source TEXT, rawoff INTEGER, keyword TEXT, bookmark INTEGER, note TEXT
                           )''')
            cur.execute('''CREATE TABLE IF NOT EXISTS timeline(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            date TEXT, data TEXT, hexoffset TEXT, source TEXT, 
                            rawdate TEXT, lsn TEXT, type TEXT
                           )''')
            cur.execute('''CREATE TABLE IF NOT EXISTS metadata(k TEXT PRIMARY KEY, v TEXT)''')
            cur.execute('''CREATE TABLE IF NOT EXISTS keyword_stats(kw TEXT PRIMARY KEY, cnt INTEGER)''')
            cur.execute('''CREATE TABLE IF NOT EXISTS case_info(k TEXT PRIMARY KEY, v TEXT)''')

            # Insert artifacts
            art_cols = ['HexOffset','PageID','PageType','Type','Data','Suspicious','Decoded',
                        'Source','RawOff','Keyword','Bookmark','Note']
            to_insert = []
            for _, r in self.df.iterrows():
                row = [str(r.get(c, '')) for c in art_cols]
                row[-2] = '1' if str(row[-2]) == 'True' or row[-2] == '1' else '0'
                to_insert.append(tuple(row))

            cur.executemany('''INSERT INTO artifacts(hexoffset,pageid,pagetype,type,data,suspicious,
                               decoded,source,rawoff,keyword,bookmark,note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''', 
                            to_insert)

            # Insert timeline
            if not self.df_timeline.empty:
                tl_cols = ['Date','Data','HexOffset','Source','RawDate','LSN','Type']
                to_tl = []
                for _, r in self.df_timeline.iterrows():
                    to_tl.append(tuple(str(r.get(c, '')) for c in tl_cols))
                cur.executemany('''INSERT INTO timeline(date,data,hexoffset,source,rawdate,lsn,type) 
                                   VALUES (?,?,?,?,?,?,?)''', to_tl)

            # Metadata
            for k, v in self.file_metadata.items():
                cur.execute('REPLACE INTO metadata(k,v) VALUES (?,?)', (k, json.dumps(v)))

            # Keyword stats
            if hasattr(self.keyword_stats, 'items'):
                for k, cnt in self.keyword_stats.items():
                    cur.execute('REPLACE INTO keyword_stats(kw,cnt) VALUES (?,?)', (k, int(cnt)))

            # Case info
            for k, v in self.case_info.items():
                cur.execute('REPLACE INTO case_info(k,v) VALUES (?,?)', (k, str(v)))

            conn.commit()
            conn.close()

            QMessageBox.information(self, "✓ Exported", f"Evidence exported to:\n{db_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    # ═══════════════════════════════════════════════════════════════════
    # ENHANCEMENT: Quick Search Dialog
    # ═══════════════════════════════════════════════════════════════════
    def open_quick_search(self):
        """Opens quick search dialog"""
        if self.df.empty:
            QMessageBox.information(self, "No Data", "Load data first.")
            return

        dlg = QuickSearchDialog(self, self.df)
        dlg.exec()

    # ═══════════════════════════════════════════════════════════════════
    # ENHANCEMENT: Tablespace Detector
    # ═══════════════════════════════════════════════════════════════════
    def detect_tablespace_layout_ui(self):
        """Open tablespace detector dialog"""
        dlg = TablespaceDetectorDialog(self)
        dlg.exec()




    def load_tde_keyring(self):
        """Load TDE keyring"""
        if not TDE_AVAILABLE:
            QMessageBox.warning(self, "TDE Not Available", "Install: pip install cryptography")
            return
        dlg = TDEKeyringDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            if dlg.keyring_path:
                try:
                    with open(dlg.keyring_path, 'rb') as f:
                        self.tde_master_key = f.read()[:32]
                    self.lbl_tde_status.setText("TDE: ✅")
                    self.lbl_tde_status.setStyleSheet("color: #4caf50; font-size: 9px; font-weight: bold;")
                    QMessageBox.information(self, "Success", "TDE keyring loaded!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))
            elif dlg.master_key_hex:
                try:
                    self.tde_master_key = bytes.fromhex(dlg.master_key_hex)
                    self.lbl_tde_status.setText("TDE: ✅")
                    self.lbl_tde_status.setStyleSheet("color: #4caf50; font-size: 9px; font-weight: bold;")
                    QMessageBox.information(self, "Success", "TDE master key loaded!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))

    def generate_graph_image(self, output_path):
        if self.graph_widget.G and len(self.graph_widget.G) > 0:
            try:
                self.graph_widget.fig.savefig(output_path, facecolor=self.graph_widget.fig.get_facecolor(), bbox_inches='tight')
                return True
            except: return False
        return False

    def export_html_dashboard(self):
        if self.df.empty: return
        p, _ = QFileDialog.getSaveFileName(self, "Save Dashboard", "Dashboard.html", "HTML (*.html)")
        if not p: return
        
        graph_html = ""
        temp_img = "temp_graph.png"
        if self.generate_graph_image(temp_img):
            try:
                with open(temp_img, "rb") as img_file:
                    b64_string = base64.b64encode(img_file.read()).decode('utf-8')
                graph_html = f"""
                <div class="card" style="text-align:center;">
                    <h3>Link Analysis Visualization</h3>
                    <img src="data:image/png;base64,{b64_string}" style="max-width:100%; border:1px solid #444; border-radius:8px;">
                </div>
                """
                os.remove(temp_img)
            except: pass

        total_artifacts = len(self.df)
        suspicious_count = len(self.df[self.df['Suspicious']=='Yes'])
        deleted_count = len(self.df[self.df['Type'].str.contains("Deleted|Recovered", na=False)])
        
        # Case Info HTML
        case_html = ""
        if self.case_info:
            case_html = f"""
            <div class="card">
                <h3 style="color:#00bcd4;">Case Details: {self.case_info.get('Case ID')}</h3>
                <table style="width:100%; text-align:left; color:#ccc;">
                    <tr><td style="width:150px; font-weight:bold;">Name:</td><td>{self.case_info.get('Case Name')}</td></tr>
                    <tr><td style="font-weight:bold;">Type:</td><td>{self.case_info.get('Type')}</td></tr>
                    <tr><td style="font-weight:bold;">Investigator:</td><td>{self.case_info.get('Investigator Name')} ({self.case_info.get('Investigator ID')})</td></tr>
                    <tr><td style="font-weight:bold;">Incident Date:</td><td>{self.case_info.get('Incident Date')}</td></tr>
                    <tr><td style="font-weight:bold;">Notes:</td><td><pre style="color:#aaa; background:#12151a; padding:5px;">{self.case_info.get('Notes')}</pre></td></tr>
                </table>
            </div>
            """

        metadata_html = ""
        if self.file_metadata:
            for fname, meta in self.file_metadata.items():
                metadata_html += f"""
                <div class="card">
                    <h3>File Info: {fname}</h3>
                    <table style="width:100%; text-align:left; color:#ccc;">
                        <tr><td style="width:100px; font-weight:bold;">Path:</td><td>{meta.get('Path', 'N/A')}</td></tr>
                        <tr><td style="font-weight:bold;">Size:</td><td>{meta.get('Size', 0):,} bytes</td></tr>
                        <tr><td style="font-weight:bold;">MD5:</td><td style="font-family:monospace; color:#00bcd4;">{meta.get('MD5', 'N/A')}</td></tr>
                        <tr><td style="font-weight:bold;">SHA256:</td><td style="font-family:monospace; color:#00bcd4;">{meta.get('SHA256', 'N/A')}</td></tr>
                    </table>
                </div>
                """

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>InnoSleuth - Forensic Report</title>
            <link rel="stylesheet" href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.min.css">
            <style>
                body {{ background-color: #12151a; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header-box {{ background-color: #1e222a; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #333; text-align: center; }}
                h1 {{ color: #00bcd4; margin: 0; }}
                .card {{ background-color: #1e222a; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #333; }}
                .stats-row {{ display: flex; gap: 20px; margin-bottom: 20px; }}
                .stat-box {{ flex: 1; background: #252a33; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #444; }}
                .stat-num {{ font-size: 24px; font-weight: bold; }}
                .green {{ color: #4caf50; }} .red {{ color: #ff5252; }} .orange {{ color: #ff9800; }}
                
                table.dataTable {{ color: #e0e0e0 !important; }}
                table.dataTable tbody tr {{ background-color: #1e222a !important; }}
                table.dataTable tbody tr.odd {{ background-color: #252a33 !important; }}
                
                table.dataTable tbody tr.deleted-row {{ background-color: #3d0c0c !important; color: #ffaaaa !important; }}
                table.dataTable tbody tr.deleted-row td {{ border-top: 1px solid #ff5252; border-bottom: 1px solid #ff5252; }}

                table.dataTable thead th {{ background-color: #12151a !important; color: #00bcd4 !important; border-bottom: 1px solid #444 !important; }}
                table.dataTable td {{ border-bottom: 1px solid #333 !important; }}
                .dataTables_wrapper .dataTables_filter input, .dataTables_wrapper .dataTables_length select {{ background-color: #12151a; color: white; border: 1px solid #444; }}
                
                .susp-cell {{ color: #ff5252; font-weight: bold; }}
                .type-cell {{ color: #00bcd4; }}
                .offset-cell {{ color: #76ff03; font-family: monospace; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header-box">
                    <h1>InnoSleuth Report</h1>
                    <p style="color:#888;">Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                </div>
                
                {case_html}
                
                <div class="stats-row">
                    <div class="stat-box"><div>Total Artifacts</div><div class="stat-num green">{total_artifacts}</div></div>
                    <div class="stat-box"><div>Suspicious Hits</div><div class="stat-num red">{suspicious_count}</div></div>
                    <div class="stat-box"><div>Recovered (Deleted)</div><div class="stat-num orange">{deleted_count}</div></div>
                </div>
                
                {metadata_html}
                {graph_html}

                <div class="card">
                    <label><strong>Filter Results: </strong></label>
                    <select id="filterSuspicious" style="padding:5px; background:#12151a; color:white; border:1px solid #444;">
                        <option value="">Show All</option>
                        <option value="Yes">Show Suspicious Only</option>
                        <option value="Deleted">Show Deleted Only</option>
                    </select>
                    <hr style="border:0; border-top:1px solid #333; margin:15px 0;">
                    
                    <table id="mainTable" class="display">
                        <thead>
                            <tr><th>Offset</th><th>Type</th><th>Data Content</th><th>Suspicious</th><th>Source File</th></tr>
                        </thead>
                        <tbody>
        """
        for i, r in self.df.head(5000).iterrows():
            susp_class = "susp-cell" if r['Suspicious'] == "Yes" else ""
            
            row_class = ""
            if "Deleted" in str(r['Type']) or "Recovered" in str(r['Type']):
                row_class = "deleted-row"

            safe_data = str(r['Data']).replace("<","&lt;").replace(">","&gt;")
            if len(safe_data) > 150: safe_data = safe_data[:150] + "..."
            
            html_content += f"""
                <tr class="{row_class}">
                    <td class="offset-cell">{r['HexOffset']}</td>
                    <td class="type-cell">{r['Type']}</td>
                    <td>{safe_data}</td>
                    <td class="{susp_class}">{r['Suspicious']}</td>
                    <td>{r['Source']}</td>
                </tr>
            """
            
        html_content += """
                        </tbody>
                    </table>
                </div>
            </div>
            
            <script src="https://code.jquery.com/jquery-3.5.1.js"></script>
            <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
            <script>
                $(document).ready(function() {
                    var table = $('#mainTable').DataTable({ "pageLength": 25, "order": [[ 0, "asc" ]] });
                    
                    $('#filterSuspicious').on('change', function() {
                        var val = this.value;
                        table.search('').columns().search('');
                        if(val === "Deleted") {
                             table.column(1).search('Deleted|Recovered', true, false).draw();
                        } else if (val === "Yes") {
                             table.column(3).search('Yes').draw();
                        } else {
                             table.draw();
                        }
                    });
                });
            </script>
        </body>
        </html>
        """
        try:
            with open(p, "w", encoding="utf-8") as f: f.write(html_content)
            QMessageBox.information(self, "Success", "HTML Report Generated!")
        except Exception as e: QMessageBox.critical(self, "Error", str(e))

    def export_report(self):
        if self.df.empty: return
        p, _ = QFileDialog.getSaveFileName(self, "PDF", "Report.pdf", "PDF (*.pdf)")
        if not p: return

        self.progress_dialog = QProgressDialog("Generating PDF (Full Export)...", "Cancel", 0, len(self.df), self)
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.setMinimumDuration(0)
        
        self.pdf_thread = PDFExportThread(self.df, self.file_metadata, p, self.case_info)
        self.pdf_thread.progress.connect(self.progress_dialog.setValue)
        self.pdf_thread.finished.connect(lambda msg: (self.progress_dialog.close(), QMessageBox.information(self, "Success", msg)))
        self.pdf_thread.error.connect(lambda msg: (self.progress_dialog.close(), QMessageBox.critical(self, "Error", msg)))
        self.progress_dialog.canceled.connect(self.pdf_thread.stop)
        
        self.pdf_thread.start()

    def apply_theme(self):
        self.setStyleSheet("""
        QWidget { background-color: #12151a; color: #e0e0e0; font-family: 'Segoe UI'; font-size: 10pt; }
        QFrame#ToolFrame { background-color: #1a1e24; border-bottom: 1px solid #333; }
        QPushButton { background-color: #252a33; border: 1px solid #3e4451; border-radius: 5px; padding: 8px; color: white; font-weight: bold; }
        QPushButton:hover { border: 1px solid #00bcd4; color: #00bcd4; }
        QPushButton#ResetBtn { background-color: #4a0e16; color: #ff5252; border: 1px solid #ff5252; }
        QLineEdit, QComboBox, QDateEdit, QTextEdit { background-color: #0d1014; border: 1px solid #333; padding: 6px; color: #00bcd4; }
        QTabWidget::pane { border: 0; }
        QTabBar::tab { background: #1a1e24; color: #888; padding: 10px 20px; margin-right: 2px; }
        QTabBar::tab:selected { background: #252a33; color: #00bcd4; border-bottom: 2px solid #00bcd4; }
        QTableWidget { background-color: #1a1e24; gridline-color: #2c313a; border: none; }
        QHeaderView::section { background-color: #252a33; color: #00bcd4; padding: 5px; border: none; }
        QGroupBox { border: 1px solid #333; margin-top: 10px; font-weight: bold; }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; color: #00bcd4; }
        QProgressBar { background-color: #1a1e24; height: 4px; border: none; }
        QProgressBar::chunk { background-color: #00bcd4; }
        QListWidget { background-color: #1a1e24; border: 1px solid #333; }
        QListWidget::item:selected { background-color: #00bcd4; color: black; }
        """)



    # ============================================================================
    # IOC THREAT INTELLIGENCE METHODS
    # ============================================================================

    def configure_ioc_threat_intel(self):
        """Configure IOC Threat Intelligence API Keys"""
        dialog = QDialog(self)
        dialog.setWindowTitle("🔒 IOC Threat Intelligence Configuration")
        dialog.resize(550, 350)
        dialog.setStyleSheet("""
            QDialog { background-color: #1a1e24; color: white; }
            QLabel { color: #00bcd4; font-weight: bold; font-size: 12px; }
            QLineEdit { 
                background-color: #0d1014; 
                border: 2px solid #00bcd4; 
                padding: 10px; 
                color: white; 
                border-radius: 5px;
                font-size: 11px;
            }
            QPushButton { 
                background-color: #00bcd4; 
                color: white; 
                font-weight: bold;
                padding: 12px; 
                border-radius: 5px;
                font-size: 12px;
            }
            QPushButton:hover { background-color: #00acc1; }
            QGroupBox {
                border: 2px solid #00bcd4;
                border-radius: 5px;
                margin-top: 15px;
                padding: 15px;
                font-weight: bold;
                color: #00bcd4;
            }
        """)

        layout = QVBoxLayout(dialog)

        info_label = QLabel("🔐 Enter API Keys for Threat Intelligence Services:")
        info_label.setStyleSheet("font-size: 14px; color: #00bcd4; font-weight: bold; padding: 10px;")
        layout.addWidget(info_label)

        form = QFormLayout()

        vt_input = QLineEdit()
        vt_input.setPlaceholderText("Enter VirusTotal API Key (free or premium)")
        vt_input.setEchoMode(QLineEdit.EchoMode.Password)
        vt_input.setText(self.ioc_api_keys.get('virustotal', ''))
        form.addRow("🦠 VirusTotal:", vt_input)

        otx_input = QLineEdit()
        otx_input.setPlaceholderText("Enter AlienVault OTX API Key (free)")
        otx_input.setEchoMode(QLineEdit.EchoMode.Password)
        otx_input.setText(self.ioc_api_keys.get('alienvault_otx', ''))
        form.addRow("👽 AlienVault OTX:", otx_input)

        abuse_input = QLineEdit()
        abuse_input.setPlaceholderText("Enter AbuseIPDB API Key (free)")
        abuse_input.setEchoMode(QLineEdit.EchoMode.Password)
        abuse_input.setText(self.ioc_api_keys.get('abuseipdb', ''))
        form.addRow("🚫 AbuseIPDB:", abuse_input)

        layout.addLayout(form)

        help_label = QLabel("💡 Tip: At least one API key is required. Get free keys from respective websites.")
        help_label.setStyleSheet("color: #888; font-size: 10px; font-style: italic; padding: 10px;")
        help_label.setWordWrap(True)
        layout.addWidget(help_label)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("💾 Save & Initialize")
        cancel_btn = QPushButton("❌ Cancel")
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

        def save_config():
            config = {}
            if vt_input.text().strip():
                config['virustotal'] = {'api_key': vt_input.text().strip()}
                self.ioc_api_keys['virustotal'] = vt_input.text().strip()
            if otx_input.text().strip():
                config['alienvault_otx'] = {'api_key': otx_input.text().strip()}
                self.ioc_api_keys['alienvault_otx'] = otx_input.text().strip()
            if abuse_input.text().strip():
                config['abuseipdb'] = {'api_key': abuse_input.text().strip()}
                self.ioc_api_keys['abuseipdb'] = abuse_input.text().strip()

            if not config:
                QMessageBox.warning(dialog, "No API Keys", "Please enter at least one API key.")
                return

            try:
                self.ti_aggregator = ThreatIntelAggregator(config)
                count = len(self.ti_aggregator.providers)
                self.ioc_status.setText(f"Status: ✅ Ready ({count} provider{'s' if count > 1 else ''})")
                self.ioc_status.setStyleSheet("color: #4caf50; font-weight: bold; font-size: 12px;")
                QMessageBox.information(dialog, "✅ Success", 
                    f"Threat Intelligence initialized successfully!\n\n{count} provider(s) ready:\n" +
                    "\n".join([f"  • {p.title()}" for p in self.ti_aggregator.providers.keys()]))
                dialog.accept()
            except Exception as e:
                QMessageBox.critical(dialog, "❌ Error", f"Initialization failed:\n\n{str(e)}")

        save_btn.clicked.connect(save_config)
        cancel_btn.clicked.connect(dialog.reject)

        dialog.exec()

    def check_ioc_from_table(self, data_text):
        """Check IOC from table data with right-click"""
        if not self.ti_aggregator:
            reply = QMessageBox.question(self, "Not Configured", 
                "IOC Threat Intelligence is not configured.\n\nConfigure now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.configure_ioc_threat_intel()
            return

        ioc_value = data_text.strip()
        ioc_type = self.detect_ioc_type(ioc_value)

        if not ioc_type:
            QMessageBox.warning(self, "Unknown IOC Type", 
                f"Could not determine IOC type for:\n\n{ioc_value[:100]}\n\nSupported types: Hash (MD5/SHA1/SHA256), IP, Domain, URL")
            return

        progress = QProgressDialog(f"Checking {ioc_type.upper()}: {ioc_value[:50]}...", 
                                   "Cancel", 0, 0, self)
        progress.setWindowTitle("🔍 Threat Intelligence Check")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.show()
        QApplication.processEvents()

        try:
            results = self.ti_aggregator.check_ioc(ioc_value, ioc_type)
            progress.close()

            if not results:
                QMessageBox.information(self, "No Results", 
                    f"No threat intelligence data found for this {ioc_type.upper()}.")
                return

            self.show_ioc_results_dialog(ioc_value, ioc_type, results)

        except Exception as e:
            progress.close()
            QMessageBox.critical(self, "Error", f"IOC check failed:\n\n{str(e)}")

    def detect_ioc_type(self, value):
        """Auto-detect IOC type from value"""
        import re
        value = value.strip()

        # Hash detection
        if re.match(r'^[a-fA-F0-9]{32}$', value): return 'hash'  # MD5
        if re.match(r'^[a-fA-F0-9]{40}$', value): return 'hash'  # SHA1
        if re.match(r'^[a-fA-F0-9]{64}$', value): return 'hash'  # SHA256

        # IP Address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            parts = value.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                return 'ip'

        # URL
        if value.startswith(('http://', 'https://', 'ftp://')):
            return 'url'

        # Domain
        if '.' in value and not '/' in value and len(value.split('.')) >= 2:
            if not any(c in value for c in ['@', ' ', '<', '>']):
                return 'domain'

        return None

    def show_ioc_results_dialog(self, ioc_value, ioc_type, results):
        """Show IOC results in detailed dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"🔒 Threat Intelligence Results: {ioc_type.upper()}")
        dialog.resize(1000, 650)
        dialog.setStyleSheet("""
            QDialog { background-color: #1a1e24; color: white; }
            QLabel { color: #00bcd4; font-weight: bold; }
            QTableWidget { 
                background-color: #0d1014; 
                color: white; 
                gridline-color: #333;
                border: 1px solid #444;
            }
            QHeaderView::section { 
                background-color: #252a33; 
                color: #00bcd4; 
                font-weight: bold; 
                padding: 8px;
                border: 1px solid #444;
            }
            QPushButton { 
                background-color: #00bcd4; 
                color: white; 
                padding: 10px; 
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #00acc1; }
        """)

        layout = QVBoxLayout(dialog)

        header = QLabel(f"Checking: {ioc_value[:100]}")
        header.setStyleSheet("font-size: 13px; color: #00bcd4; font-weight: bold; padding: 10px;")
        header.setWordWrap(True)
        layout.addWidget(header)

        mal_count = sum(1 for r in results if r.malicious)
        total_count = len(results)

        summary_text = f"📊 Results: {total_count} source{'s' if total_count > 1 else ''} checked"
        if mal_count > 0:
            summary_text += f" | ⚠️ {mal_count} flagged as MALICIOUS"
        else:
            summary_text += " | ✅ All sources: CLEAN"

        summary = QLabel(summary_text)
        summary.setStyleSheet(f"font-size: 13px; color: {'#f44336' if mal_count > 0 else '#4caf50'}; "
                             "font-weight: bold; padding: 10px; background-color: #252a33; border-radius: 5px;")
        summary.setWordWrap(True)
        layout.addWidget(summary)

        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "Source", "Malicious", "Score", "Detections", "Tags", "Country", "First Seen", "Details"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

        for result in results:
            row = table.rowCount()
            table.insertRow(row)

            table.setItem(row, 0, QTableWidgetItem(result.source))

            mal_text = "✅ YES" if result.malicious else "❌ NO" if result.malicious is False else "❓ Unknown"
            mal_item = QTableWidgetItem(mal_text)
            if result.malicious:
                mal_item.setForeground(QColor("#f44336"))
                mal_item.setBackground(QColor("#4a1010"))
            elif result.malicious is False:
                mal_item.setForeground(QColor("#4caf50"))
            table.setItem(row, 1, mal_item)

            score_text = f"{result.score:.1f}/100" if result.score is not None else "N/A"
            score_item = QTableWidgetItem(score_text)
            if result.score and result.score > 75:
                score_item.setForeground(QColor("#f44336"))
            elif result.score and result.score > 50:
                score_item.setForeground(QColor("#ff9800"))
            elif result.score is not None:
                score_item.setForeground(QColor("#4caf50"))
            table.setItem(row, 2, score_item)

            det_text = f"{result.detections}/{result.total_engines}" if result.detections is not None else str(result.detections) if result.detections else "N/A"
            table.setItem(row, 3, QTableWidgetItem(det_text))

            tags = ", ".join(result.tags[:3]) if result.tags else "None"
            table.setItem(row, 4, QTableWidgetItem(tags))

            table.setItem(row, 5, QTableWidgetItem(result.country or "N/A"))
            table.setItem(row, 6, QTableWidgetItem(str(result.first_seen)[:19] if result.first_seen else "N/A"))

            details = result.error if result.error else "OK"
            table.setItem(row, 7, QTableWidgetItem(details))

        layout.addWidget(table)

        btn_layout = QHBoxLayout()

        export_btn = QPushButton("💾 Export to JSON")
        def export():
            filepath, _ = QFileDialog.getSaveFileName(
                dialog, "Export Results", 
                f"ioc_{ioc_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json)")
            if filepath:
                try:
                    self.ti_aggregator.export_results_json(results, filepath)
                    QMessageBox.information(dialog, "Success", f"Results exported to:\n\n{filepath}")
                except Exception as e:
                    QMessageBox.critical(dialog, "Error", f"Export failed:\n\n{str(e)}")
        export_btn.clicked.connect(export)
        btn_layout.addWidget(export_btn)

        close_btn = QPushButton("✖️ Close")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        dialog.exec()

    def batch_check_artifacts_ioc(self):
        """Batch check all artifacts with IOC TI"""
        if not self.ti_aggregator:
            reply = QMessageBox.question(self, "Not Configured", 
                "IOC Threat Intelligence is not configured.\n\nConfigure now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.configure_ioc_threat_intel()
            return

        if self.df.empty:
            QMessageBox.warning(self, "No Data", "No artifacts loaded to check.\n\nPlease load an InnoDB file first.")
            return

        iocs_to_check = []
        for idx, row in self.df.iterrows():
            data = str(row.get('Data', ''))
            ioc_type = self.detect_ioc_type(data)
            if ioc_type:
                iocs_to_check.append((data, ioc_type, idx))

        if not iocs_to_check:
            QMessageBox.information(self, "No IOCs Found", 
                "No recognizable IOCs (hashes, IPs, domains, URLs) found in artifacts.\n\nIOCs must match standard formats.")
            return

        reply = QMessageBox.question(self, "Batch IOC Check", 
            f"Found {len(iocs_to_check)} potential IOC{'s' if len(iocs_to_check) > 1 else ''} to check:\n\n" +
            f"  • Hashes: {sum(1 for _, t, _ in iocs_to_check if t == 'hash')}\n" +
            f"  • IPs: {sum(1 for _, t, _ in iocs_to_check if t == 'ip')}\n" +
            f"  • Domains: {sum(1 for _, t, _ in iocs_to_check if t == 'domain')}\n" +
            f"  • URLs: {sum(1 for _, t, _ in iocs_to_check if t == 'url')}\n\n" +
            "⚠️ This may take several minutes due to API rate limits.\n\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply != QMessageBox.StandardButton.Yes:
            return

        progress = QProgressDialog("Checking IOCs...", "Cancel", 0, len(iocs_to_check), self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("🔍 Batch IOC Analysis")

        all_results = []
        malicious_found = []

        for i, (ioc_value, ioc_type, df_idx) in enumerate(iocs_to_check):
            if progress.wasCanceled():
                break

            progress.setValue(i)
            progress.setLabelText(f"Checking {i+1}/{len(iocs_to_check)}: {ioc_type.upper()} - {ioc_value[:40]}...")
            QApplication.processEvents()

            try:
                results = self.ti_aggregator.check_ioc(ioc_value, ioc_type)
                all_results.extend(results)

                if any(r.malicious for r in results):
                    malicious_found.append((ioc_value, ioc_type, results, df_idx))

            except Exception as e:
                logging.error(f"Batch IOC check error for {ioc_value}: {e}")

        progress.setValue(len(iocs_to_check))

        msg = f"✅ Batch IOC Check Complete!\n\n"
        msg += f"📊 Total IOCs checked: {len(iocs_to_check)}\n"
        msg += f"⚠️ Malicious IOCs found: {len(malicious_found)}\n"
        msg += f"✅ Clean IOCs: {len(iocs_to_check) - len(malicious_found)}\n"

        if malicious_found:
            msg += "\n⚠️ WARNING: Malicious IOCs detected!\n\nView detailed results?"
            reply = QMessageBox.warning(self, "Malicious IOCs Found", msg,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

            if reply == QMessageBox.StandardButton.Yes:
                self.show_batch_ioc_results(malicious_found)
        else:
            QMessageBox.information(self, "✅ All Clean", msg)

    def show_batch_ioc_results(self, malicious_iocs):
        """Show batch IOC results for malicious findings"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"⚠️ Malicious IOCs Detected ({len(malicious_iocs)})")
        dialog.resize(1100, 700)
        dialog.setStyleSheet("""
            QDialog { background-color: #1a1e24; color: white; }
            QTableWidget { 
                background-color: #0d1014; 
                color: white; 
                gridline-color: #333;
                border: 1px solid #f44336;
            }
            QHeaderView::section { 
                background-color: #252a33; 
                color: #f44336; 
                font-weight: bold; 
                padding: 8px;
            }
            QPushButton { 
                background-color: #f44336; 
                color: white; 
                padding: 10px; 
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #d32f2f; }
        """)

        layout = QVBoxLayout(dialog)

        header = QLabel(f"⚠️ CRITICAL: Found {len(malicious_iocs)} Malicious IOC{'s' if len(malicious_iocs) > 1 else ''}")
        header.setStyleSheet("font-size: 16px; color: #f44336; font-weight: bold; padding: 15px; background-color: #4a1010; border-radius: 5px;")
        layout.addWidget(header)

        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(["IOC Value", "Type", "Sources Flagged", "Max Score", "Detections", "Details"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

        for ioc_value, ioc_type, results, df_idx in malicious_iocs:
            row = table.rowCount()
            table.insertRow(row)

            ioc_item = QTableWidgetItem(ioc_value[:70])
            ioc_item.setForeground(QColor("#f44336"))
            table.setItem(row, 0, ioc_item)

            type_item = QTableWidgetItem(ioc_type.upper())
            type_item.setForeground(QColor("#ff9800"))
            table.setItem(row, 1, type_item)

            mal_sources = [r.source for r in results if r.malicious]
            sources_item = QTableWidgetItem(", ".join(mal_sources))
            table.setItem(row, 2, sources_item)

            max_score = max((r.score for r in results if r.score is not None), default=0)
            score_item = QTableWidgetItem(f"{max_score:.1f}/100")
            score_item.setForeground(QColor("#f44336"))
            score_item.setBackground(QColor("#4a1010"))
            table.setItem(row, 3, score_item)

            total_det = sum(r.detections for r in results if r.detections is not None)
            det_item = QTableWidgetItem(str(total_det))
            table.setItem(row, 4, det_item)

            details = f"{len(results)} sources checked, {len(mal_sources)} flagged"
            table.setItem(row, 5, QTableWidgetItem(details))

        layout.addWidget(table)

        btn_layout = QHBoxLayout()

        export_btn = QPushButton("💾 Export Report")
        def export_report():
            filepath, _ = QFileDialog.getSaveFileName(
                dialog, "Export Malicious IOCs Report",
                f"malicious_iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json)")
            if filepath:
                try:
                    report_data = []
                    for ioc_value, ioc_type, results, df_idx in malicious_iocs:
                        report_data.append({
                            'ioc': ioc_value,
                            'type': ioc_type,
                            'results': [r.to_dict() for r in results]
                        })
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(report_data, f, indent=2, ensure_ascii=False)
                    QMessageBox.information(dialog, "Success", f"Report exported to:\n\n{filepath}")
                except Exception as e:
                    QMessageBox.critical(dialog, "Error", f"Export failed:\n\n{str(e)}")
        export_btn.clicked.connect(export_report)
        btn_layout.addWidget(export_btn)

        close_btn = QPushButton("✖️ Close")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        dialog.exec()

    # End of IOC Threat Intelligence Methods
    # ============================================================================


if __name__ == "__main__":
    # =================================================================
    # TASKBAR & WINDOW ICON FIX - Uses the turquoise SVG logo
    # =================================================================

    # 1. Set unique App ID for Windows Taskbar
    myappid = 'innosleuth.forensic.tool.v7'
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    # 2. Create Application
    app = QApplication(sys.argv)

    # 3. Create icon from the SVG (turquoise logo) instead of external file
    svg_pixmap = QPixmap()
    svg_pixmap.loadFromData(APP_ICON_SVG.encode('utf-8'))
    app_icon = QIcon(svg_pixmap)
    app.setWindowIcon(app_icon)

    # 4. Create Main Window
    window = IBDInvestigatorApp()

    # 5. Set window icon explicitly (ensures taskbar uses SVG icon)
    window.setWindowIcon(app_icon)

    # 6. Show window and start application
    window.show()
    sys.exit(app.exec())
