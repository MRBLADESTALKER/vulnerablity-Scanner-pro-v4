"""
Cyber Expert Bladex ” Professional GUI Network Scanner & Vulnerability Finder (v4)
Enhanced Features:
 - Modern professional hacker-style GUI with smooth animations
 - Comprehensive nmap command presets with click-to-run functionality
 - Secure login/logout system with credential storage
 - Search history tracking and management
 - Enhanced dark theme with professional styling
 - Improved UI flow and butter-smooth interactions
 - All existing scanning functionality preserved

Usage: python Cyber_Expert_Bladex_Pro_v4.py
Requires: Python 3.8+, nmap binary, python-nmap, PyQt5, cryptography, requests
Install: pip install python-nmap PyQt5 cryptography requests

Legal: Use only on authorized targets. This tool helps defenders and auditors.
"""

import os
import re
import sys
import json
import time
import traceback
import sqlite3
import requests
import hashlib
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import nmap  # Ensure python-nmap is installed: pip install python-nmap
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtCore import QTimer, QPropertyAnimation, QEasingCurve, QRect, pyqtSignal
from PyQt5.QtWidgets import QGraphicsOpacityEffect


# ----------------- Data classes (unchanged) -----------------
@dataclass
class Vulnerability:
    id: Optional[str]
    title: Optional[str]
    description: Optional[str]
    severity: Optional[str]
    score: Optional[str] = None
    refs: Optional[List[str]] = None


@dataclass
class PortEntry:
    port: int
    protocol: str
    state: str
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]
    extra: Optional[str]
    vulns: List[Vulnerability]


@dataclass
class HostEntry:
    ip: str
    hostname: Optional[str]
    status: str
    os: Optional[str]
    ports: List[PortEntry]
    raw: Dict[str, Any]


# ----------------- Enhanced Classes -----------------


class UserManager:
    """Enhanced user management with secure credential storage"""

    def __init__(self, db_path: str = "bladex_users.db"):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """
            )
            # Create default admin user if not exists
            self.create_user("admin", "bladex2025", "admin")

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def create_user(self, username: str, password: str, role: str = "user") -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, self._hash_password(password), role),
                )
                return True
        except Exception:
            return False

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?",
                    (username, self._hash_password(password)),
                )
                row = cursor.fetchone()
                if row:
                    # Update last login
                    conn.execute(
                        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                        (row[0],),
                    )
                    return {"id": row[0], "username": row[1], "role": row[2]}
        except Exception:
            pass
        return None


class HistoryManager:
    """Search history tracking and management"""

    def __init__(self, db_path: str = "bladex_history.db"):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    target TEXT NOT NULL,
                    nmap_args TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    results_count INTEGER DEFAULT 0
                )
            """
            )

    def add_scan(
        self, user_id: int, target: str, nmap_args: str, results_count: int = 0
    ):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO scan_history (user_id, target, nmap_args, results_count) VALUES (?, ?, ?, ?)",
                    (user_id, target, nmap_args, results_count),
                )
        except Exception:
            pass

    def get_history(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT target, nmap_args, timestamp, results_count FROM scan_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (user_id, limit),
                )
                return [
                    {
                        "target": row[0],
                        "args": row[1],
                        "timestamp": row[2],
                        "results": row[3],
                    }
                    for row in cursor.fetchall()
                ]
        except Exception:
            return []


class AnimatedButton(QtWidgets.QPushButton):
    """Custom animated button with hover effects"""

    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.animation = None
        self.setMinimumHeight(40)

    def enterEvent(self, event):
        if not self.animation:
            self.animation = QPropertyAnimation(self, b"geometry")
            self.animation.setDuration(200)
            self.animation.setEasingCurve(QEasingCurve.OutCubic)

        current_rect = self.geometry()
        new_rect = QRect(
            current_rect.x() - 2,
            current_rect.y() - 1,
            current_rect.width() + 4,
            current_rect.height() + 2,
        )

        self.animation.setStartValue(current_rect)
        self.animation.setEndValue(new_rect)
        self.animation.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        if self.animation:
            current_rect = self.geometry()
            original_rect = QRect(
                current_rect.x() + 2,
                current_rect.y() + 1,
                current_rect.width() - 4,
                current_rect.height() - 2,
            )

            self.animation.setStartValue(current_rect)
            self.animation.setEndValue(original_rect)
            self.animation.start()
        super().leaveEvent(event)


class LoginDialog(QtWidgets.QDialog):
    """Enhanced login dialog with modern styling"""

    login_successful = pyqtSignal(dict)

    def __init__(self, user_manager: UserManager, parent=None):
        super().__init__(parent)
        self.user_manager = user_manager
        self.setWindowTitle("Bladex Login")
        self.setFixedSize(600, 500)
        self.setModal(True)
        self._setup_ui()
        self._apply_theme()

    def _setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)

        # Logo/Title
        title = QtWidgets.QLabel("BLADEX SECURITY")
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setStyleSheet(
            "font-size: 24px; font-weight: bold; color: #7cffc5; margin-bottom: 20px;"
        )
        layout.addWidget(title)

        # Username field
        self.username_label = QtWidgets.QLabel("Username:")
        self.username_edit = QtWidgets.QLineEdit()
        self.username_edit.setMinimumHeight(30) 
        self.username_edit.setPlaceholderText("Enter your username")
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_edit)

        # Password field
        self.password_label = QtWidgets.QLabel("Password:")
        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setMinimumHeight(30)
        self.password_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_edit.setPlaceholderText("Enter your password")
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_edit)

        # Remember me checkbox
        self.remember_check = QtWidgets.QCheckBox("Remember me")
        layout.addWidget(self.remember_check)

        # Error message
        self.error_label = QtWidgets.QLabel("")
        self.error_label.setStyleSheet("color: #ff6b6b; font-size: 12px;")
        self.error_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(self.error_label)

        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        self.login_btn = AnimatedButton("LOGIN")
        self.cancel_btn = AnimatedButton("CANCEL")

        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.login_btn)
        layout.addLayout(button_layout)

        # Connect signals
        self.login_btn.clicked.connect(self._attempt_login)
        self.cancel_btn.clicked.connect(self.reject)
        self.password_edit.returnPressed.connect(self._attempt_login)

    def _attempt_login(self):
        username = self.username_edit.text().strip()
        password = self.password_edit.text()

        if not username or not password:
            self.error_label.setText("Please enter both username and password")
            return

        user = self.user_manager.authenticate(username, password)
        if user:
            self.login_successful.emit(user)
            self.accept()
        else:
            self.error_label.setText("Invalid username or password")

    def _apply_theme(self):
        self.setStyleSheet(
            """
            QDialog { 
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #0a0a0a, stop: 1 #1a1a1a);
                border: 2px solid #7cffc5;
                border-radius: 10px;
            }
            QLabel { color: #cfe9d6; font-size: 14px; }
            QLineEdit { 
                background: #091015; 
                color: #bfe6b3; 
                border: 2px solid #2a2f33; 
                border-radius: 6px; 
                padding: 8px; 
                font-size: 14px;
            }
            QLineEdit:focus { border-color: #7cffc5; }
            QCheckBox { color: #cfe9d6; }
            QCheckBox::indicator:checked { background: #7cffc5; }
        """
        )


class NmapPresetWidget(QtWidgets.QWidget):
    """Advanced nmap command preset selector"""

    preset_selected = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._create_presets()

    def _setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Search filter
        search_layout = QtWidgets.QHBoxLayout()
        search_label = QtWidgets.QLabel("Filter:")
        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText("Search scan types...")
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_edit)
        layout.addLayout(search_layout)

        # Preset list
        self.preset_list = QtWidgets.QListWidget()
        self.preset_list.setAlternatingRowColors(True)
        layout.addWidget(self.preset_list)

        # Connect signals
        self.search_edit.textChanged.connect(self._filter_presets)
        self.preset_list.itemDoubleClicked.connect(self._on_preset_selected)

    def _create_presets(self):
        """Create comprehensive nmap preset commands"""
        self.presets = [
            # Basic Scans
            ("Quick Scan", "-T4 -F", "Fast scan of common ports"),
            ("Intense Scan", "-T4 -A -v", "Comprehensive scan with OSdetection"),
            ("Intense + UDP", "-sS -sU -T4 -A -v", "Intense scan + UDP ports"),
            (
                "Slow Comprehensive",
                "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY",
                "Very thorough scan",
            ),
            # Service Detection
            ("Service Version", "-sV", "Probe open ports for service versions"),
            ("Service + OS", "-sV -O", "Service version + OS detection"),
            (
                "Aggressive Service",
                "-sV --version-intensity 9",
                "Intensive version detection",
            ),
            # Port Scanning Techniques
            ("SYN Stealth", "-sS", "SYN stealth scan (default)"),
            ("TCP Connect", "-sT", "Full TCP connect scan"),
            ("UDP Scan", "-sU", "UDP port scan"),
            ("SCTP Init", "-sY", "SCTP INIT scan"),
            ("TCP Null", "-sN", "TCP Null scan"),
            ("TCP FIN", "-sF", "TCP FIN scan"),
            ("TCP Xmas", "-sX", "TCP Xmas scan"),
            ("TCP ACK", "-sA", "TCP ACK scan"),
            ("TCP Window", "-sW", "TCP Window scan"),
            ("TCP Maimon", "-sM", "TCP Maimon scan"),
            # Discovery Options
            ("Ping Sweep", "-sn", "Ping scan only (no port scan)"),
            ("ARP Scan", "-PR -sn", "ARP discovery scan"),
            ("No Ping", "-Pn", "Skip host discovery"),
            ("TCP SYN Discovery", "-PS80,443,22", "TCP SYN discovery probes"),
            ("TCP ACK Discovery", "-PA80,443,22", "TCP ACK discovery probes"),
            (
                "UDP Discovery",
                "-PU53,67,68,135,137,138,161,445",
                "UDP discovery probes",
            ),
            # Vulnerability Scans
            ("Vulnerability Scan", "--script vuln", "Check for vulnerabilities"),
            ("Default Scripts", "-sC", "Run default NSE scripts"),
            ("All Scripts", "--script all", "Run all available scripts"),
            ("Safe Scripts", "--script safe", "Run only safe scripts"),
            ("Malware Detection", "--script malware", "Detect malware"),
            ("Brute Force", "--script brute", "Brute force attacks"),
            # Stealth & Evasion
            ("Decoy Scan", "-D RND:10", "Use random decoys"),
            ("Fragmented Packets", "-f", "Fragment IP packets"),
            ("Bad Checksum", "--badsum", "Use bad checksums"),
            ("Random Data", "--data-length 200", "Append random data"),
            ("Source Port", "--source-port 53", "Use specific source port"),
            ("Spoof MAC", "--spoof-mac Apple", "Spoof MAC address"),
            # Timing Templates
            ("Paranoid (-T0)", "-T0", "Very slow scan (IDS evasion)"),
            ("Sneaky (-T1)", "-T1", "Slow scan"),
            ("Polite (-T2)", "-T2", "Polite scan"),
            ("Normal (-T3)", "-T3", "Normal timing (default)"),
            ("Aggressive (-T4)", "-T4", "Aggressive timing"),
            ("Insane (-T5)", "-T5", "Very fast scan"),
            # Output Options
            ("Verbose", "-v", "Increase verbosity"),
            ("Debug", "-d", "Enable debugging"),
            ("Reason", "--reason", "Display port state reasons"),
            ("Packet Trace", "--packet-trace", "Show all packets sent/received"),
            ("Open Only", "--open", "Show only open ports"),
            # Custom Port Ranges
            ("Top 100 Ports", "--top-ports 100", "Scan top 100 ports"),
            ("Top 1000 Ports", "--top-ports 1000", "Scan top 1000 ports"),
            ("All Ports", "-p-", "Scan all 65535 ports"),
            (
                "Common Ports",
                "-p 21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080",
                "Scan common ports",
            ),
            ("Web Ports", "-p 80,443,8080,8443,8000,8888", "Scan web service ports"),
            # Specialized Scans
            ("IPv6 Scan", "-6", "IPv6 scanning"),
            ("List Scan", "-sL", "List targets only"),
            ("Traceroute", "--traceroute", "Enable traceroute"),
            ("MTU Discovery", "--mtu-disc", "Enable MTU discovery"),
            ("Idle Scan", "-sI zombie_host", "Idle scan (replace zombie_host)"),
        ]

        for name, command, description in self.presets:
            item = QtWidgets.QListWidgetItem(f"{name}: {command}")
            item.setData(QtCore.Qt.UserRole, (name, command, description))
            item.setToolTip(description)
            self.preset_list.addItem(item)

    def _filter_presets(self, text):
        """Filter presets based on search text"""
        for i in range(self.preset_list.count()):
            item = self.preset_list.item(i)
            item.setHidden(text.lower() not in item.text().lower())

    def _on_preset_selected(self, item):
        """Handle preset selection"""
        data = item.data(QtCore.Qt.UserRole)
        if data:
            name, command, description = data
            self.preset_selected.emit(command, f"{name}: {description}")


class CredentialVault:
    def __init__(self, path: str = "vault.bin"):
        self.path = path
        self.data = {}

    def _derive_key(self, password: str):
        salt = b"bladex_salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def load(self, password: str) -> Dict[str, Any]:
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "rb") as f:
            token = f.read()
        fernet = Fernet(self._derive_key(password))
        raw = fernet.decrypt(token)
        self.data = json.loads(raw.decode())
        return self.data

    def save(self, password: str, data: Dict[str, Any]):
        fernet = Fernet(self._derive_key(password))
        token = fernet.encrypt(json.dumps(data).encode())
        with open(self.path, "wb") as f:
            f.write(token)
        self.data = data


class VulnerabilityEnricher:
    def __init__(
        self, nvd_api_key: Optional[str] = None, cache_db: str = "nvd_cache.sqlite"
    ):
        self.api_key = nvd_api_key
        self.cache_db = cache_db

    def enrich(self, vuln: Vulnerability) -> Vulnerability:
        if not vuln.id:
            return vuln
        # try cache first
        if os.path.exists(self.cache_db):
            try:
                with sqlite3.connect(self.cache_db) as conn:
                    c = conn.cursor()
                    c.execute(
                        "SELECT score, severity, desc, refs FROM cve WHERE id=?",
                        (vuln.id,),
                    )
                    row = c.fetchone()
                    if row:
                        vuln.score, vuln.severity, vuln.description, refs_json = row
                        vuln.refs = json.loads(refs_json)
                        return vuln
            except Exception:
                pass  # Failed to read from cache, proceed to API
        # fallback: query NVD API
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={vuln.id}"
            headers = {"apiKey": self.api_key} if self.api_key else {}
            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code == 200:
                j = r.json()
                cve_item = j.get("vulnerabilities", [{}])[0].get("cve", {})

                # Description
                vuln.description = next(
                    (
                        desc["value"]
                        for desc in cve_item.get("descriptions", [])
                        if desc["lang"] == "en"
                    ),
                    None,
                )

                # CVSS Score and Severity
                metrics = cve_item.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    vuln.score = cvss_data.get("baseScore")
                    vuln.severity = cvss_data.get("baseSeverity")
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    vuln.score = cvss_data.get("baseScore")
                    vuln.severity = metrics["cvssMetricV2"][0].get("baseSeverity")

                # References
                refs = cve_item.get("references", [])
                vuln.refs = [ref["url"] for ref in refs]

        except Exception:
            pass  # API call failed
        return vuln


# ----------------- Worker Thread (unchanged functionality) -----------------
class ScanWorker(QtCore.QThread):
    log = QtCore.pyqtSignal(str)
    result = QtCore.pyqtSignal(object)  # HostEntry
    finished_all = QtCore.pyqtSignal()
    error = QtCore.pyqtSignal(str)

    def __init__(
        self,
        targets: List[str],
        nmap_args: str,
        vault: Optional[CredentialVault] = None,
        creds: Optional[Dict[str, Dict[str, str]]] = None,
        enricher: Optional[VulnerabilityEnricher] = None,
        parent: Optional[Any] = None,
    ):
        super().__init__(parent)
        self._targets = targets
        self._args = nmap_args
        self._scanner = nmap.PortScanner()
        self._stop_requested = False
        self._vault = vault
        self._creds: Dict[str, Dict[str, str]] = creds or {}
        self._enricher = enricher

    def stop(self):
        self._stop_requested = True

    def run(self):
        try:
            for t in self._targets:
                if self._stop_requested:
                    self.log.emit("[!] Stop requested, aborting remaining targets.")
                    break
                self.log.emit(f"[+] Starting scan: {t} args: {self._args}")
                try:
                    args = self._args
                    # inject creds if available
                    if "smb" in self._creds:
                        u, p = self._creds["smb"]["user"], self._creds["smb"]["pass"]
                        args += f" --script-args smbuser={u},smbpass={p}"
                    if "ssh" in self._creds:
                        u, p = self._creds["ssh"]["user"], self._creds["ssh"]["pass"]
                        args += f" --script-args sshuser={u},sshpass={p}"
                    scan_output = self._scanner.scan(hosts=t, arguments=args)
                except Exception as e:
                    tb = traceback.format_exc()
                    self.error.emit(f"Error running nmap on {t}: {e}\n{tb}")
                    continue

                for host in self._scanner.all_hosts():
                    if self._stop_requested:
                        break
                    try:
                        h = self._scanner[host]
                        hostname = h.hostname() or None
                        status = h.state()
                        os_guess = None
                        if "osmatch" in h and h["osmatch"]:
                            os_guess = h["osmatch"][0].get("name")

                        ports = []
                        for proto in ("tcp", "udp"):
                            if proto in h:
                                for port, pinfo in h[proto].items():
                                    vulns = []
                                    scripts = pinfo.get("script", {}) or {}
                                    for script_name, script_out in scripts.items():
                                        cves = re.findall(
                                            r"CVE-\d{4}-\d{4,7}",
                                            str(script_out),
                                            flags=re.I,
                                        )
                                        title = None
                                        desc = None
                                        severity = None
                                        if isinstance(script_out, str):
                                            lines = [
                                                l.strip()
                                                for l in script_out.splitlines()
                                                if l.strip()
                                            ]
                                            if lines:
                                                title = lines[0]
                                                desc = "\n".join(lines[:6])

                                            # Handle CVEs found in script output
                                            for c in cves:
                                                v = Vulnerability(
                                                    id=c,
                                                    title=title,
                                                    description=desc,
                                                    severity=severity,
                                                )
                                                if self._enricher:
                                                    v = self._enricher.enrich(v)
                                                vulns.append(v)

                                        # Handle non-CVE vulnerabilities
                                        if not cves and re.search(
                                            r"(vulnerable|exploitable|bypass|denial of service|remote code execution)",
                                            str(script_out),
                                            flags=re.I,
                                        ):
                                            v = Vulnerability(
                                                id=None,
                                                title=script_name,
                                                description=str(script_out)[:1000],
                                                severity="High",  # Assume high severity for these keywords
                                            )
                                            vulns.append(v)

                                    pe = PortEntry(
                                        port=int(port),
                                        protocol=proto,
                                        state=pinfo.get("state", ""),
                                        service=pinfo.get("name"),
                                        product=pinfo.get("product"),
                                        version=pinfo.get("version"),
                                        extra=pinfo.get("extrainfo"),
                                        vulns=vulns,
                                    )
                                    ports.append(pe)

                        he = HostEntry(
                            ip=host,
                            hostname=hostname,
                            status=status,
                            os=os_guess,
                            ports=ports,
                            raw=h,
                        )
                        self.log.emit(f"[+] Parsed host {host} ({len(ports)} ports)")
                        self.result.emit(he)
                    except Exception as e:
                        tb = traceback.format_exc()
                        self.error.emit(f"Parsing error for host {host}: {e}\n{tb}")
                        continue
            self.finished_all.emit()
        except Exception as e:
            tb = traceback.format_exc()
            self.error.emit(f"Fatal worker error: {e}\n{tb}")


# ----------------- Enhanced Main Window -----------------
class CyberExpertBladexPro(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Expert Bladex ” Professional Edition")
        self.resize(1400, 900)

        # Initialize managers
        self.user_manager = UserManager()
        self.history_manager = HistoryManager()
        self.current_user = None

        # Initialize other components
        self._workers: List[ScanWorker] = []
        self._results: List[HostEntry] = []
        self._vault = CredentialVault()
        self._creds = {}
        self._enricher = VulnerabilityEnricher()

        # Show login dialog first
        self._show_login()

    def _show_login(self):
        """Show login dialog"""
        login_dialog = LoginDialog(self.user_manager, self)
        login_dialog.login_successful.connect(self._on_login_success)

        if login_dialog.exec_() != QtWidgets.QDialog.Accepted:
            sys.exit()

    def _on_login_success(self, user_data):
        """Handle successful login"""
        self.current_user = user_data
        self._setup_ui()
        self._apply_theme()
        self.show()
        self._load_history()

    def _setup_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QVBoxLayout(central)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(15)

        # --- Enhanced Header ---
        header_widget = QtWidgets.QWidget()
        header_layout = QtWidgets.QHBoxLayout(header_widget)
        header_layout.setContentsMargins(20, 10, 20, 10)

        # Logo and title
        logo_title = QtWidgets.QLabel(
            "<b>CYBER EXPERT BLADEX</b>” Professional Edition"
        )
        logo_title.setStyleSheet(
            "font-family: 'Courier New'; font-size: 20px; color: #7cffc5;"
        )
        header_layout.addWidget(logo_title)

        # User info and logout
        header_layout.addStretch()
        user_info = QtWidgets.QLabel(
            f"Welcome, <b>{ self.current_user ['username']} </b> ({self.current_user['role']})"
        )
        user_info.setStyleSheet("color: #bfe6b3; font-size: 14px; margin-right: 20px;")
        self.logout_btn = AnimatedButton("LOGOUT")
        self.logout_btn.setMaximumWidth(100)

        header_layout.addWidget(user_info)
        header_layout.addWidget(self.logout_btn)
        main_layout.addWidget(header_widget)

        # --- Main Content Splitter ---
        main_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        # Left Panel: Controls and Presets
        left_panel = QtWidgets.QWidget()
        left_panel.setMaximumWidth(500)
        left_layout = QtWidgets.QVBoxLayout(left_panel)

        # Scan Controls Group
        controls_group = QtWidgets.QGroupBox("Scan Configuration")
        controls_layout = QtWidgets.QVBoxLayout(controls_group)

        # Target input
        target_layout = QtWidgets.QHBoxLayout()
        target_layout.addWidget(QtWidgets.QLabel("Targets:"))
        self.targets_edit = QtWidgets.QLineEdit("127.0.0.1")
        self.targets_edit.setPlaceholderText("IP, hostname, CIDR (comma-separated)")
        target_layout.addWidget(self.targets_edit)
        controls_layout.addLayout(target_layout)

        # Command input
        cmd_layout = QtWidgets.QHBoxLayout()
        cmd_layout.addWidget(QtWidgets.QLabel("Command:"))
        self.args_edit = QtWidgets.QLineEdit("-sV -T4 --open")
        self.args_edit.setPlaceholderText("Nmap arguments")
        cmd_layout.addWidget(self.args_edit)
        controls_layout.addLayout(cmd_layout)

        # Action buttons
        button_layout = QtWidgets.QHBoxLayout()
        self.start_btn = AnimatedButton("START SCAN")
        self.stop_btn = AnimatedButton("STOP")
        self.clear_btn = AnimatedButton("CLEAR")
        self.export_btn = AnimatedButton("EXPORT")

        self.stop_btn.setEnabled(False)

        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.clear_btn)
        button_layout.addWidget(self.export_btn)
        controls_layout.addLayout(button_layout)

        left_layout.addWidget(controls_group)

        # Nmap Presets Group
        presets_group = QtWidgets.QGroupBox("Nmap Command Presets")
        presets_layout = QtWidgets.QVBoxLayout(presets_group)
        self.preset_widget = NmapPresetWidget()
        presets_layout.addWidget(self.preset_widget)
        left_layout.addWidget(presets_group)

        # History Group
        history_group = QtWidgets.QGroupBox("Scan History")
        history_layout = QtWidgets.QVBoxLayout(history_group)
        self.history_list = QtWidgets.QListWidget()
        self.history_list.setMaximumHeight(150)
        self.clear_history_btn = QtWidgets.QPushButton("Clear History")
        history_layout.addWidget(self.history_list)
        history_layout.addWidget(self.clear_history_btn)
        left_layout.addWidget(history_group)

        main_splitter.addWidget(left_panel)

        # Right Panel: Results and Details
        right_panel = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_panel)

        # Results and details splitter
        results_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        # Results tree
        results_widget = QtWidgets.QWidget()
        results_layout = QtWidgets.QVBoxLayout(results_widget)

        # Filter options
        filter_layout = QtWidgets.QHBoxLayout()
        self.show_only_vuln = QtWidgets.QCheckBox("Vulnerabilities Only")
        self.show_only_open = QtWidgets.QCheckBox("Open Ports Only")
        filter_layout.addWidget(self.show_only_vuln)
        filter_layout.addWidget(self.show_only_open)
        filter_layout.addStretch()
        results_layout.addLayout(filter_layout)

        self.results_tree = QtWidgets.QTreeWidget()
        self.results_tree.setHeaderLabels(
            [
                "Host / Port / Vulnerability",
                "State / Severity",
                "Service",
            ]
        )
        self.results_tree.header().setSectionResizeMode(
            0, QtWidgets.QHeaderView.Stretch
        )
        results_layout.addWidget(self.results_tree)
        results_splitter.addWidget(results_widget)

        # Details and log tabs
        tab_widget = QtWidgets.QTabWidget()

        # Details tab
        self.details_text = QtWidgets.QTextEdit()
        self.details_text.setReadOnly(True)
        tab_widget.addTab(self.details_text, "‹ Details")

        # Log tab
        self.log_text = QtWidgets.QTextEdit()
        self.log_text.setReadOnly(True)
        tab_widget.addTab(self.log_text, "Live Log")

        results_splitter.addWidget(tab_widget)
        results_splitter.setSizes([600, 300])
        right_layout.addWidget(results_splitter)

        main_splitter.addWidget(right_panel)
        main_splitter.setSizes([500, 900])
        main_layout.addWidget(main_splitter)

        # Status bar
        self.status_bar = self.statusBar()
        self.status_label = QtWidgets.QLabel(
            "Ready - Logged in as " + self.current_user["username"]
        )
        self.status_bar.addWidget(self.status_label)

        # --- Connect Signals ---
        self.start_btn.clicked.connect(self._start_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        self.clear_btn.clicked.connect(self._clear)
        self.export_btn.clicked.connect(self._export)
        self.logout_btn.clicked.connect(self._logout)
        self.results_tree.itemClicked.connect(self._on_tree_click)
        self.preset_widget.preset_selected.connect(self._on_preset_selected)
        self.history_list.itemDoubleClicked.connect(self._on_history_selected)
        self.clear_history_btn.clicked.connect(self._clear_history)

    def _apply_theme(self):
        """Apply professional hacker-style theme with smooth animations"""
        style = """
            QMainWindow {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #0a0a0a, stop: 1 #1a1a1a);
                color: #cfe9d6;
            }
            QWidget {
                background-color: transparent;
                color: #cfe9d6;
                font-family: 'Courier New', 'Consolas', monospace; 
                font-size: 13px;
            }
            QGroupBox {
                border: 2px solid #7cffc5;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
                font-weight: bold;
                color: #7cffc5;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 8px;
                color: #7cffc5;
                font-size: 14px;
            }
            QLineEdit, QTextEdit, QTreeWidget, QListWidget {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #091015, stop: 1 #0f1419);
                color: #bfe6b3;
                border: 2px solid #2a2f33;
                border-radius: 6px;
                padding: 8px;
                selection-background-color: #7cffc5;
                selection-color: #0a0a0a;
            }
            QLineEdit:focus, QTextEdit:focus {
                border-color: #7cffc5;
                background: #0f1419;
            }
            QPushButton, AnimatedButton {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #1a3d2e, stop: 1 #0b2b1f);
                color: #cfe9d6;
                padding: 12px 20px;
                border: 2px solid #7cffc5;
                border-radius: 6px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover, AnimatedButton:hover {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #2d5a47, stop: 1 #164b34);
                border-color: #a8ffdb;
            }
            QPushButton:pressed, AnimatedButton:pressed {
                background: #0b2b1f;
            }
            QPushButton:disabled, AnimatedButton:disabled {
                background: #1a2025;
                color: #666;
                border: 2px solid #444;
            }
            QHeaderView::section {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #1a3d2e, stop: 1 #082018);
                color: #7cffc5;
                padding: 8px;
                border: 1px solid #7cffc5;
                font-weight: bold;
            }
            QComboBox, QCheckBox {
                color: #cfe9d6;
            }
            QCheckBox::indicator:checked {
                background: #7cffc5;
                border: 2px solid #7cffc5;
            }
            QSplitter::handle {
                background: #7cffc5;
                width: 3px;
                height: 3px;
            }
            QTabWidget::pane {
                border: 2px solid #2a2f33;
                border-radius: 6px;
            }
            QTabBar::tab {
                background: #1a2025;
                color: #bfe6b3;
                padding: 8px 15px;
                border: 1px solid #2a2f33;
                border-radius: 4px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #7cffc5;
                color: #0a0a0a;
                font-weight: bold;
            }
            QStatusBar {
                background: #0a0a0a;
                color: #7cffc5;
                border-top: 1px solid #7cffc5;
                font-weight: bold;
            }
            QListWidget::item:selected {
                background: #7cffc5;
                color: #0a0a0a;
            }
        """
        self.setStyleSheet(style)

    def _on_preset_selected(self, command: str, description: str):
        """Handle nmap preset selection"""
        self.args_edit.setText(command)
        self.log_text.append(f"[*] Selected preset: {description}")

    def _load_history(self):
        """Load scan history for current user"""
        history = self.history_manager.get_history(self.current_user["id"])
        self.history_list.clear()
        for item in history:
            list_item = QtWidgets.QListWidgetItem(
                f"{item['target']} | {item['args']} | {item['timestamp']}"
            )
            list_item.setData(QtCore.Qt.UserRole,item)
            self.history_list.addItem(list_item)

    def _on_history_selected(self, item):
        """Handle history item selection"""
        data = item.data(QtCore.Qt.UserRole)
        if data:
            self.targets_edit.setText(data["target"])
            self.args_edit.setText(data["args"])
            self.log_text.append(
                f"[*] Loaded from history: {data['target']} with args '{data['args']}'"
            )

    def _clear_history(self):
        """Clear scan history"""
        reply = QtWidgets.QMessageBox.question(
            self,
            "Clear History",
            "Are you sure you want to clear scan history?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        )
        if reply == QtWidgets.QMessageBox.Yes:
            try:
                with sqlite3.connect(self.history_manager.db_path) as conn:
                    conn.execute(
                        "DELETE FROM scan_history WHERE user_id = ?",
                        (self.current_user["id"],),
                    )
                self.history_list.clear()
                self.log_text.append("[*] Scan history cleared")
            except Exception as e:
                QtWidgets.QMessageBox.warning(
                    self, "Error", f"Failed to clear history: {e}"
                )

    def _start_scan(self):
        targets_str = self.targets_edit.text()
        if not targets_str:
            self.log_text.append("[!] Error: No targets specified.")
            return

        targets = [t.strip() for t in targets_str.split(",")]
        nmap_args = self.args_edit.text()

        # Add to history
        self.history_manager.add_scan(self.current_user["id"], targets_str, nmap_args)
        self._load_history()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("ðŸ”¥ Scanning in progress...")
        self.log_text.append(
            f"[*] Starting new scan on {targets} with args '{nmap_args}'"
        )

        worker = ScanWorker(
            targets=targets, nmap_args=nmap_args, enricher=self._enricher
        )
        self._workers.append(worker)

        worker.log.connect(self.log_text.append)
        worker.error.connect(self.log_text.append)
        worker.result.connect(self._add_result_to_tree)
        worker.finished_all.connect(self._on_scan_finished)

        worker.start()

    def _add_result_to_tree(self, host_entry: HostEntry):
        self._results.append(host_entry)
        host_item = QtWidgets.QTreeWidgetItem(
            self.results_tree,
            [f" {host_entry.ip}", host_entry.status, host_entry.os or "Unknown"],
        )

        for port in sorted(host_entry.ports, key=lambda p: p.port):
            port_text = f"   Port {port.port}/{port.protocol}"
            port_item = QtWidgets.QTreeWidgetItem(
                host_item, [port_text, port.state, port.service or ""]
               
            )
            port_item.setData(0, QtCore.Qt.UserRole, port)

            for vuln in port.vulns:
                severity = vuln.severity or "Info"
                vuln_icon = {
                    "Critical": "warning",
                    "High": "warning",
                    "Medium": "warning",
                    "Low": "warning",
                }.get(severity, "")
                vuln_text = f"    {vuln_icon} {vuln.id or vuln.title}"
                vuln_item = QtWidgets.QTreeWidgetItem(
                    port_item, [vuln_text, severity, ""]
                )
                vuln_item.setData(0, QtCore.Qt.UserRole, vuln)

        self.results_tree.expandAll()

    def _on_scan_finished(self):
        results_count = len(self._results)
        self.status_label.setText(f" Scan completed - {results_count} hosts found")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        # Update history with results count
        if self._results:
            try:
                with sqlite3.connect(self.history_manager.db_path) as conn:
                    conn.execute(
                        "UPDATE scan_history SET results_count = ? WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1",
                        (results_count, self.current_user["id"]),
                    )
                self._load_history()
            except Exception:
                pass

    def _stop_scan(self):
        self.log_text.append("[!] Sending stop signal to active scanners...")
        for worker in self._workers:
            if worker.isRunning():
                worker.stop()
        self.stop_btn.setEnabled(False)

    def _clear(self):
        self._results = []
        self.results_tree.clear()
        self.details_text.clear()
        self.log_text.clear()
        self.status_label.setText(
            "Ready - Logged in as " + self.current_user["username"]
        )

    def _export(self):
        # Enhanced export functionality
        if not self._results:
            QtWidgets.QMessageBox.information(self, "Export", "No results to export.")
            return

        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export Results",
            f"bladex_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;CSV Files (*.csv)",
        )

        if filename:
            try:
                if filename.endswith(".json"):
                    export_data = []
                    for host in self._results:
                        host_data = {
                            "ip": host.ip,
                            "hostname": host.hostname,
                            "status": host.status,
                            "os": host.os,
                            "ports": [],
                        }
                        for port in host.ports:
                            port_data = {
                                "port": port.port,
                                "protocol": port.protocol,
                                "state": port.state,
                                "service": port.service,
                                "vulnerabilities": [
                                    {
                                        "id": v.id,
                                        "title": v.title,
                                        "severity": v.severity,
                                    }
                                    for v in port.vulns
                                ],
                            }
                            host_data["ports"].append(port_data)
                        export_data.append(host_data)

                    with open(filename, "w") as f:
                        json.dump(export_data, f, indent=2)

                self.log_text.append(f"[*] Results exported to {filename}")
                QtWidgets.QMessageBox.information(
                    self, "Export", f"Results exported to {filename}"
                )

            except Exception as e:
                QtWidgets.QMessageBox.warning(
                    self, "Export Error", f"Failed to export: {e}"
                )

    def _on_tree_click(self, item, column):
        data = item.data(0, QtCore.Qt.UserRole)
        if isinstance(data, Vulnerability):
            details = f"Vulnerability: {data.id or data.title}\n\n"
            details += f"Severity: {data.severity} (Score: {data.score})\n\n"
            details += "Description:\n" + ("-" * 40) + f"\n{data.description}\n\n"
            if data.refs:
                details += (
                    "References:\n" + ("-" * 40) + "\n" + "\n".join(data.refs)
                )
            self.details_text.setText(details)
        elif isinstance(data, PortEntry):
            details = f"Port: {data.port}/{data.protocol}\n"
            details += f"State: {data.state}\n"
            details += f"Service: {data.service}\n"
            details += f"Product: {data.product}\n"
            details += f"Version: {data.version}\n"
            if data.vulns:
                details += f"\n Vulnerabilities: {len(data.vulns)} found"
            self.details_text.setText(details)

    def _logout(self):
        """Handle logout"""
        reply = QtWidgets.QMessageBox.question(
            self,
            "Logout",
            "Are you sure you want to logout?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        )
        if reply == QtWidgets.QMessageBox.Yes:
            self.close()
            self._show_login()

    def closeEvent(self, event):
        """Handle application close"""
        for worker in self._workers:
            if worker.isRunning():
                worker.stop()
                worker.wait()
        event.accept()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")  # Modern look
    window = CyberExpertBladexPro()
    sys.exit(app.exec_())
