#!/usr/bin/env python3
"""
Nostalgia Browser - Безопасный браузер в стиле Windows 98
Версия: 0.8.5 (Полностью рабочий, без CSP блокировок)
"""

import sys
import json
import os
import re
import hashlib
import secrets
import datetime
import shutil
import logging
import logging.handlers
import tempfile
import uuid
import base64
import time
import gc
import hmac
import ipaddress
from html import escape as html_escape
from urllib.parse import urlparse, quote_plus
from typing import Optional, Set, Dict, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from PyQt6.QtCore import (
    QUrl, Qt, QSize, QTimer, QPoint,
    pyqtSignal, QStandardPaths, QDateTime,
    QByteArray
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QToolBar,
    QLineEdit, QPushButton, QTabWidget,
    QVBoxLayout, QWidget, QProgressBar,
    QStatusBar, QFrame, QLabel,
    QMenu, QStyleFactory,
    QMessageBox, QDialog,
    QListWidget, QListWidgetItem, QHBoxLayout,
    QInputDialog, QTextEdit,
    QDialogButtonBox, QFormLayout,
    QCheckBox, QTableWidget,
    QTableWidgetItem, QHeaderView,
    QFileDialog, QScrollArea, QGroupBox,
    QRadioButton, QButtonGroup, QTabBar,
    QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile, QWebEnginePage,
    QWebEngineDownloadRequest,
    QWebEngineScript, QWebEngineSettings,
    QWebEngineCertificateError,
    QWebEngineUrlSchemeHandler,
    QWebEngineUrlRequestJob,
    QWebEngineUrlScheme
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QPixmap,
    QFontDatabase, QPainter, QPen, QBrush,
    QKeySequence, QMovie, QPolygon, QAction,
    QShortcut, QIcon
)
from PyQt6.QtNetwork import QHostInfo

# ──────────────────────────────────────────────
# КОНСТАНТЫ БЕЗОПАСНОСТИ
# ──────────────────────────────────────────────
ALLOWED_SCHEMES = frozenset({"http", "https", "about", "nostalgia"})
BLOCKED_SCHEMES = frozenset({
    "file", "javascript", "data", "vbscript", "ftp",
    "gopher", "chrome", "chrome-extension", "moz-extension",
    "ms-browser-extension", "edge", "view-source"
})
DANGEROUS_PROTOCOLS = frozenset({
    "tel", "mailto", "sms", "callto", "skype", "steam",
    "magnet", "bitcoin", "ethereum", "webcal", "facetime",
    "tg", "viber", "whatsapp", "zoommtg", "slack"
})

LOCAL_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

TRUSTED_LOCAL_DOMAINS = {
    "localhost",
    "local",
    "home",
    "lan",
    "localdomain",
}

MAX_URL_LENGTH = 2048
MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_DOWNLOADS_SIMULTANEOUS = 5
MAX_DOWNLOAD_SIZE = 1024 * 1024 * 1024
MAX_PAGE_SIZE = 50 * 1024 * 1024
PASSWORD_DISPLAY_TIMEOUT = 10000
NAVIGATION_RATE_LIMIT = 10
CLIPBOARD_CLEAR_TIMEOUT = 30000
MAX_HISTORY_ENTRIES = 200
MAX_BOOKMARK_URL_LENGTH = 2048
MAX_TITLE_LENGTH = 500
MAX_DISPLAY_LENGTH = 25
RECENT_HISTORY_CHECK = 10
DEDUP_TIME_MINUTES = 5
KEY_FILE_PERMISSIONS = 0o600
MAX_TABS = 50
MAX_REDIRECTS_PER_SECOND = 3
MIN_PASSWORD_LENGTH = 8
PBKDF2_ITERATIONS = 100000
MAX_MASTER_PASSWORD_ATTEMPTS = 5
MASTER_PASSWORD_LOCKOUT_SECONDS = 900
PASSWORD_MANAGER_UNLOCK_TIMEOUT = 300
MAX_RATE_LIMITER_OPERATIONS = 1000
MAX_REDIRECT_CHAIN_LENGTH = 10
MAX_HISTORY_WRITE_QUEUE = 50
MAX_BOOKMARK_IMPORT_COUNT = 1000
MAX_LOGIN_LENGTH = 256

_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

NOSTALGIA_PATH_RE = re.compile(r'^[a-zA-Z0-9_]+$')
CONTENT_DISPOSITION_RE = re.compile(r'filename[^;=\n]*=(([\'"]).*?\2|[^;\n]*)', re.IGNORECASE)

# ──────────────────────────────────────────────
# БЕЗОПАСНОЕ ЛОГИРОВАНИЕ
# ──────────────────────────────────────────────

class SafeLogger:
    @staticmethod
    def sanitize_log_data(data: str) -> str:
        if not data:
            return ""
        data = re.sub(r'[\x00-\x1f\x7f-\x9f]', '?', data)
        if len(data) > 500:
            data = data[:497] + "..."
        return data
    
    @classmethod
    def warning(cls, message: str, *args, **kwargs):
        safe_args = [cls.sanitize_log_data(str(arg)) for arg in args]
        logger.warning(message, *safe_args, **kwargs)
    
    @classmethod
    def info(cls, message: str, *args, **kwargs):
        safe_args = [cls.sanitize_log_data(str(arg)) for arg in args]
        logger.info(message, *safe_args, **kwargs)
    
    @classmethod
    def error(cls, message: str, *args, **kwargs):
        safe_args = [cls.sanitize_log_data(str(arg)) for arg in args]
        logger.error(message, *safe_args, **kwargs)


logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

handler = logging.handlers.RotatingFileHandler(
    'nostalgia.log',
    maxBytes=1024*1024,
    backupCount=3,
    encoding='utf-8'
)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

if os.environ.get('NOSTALGIA_DEBUG'):
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(console_handler)


# ──────────────────────────────────────────────
# УТИЛИТЫ БЕЗОПАСНОСТИ
# ──────────────────────────────────────────────

class MonotonicTime:
    _start_time = time.monotonic()
    
    @classmethod
    def now(cls) -> float:
        return time.monotonic() - cls._start_time
    
    @classmethod
    def datetime_now(cls) -> datetime.datetime:
        return datetime.datetime.now()


def secure_zero_memory(data: str):
    if not data:
        return
    try:
        import ctypes
        str_addr = id(data) + 32
        str_len = len(data)
        for i in range(str_len):
            ctypes.memset(str_addr + i, 0, 1)
        gc.collect()
    except Exception:
        garbage = 'x' * 1024 * 1024
        del garbage
        gc.collect()


def sanitize_display_text(text: str, max_len: int = MAX_DISPLAY_LENGTH) -> str:
    if not text:
        return ""
    escaped = html_escape(text)
    if max_len < 4:
        max_len = 4
    if len(escaped) > max_len:
        return escaped[:max_len - 3] + "..."
    return escaped


def safe_domain_match(domain: str, pattern: str) -> bool:
    if not domain or not pattern:
        return False
    domain = domain.lower().strip()
    pattern = pattern.lower().strip()
    if domain == pattern:
        return True
    if domain.endswith('.' + pattern):
        return domain.count('.') == pattern.count('.') + 1
    return False


def validate_nostalgia_path(path: str) -> bool:
    if not path:
        return False
    if path.startswith('/'):
        path = path[1:]
    return bool(NOSTALGIA_PATH_RE.match(path))


def is_local_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in LOCAL_IP_RANGES:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


def is_local_domain(domain: str) -> bool:
    domain_lower = domain.lower()
    for local_domain in TRUSTED_LOCAL_DOMAINS:
        if domain_lower == local_domain or domain_lower.endswith('.' + local_domain):
            return True
    return False


def is_local_url(url: QUrl) -> bool:
    host = url.host()
    if not host:
        return False
    
    if host in ('localhost', '::1', '127.0.0.1'):
        return True
    
    if is_local_domain(host):
        return True
    
    if is_local_ip(host):
        return True
    
    return False


def sanitize_search_query(query: str) -> str:
    query = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', query)
    query = query[:500]
    query = re.sub(r'\s+', ' ', query).strip()
    return query


def sanitize_content_disposition(header: str) -> str:
    if not header:
        return 'attachment'
    
    match = CONTENT_DISPOSITION_RE.search(header)
    if match:
        filename = match.group(1).strip('"\'')
        filename = os.path.basename(filename)
        filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250] + ext
        return f'attachment; filename="{filename}"'
    
    return 'attachment'


def is_safe_external_protocol(url: QUrl) -> bool:
    scheme = url.scheme().lower()
    if scheme in DANGEROUS_PROTOCOLS:
        return False
    if scheme in BLOCKED_SCHEMES:
        return False
    return True


def secure_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


class SecureClipboard:
    _timer: Optional[QTimer] = None
    _last_content: str = ""

    @classmethod
    def set_text(cls, text: str, timeout: int = CLIPBOARD_CLEAR_TIMEOUT):
        clipboard = QApplication.clipboard()
        if cls._timer and cls._timer.isActive():
            cls._timer.stop()
        cls._last_content = clipboard.text()
        clipboard.setText(text)
        cls._timer = QTimer()
        cls._timer.setSingleShot(True)
        cls._timer.timeout.connect(cls._clear_clipboard)
        cls._timer.start(timeout)

    @classmethod
    def _clear_clipboard(cls):
        clipboard = QApplication.clipboard()
        current = clipboard.text()
        if current == cls._last_content or not current:
            clipboard.clear()
            SafeLogger.info("Clipboard cleared for security")


class RateLimiter:
    def __init__(self, max_operations: int, per_seconds: float = 1.0):
        self.max_operations = max_operations
        self.per_seconds = per_seconds
        self._operations: list[float] = []

    def can_proceed(self) -> bool:
        now = MonotonicTime.now()
        cutoff = now - self.per_seconds
        self._operations = [t for t in self._operations if t > cutoff]
        if len(self._operations) < self.max_operations:
            self._operations.append(now)
            if len(self._operations) > MAX_RATE_LIMITER_OPERATIONS:
                self._operations = self._operations[-MAX_RATE_LIMITER_OPERATIONS:]
            return True
        return False

    def reset(self):
        self._operations.clear()


class SecureFileHandler:
    @staticmethod
    def safe_read_json(filepath: str, max_size: int = MAX_FILE_SIZE) -> dict:
        if not os.path.exists(filepath):
            return {}
        file_size = os.path.getsize(filepath)
        if file_size > max_size:
            SafeLogger.warning("File too large: %s (%d bytes)", filepath, file_size)
            return {}
        if os.path.islink(filepath):
            real_path = os.path.realpath(filepath)
            if not real_path.startswith(os.path.abspath(os.getcwd())):
                SafeLogger.warning("Symlink attack detected: %s -> %s", filepath, real_path)
                return {}
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            if '\0' in content:
                SafeLogger.warning("Binary data detected in JSON: %s", filepath)
                return {}
            data = json.loads(content)
            if not isinstance(data, dict):
                SafeLogger.warning("Invalid JSON structure in: %s", filepath)
                return {}
            if SecureFileHandler._get_depth(data) > 10:
                SafeLogger.warning("JSON too deeply nested: %s", filepath)
                return {}
            return data
        except json.JSONDecodeError as e:
            SafeLogger.warning("JSON decode error in %s: %s", filepath, e)
            backup_path = filepath + '.backup'
            try:
                shutil.copy2(filepath, backup_path)
                SafeLogger.info("Created backup of corrupted file: %s", backup_path)
            except Exception:
                pass
            return {}
        except Exception as e:
            SafeLogger.warning("Error reading file %s: %s", filepath, e)
            return {}

    @staticmethod
    def safe_write_json(filepath: str, data: dict, create_backup: bool = True):
        temp_path = SecureTempFile.create_temp_path()
        try:
            json_str = json.dumps(data, ensure_ascii=False, indent=2)
            if len(json_str) > MAX_FILE_SIZE:
                SafeLogger.warning("Data too large for writing to %s", filepath)
                return False
            if create_backup and os.path.exists(filepath):
                backup_path = filepath + '.backup'
                try:
                    shutil.copy2(filepath, backup_path)
                except Exception:
                    pass
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
                f.flush()
                os.fsync(f.fileno())
            if sys.platform == 'win32':
                if os.path.exists(filepath):
                    os.remove(filepath)
                os.rename(temp_path, filepath)
            else:
                os.replace(temp_path, filepath)
            os.chmod(filepath, 0o600)
            return True
        except Exception as e:
            SafeLogger.warning("Error writing file %s: %s", filepath, e)
            SecureTempFile.safe_temp_cleanup(temp_path)
            return False

    @staticmethod
    def _get_depth(obj, current_depth=0):
        if not isinstance(obj, (dict, list)):
            return current_depth
        if current_depth > 10:
            return current_depth
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(SecureFileHandler._get_depth(v, current_depth + 1) for v in obj.values())
        if isinstance(obj, list):
            if not obj:
                return current_depth
            return max(SecureFileHandler._get_depth(item, current_depth + 1) for item in obj)
        return current_depth


class SecureTempFile:
    @staticmethod
    def create_temp_path(prefix: str = 'nostalgia_', suffix: str = '.tmp') -> str:
        random_name = f"{prefix}{uuid.uuid4().hex}{suffix}"
        return os.path.join(tempfile.gettempdir(), random_name)

    @staticmethod
    def safe_temp_write(content: str) -> Optional[str]:
        try:
            temp_path = SecureTempFile.create_temp_path()
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(temp_path, 0o600)
            return temp_path
        except Exception as e:
            SafeLogger.warning("Error creating temp file: %s", e)
            return None

    @staticmethod
    def safe_temp_cleanup(temp_path: str):
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception as e:
            SafeLogger.warning("Error cleaning temp file: %s", e)


class SanitizedUrl:
    @staticmethod
    def sanitize(url_str: str) -> Optional[str]:
        if not url_str:
            return None
        if len(url_str) > MAX_URL_LENGTH:
            SafeLogger.warning("URL too long: %d characters", len(url_str))
            return None
        if '\0' in url_str:
            SafeLogger.warning("Null byte detected in URL")
            return None
        if any(ord(c) < 32 for c in url_str):
            SafeLogger.warning("Control characters detected in URL")
            return None
        url_str = url_str.strip()
        try:
            parsed = urlparse(url_str)
            if parsed.scheme.lower() in BLOCKED_SCHEMES:
                SafeLogger.warning("Blocked URL scheme: %s", parsed.scheme)
                return None
            if parsed.scheme in ('http', 'https') and not parsed.netloc:
                return None
            if parsed.fragment and any(
                dangerous in parsed.fragment.lower()
                for dangerous in ('javascript:', 'data:', 'vbscript:')
            ):
                url_str = url_str.split('#')[0]
            return url_str
        except Exception as e:
            SafeLogger.warning("URL parsing error: %s", e)
            return None


class DownloadSecurityManager:
    @staticmethod
    def is_safe_download(mime_type: str, file_extension: str, content_length: int = 0, origin: str = "") -> bool:
        if content_length > MAX_DOWNLOAD_SIZE:
            return False
        
        mime_type = sanitize_display_text(mime_type, 100)
        
        if origin:
            try:
                parsed_origin = urlparse(origin)
                if parsed_origin.scheme not in ('http', 'https'):
                    return False
            except Exception:
                pass
        
        mime_type = mime_type.lower().split(';')[0].strip()
        if mime_type in DANGEROUS_MIME_TYPES:
            return False
        dangerous_extensions = {'.exe', '.bat', '.cmd', '.msi', '.scr', '.ps1', '.vbs', '.sh', '.run', '.dll', '.sys'}
        if file_extension.lower() in dangerous_extensions:
            if mime_type == 'application/octet-stream':
                return False
        return True

    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        try:
            hash_func = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            SafeLogger.warning("Error calculating file hash: %s", e)
            return None

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        filename = os.path.basename(filename)
        filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250] + ext
        if not filename:
            filename = f"download_{uuid.uuid4().hex[:8]}"
        return filename


class SecurePasswordItem:
    def __init__(self):
        self._password: str = ""
        self._password_bytes: Optional[bytearray] = None
        self._visible: bool = False
        self._timer: Optional[QTimer] = None
        self._widget: Optional[QTableWidgetItem] = None
        self._is_deleted = False

    def show_password(self, widget: QTableWidgetItem, password: str):
        if self._is_deleted:
            return
        self._widget = widget
        self._password = password
        self._password_bytes = bytearray(password.encode('utf-8'))
        self._visible = True
        if widget:
            widget.setText(password)
        if self._timer:
            self._timer.stop()
        self._timer = QTimer()
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide_password)
        self._timer.start(PASSWORD_DISPLAY_TIMEOUT)

    def hide_password(self):
        if self._is_deleted:
            return
        if self._widget and self._visible:
            try:
                if self._widget and not self._widget.isSelected():
                    self._widget.setText("••••••••")
            except RuntimeError:
                pass
            self._visible = False
            if self._password_bytes:
                for i in range(len(self._password_bytes)):
                    self._password_bytes[i] = 0
                self._password_bytes = None
            self._password = ""
        if self._timer:
            self._timer.stop()
            self._timer = None

    def __del__(self):
        self._is_deleted = True
        self.hide_password()
        if hasattr(self, '_password'):
            secure_zero_memory(self._password)
        self._widget = None


class TabManager:
    def __init__(self, tab_widget: QTabWidget):
        self.tab_widget = tab_widget
        self._redirect_times: list[float] = []
        self._redirect_chains: dict[int, list[str]] = {}
        self._domain_ip_cache: dict[str, str] = {}

    def can_add_tab(self) -> bool:
        return self.tab_widget.count() < MAX_TABS

    def can_redirect(self, tab_index: int = -1) -> bool:
        now = MonotonicTime.now()
        cutoff = now - 1.0
        self._redirect_times = [t for t in self._redirect_times if t > cutoff]
        if len(self._redirect_times) < MAX_REDIRECTS_PER_SECOND:
            self._redirect_times.append(now)
            return True
        return False

    def track_redirect_chain(self, tab_index: int, url: str) -> bool:
        if tab_index not in self._redirect_chains:
            self._redirect_chains[tab_index] = []
        
        chain = self._redirect_chains[tab_index]
        chain.append(url)
        
        if len(chain) > MAX_REDIRECT_CHAIN_LENGTH:
            SafeLogger.warning("Redirect chain too long for tab %d: %d redirects", tab_index, len(chain))
            return False
        
        return True

    def clear_redirect_chain(self, tab_index: int):
        if tab_index in self._redirect_chains:
            del self._redirect_chains[tab_index]

    def check_dns_rebinding(self, domain: str, ip: str, is_local: bool = False) -> bool:
        if is_local:
            return True
        
        if domain in self._domain_ip_cache:
            cached_ip = self._domain_ip_cache[domain]
            if cached_ip != ip:
                old_is_local = is_local_ip(cached_ip)
                new_is_local = is_local_ip(ip)
                if not old_is_local and new_is_local:
                    SafeLogger.warning("DNS rebinding detected: %s changed from %s to %s (local)", domain, cached_ip, ip)
                    return False
        self._domain_ip_cache[domain] = ip
        return True
    
    def resolve_and_check_dns(self, domain: str) -> bool:
        try:
            host_info = QHostInfo.fromName(domain)
            is_local = is_local_domain(domain)
            if host_info.error() == QHostInfo.HostInfoError.NoError:
                for address in host_info.addresses():
                    ip = address.toString()
                    if not self.check_dns_rebinding(domain, ip, is_local):
                        return False
            return True
        except Exception as e:
            SafeLogger.warning("DNS resolution error for %s: %s", domain, e)
            return True


# ──────────────────────────────────────────────
# КЛАССЫ ДЛЯ ОБРАБОТКИ NOSTALGIA СХЕМЫ
# ──────────────────────────────────────────────

class NostalgiaPageHandler:
    def __init__(self):
        self._blocked_pages: Dict[str, str] = {}
        self._counter = 0
        self._allowed_ids: Set[str] = set()
    
    def register_page(self, html_content: str, allow_public: bool = True) -> str:
        self._counter += 1
        pid = f"blocked_{self._counter}"
        self._blocked_pages[pid] = html_content
        if allow_public:
            self._allowed_ids.add(pid)
        return f"nostalgia:{pid}"
    
    def get_page(self, pid: str) -> str:
        if not validate_nostalgia_path(pid):
            SafeLogger.warning("Invalid nostalgia page ID: %s", pid)
            return "<html><body><h1>Доступ запрещен</h1><p>Неверный ID.</p></body></html>"
        
        if pid not in self._allowed_ids:
            SafeLogger.warning("Attempt to access unauthorized nostalgia page: %s", pid)
            return "<html><body><h1>Доступ запрещен</h1><p>Нет доступа.</p></body></html>"
        
        return self._blocked_pages.get(pid, "<html><body><h1>Страница не найдена</h1></body></html>")


class NostalgiaSchemeHandler(QWebEngineUrlSchemeHandler):
    def __init__(self, page_handler=None):
        super().__init__()
        self._page_handler = page_handler or NostalgiaPageHandler()
    
    def requestStarted(self, job: QWebEngineUrlRequestJob):
        url = job.requestUrl()
        path = url.path()
        
        if not validate_nostalgia_path(path):
            SafeLogger.warning("Invalid nostalgia path: %s", path)
            self._send_error(job, "Invalid path")
            return
        
        page_id = path.lstrip('/')
        
        try:
            html_content = self._page_handler.get_page(page_id)
            buf = QByteArray(html_content.encode('utf-8'))
            job.reply(QByteArray(b"text/html"), buf)
        except Exception as e:
            SafeLogger.warning("Error serving nostalgia page %s: %s", page_id, e)
            self._send_error(job, "Page not found")
    
    def _send_error(self, job: QWebEngineUrlRequestJob, message: str):
        error_html = f"<html><body><h1>Error</h1><p>{html_escape(message)}</p></body></html>"
        buf = QByteArray(error_html.encode('utf-8'))
        job.reply(QByteArray(b"text/html"), buf)


def is_safe_url(url: QUrl) -> bool:
    if not url.isValid():
        return False
    url_str = url.toString()
    if len(url_str) > MAX_URL_LENGTH:
        return False
    scheme = url.scheme().lower()
    if scheme in BLOCKED_SCHEMES:
        return False
    if scheme not in ALLOWED_SCHEMES:
        return False
    if scheme in ('http', 'https'):
        if not url.host():
            return False
        if url.userName() or url.password():
            return False
    return True


def sanitize_url_for_history(url_str: str) -> str:
    if not url_str or url_str in ("about:blank", ""):
        return ""
    sanitized = SanitizedUrl.sanitize(url_str)
    if not sanitized:
        return ""
    q = QUrl(sanitized)
    if not is_safe_url(q):
        return ""
    return sanitized[:MAX_URL_LENGTH]


def validate_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    if domain.startswith("*."):
        domain = domain[2:]
    return bool(_DOMAIN_RE.match(domain))


# ──────────────────────────────────────────────
# ТЕМЫ
# ──────────────────────────────────────────────
THEMES = {
    "Классическая (Windows 98)": {
        "Window": "#D4D0C8", "WindowText": "#000000", "Base": "#FFFFFF",
        "AlternateBase": "#D4D0C8", "Button": "#D4D0C8", "ButtonText": "#000000",
        "Highlight": "#000080", "HighlightedText": "#FFFFFF", "Link": "#0000FF",
        "ToolTipBase": "#FFFFE1", "ToolTipText": "#000000", "Light": "#FFFFFF",
        "Midlight": "#E3DFDB", "Mid": "#808080", "Dark": "#808080", "Shadow": "#000000",
        "titlebar_active": "#000080", "titlebar_inactive": "#808080", "titlebar_text": "#FFFFFF",
    },
    "Морской (Teal)": {
        "Window": "#C8D4D0", "WindowText": "#000000", "Base": "#FFFFFF",
        "AlternateBase": "#C8D4D0", "Button": "#C8D4D0", "ButtonText": "#000000",
        "Highlight": "#008080", "HighlightedText": "#FFFFFF", "Link": "#006666",
        "ToolTipBase": "#FFFFE1", "ToolTipText": "#000000", "Light": "#E0FFFF",
        "Midlight": "#B0D0CC", "Mid": "#608080", "Dark": "#406060", "Shadow": "#000000",
        "titlebar_active": "#008080", "titlebar_inactive": "#607070", "titlebar_text": "#FFFFFF",
    },
    "Шоколадная": {
        "Window": "#D4C8B4", "WindowText": "#000000", "Base": "#FFF8F0",
        "AlternateBase": "#D4C8B4", "Button": "#D4C8B4", "ButtonText": "#000000",
        "Highlight": "#804000", "HighlightedText": "#FFFFFF", "Link": "#804000",
        "ToolTipBase": "#FFFFE1", "ToolTipText": "#000000", "Light": "#FFF0DC",
        "Midlight": "#C8B898", "Mid": "#907060", "Dark": "#604030", "Shadow": "#000000",
        "titlebar_active": "#804000", "titlebar_inactive": "#907060", "titlebar_text": "#FFFFFF",
    },
    "Лиловая": {
        "Window": "#D0C8D4", "WindowText": "#000000", "Base": "#FAF8FF",
        "AlternateBase": "#D0C8D4", "Button": "#D0C8D4", "ButtonText": "#000000",
        "Highlight": "#400080", "HighlightedText": "#FFFFFF", "Link": "#6000AA",
        "ToolTipBase": "#FFFFE1", "ToolTipText": "#000000", "Light": "#F0E8FF",
        "Midlight": "#C0B8CC", "Mid": "#806090", "Dark": "#503060", "Shadow": "#000000",
        "titlebar_active": "#400080", "titlebar_inactive": "#705080", "titlebar_text": "#FFFFFF",
    },
    "Тёмная (Ночная)": {
        "Window": "#2B2B2B", "WindowText": "#E0E0E0", "Base": "#1E1E1E",
        "AlternateBase": "#2B2B2B", "Button": "#3C3C3C", "ButtonText": "#E0E0E0",
        "Highlight": "#264F78", "HighlightedText": "#FFFFFF", "Link": "#4EC9B0",
        "ToolTipBase": "#3C3C3C", "ToolTipText": "#E0E0E0", "Light": "#505050",
        "Midlight": "#3C3C3C", "Mid": "#252525", "Dark": "#1A1A1A", "Shadow": "#000000",
        "titlebar_active": "#264F78", "titlebar_inactive": "#3C3C3C", "titlebar_text": "#FFFFFF",
    },
}


def apply_theme(app: QApplication, theme_name: str):
    theme = THEMES.get(theme_name, THEMES["Классическая (Windows 98)"])
    app.setStyle(QStyleFactory.create('Windows'))
    palette = QPalette()
    role_map = {
        "Window": QPalette.ColorRole.Window, "WindowText": QPalette.ColorRole.WindowText,
        "Base": QPalette.ColorRole.Base, "AlternateBase": QPalette.ColorRole.AlternateBase,
        "Button": QPalette.ColorRole.Button, "ButtonText": QPalette.ColorRole.ButtonText,
        "Highlight": QPalette.ColorRole.Highlight, "HighlightedText": QPalette.ColorRole.HighlightedText,
        "Link": QPalette.ColorRole.Link, "ToolTipBase": QPalette.ColorRole.ToolTipBase,
        "ToolTipText": QPalette.ColorRole.ToolTipText, "Light": QPalette.ColorRole.Light,
        "Midlight": QPalette.ColorRole.Midlight, "Mid": QPalette.ColorRole.Mid,
        "Dark": QPalette.ColorRole.Dark, "Shadow": QPalette.ColorRole.Shadow,
    }
    for key, role in role_map.items():
        color_hex = theme.get(key)
        if color_hex:
            palette.setColor(role, QColor(color_hex))
    palette.setColor(QPalette.ColorRole.Text, QColor(theme.get("WindowText", "#000000")))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(Qt.GlobalColor.red))
    app.setPalette(palette)
    app._current_theme = theme_name
    app._current_theme_data = theme
    app.setStyleSheet("""
        QWebEngineView { background: white; }
        QToolTip { background-color: #FFFFE1; color: #000000; border: 1px solid black; font-size: 8pt; }
        QTabBar::tab:hover { background-color: #E3DFDB; }
    """)


# ──────────────────────────────────────────────
# ДИАЛОГИ И ВИДЖЕТЫ
# ──────────────────────────────────────────────

class ThemeDialog(QDialog):
    def __init__(self, current_theme: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Темы оформления - Nostalgia")
        self.setFixedSize(400, 360)
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x() - 200, geo.center().y() - 180)
        self.selected_theme = current_theme
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 10)
        lbl = QLabel("Выберите тему оформления:")
        lbl.setFont(QFont("Tahoma", 8, QFont.Weight.Bold))
        layout.addWidget(lbl)
        self.btn_group = QButtonGroup(self)
        themes_box = QGroupBox()
        themes_layout = QVBoxLayout(themes_box)
        for i, name in enumerate(THEMES.keys()):
            rb = QRadioButton(name)
            rb.setChecked(name == current_theme)
            self.btn_group.addButton(rb, i)
            themes_layout.addWidget(rb)
        layout.addWidget(themes_box)
        self.preview_frame = QFrame()
        self.preview_frame.setFixedHeight(40)
        self.preview_frame.setFrameShape(QFrame.Shape.Box)
        layout.addWidget(self.preview_frame)
        self._preview_label = QLabel(self.preview_frame)
        self._preview_label.setGeometry(0, 0, 372, 40)
        self._preview_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.btn_group.buttonClicked.connect(self._on_select)
        self._update_preview(current_theme)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._on_ok)
        bb.rejected.connect(self.reject)
        layout.addWidget(bb)

    def _on_select(self, btn: QRadioButton):
        self.selected_theme = btn.text()
        self._update_preview(self.selected_theme)

    def _update_preview(self, theme_name: str):
        theme = THEMES.get(theme_name, {})
        win_c = theme.get("Window", "#D4D0C8")
        hi_c = theme.get("Highlight", "#000080")
        txt_c = theme.get("WindowText", "#000000")
        title_c = theme.get("titlebar_active", "#000080")
        self._preview_label.setText(
            f'<span style="color:{title_c};">▐ </span>'
            f'<span style="background:{win_c};color:{txt_c};">  Окно  </span>  '
            f'<span style="background:{hi_c};color:white;"> Выделение </span>'
        )

    def _on_ok(self):
        checked = self.btn_group.checkedButton()
        if checked:
            self.selected_theme = checked.text()
        self.accept()


class EnhancedGifLoadingWidget(QWidget):
    SIZE = QSize(26, 26)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(self.SIZE)
        self.label = QLabel(self)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setFixedSize(self.SIZE)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.label)
        self.movie = None
        self._static_frame = None
        self._frames = []
        self._current_frame = 0
        self._animation_timer = None
        self._load_gif_or_fallback()
        self.show()

    def _load_gif_or_fallback(self):
        gif_paths = ['planet.gif', 'loading.gif', 'ie_spinner.gif']
        for path in gif_paths:
            if os.path.exists(path):
                self._init_movie(path)
                return
        self._create_animated_fallback()

    def _init_movie(self, gif_path):
        self.movie = QMovie(gif_path)
        if not self.movie.isValid():
            self._create_animated_fallback()
            return
        self.movie.setScaledSize(self.SIZE)
        self.movie.jumpToFrame(0)
        first = self.movie.currentImage()
        if not first.isNull():
            self._static_frame = QPixmap.fromImage(
                first.scaled(self.SIZE, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
            )
        self._show_static()
        self.movie.frameChanged.connect(self._on_frame)

    def _create_animated_fallback(self):
        self._frames.clear()
        self._current_frame = 0
        for i in range(12):
            px = QPixmap(self.SIZE)
            px.fill(Qt.GlobalColor.transparent)
            p = QPainter(px)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.setBrush(QBrush(QColor(0, 80, 180)))
            p.setPen(QPen(QColor(0, 0, 120), 1))
            p.drawRoundedRect(2, 2, self.SIZE.width()-4, self.SIZE.height()-4, 4, 4)
            p.save()
            p.translate(13, 13)
            p.rotate(i * 30)
            p.setBrush(QBrush(QColor(0, 200, 0)))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRect(8, -2, 4, 4)
            p.restore()
            p.setPen(QColor(Qt.GlobalColor.white))
            p.setFont(QFont("Tahoma", 8, QFont.Weight.Bold))
            p.drawText(px.rect(), Qt.AlignmentFlag.AlignCenter, "N")
            p.end()
            self._frames.append(px)
        self._static_frame = self._frames[0] if self._frames else None
        self._show_static()
        if self._animation_timer is None:
            self._animation_timer = QTimer(self)
            self._animation_timer.timeout.connect(self._animate_frame)
            self._animation_timer.setInterval(100)

    def _animate_frame(self):
        if self._frames:
            self._current_frame = (self._current_frame + 1) % len(self._frames)
            self.label.setPixmap(self._frames[self._current_frame])

    def _show_static(self):
        if self._static_frame:
            self.label.setPixmap(self._static_frame)

    def _on_frame(self, _):
        if self.movie:
            img = self.movie.currentImage()
            if not img.isNull():
                self.label.setPixmap(QPixmap.fromImage(
                    img.scaled(self.SIZE, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
                ))

    def start(self):
        if self.movie:
            self.movie.start()
        elif self._animation_timer:
            self._animation_timer.start()

    def stop(self):
        if self.movie:
            self.movie.stop()
            self.movie.jumpToFrame(0)
        elif self._animation_timer:
            self._animation_timer.stop()
        self._show_static()
        self._frames.clear()

    def __del__(self):
        self.stop()
        if self._animation_timer:
            self._animation_timer.stop()
            self._animation_timer.deleteLater()
            self._animation_timer = None


class SiteFilter:
    def __init__(self):
        self.blacklist = []
        self.whitelist = []
        self.use_whitelist = False
        self.use_blacklist = True
        self.filter_enabled = True
        self.block_message = True
        self._filter_hash = None
        self._filter_file = 'nostalgia_filter.json'
        self.load_lists()

    def _calculate_file_hash(self) -> Optional[str]:
        try:
            if os.path.exists(self._filter_file):
                with open(self._filter_file, 'rb') as f:
                    return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            pass
        return None

    def load_lists(self):
        try:
            if os.path.exists(self._filter_file):
                current_hash = self._calculate_file_hash()
                if self._filter_hash and current_hash != self._filter_hash:
                    SafeLogger.warning("Filter file hash mismatch - possible tampering")
                
                data = SecureFileHandler.safe_read_json(self._filter_file)
                if data:
                    self.blacklist = [d for d in data.get('blacklist', []) if isinstance(d, str) and validate_domain(d)]
                    self.whitelist = [d for d in data.get('whitelist', []) if isinstance(d, str) and validate_domain(d)]
                    self.use_whitelist = bool(data.get('use_whitelist', False))
                    self.use_blacklist = bool(data.get('use_blacklist', True))
                    self.filter_enabled = bool(data.get('filter_enabled', True))
                    self.block_message = bool(data.get('block_message', True))
                
                self._filter_hash = self._calculate_file_hash()
        except Exception as e:
            SafeLogger.warning("Ошибка загрузки фильтра: %s", e)

    def save_lists(self):
        try:
            SecureFileHandler.safe_write_json(self._filter_file, {
                'blacklist': self.blacklist, 'whitelist': self.whitelist,
                'use_whitelist': self.use_whitelist, 'use_blacklist': self.use_blacklist,
                'filter_enabled': self.filter_enabled, 'block_message': self.block_message,
            })
            self._filter_hash = self._calculate_file_hash()
        except Exception as e:
            SafeLogger.warning("Ошибка сохранения фильтра: %s", e)

    def extract_domain(self, url):
        try:
            if isinstance(url, QUrl):
                url = url.toString()
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            if ':' in domain:
                domain = domain.split(':')[0]
            return domain
        except Exception:
            return ""

    def is_blocked(self, url) -> bool:
        if not self.filter_enabled:
            return False
        domain = self.extract_domain(url)
        if not domain:
            return False
        if self.use_whitelist:
            for wd in self.whitelist:
                if safe_domain_match(domain, wd):
                    return False
            return True
        if self.use_blacklist:
            for bd in self.blacklist:
                if safe_domain_match(domain, bd):
                    return True
        return False


class FilterDialog(QDialog):
    def __init__(self, site_filter, parent=None):
        super().__init__(parent)
        self.site_filter = site_filter
        self.setWindowTitle("Настройка фильтрации сайтов - Nostalgia")
        self.resize(650, 550)
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-325, geo.center().y()-275)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        sg = QWidget()
        sl = QVBoxLayout(sg)
        self.enable_filter = QCheckBox("Включить фильтрацию сайтов")
        self.enable_filter.setChecked(self.site_filter.filter_enabled)
        sl.addWidget(self.enable_filter)
        self.use_blacklist = QCheckBox("Использовать черный список")
        self.use_blacklist.setChecked(self.site_filter.use_blacklist)
        sl.addWidget(self.use_blacklist)
        self.use_whitelist = QCheckBox("Использовать белый список")
        self.use_whitelist.setChecked(self.site_filter.use_whitelist)
        sl.addWidget(self.use_whitelist)
        self.show_message = QCheckBox("Показывать сообщение о блокировке")
        self.show_message.setChecked(self.site_filter.block_message)
        sl.addWidget(self.show_message)
        layout.addWidget(sg)
        self.tab_widget = QTabWidget()
        for title, attr, lbl in [
            ("Черный список", 'blacklist_table', "Запрещенные сайты"),
            ("Белый список", 'whitelist_table', "Разрешенные сайты"),
        ]:
            tab = QWidget()
            tl = QVBoxLayout(tab)
            tbl = QTableWidget()
            tbl.setColumnCount(1)
            tbl.setHorizontalHeaderLabels([lbl])
            tbl.horizontalHeader().setStretchLastSection(True)
            tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            setattr(self, attr, tbl)
            tl.addWidget(tbl)
            bw = QWidget()
            bl = QHBoxLayout(bw)
            list_type = 'black' if 'black' in attr else 'white'
            add_btn = QPushButton("Добавить")
            add_btn.clicked.connect((lambda lt: lambda: self._add(lt))(list_type))
            bl.addWidget(add_btn)
            rem_btn = QPushButton("Удалить")
            rem_btn.clicked.connect((lambda t, lt: lambda: self._remove(t, lt))(tbl, list_type))
            bl.addWidget(rem_btn)
            bl.addStretch()
            tl.addWidget(bw)
            self.tab_widget.addTab(tab, title)
        layout.addWidget(self.tab_widget)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        layout.addWidget(bb)
        self._refresh_tables()

    def _refresh_tables(self):
        for tbl, lst in [(self.blacklist_table, self.site_filter.blacklist),
                         (self.whitelist_table, self.site_filter.whitelist)]:
            tbl.setRowCount(len(lst))
            for i, d in enumerate(lst):
                tbl.setItem(i, 0, QTableWidgetItem(d))

    def _add(self, list_type: str):
        label = "черный" if list_type == 'black' else "белый"
        domain, ok = QInputDialog.getText(self, f"Добавить в {label} список", "Введите домен:")
        if ok and domain:
            domain = domain.strip().lower()
            if not validate_domain(domain):
                QMessageBox.warning(self, "Ошибка", f"«{sanitize_display_text(domain, 50)}» не является допустимым доменным именем.")
                return
            lst = self.site_filter.blacklist if list_type == 'black' else self.site_filter.whitelist
            if domain not in lst:
                lst.append(domain)
                self._refresh_tables()

    def _remove(self, table: QTableWidget, list_type: str):
        row = table.currentRow()
        if row >= 0:
            item = table.item(row, 0)
            if item:
                lst = self.site_filter.blacklist if list_type == 'black' else self.site_filter.whitelist
                domain = item.text()
                if domain in lst:
                    lst.remove(domain)
                self._refresh_tables()

    def accept(self):
        self.site_filter.filter_enabled = self.enable_filter.isChecked()
        self.site_filter.use_blacklist = self.use_blacklist.isChecked()
        self.site_filter.use_whitelist = self.use_whitelist.isChecked()
        self.site_filter.block_message = self.show_message.isChecked()
        self.site_filter.save_lists()
        super().accept()


class IncognitoProfile:
    _instance: QWebEngineProfile | None = None

    @classmethod
    def get(cls) -> QWebEngineProfile:
        if cls._instance is None:
            cls._instance = QWebEngineProfile("IncognitoProfile")
            cls._instance.setHttpUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            cls._instance.setHttpAcceptLanguage("ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
            cls._instance.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)
            cls._instance.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
        return cls._instance


class DownloadItem(QWidget):
    def __init__(self, download: QWebEngineDownloadRequest, parent=None):
        super().__init__(parent)
        self.download = download
        self._finished = False
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)
        self.name_label = QLabel()
        self.name_label.setMinimumWidth(180)
        self.name_label.setMaximumWidth(180)
        fname = download.downloadFileName()
        safe_fname = sanitize_display_text(fname, 30)
        self.name_label.setText(safe_fname)
        self.name_label.setToolTip(sanitize_display_text(fname, 100))
        layout.addWidget(self.name_label)
        self.pbar = QProgressBar()
        self.pbar.setRange(0, 100)
        self.pbar.setValue(0)
        self.pbar.setMaximumHeight(14)
        self.pbar.setMinimumWidth(140)
        layout.addWidget(self.pbar)
        self.info_label = QLabel("Ожидание…")
        self.info_label.setMinimumWidth(110)
        layout.addWidget(self.info_label)
        self.action_btn = QPushButton("Отмена")
        self.action_btn.setFixedWidth(90)
        self.action_btn.clicked.connect(self._on_action)
        layout.addWidget(self.action_btn)
        download.receivedBytesChanged.connect(self._on_progress_changed)
        download.isFinishedChanged.connect(self._on_finished_changed)

    @staticmethod
    def _fmt(b: int) -> str:
        if b < 1024:
            return f"{b} Б"
        elif b < 1024**2:
            return f"{b/1024:.1f} КБ"
        elif b < 1024**3:
            return f"{b/1024**2:.1f} МБ"
        return f"{b/1024**3:.2f} ГБ"

    def _on_progress_changed(self):
        received = self.download.receivedBytes()
        total = self.download.totalBytes()
        if total > 0:
            self.pbar.setRange(0, 100)
            self.pbar.setValue(int(received * 100 / total))
            self.info_label.setText(f"{self._fmt(received)} / {self._fmt(total)}")
        else:
            self.pbar.setRange(0, 0)
            self.info_label.setText(self._fmt(received))

    def _on_finished_changed(self):
        if not self.download.isFinished():
            return
        self._finished = True
        self.pbar.setRange(0, 100)
        self.pbar.setValue(100)
        st = self.download.state()
        DS = QWebEngineDownloadRequest.DownloadState
        if st == DS.DownloadCompleted:
            self.info_label.setText("Готово")
            self.action_btn.setText("Открыть папку")
        elif st == DS.DownloadCancelled:
            self.info_label.setText("Отменено")
            self.action_btn.setText("Удалить")
        else:
            self.info_label.setText("Ошибка")
            self.action_btn.setText("Удалить")

    def _on_action(self):
        if not self._finished:
            self.download.cancel()
        else:
            st = self.download.state()
            DS = QWebEngineDownloadRequest.DownloadState
            if st == DS.DownloadCompleted:
                folder = self.download.downloadDirectory()
                QApplication.instance().open_folder(folder)
            else:
                p = self.parent()
                while p and not isinstance(p, DownloadManagerDialog):
                    p = p.parent()
                if p:
                    p.remove_item(self)


class DownloadManagerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Менеджер загрузок - Nostalgia")
        self.resize(620, 380)
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-310, geo.center().y()-190)
        ml = QVBoxLayout(self)
        ml.setContentsMargins(8, 8, 8, 8)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.container = QWidget()
        self.items_layout = QVBoxLayout(self.container)
        self.items_layout.setContentsMargins(2, 2, 2, 2)
        self.items_layout.addStretch()
        self.scroll.setWidget(self.container)
        ml.addWidget(self.scroll)
        bottom = QHBoxLayout()
        self.total_label = QLabel("Загрузок: 0")
        bottom.addWidget(self.total_label)
        bottom.addStretch()
        clear_btn = QPushButton("Очистить завершённые")
        clear_btn.clicked.connect(self.clear_finished)
        bottom.addWidget(clear_btn)
        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(self.hide)
        bottom.addWidget(close_btn)
        ml.addLayout(bottom)
        self._items: list[DownloadItem] = []

    def add_download(self, download: QWebEngineDownloadRequest):
        w = DownloadItem(download, self.container)
        self.items_layout.insertWidget(self.items_layout.count() - 1, w)
        self._items.append(w)
        self._update_count()
        self.show()
        self.raise_()

    def remove_item(self, w: DownloadItem):
        if w in self._items:
            self._items.remove(w)
            self.items_layout.removeWidget(w)
            w.deleteLater()
            self._update_count()

    def clear_finished(self):
        for w in list(self._items):
            if w._finished:
                self.remove_item(w)

    def _update_count(self):
        self.total_label.setText(f"Загрузок: {len(self._items)}")


class FindBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(28)
        self.setVisible(False)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(4)
        layout.addWidget(QLabel("Найти:"))
        self.search_edit = QLineEdit()
        self.search_edit.setFixedWidth(200)
        self.search_edit.setPlaceholderText("Поиск на странице...")
        self.search_edit.textChanged.connect(self._on_text_changed)
        self.search_edit.returnPressed.connect(self.find_next)
        layout.addWidget(self.search_edit)
        prev_btn = QPushButton("◄ Назад")
        prev_btn.setFixedWidth(70)
        prev_btn.clicked.connect(self.find_prev)
        layout.addWidget(prev_btn)
        next_btn = QPushButton("Вперёд ►")
        next_btn.setFixedWidth(70)
        next_btn.clicked.connect(self.find_next)
        layout.addWidget(next_btn)
        self.case_check = QCheckBox("С учётом регистра")
        layout.addWidget(self.case_check)
        self.result_label = QLabel("")
        self.result_label.setMinimumWidth(120)
        layout.addWidget(self.result_label)
        layout.addStretch()
        close_btn = QPushButton("✕")
        close_btn.setFixedSize(20, 20)
        close_btn.clicked.connect(self.close_bar)
        layout.addWidget(close_btn)
        self._webview: QWebEngineView | None = None

    def set_webview(self, wv):
        self._webview = wv

    def open_bar(self):
        self.setVisible(True)
        self.search_edit.setFocus()
        self.search_edit.selectAll()

    def close_bar(self):
        self.setVisible(False)
        if self._webview:
            self._webview.findText("")
            self._webview.setFocus()

    def _flags(self):
        f = QWebEnginePage.FindFlag(0)
        if self.case_check.isChecked():
            f |= QWebEnginePage.FindFlag.FindCaseSensitively
        return f

    def find_next(self):
        t = self.search_edit.text()
        if self._webview and t:
            self._webview.findText(t, self._flags(), self._on_result)

    def find_prev(self):
        t = self.search_edit.text()
        if self._webview and t:
            self._webview.findText(t, self._flags() | QWebEnginePage.FindFlag.FindBackward, self._on_result)

    def _on_text_changed(self, t: str):
        self.result_label.setText("")
        if self._webview:
            if t:
                self._webview.findText(t, self._flags(), self._on_result)
            else:
                self._webview.findText("")

    def _on_result(self, result):
        t = self.search_edit.text()
        if not t:
            self.result_label.setText("")
            return
        found = False
        try:
            found = result.numberOfMatches() > 0
        except Exception:
            found = bool(result)
        if found:
            self.result_label.setText("✓ Найдено")
            self.result_label.setStyleSheet("color: green;")
        else:
            self.result_label.setText("✗ Не найдено")
            self.result_label.setStyleSheet("color: red;")


SEARCH_ENGINES = {
    "Google": "https://www.google.com/search?q={query}",
    "Yandex": "https://yandex.ru/search/?text={query}",
    "Bing": "https://www.bing.com/search?q={query}",
    "DuckDuckGo": "https://duckduckgo.com/?q={query}",
    "Mail.ru": "https://go.mail.ru/search?q={query}",
    "Rambler": "https://nova.rambler.ru/search?query={query}",
}


class SearchEngineDialog(QDialog):
    def __init__(self, current_engine: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Поисковые системы - Nostalgia")
        self.setFixedSize(420, 320)
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-210, geo.center().y()-160)
        self.selected = current_engine
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 10)
        lbl = QLabel("Выберите поисковую систему по умолчанию:")
        lbl.setFont(QFont("Tahoma", 8, QFont.Weight.Bold))
        layout.addWidget(lbl)
        self.btn_group = QButtonGroup(self)
        box = QGroupBox()
        bl = QVBoxLayout(box)
        for i, name in enumerate(SEARCH_ENGINES.keys()):
            rb = QRadioButton(name)
            rb.setChecked(name == current_engine)
            self.btn_group.addButton(rb, i)
            bl.addWidget(rb)
        layout.addWidget(box)
        self.preview = QLabel()
        self.preview.setWordWrap(True)
        self.preview.setStyleSheet("color: gray; font-size: 8pt;")
        layout.addWidget(self.preview)
        self._update_preview(current_engine)
        self.btn_group.buttonClicked.connect(lambda btn: self._update_preview(btn.text()))
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._on_ok)
        bb.rejected.connect(self.reject)
        layout.addWidget(bb)

    def _update_preview(self, name: str):
        url = SEARCH_ENGINES.get(name, "")
        self.preview.setText(f"URL: {sanitize_display_text(url.replace('{query}', 'пример'), 100)}")

    def _on_ok(self):
        checked = self.btn_group.checkedButton()
        if checked:
            self.selected = checked.text()
        self.accept()


class SecurePasswordManager:
    def __init__(self, parent_widget=None):
        self._entries: list[dict] = []
        self._cipher: Optional[Fernet] = None
        self._access_times: dict[int, float] = {}
        self._failed_attempts: dict[str, int] = {}
        self._lockout_until: dict[str, float] = {}
        self._secure_items: dict[int, SecurePasswordItem] = {}
        self._master_password_hash: Optional[str] = None
        self._salt: Optional[bytes] = None
        self._failed_master_attempts = 0
        self._master_lockout_until: Optional[float] = None
        self._is_unlocked = False
        self._last_unlock_time: float = 0
        self._parent_widget = parent_widget
        self._key_dir = self._get_secure_key_dir()
        self._key_file = os.path.join(self._key_dir, "nostalgia_key.key")
        self._passwords_file = os.path.join(self._key_dir, "nostalgia_passwords.dat")
        self._load()

    def _get_secure_key_dir(self) -> str:
        if sys.platform == 'win32':
            base_dir = os.environ.get('APPDATA', '')
        elif sys.platform == 'darwin':
            base_dir = os.path.expanduser('~/Library/Application Support')
        else:
            base_dir = os.path.expanduser('~/.config')
        key_dir = os.path.join(base_dir, 'NostalgiaBrowser', 'secure')
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        return key_dir

    def _get_cipher(self) -> Optional[Fernet]:
        if self._cipher is None and os.path.exists(self._key_file):
            try:
                with open(self._key_file, 'rb') as f:
                    key = f.read()
                self._cipher = Fernet(key)
            except Exception:
                pass
        return self._cipher

    def _encrypt(self, data: str) -> str:
        cipher = self._get_cipher()
        return cipher.encrypt(data.encode()).decode() if cipher else ""

    def _decrypt(self, encrypted: str) -> str:
        cipher = self._get_cipher()
        try:
            return cipher.decrypt(encrypted.encode()).decode() if cipher else ""
        except Exception:
            return ""

    def _load(self):
        try:
            if os.path.exists(self._passwords_file):
                with open(self._passwords_file, 'rb') as f:
                    data = f.read()
                if data and self._get_cipher():
                    decrypted = self._cipher.decrypt(data).decode()
                    self._entries = json.loads(decrypted)
        except Exception as e:
            SafeLogger.warning("Ошибка загрузки паролей: %s", e)

    def _save(self):
        cipher = self._get_cipher()
        if not cipher:
            return
        try:
            data = json.dumps(self._entries, ensure_ascii=False, indent=2)
            encrypted = cipher.encrypt(data.encode())
            with open(self._passwords_file, 'wb') as f:
                f.write(encrypted)
            os.chmod(self._passwords_file, KEY_FILE_PERMISSIONS)
        except Exception as e:
            SafeLogger.warning("Ошибка сохранения паролей: %s", e)

    def entries(self) -> list[dict]:
        return list(self._entries)

    def add(self, url: str, login: str, password: str):
        for e in self._entries:
            if e['url'] == url and e['login'] == login:
                e['password'] = self._encrypt(password)
                self._save()
                return
        self._entries.append({'url': url, 'login': login, 'password': self._encrypt(password)})
        self._save()

    def remove(self, index: int):
        if 0 <= index < len(self._entries):
            del self._entries[index]
            self._save()

    def show_password_secure(self, index: int, widget: QTableWidgetItem) -> bool:
        if 0 <= index < len(self._entries):
            password = self._decrypt(self._entries[index]['password'])
            if password:
                item = self._secure_items.get(index)
                if not item:
                    item = SecurePasswordItem()
                    self._secure_items[index] = item
                item.show_password(widget, password)
                return True
        return False

    def clear_secure_items(self):
        for item in self._secure_items.values():
            item.hide_password()
        self._secure_items.clear()

    def clear_all(self):
        self.clear_secure_items()
        self._entries = []
        self._save()


class PasswordManagerDialog(QDialog):
    def __init__(self, password_manager: SecurePasswordManager, parent=None):
        super().__init__(parent)
        self.pm = password_manager
        self.setWindowTitle("Управление паролями - Nostalgia")
        self.resize(680, 440)
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-340, geo.center().y()-220)
        self._build_ui()
        self._refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        warn = QLabel("🔒 Пароли хранятся в зашифрованном виде.")
        warn.setStyleSheet("color: #008000; font-size: 8pt;")
        layout.addWidget(warn)
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Сайт", "Логин", "Пароль", ""])
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(3, 30)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)
        bottom = QHBoxLayout()
        self.count_lbl = QLabel("Записей: 0")
        bottom.addWidget(self.count_lbl)
        bottom.addStretch()
        add_btn = QPushButton("Добавить")
        add_btn.clicked.connect(self._add_entry)
        bottom.addWidget(add_btn)
        del_btn = QPushButton("Удалить")
        del_btn.clicked.connect(self._delete_selected)
        bottom.addWidget(del_btn)
        del_all_btn = QPushButton("Удалить все")
        del_all_btn.clicked.connect(self._delete_all)
        bottom.addWidget(del_all_btn)
        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(self.close)
        bottom.addWidget(close_btn)
        layout.addLayout(bottom)

    def _refresh(self):
        self.table.setRowCount(0)
        for i, e in enumerate(self.pm.entries()):
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(sanitize_display_text(e['url'], 50)))
            self.table.setItem(row, 1, QTableWidgetItem(sanitize_display_text(e['login'], 30)))
            pwd_item = QTableWidgetItem("••••••••")
            pwd_item.setData(Qt.ItemDataRole.UserRole, i)
            self.table.setItem(row, 2, pwd_item)
            show_btn = QPushButton("👁")
            show_btn.setFixedSize(26, 22)
            show_btn.clicked.connect((lambda idx, item=pwd_item: lambda: self._show_password_secure(idx, item))(i))
            self.table.setCellWidget(row, 3, show_btn)
        self.count_lbl.setText(f"Записей: {self.table.rowCount()}")

    def _show_password_secure(self, entry_index: int, widget: QTableWidgetItem):
        if not self.pm.show_password_secure(entry_index, widget):
            QMessageBox.warning(self, "Ошибка", "Не удалось показать пароль.")

    def _add_entry(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Добавить пароль")
        dlg.setFixedSize(360, 210)
        layout = QVBoxLayout(dlg)
        form = QFormLayout()
        url_edit = QLineEdit()
        url_edit.setPlaceholderText("https://example.com")
        login_edit = QLineEdit()
        pwd_edit = QLineEdit()
        pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Сайт:", url_edit)
        form.addRow("Логин:", login_edit)
        form.addRow("Пароль:", pwd_edit)
        layout.addLayout(form)
        show_cb = QCheckBox("Показать пароль")
        show_cb.toggled.connect(lambda c: pwd_edit.setEchoMode(QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        layout.addWidget(show_cb)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        result = [None, None, None]
        def on_ok():
            url = url_edit.text().strip()
            login = login_edit.text().strip()
            pwd = pwd_edit.text()
            if not url or not login or not pwd:
                QMessageBox.warning(dlg, "Ошибка", "Заполните все поля.")
                return
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            result[0], result[1], result[2] = url, login, pwd
            dlg.accept()
        bb.accepted.connect(on_ok)
        bb.rejected.connect(dlg.reject)
        layout.addWidget(bb)
        if dlg.exec() == QDialog.DialogCode.Accepted and result[0]:
            self.pm.add(result[0], result[1], result[2])
            self._refresh()

    def _delete_selected(self):
        rows = sorted(set(idx.row() for idx in self.table.selectedIndexes()), reverse=True)
        for row in rows:
            item = self.table.item(row, 2)
            if item:
                self.pm.remove(item.data(Qt.ItemDataRole.UserRole))
        self._refresh()

    def _delete_all(self):
        reply = QMessageBox.question(self, "Удалить все пароли", "Удалить все сохранённые пароли?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.pm.clear_all()
            self._refresh()

    def closeEvent(self, event):
        self.pm.clear_secure_items()
        super().closeEvent(event)


class SavePasswordDialog(QDialog):
    def __init__(self, url: str, login: str, password: str, parent=None):
        super().__init__(parent)
        self.url = url
        self.login = login
        self.password = password
        self.setWindowTitle("Nostalgia Browser")
        self.setFixedSize(400, 180)
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-200, geo.center().y()-90)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 10)
        top = QHBoxLayout()
        top.setSpacing(14)
        icon = QLabel()
        icon.setFixedSize(40, 40)
        px = QPixmap(40, 40)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setBrush(QBrush(QColor(0, 80, 180)))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(0, 0, 40, 40)
        p.setPen(QPen(QColor(Qt.GlobalColor.white), 3))
        p.setFont(QFont("Tahoma", 18, QFont.Weight.Bold))
        p.drawText(px.rect(), Qt.AlignmentFlag.AlignCenter, "🔑")
        p.end()
        icon.setPixmap(px)
        top.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)
        safe_login = html_escape(login)
        safe_url = html_escape(urlparse(url).netloc)
        msg = QLabel(f"<b>Сохранить пароль?</b><br><br>Логин: <b>{safe_login}</b> на сайте <b>{safe_url}</b>")
        msg.setWordWrap(True)
        top.addWidget(msg, 1)
        layout.addLayout(top)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line)
        bl = QHBoxLayout()
        bl.addStretch()
        yes_btn = QPushButton("Сохранить")
        yes_btn.setFixedWidth(90)
        yes_btn.clicked.connect(self.accept)
        bl.addWidget(yes_btn)
        no_btn = QPushButton("Не сохранять")
        no_btn.setFixedWidth(110)
        no_btn.clicked.connect(self.reject)
        bl.addWidget(no_btn)
        bl.addStretch()
        layout.addLayout(bl)


class ClearDataDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Очистка данных браузера - Nostalgia")
        self.setFixedSize(400, 350)
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-200, geo.center().y()-175)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 10)
        lbl = QLabel("Выберите данные для удаления:")
        lbl.setFont(QFont("Tahoma", 8, QFont.Weight.Bold))
        layout.addWidget(lbl)
        box = QGroupBox()
        bl = QVBoxLayout(box)
        self.cb_history = QCheckBox("История просмотров")
        self.cb_history.setChecked(True)
        self.cb_cookies = QCheckBox("Cookie и данные сайтов")
        self.cb_cookies.setChecked(True)
        self.cb_cache = QCheckBox("Кэш браузера")
        self.cb_cache.setChecked(True)
        self.cb_passwords = QCheckBox("Сохранённые пароли")
        self.cb_bookmarks = QCheckBox("Закладки")
        for cb in [self.cb_history, self.cb_cookies, self.cb_cache, self.cb_passwords, self.cb_bookmarks]:
            bl.addWidget(cb)
        layout.addWidget(box)
        warn = QLabel("⚠  Действие необратимо!")
        warn.setStyleSheet("color: red;")
        layout.addWidget(warn)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("Очистить")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        layout.addWidget(bb)

    @property
    def clear_history(self): return self.cb_history.isChecked()
    @property
    def clear_cookies(self): return self.cb_cookies.isChecked()
    @property
    def clear_cache(self): return self.cb_cache.isChecked()
    @property
    def clear_passwords(self): return self.cb_passwords.isChecked()
    @property
    def clear_bookmarks(self): return self.cb_bookmarks.isChecked()


class BookmarkManagerDialog(QDialog):
    def __init__(self, bookmarks: dict, parent=None):
        super().__init__(parent)
        self.bookmarks = bookmarks
        self.setWindowTitle("Управление закладками - Nostalgia")
        self.resize(600, 450)
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-300, geo.center().y()-225)
        self._build_ui()
        self._refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Название", "URL"])
        self.tree.setColumnWidth(0, 250)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemDoubleClicked.connect(self._open_bookmark)
        layout.addWidget(self.tree)
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Добавить")
        add_btn.clicked.connect(self._add_bookmark)
        btn_layout.addWidget(add_btn)
        edit_btn = QPushButton("Изменить")
        edit_btn.clicked.connect(self._edit_bookmark)
        btn_layout.addWidget(edit_btn)
        del_btn = QPushButton("Удалить")
        del_btn.clicked.connect(self._delete_bookmark)
        btn_layout.addWidget(del_btn)
        btn_layout.addStretch()
        import_btn = QPushButton("Импорт из HTML")
        import_btn.clicked.connect(self._import_bookmarks)
        btn_layout.addWidget(import_btn)
        export_btn = QPushButton("Экспорт в HTML")
        export_btn.clicked.connect(self._export_bookmarks)
        btn_layout.addWidget(export_btn)
        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def _refresh(self):
        self.tree.clear()
        for name, url in self.bookmarks.items():
            item = QTreeWidgetItem([sanitize_display_text(name, 100), sanitize_display_text(url, 100)])
            self.tree.addTopLevelItem(item)

    def _open_bookmark(self, item: QTreeWidgetItem, column):
        url = item.text(1)
        if url and is_safe_url(QUrl(url)):
            parent = self.parent()
            if parent and hasattr(parent, 'add_new_tab'):
                parent.add_new_tab(QUrl(url))

    def _add_bookmark(self):
        name, ok1 = QInputDialog.getText(self, "Добавить закладку", "Название:")
        if not ok1 or not name:
            return
        url, ok2 = QInputDialog.getText(self, "Добавить закладку", "URL:")
        if not ok2 or not url:
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if is_safe_url(QUrl(url)):
            self.bookmarks[name] = url
            self._refresh()

    def _edit_bookmark(self):
        item = self.tree.currentItem()
        if not item:
            return
        old_name = item.text(0)
        old_url = item.text(1)
        name, ok1 = QInputDialog.getText(self, "Редактировать", "Название:", text=old_name)
        if not ok1 or not name:
            return
        url, ok2 = QInputDialog.getText(self, "Редактировать", "URL:", text=old_url)
        if not ok2 or not url:
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if is_safe_url(QUrl(url)):
            del self.bookmarks[old_name]
            self.bookmarks[name] = url
            self._refresh()

    def _delete_bookmark(self):
        item = self.tree.currentItem()
        if item:
            name = item.text(0)
            del self.bookmarks[name]
            self._refresh()

    def _import_bookmarks(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Импорт закладок", "", "HTML Files (*.html *.htm)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                matches = re.findall(r'<a\s+href="([^"]+)"[^>]*>([^<]+)</a>', content)
                for url, name in matches[:MAX_BOOKMARK_IMPORT_COUNT]:
                    safe_name = html_escape(name.strip())[:200]
                    if is_safe_url(QUrl(url)):
                        self.bookmarks[safe_name] = url
                self._refresh()
                QMessageBox.information(self, "Импорт", f"Импортировано {len(matches)} закладок.")
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", "Не удалось импортировать файл.")

    def _export_bookmarks(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Экспорт закладок", "bookmarks.html", "HTML Files (*.html)")
        if file_path:
            try:
                html = ['<!DOCTYPE html><html><head><title>Закладки Nostalgia</title></head>',
                       '<body><h1>Закладки Nostalgia Browser</h1><ul>']
                for name, url in self.bookmarks.items():
                    html.append(f'<li><a href="{html_escape(url)}">{html_escape(name)}</a></li>')
                html.append('</ul></body></html>')
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(html))
                QMessageBox.information(self, "Экспорт", "Закладки экспортированы.")
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", "Не удалось экспортировать файл.")


class CertificateErrorDialog(QDialog):
    def __init__(self, error: QWebEngineCertificateError, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ошибка сертификата - Nostalgia")
        self.setFixedSize(500, 300)
        layout = QVBoxLayout(self)
        icon_label = QLabel()
        icon_label.setFixedSize(48, 48)
        px = QPixmap(48, 48)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setBrush(QBrush(QColor(255, 200, 0)))
        p.setPen(QPen(QColor(160, 100, 0), 2))
        p.drawPolygon(QPolygon([QPoint(24, 2), QPoint(46, 45), QPoint(2, 45)]))
        p.setPen(QPen(QColor(80, 40, 0), 3))
        p.drawLine(24, 16, 24, 32)
        p.drawLine(24, 37, 24, 40)
        p.end()
        icon_label.setPixmap(px)
        top = QHBoxLayout()
        top.addWidget(icon_label)
        safe_url = html_escape(error.url().toString())
        error_text = QLabel(f"<b>Ошибка сертификата безопасности</b><br><br>URL: {safe_url}<br><br>Продолжить?")
        error_text.setWordWrap(True)
        top.addWidget(error_text, 1)
        layout.addLayout(top)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line)
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        proceed_btn = QPushButton("Продолжить (небезопасно)")
        proceed_btn.clicked.connect(self.accept)
        proceed_btn.setStyleSheet("color: red;")
        btn_layout.addWidget(proceed_btn)
        layout.addLayout(btn_layout)
        self.error = error

    def accept(self):
        self.error.ignoreCertificateError()
        super().accept()


class NostalgiaPage(QWebEnginePage):
    open_in_new_tab = pyqtSignal(QUrl)
    page_blocked = pyqtSignal(str)
    scheme_blocked = pyqtSignal(str)
    credentials_found = pyqtSignal(str, str, str)

    def __init__(self, site_filter, scheme_handler, block_popups: bool = True, profile=None, parent=None):
        if profile:
            super().__init__(profile, parent)
        else:
            super().__init__(parent)
        self.site_filter = site_filter
        self.scheme_handler = scheme_handler
        self.block_popups = block_popups
        self._blocked = False
        self._incognito = (profile is not None and profile == IncognitoProfile.get())
        self.certificateError.connect(self._on_certificate_error)

    def _on_certificate_error(self, error: QWebEngineCertificateError):
        dialog = CertificateErrorDialog(error, self.view())
        return dialog.exec() == QDialog.DialogCode.Accepted

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):
        if url.scheme().lower() == "nostalgia":
            return True
        
        if not is_safe_external_protocol(url):
            SafeLogger.warning("Blocked external protocol: %s", url.scheme())
            return False
        
        if is_main_frame:
            if nav_type == QWebEnginePage.NavigationType.NavigationTypeFormSubmitted:
                self._check_credentials(url)
            if not is_safe_url(url):
                self._blocked = True
                QTimer.singleShot(0, lambda: self.scheme_blocked.emit(url.scheme()))
                return False
            if self.site_filter.is_blocked(url):
                self._blocked = True
                QTimer.singleShot(0, lambda: self.page_blocked.emit(self.site_filter.extract_domain(url)))
                return False
            self._blocked = False
        
        return super().acceptNavigationRequest(url, nav_type, is_main_frame)

    def _check_credentials(self, url: QUrl):
        if self._incognito:
            return
        self.runJavaScript("window.__nostalgiaCredentials || null;", lambda creds: self._emit_credentials(url.toString(), creds))

    def _emit_credentials(self, url: str, creds):
        if isinstance(creds, dict):
            login = creds.get('login', '')
            pwd = creds.get('password', '')
            if login and pwd:
                self.credentials_found.emit(url, login, pwd)
            self.runJavaScript("window.__nostalgiaCredentials = null;")

    def createWindow(self, win_type):
        if self.block_popups and win_type in (QWebEnginePage.WebWindowType.WebDialog, QWebEnginePage.WebWindowType.WebBrowserWindow):
            return None
        
        placeholder = NostalgiaPage(self.site_filter, self.scheme_handler, self.block_popups, self.profile(), self.parent())
        
        def _on_url(url):
            if not (url.isEmpty() or url.toString() == "about:blank") and is_safe_url(url):
                self.open_in_new_tab.emit(url)
            placeholder.deleteLater()
        placeholder.urlChanged.connect(_on_url)
        return placeholder


class BrowserTab(QWidget):
    def __init__(self, site_filter, scheme_handler, block_popups: bool = True, incognito: bool = False, parent=None):
        super().__init__(parent)
        self.is_incognito = incognito
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        if incognito:
            inc_bar = QLabel("  🕵  Режим инкогнито — история, cookie и кэш не сохраняются")
            inc_bar.setStyleSheet("background: #3a3a3a; color: #e0e0e0; padding: 3px 6px; font-size: 8pt;")
            inc_bar.setFixedHeight(22)
            outer.addWidget(inc_bar)
        self.find_bar = FindBar(self)
        outer.addWidget(self.find_bar)
        self.webview = QWebEngineView()
        self.webview.setStyleSheet("background: white;")
        profile = IncognitoProfile.get() if incognito else QWebEngineProfile.defaultProfile()
        page = NostalgiaPage(site_filter, scheme_handler, block_popups, profile, self.webview)
        self.webview.setPage(page)
        self.webview.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.webview.customContextMenuRequested.connect(self._show_context_menu)
        outer.addWidget(self.webview)
        self.find_bar.set_webview(self.webview)

    @property
    def nostalgia_page(self) -> NostalgiaPage:
        return self.webview.page()

    def _show_context_menu(self, pos):
        menu = QMenu(self)
        page = self.webview.page()
        back_a = QAction("← Назад", self)
        back_a.setEnabled(self.webview.history().canGoBack())
        back_a.triggered.connect(self.webview.back)
        menu.addAction(back_a)
        fwd_a = QAction("Вперёд →", self)
        fwd_a.setEnabled(self.webview.history().canGoForward())
        fwd_a.triggered.connect(self.webview.forward)
        menu.addAction(fwd_a)
        reload_a = QAction("Обновить", self)
        reload_a.triggered.connect(self.webview.reload)
        menu.addAction(reload_a)
        menu.addSeparator()
        copy_a = QAction("Копировать", self)
        copy_a.triggered.connect(lambda: page.triggerAction(QWebEnginePage.WebAction.Copy))
        menu.addAction(copy_a)
        select_all_a = QAction("Выделить всё", self)
        select_all_a.triggered.connect(lambda: page.triggerAction(QWebEnginePage.WebAction.SelectAll))
        menu.addAction(select_all_a)
        menu.addSeparator()
        hit = None
        try:
            hit = page.lastContextMenuRequest()
        except Exception:
            hit = None
        link_url = hit.linkUrl() if hit else QUrl()
        if link_url.isValid() and is_safe_url(link_url):
            open_tab_a = QAction("Открыть ссылку в новой вкладке", self)
            open_tab_a.triggered.connect(lambda: self.nostalgia_page.open_in_new_tab.emit(link_url))
            menu.addAction(open_tab_a)
            copy_link_a = QAction("Копировать адрес ссылки", self)
            copy_link_a.triggered.connect(lambda url=link_url.toString(): SecureClipboard.set_text(url))
            menu.addAction(copy_link_a)
            menu.addSeparator()
        find_a = QAction("Найти на странице... (Ctrl+F)", self)
        find_a.triggered.connect(self.find_bar.open_bar)
        menu.addAction(find_a)
        zoom_menu = menu.addMenu("Масштаб")
        for pct in (75, 90, 100, 110, 125, 150, 175, 200):
            za = QAction(f"{pct}%", self)
            za.triggered.connect((lambda z: lambda: self.webview.setZoomFactor(z / 100))(pct))
            zoom_menu.addAction(za)
        menu.addSeparator()
        src_a = QAction("Просмотр кода страницы", self)
        src_a.triggered.connect(lambda: self.webview.page().toHtml(lambda html: self._show_source_dialog(html)))
        menu.addAction(src_a)
        menu.exec(self.webview.mapToGlobal(pos))

    def _show_source_dialog(self, html: str):
        dlg = QDialog(self)
        dlg.setWindowTitle("Исходный код страницы")
        dlg.resize(800, 600)
        layout = QVBoxLayout(dlg)
        te = QTextEdit()
        te.setReadOnly(True)
        te.setFont(QFont("Courier New", 9))
        te.setPlainText(html)
        layout.addWidget(te)
        cb = QPushButton("Закрыть")
        cb.clicked.connect(dlg.accept)
        layout.addWidget(cb)
        dlg.exec()


class BlockedDialog(QDialog):
    def __init__(self, domain: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nostalgia Browser")
        self.setFixedSize(380, 200)
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-190, geo.center().y()-100)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 12)
        icon_label = QLabel()
        icon_label.setFixedSize(48, 48)
        px = QPixmap(48, 48)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setBrush(QBrush(QColor(200, 0, 0)))
        p.setPen(QPen(QColor(140, 0, 0), 2))
        p.drawEllipse(2, 2, 44, 44)
        p.setPen(QPen(QColor(Qt.GlobalColor.white), 6))
        p.drawLine(14, 14, 34, 34)
        p.drawLine(34, 14, 14, 34)
        p.end()
        icon_label.setPixmap(px)
        top = QHBoxLayout()
        top.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)
        msg = QLabel(f"<b>Сайт заблокирован</b><br><br>Доступ к сайту <b>{html_escape(domain)}</b> ограничен.")
        msg.setWordWrap(True)
        top.addWidget(msg, 1)
        layout.addLayout(top)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line)
        bl = QHBoxLayout()
        bl.addStretch()
        ok = QPushButton("  ОК  ")
        ok.setFixedWidth(80)
        ok.clicked.connect(self.accept)
        bl.addWidget(ok)
        bl.addStretch()
        layout.addLayout(bl)


class SchemeBlockedDialog(QDialog):
    def __init__(self, scheme: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nostalgia Browser")
        self.setFixedSize(380, 180)
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-190, geo.center().y()-90)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 12)
        icon_label = QLabel()
        icon_label.setFixedSize(48, 48)
        px = QPixmap(48, 48)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setBrush(QBrush(QColor(255, 200, 0)))
        p.setPen(QPen(QColor(160, 100, 0), 2))
        p.drawPolygon(QPolygon([QPoint(24, 2), QPoint(46, 45), QPoint(2, 45)]))
        p.setPen(QPen(QColor(80, 40, 0), 3))
        p.drawLine(24, 16, 24, 32)
        p.drawLine(24, 37, 24, 40)
        p.end()
        icon_label.setPixmap(px)
        top = QHBoxLayout()
        top.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)
        msg = QLabel(f"<b>Протокол не поддерживается</b><br><br>Схема <b>{html_escape(scheme)}://</b> заблокирована.")
        msg.setWordWrap(True)
        top.addWidget(msg, 1)
        layout.addLayout(top)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line)
        bl = QHBoxLayout()
        bl.addStretch()
        ok = QPushButton("  ОК  ")
        ok.setFixedWidth(80)
        ok.clicked.connect(self.accept)
        bl.addWidget(ok)
        bl.addStretch()
        layout.addLayout(bl)


class HomepageDialog(QDialog):
    def __init__(self, current_homepage: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройка домашней страницы")
        self.setFixedSize(460, 160)
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-230, geo.center().y()-80)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 10)
        form = QFormLayout()
        self.url_edit = QLineEdit(current_homepage)
        self.url_edit.setMinimumWidth(340)
        form.addRow("Домашняя страница:", self.url_edit)
        layout.addLayout(form)
        hint = QLabel("Пример: https://www.google.com")
        hint.setStyleSheet("color: gray; font-size: 8pt;")
        layout.addWidget(hint)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._validate_and_accept)
        bb.rejected.connect(self.reject)
        layout.addWidget(bb)

    def _validate_and_accept(self):
        raw = self.url_edit.text().strip()
        if not raw:
            QMessageBox.warning(self, "Ошибка", "Введите адрес.")
            return
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw
        q = QUrl(raw)
        if not q.isValid() or not is_safe_url(q):
            QMessageBox.warning(self, "Ошибка", "Недопустимый адрес.")
            return
        self.result_url = raw
        self.accept()

    @property
    def homepage(self) -> str:
        return getattr(self, 'result_url', self.url_edit.text().strip())


class ColoredTabLoadingWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(16, 16)
        self.angle = 0
        self.active = False
        self.loading_stage = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.rotate)
        self.timer.setInterval(80)

    def start(self):
        self.active = True
        self.timer.start()
        self.show()

    def stop(self):
        self.active = False
        self.timer.stop()
        self.hide()

    def set_stage(self, stage: int):
        self.loading_stage = stage
        self.update()

    def rotate(self):
        if self.active:
            self.angle = (self.angle + 15) % 360
            self.update()

    def paintEvent(self, event):
        if not self.active:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self.loading_stage == 0:
            color = QColor(255, 165, 0)
        elif self.loading_stage == 1:
            color = QColor(0, 80, 200)
        else:
            color = QColor(0, 200, 0)
        p.setPen(QPen(color, 1))
        p.setBrush(QBrush(color))
        p.drawEllipse(1, 1, 14, 14)
        p.save()
        p.translate(8, 8)
        p.rotate(self.angle)
        p.setPen(QPen(QColor(255, 255, 255), 0.8))
        p.setBrush(QBrush(QColor(255, 255, 255)))
        for rect in [(-4, -2, 3, 2), (1, -2, 3, 2), (-3, 1, 2, 2), (1, 1, 2, 2)]:
            p.drawRect(*rect)
        p.restore()
        p.setPen(QPen(color.lighter(150), 0.5))
        p.drawEllipse(0, 0, 16, 16)


TabLoadingWidget = ColoredTabLoadingWidget


# ──────────────────────────────────────────────
# ОСНОВНОЙ КЛАСС БРАУЗЕРА
# ──────────────────────────────────────────────

class NostalgiaBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nostalgia Browser")
        self.setGeometry(100, 100, 1024, 768)
        
        self._is_cleaning_up = False
        self._history_queue: List[dict] = []
        self._history_timer = QTimer()
        self._history_timer.setSingleShot(True)
        self._history_timer.timeout.connect(self._flush_history_queue)
        
        self._profile_dir = os.path.join(tempfile.gettempdir(), f"nostalgia_profile_{uuid.uuid4().hex[:8]}")
        os.makedirs(self._profile_dir, exist_ok=True)
        os.chmod(self._profile_dir, 0o700)
        
        self._profile = QWebEngineProfile("NostalgiaProfile", self)
        self._profile.setCachePath(os.path.join(self._profile_dir, "cache"))
        self._profile.setPersistentStoragePath(os.path.join(self._profile_dir, "storage"))
        
        self.site_filter = SiteFilter()
        self.scheme_handler = NostalgiaPageHandler()
        self.bookmarks = {}
        self.history = []
        self.homepage = "https://www.google.com"
        self.block_popups = True
        self.current_theme = "Классическая (Windows 98)"
        self.current_engine = "Google"
        self.loading_tabs: dict = {}
        self.password_manager = SecurePasswordManager(parent_widget=self)
        self._download_manager = None
        self._navigation_limiter = RateLimiter(NAVIGATION_RATE_LIMIT)
        self._active_downloads = 0
        self._clipboard_cleanup_timer = None
        self.tab_manager = None
        self.download_security = DownloadSecurityManager()

        self.setup_profile()
        self.load_settings()
        self.create_menubar()
        self.create_toolbars()
        self.create_tabs()
        self.tab_manager = TabManager(self.tab_widget)
        self.setup_statusbar()
        self.setup_shortcuts()

        QTimer.singleShot(100, lambda: self.add_new_tab(QUrl(self.homepage), "Домашняя страница"))
        self.status_label.setText("Готово")

    def open_folder(self, path: str):
        import subprocess
        import platform
        try:
            if platform.system() == "Windows":
                os.startfile(path)
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            SafeLogger.warning("Не удалось открыть папку: %s", e)

    def setup_profile(self):
        profile = self._profile
        profile.setHttpUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        profile.setHttpAcceptLanguage("ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
        profile.downloadRequested.connect(self._on_download_requested)
        
        incognito = IncognitoProfile.get()
        incognito.downloadRequested.connect(self._on_download_requested)

        settings = profile.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.AllowRunningInsecureContent, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.WebRTCPublicInterfacesOnly, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.DnsPrefetchEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.ErrorPageEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.WebGLEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.AutoLoadIconsForPage, False)
        
        profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
        profile.setHttpCacheMaximumSize(50 * 1024 * 1024)

        QApplication.instance().aboutToQuit.connect(self._cleanup_security)

    def _cleanup_security(self):
        if self._is_cleaning_up:
            return
        self._is_cleaning_up = True
        
        clipboard = QApplication.clipboard()
        clipboard.clear()
        
        if hasattr(self, 'password_manager'):
            self.password_manager.clear_secure_items()
        
        if self._clipboard_cleanup_timer:
            self._clipboard_cleanup_timer.stop()
        
        self.history.clear()
        self._history_queue.clear()
        
        try:
            self._profile.clearHttpCache()
        except Exception:
            pass
        
        try:
            if hasattr(self, '_profile_dir') and os.path.exists(self._profile_dir):
                shutil.rmtree(self._profile_dir, ignore_errors=True)
        except Exception as e:
            SafeLogger.warning("Error cleaning profile directory: %s", e)
        
        gc.collect()
        SafeLogger.info("Security cleanup completed")

    def _on_download_requested(self, download: QWebEngineDownloadRequest):
        if self._active_downloads >= MAX_DOWNLOADS_SIMULTANEOUS:
            download.cancel()
            QMessageBox.warning(self, "Слишком много загрузок", f"Лимит {MAX_DOWNLOADS_SIMULTANEOUS}")
            return

        original_filename = download.downloadFileName() or "download"
        safe_filename = DownloadSecurityManager.sanitize_filename(original_filename)
        
        content_length = download.totalBytes()
        if content_length > MAX_DOWNLOAD_SIZE:
            download.cancel()
            QMessageBox.warning(self, "Файл слишком большой", "")
            return

        save_path, _ = QFileDialog.getSaveFileName(self, "Сохранить файл",
            os.path.join(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation), safe_filename))
        if not save_path:
            download.cancel()
            return

        self._active_downloads += 1

        def on_download_finished():
            self._active_downloads -= 1

        download.isFinishedChanged.connect(on_download_finished)
        download.setDownloadDirectory(os.path.dirname(save_path))
        download.setDownloadFileName(os.path.basename(save_path))
        download.accept()

        if self._download_manager is None:
            self._download_manager = DownloadManagerDialog(self)
        self._download_manager.add_download(download)

    def load_settings(self):
        try:
            if os.path.exists('nostalgia_settings.json'):
                data = SecureFileHandler.safe_read_json('nostalgia_settings.json')
                if data:
                    raw_bm = data.get('bookmarks', {})
                    if isinstance(raw_bm, dict):
                        self.bookmarks = {}
                        for k, v in raw_bm.items():
                            if isinstance(v, str) and is_safe_url(QUrl(v)):
                                self.bookmarks[k] = v
                    
                    raw_hist = data.get('history', [])
                    if isinstance(raw_hist, list):
                        self.history = []
                        for e in raw_hist[:MAX_HISTORY_ENTRIES]:
                            if isinstance(e, dict):
                                self.history.append(e)
                    
                    raw_hp = data.get('homepage', 'https://www.google.com')
                    if isinstance(raw_hp, str) and is_safe_url(QUrl(raw_hp)):
                        self.homepage = raw_hp
                    
                    self.block_popups = bool(data.get('block_popups', True))
                    raw_theme = data.get('theme', 'Классическая (Windows 98)')
                    self.current_theme = raw_theme if raw_theme in THEMES else 'Классическая (Windows 98)'
                    raw_engine = data.get('search_engine', 'Google')
                    self.current_engine = raw_engine if raw_engine in SEARCH_ENGINES else 'Google'
        except Exception as e:
            SafeLogger.warning("Error loading settings: %s", e)

    def save_settings(self):
        try:
            data = {
                'bookmarks': self.bookmarks,
                'history': self.history[-MAX_HISTORY_ENTRIES:],
                'homepage': self.homepage,
                'block_popups': self.block_popups,
                'theme': self.current_theme,
                'search_engine': self.current_engine,
            }
            SecureFileHandler.safe_write_json('nostalgia_settings.json', data)
        except Exception as e:
            SafeLogger.warning("Error saving settings: %s", e)

    def create_menubar(self):
        mb = self.menuBar()
        fm = mb.addMenu("&Файл")
        a = QAction("Новая &вкладка", self)
        a.setShortcut("Ctrl+T")
        a.triggered.connect(lambda: self.add_new_tab(QUrl(self.homepage)))
        fm.addAction(a)
        a = QAction("🕵 Новая вкладка &инкогнито", self)
        a.setShortcut("Ctrl+Shift+N")
        a.triggered.connect(self.open_incognito_tab)
        fm.addAction(a)
        fm.addSeparator()
        a = QAction("&Выход", self)
        a.setShortcut("Ctrl+Q")
        a.triggered.connect(self.close)
        fm.addAction(a)

        vm = mb.addMenu("&Вид")
        a = QAction("&Остановить", self)
        a.setShortcut("Escape")
        a.triggered.connect(self.stop_loading)
        vm.addAction(a)
        a = QAction("&Обновить", self)
        a.setShortcut("F5")
        a.triggered.connect(self.reload_page)
        vm.addAction(a)
        vm.addSeparator()
        a = QAction("🎨 &Темы оформления...", self)
        a.triggered.connect(self.show_theme_dialog)
        vm.addAction(a)
        a = QAction("&Полный экран", self)
        a.setShortcut("F11")
        a.triggered.connect(self.toggle_fullscreen)
        vm.addAction(a)

        self.fav_menu = mb.addMenu("&Избранное")
        a = QAction("&Добавить в избранное...", self)
        a.setShortcut("Ctrl+D")
        a.triggered.connect(self.add_to_bookmarks)
        self.fav_menu.addAction(a)
        a = QAction("&Управление закладками...", self)
        a.triggered.connect(self.show_bookmark_manager)
        self.fav_menu.addAction(a)
        self.fav_menu.addSeparator()
        self.fav_menu.aboutToShow.connect(self.update_bookmarks_menu)

        tm = mb.addMenu("&Сервис")
        a = QAction("&Настройка фильтрации...", self)
        a.triggered.connect(self.show_filter_settings)
        tm.addAction(a)
        a = QAction("&История...", self)
        a.triggered.connect(self.show_history)
        tm.addAction(a)
        a = QAction("&Загрузки... (Ctrl+J)", self)
        a.triggered.connect(self.show_downloads)
        tm.addAction(a)
        tm.addSeparator()
        a = QAction("🔍 Поисковые &системы...", self)
        a.triggered.connect(self.show_search_engine_dialog)
        tm.addAction(a)
        a = QAction("🔑 Управление &паролями...", self)
        a.triggered.connect(self.show_password_manager)
        tm.addAction(a)
        a = QAction("🗑 &Очистить данные браузера...", self)
        a.setShortcut("Ctrl+Shift+Del")
        a.triggered.connect(self.show_clear_data_dialog)
        tm.addAction(a)
        tm.addSeparator()
        a = QAction("Настройка &домашней страницы...", self)
        a.triggered.connect(self.show_homepage_settings)
        tm.addAction(a)
        self.popup_action = QAction("&Блокировать всплывающие окна", self)
        self.popup_action.setCheckable(True)
        self.popup_action.setChecked(self.block_popups)
        self.popup_action.triggered.connect(self._toggle_popup_blocking)
        tm.addAction(self.popup_action)

        hm = mb.addMenu("&Справка")
        a = QAction("Сведения о &программе", self)
        a.triggered.connect(self.show_about)
        hm.addAction(a)

    def update_bookmarks_menu(self):
        for action in self.fav_menu.actions()[3:]:
            self.fav_menu.removeAction(action)
        for name, url in self.bookmarks.items():
            a = QAction(sanitize_display_text(name, 50), self)
            a.triggered.connect((lambda u: lambda: self.load_url(u))(url))
            self.fav_menu.addAction(a)

    def create_toolbars(self):
        self.nav_toolbar = QToolBar("Панель инструментов")
        self.nav_toolbar.setMovable(False)
        self.addToolBar(self.nav_toolbar)
        for text, func in [("← Назад", self.go_back), ("Вперед →", self.go_forward), ("Стоп", self.stop_loading), ("Обновить", self.reload_page), ("Домой", self.go_home)]:
            btn = QPushButton(text)
            btn.clicked.connect(func)
            self.nav_toolbar.addWidget(btn)
        self.nav_toolbar.addSeparator()
        sb = QPushButton("Поиск")
        sb.clicked.connect(self.show_search)
        self.nav_toolbar.addWidget(sb)
        fb = QPushButton("🔒 Фильтр")
        fb.clicked.connect(self.show_filter_settings)
        self.nav_toolbar.addWidget(fb)
        ib = QPushButton("🕵 Инкогнито")
        ib.clicked.connect(self.open_incognito_tab)
        self.nav_toolbar.addWidget(ib)
        self.nav_toolbar.addSeparator()
        zob = QPushButton("A-")
        zob.setFixedWidth(32)
        zob.clicked.connect(self.zoom_out)
        self.nav_toolbar.addWidget(zob)
        self.zoom_label = QLabel("100%")
        self.zoom_label.setFixedWidth(38)
        self.zoom_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.nav_toolbar.addWidget(self.zoom_label)
        zib = QPushButton("A+")
        zib.setFixedWidth(32)
        zib.clicked.connect(self.zoom_in)
        self.nav_toolbar.addWidget(zib)
        self.address_toolbar = QToolBar("Адресная строка")
        self.address_toolbar.setMovable(False)
        self.addToolBar(self.address_toolbar)
        self.address_label = QLabel("Адрес: ")
        self.address_toolbar.addWidget(self.address_label)
        self.url_bar = QLineEdit()
        self.url_bar.setMinimumWidth(400)
        self.url_bar.setPlaceholderText("Введите адрес")
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        self.address_toolbar.addWidget(self.url_bar)
        gb = QPushButton("Переход")
        gb.clicked.connect(self.navigate_to_url)
        self.address_toolbar.addWidget(gb)
        self.globe = EnhancedGifLoadingWidget()
        self.address_toolbar.addWidget(self.globe)

    def create_tabs(self):
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.setMovable(True)
        self.tab_widget.currentChanged.connect(self.tab_changed)
        self.setCentralWidget(self.tab_widget)

    def setup_statusbar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Готово")
        self.status_label.setMinimumWidth(200)
        self.status_bar.addWidget(self.status_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(150)
        self.progress_bar.setMaximumHeight(16)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.filter_status = QLabel("")
        self.status_bar.addPermanentWidget(self.filter_status)
        self.update_filter_indicator()
        self.zone_label = QLabel("Зона Интернета")
        self.status_bar.addPermanentWidget(self.zone_label)

    def setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+W"), self, activated=self.close_current_tab)
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self.focus_url_bar)
        QShortcut(QKeySequence("Ctrl+F"), self, activated=self.open_find_bar)
        QShortcut(QKeySequence("Ctrl++"), self, activated=self.zoom_in)
        QShortcut(QKeySequence("Ctrl+-"), self, activated=self.zoom_out)
        QShortcut(QKeySequence("Ctrl+0"), self, activated=self.zoom_reset)
        QShortcut(QKeySequence("Ctrl+J"), self, activated=self.show_downloads)
        QShortcut(QKeySequence("Ctrl+Shift+N"), self, activated=self.open_incognito_tab)
        QShortcut(QKeySequence("Ctrl+Shift+Del"), self, activated=self.show_clear_data_dialog)
        QShortcut(QKeySequence("Ctrl+Tab"), self, activated=self.next_tab)
        QShortcut(QKeySequence("Ctrl+Shift+Tab"), self, activated=self.prev_tab)
        for i in range(1, 9):
            QShortcut(QKeySequence(f"Ctrl+{i}"), self, activated=lambda idx=i-1: self.switch_to_tab(idx))

    def _safe_add_to_history(self, entry: dict):
        url = entry.get('url', '')
        if not url:
            return
        self._history_queue.append({
            'url': url,
            'title': entry.get('title', '')[:MAX_TITLE_LENGTH],
            'time': datetime.datetime.now().isoformat()
        })
        if len(self._history_queue) > MAX_HISTORY_WRITE_QUEUE:
            self._flush_history_queue()
        else:
            self._history_timer.start(1000)
    
    def _flush_history_queue(self):
        if not self._history_queue:
            return
        for entry in self._history_queue:
            if len(self.history) >= MAX_HISTORY_ENTRIES:
                self.history = self.history[-MAX_HISTORY_ENTRIES//2:]
            self.history.append(entry)
        self._history_queue.clear()
        self.save_settings()

    def open_incognito_tab(self):
        self.add_new_tab(QUrl(self.homepage), "🕵 Инкогнито", incognito=True)

    def add_new_tab(self, url=None, title="Новая вкладка", incognito: bool = False):
        if not self.tab_manager.can_add_tab():
            QMessageBox.warning(self, "Слишком много вкладок", f"Максимум {MAX_TABS}")
            return None
        if url is None:
            url = QUrl("about:blank")
        elif isinstance(url, str):
            url = QUrl(url)
        
        tab = BrowserTab(self.site_filter, self.scheme_handler, self.block_popups, incognito)
        index = self.tab_widget.addTab(tab, sanitize_display_text(title, MAX_DISPLAY_LENGTH))
        self.tab_widget.setCurrentIndex(index)
        
        page = tab.nostalgia_page
        page.open_in_new_tab.connect(lambda u, inc=incognito: self.add_new_tab(u, incognito=inc))
        page.page_blocked.connect(lambda domain, t=tab: self._on_site_blocked(t, domain))
        page.scheme_blocked.connect(lambda scheme, t=tab: self._on_scheme_blocked(t, scheme))
        if not incognito:
            page.credentials_found.connect(self._on_credentials_found)
        
        wv = tab.webview
        wv.loadStarted.connect(lambda t=tab: self.on_load_started(t))
        wv.loadFinished.connect(lambda ok, t=tab: self.on_load_finished(t, ok))
        wv.urlChanged.connect(lambda u, t=tab: self.on_url_changed(u, t))
        wv.titleChanged.connect(lambda txt, t=tab: self.update_tab_title_by_tab(t, txt))
        wv.loadProgress.connect(lambda p, t=tab: self.update_progress(p, t))
        wv.setUrl(url)
        return tab

    def _on_credentials_found(self, url: str, login: str, pwd: str):
        dlg = SavePasswordDialog(url, login, pwd, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.password_manager.add(url, login, pwd)

    def on_load_started(self, tab: BrowserTab):
        if tab not in self.loading_tabs:
            w = TabLoadingWidget()
            self.loading_tabs[tab] = w
            idx = self.tab_widget.indexOf(tab)
            if idx >= 0:
                self.tab_widget.tabBar().setTabButton(idx, QTabBar.ButtonPosition.LeftSide, w)
        self.loading_tabs[tab].start()
        self.globe.start()
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Загрузка...")

    def on_load_finished(self, tab: BrowserTab, ok: bool):
        if tab in self.loading_tabs:
            self.loading_tabs[tab].stop()
            idx = self.tab_widget.indexOf(tab)
            if idx >= 0:
                self.tab_widget.tabBar().setTabButton(idx, QTabBar.ButtonPosition.LeftSide, None)
            self.loading_tabs[tab].deleteLater()
            del self.loading_tabs[tab]
        if not self.loading_tabs:
            self.globe.stop()
            self.progress_bar.setVisible(False)
        page = tab.nostalgia_page
        if page._blocked:
            self.status_label.setText("Сайт заблокирован")
            page._blocked = False
        elif ok:
            self.status_label.setText("Готово")
            if not tab.is_incognito:
                url = tab.webview.url()
                if url.scheme() != "nostalgia":
                    safe_url = sanitize_url_for_history(url.toString())
                    if safe_url:
                        self._safe_add_to_history({'url': safe_url, 'title': tab.webview.title()})
        else:
            self.status_label.setText("Ошибка загрузки")

    def update_progress(self, progress: int, tab: BrowserTab):
        if self.tab_widget.currentWidget() is not tab:
            return
        self.progress_bar.setValue(progress)
        if tab in self.loading_tabs:
            if progress < 30:
                self.loading_tabs[tab].set_stage(0)
            elif progress < 80:
                self.loading_tabs[tab].set_stage(1)
            else:
                self.loading_tabs[tab].set_stage(2)

    def on_url_changed(self, url: QUrl, tab: BrowserTab):
        if self.tab_widget.currentWidget() is tab:
            self.url_bar.setText("" if url.scheme() == "nostalgia" else url.toString())
            if url.scheme() == "https":
                self.zone_label.setText("🔒 HTTPS")
                self.zone_label.setStyleSheet("color: green;")
            elif url.scheme() == "http":
                if is_local_url(url):
                    self.zone_label.setText("🏠 Локальная сеть")
                    self.zone_label.setStyleSheet("color: blue;")
                else:
                    self.zone_label.setText("⚠ HTTP")
                    self.zone_label.setStyleSheet("color: orange;")
            else:
                self.zone_label.setText("🌐")
                self.zone_label.setStyleSheet("")
        
        if url.host() and url.scheme() in ('http', 'https') and not is_local_url(url):
            if not self.tab_manager.resolve_and_check_dns(url.host()):
                tab.webview.stop()
                self.status_label.setText("DNS rebinding detected!")
                return
        
        idx = self.tab_widget.indexOf(tab)
        if idx >= 0:
            if not self.tab_manager.track_redirect_chain(idx, url.toString()):
                tab.webview.stop()
                self.status_label.setText("Too many redirects")
                return

    def update_tab_title_by_tab(self, tab: BrowserTab, title: str):
        idx = self.tab_widget.indexOf(tab)
        if idx < 0:
            return
        title = sanitize_display_text(title, MAX_TITLE_LENGTH)
        display = sanitize_display_text(title, MAX_DISPLAY_LENGTH)
        if tab.is_incognito and not display.startswith("🕵"):
            display = "🕵 " + display
        self.tab_widget.setTabText(idx, display)
        if idx == self.tab_widget.currentIndex():
            self.setWindowTitle(f"{display} - Nostalgia")
        url_str = tab.webview.url().toString()
        for e in reversed(self.history):
            if e.get('url') == url_str and not e.get('title'):
                e['title'] = title
                break

    def _stop_loading_for_tab(self, tab: BrowserTab):
        if tab in self.loading_tabs:
            self.loading_tabs[tab].stop()
            idx = self.tab_widget.indexOf(tab)
            if idx >= 0:
                self.tab_widget.tabBar().setTabButton(idx, QTabBar.ButtonPosition.LeftSide, None)
            self.loading_tabs[tab].deleteLater()
            del self.loading_tabs[tab]
        if not self.loading_tabs:
            self.globe.stop()
            self.progress_bar.setVisible(False)

    def _on_site_blocked(self, tab: BrowserTab, domain: str):
        self._stop_loading_for_tab(tab)
        self.status_label.setText("Сайт заблокирован")
        if self.site_filter.block_message:
            BlockedDialog(domain, self).exec()

    def _on_scheme_blocked(self, tab: BrowserTab, scheme: str):
        self._stop_loading_for_tab(tab)
        self.status_label.setText(f"Схема {scheme} заблокирована")
        SchemeBlockedDialog(scheme, self).exec()

    def navigate_to_url(self):
        if not self._navigation_limiter.can_proceed():
            self.status_label.setText("Слишком много запросов")
            return
        text = self.url_bar.text().strip()
        if not text:
            return
        
        sanitized_url = SanitizedUrl.sanitize(text)
        if not sanitized_url:
            self.status_label.setText("Неверный URL")
            return
        
        try:
            parsed = urlparse(sanitized_url)
            if parsed.scheme.lower() in BLOCKED_SCHEMES:
                self.status_label.setText(f"Схема {parsed.scheme} заблокирована")
                return
            
            if sanitized_url.startswith(("http://", "https://", "about:")):
                url = QUrl(sanitized_url)
            elif "." in sanitized_url and " " not in sanitized_url:
                url = QUrl("https://" + sanitized_url)
            else:
                tmpl = SEARCH_ENGINES.get(self.current_engine, SEARCH_ENGINES["Google"])
                url = QUrl(tmpl.replace("{query}", quote_plus(sanitize_search_query(sanitized_url))))
            
            if not url.isValid():
                raise ValueError("Неверный URL")
            
            if is_local_url(url) and url.scheme() == 'https':
                url.setScheme('http')
            
            if not is_safe_url(url):
                self.status_label.setText(f"Схема {url.scheme()} заблокирована")
                return
            self.load_url(url)
        except Exception as e:
            self.status_label.setText(f"Ошибка: {str(e)[:100]}")

    def load_url(self, url):
        if isinstance(url, str):
            url = QUrl(url)
        if is_local_url(url) and url.scheme() == 'https':
            new_url = QUrl(url)
            new_url.setScheme('http')
            url = new_url
        wv = self.get_current_webview()
        if wv:
            wv.setUrl(url)

    def go_back(self):
        wv = self.get_current_webview()
        if wv:
            wv.back()

    def go_forward(self):
        wv = self.get_current_webview()
        if wv:
            wv.forward()

    def stop_loading(self):
        wv = self.get_current_webview()
        if wv:
            wv.stop()
        if not self.loading_tabs:
            self.globe.stop()
            self.progress_bar.setVisible(False)
        self.status_label.setText("Остановлено")

    def reload_page(self):
        wv = self.get_current_webview()
        if wv:
            wv.reload()

    def go_home(self):
        self.load_url(self.homepage)

    def focus_url_bar(self):
        self.url_bar.selectAll()
        self.url_bar.setFocus()

    def tab_changed(self, index: int):
        tab = self.tab_widget.widget(index)
        if isinstance(tab, BrowserTab):
            url = tab.webview.url()
            self.url_bar.setText("" if url.scheme() == "nostalgia" else url.toString())
            if url.scheme() == "https":
                self.zone_label.setText("🔒 HTTPS")
                self.zone_label.setStyleSheet("color: green;")
            elif url.scheme() == "http":
                if is_local_url(url):
                    self.zone_label.setText("🏠 Локальная")
                    self.zone_label.setStyleSheet("color: blue;")
                else:
                    self.zone_label.setText("⚠ HTTP")
                    self.zone_label.setStyleSheet("color: orange;")
            else:
                self.zone_label.setText("🌐")
                self.zone_label.setStyleSheet("")

    def close_tab(self, index: int):
        if self.tab_widget.count() > 1:
            tab = self.tab_widget.widget(index)
            if tab:
                self.tab_manager.clear_redirect_chain(index)
                if tab in self.loading_tabs:
                    self.loading_tabs[tab].stop()
                    del self.loading_tabs[tab]
                wv = tab.webview
                wv.stop()
                wv.setUrl(QUrl("about:blank"))
            self.tab_widget.removeTab(index)
            if tab:
                tab.deleteLater()
        else:
            reply = QMessageBox.question(self, "Выход", "Закрыть браузер?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.save_settings()
                self.site_filter.save_lists()
                QApplication.quit()

    def close_current_tab(self):
        self.close_tab(self.tab_widget.currentIndex())

    def next_tab(self):
        current = self.tab_widget.currentIndex()
        self.tab_widget.setCurrentIndex((current + 1) % self.tab_widget.count())

    def prev_tab(self):
        current = self.tab_widget.currentIndex()
        self.tab_widget.setCurrentIndex((current - 1) % self.tab_widget.count())

    def switch_to_tab(self, index: int):
        if 0 <= index < self.tab_widget.count():
            self.tab_widget.setCurrentIndex(index)

    def get_current_webview(self) -> QWebEngineView | None:
        tab = self.tab_widget.currentWidget()
        return tab.webview if isinstance(tab, BrowserTab) else None

    def zoom_in(self):
        wv = self.get_current_webview()
        if wv:
            wv.setZoomFactor(min(wv.zoomFactor() + 0.1, 5.0))
            self.zoom_label.setText(f"{int(wv.zoomFactor()*100)}%")

    def zoom_out(self):
        wv = self.get_current_webview()
        if wv:
            wv.setZoomFactor(max(wv.zoomFactor() - 0.1, 0.25))
            self.zoom_label.setText(f"{int(wv.zoomFactor()*100)}%")

    def zoom_reset(self):
        wv = self.get_current_webview()
        if wv:
            wv.setZoomFactor(1.0)
            self.zoom_label.setText("100%")

    def _toggle_popup_blocking(self, checked: bool):
        self.block_popups = checked
        for i in range(self.tab_widget.count()):
            tab = self.tab_widget.widget(i)
            if isinstance(tab, BrowserTab):
                tab.nostalgia_page.block_popups = checked
        self.save_settings()
        self.status_label.setText(f"Блокировка окон {'вкл' if checked else 'выкл'}")

    def show_filter_settings(self):
        if FilterDialog(self.site_filter, self).exec():
            self.update_filter_indicator()

    def update_filter_indicator(self):
        self.filter_status.setText("🔒" if self.site_filter.filter_enabled else "")

    def show_homepage_settings(self):
        dlg = HomepageDialog(self.homepage, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            new_hp = dlg.homepage
            if new_hp and is_safe_url(QUrl(new_hp)):
                self.homepage = new_hp
                self.save_settings()

    def show_theme_dialog(self):
        dlg = ThemeDialog(self.current_theme, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.current_theme = dlg.selected_theme
            apply_theme(QApplication.instance(), self.current_theme)
            self.save_settings()

    def show_search_engine_dialog(self):
        dlg = SearchEngineDialog(self.current_engine, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.current_engine = dlg.selected
            self.save_settings()

    def show_cookie_manager(self):
        QMessageBox.information(self, "Cookie", "Используйте Ctrl+Shift+Del для очистки")

    def show_password_manager(self):
        dlg = PasswordManagerDialog(self.password_manager, self)
        dlg.show()

    def show_bookmark_manager(self):
        dlg = BookmarkManagerDialog(self.bookmarks, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.save_settings()

    def show_clear_data_dialog(self):
        dlg = ClearDataDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        
        profile = self._profile
        cleared = []
        
        if dlg.clear_history:
            self.history.clear()
            self._history_queue.clear()
            cleared.append("история")
        
        if dlg.clear_cookies:
            try:
                profile.cookieStore().deleteAllCookies()
                cleared.append("cookie")
            except Exception as e:
                SafeLogger.warning("Error clearing cookies: %s", e)
        
        if dlg.clear_cache:
            try:
                profile.clearHttpCache()
                cleared.append("кэш")
            except Exception as e:
                SafeLogger.warning("Error clearing cache: %s", e)
        
        if dlg.clear_passwords:
            self.password_manager.clear_all()
            cleared.append("пароли")
        
        if dlg.clear_bookmarks:
            self.bookmarks.clear()
            cleared.append("закладки")
        
        self.save_settings()
        msg = ", ".join(cleared) if cleared else "ничего"
        self.status_label.setText(f"Очищено: {msg}")
        QMessageBox.information(self, "Очистка", f"Очищено: {msg}.")

    def show_downloads(self):
        if self._download_manager is None:
            self._download_manager = DownloadManagerDialog(self)
        self._download_manager.show()

    def open_find_bar(self):
        tab = self.tab_widget.currentWidget()
        if isinstance(tab, BrowserTab):
            tab.find_bar.open_bar()

    def add_to_bookmarks(self):
        wv = self.get_current_webview()
        if wv:
            url = wv.url()
            if not is_safe_url(url):
                return
            url_str = url.toString()
            title = wv.title() or url_str
            name, ok = QInputDialog.getText(self, "Добавить закладку", "Название:", text=sanitize_display_text(title, 100))
            if ok and name:
                self.bookmarks[name] = url_str
                self.save_settings()
                self.status_label.setText("Закладка добавлена")

    def show_history(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("История")
        dlg.resize(600, 400)
        layout = QVBoxLayout(dlg)
        lw = QListWidget()
        for e in reversed(self.history[-200:]):
            url = e.get('url', '')
            if not url:
                continue
            title = e.get('title', '')
            time_str = ""
            if e.get('time'):
                try:
                    dt = datetime.datetime.fromisoformat(e['time'])
                    time_str = f" [{dt.strftime('%d.%m.%Y %H:%M')}]"
                except:
                    pass
            text = f"{sanitize_display_text(title, 50)}{time_str} — {sanitize_display_text(url, 80)}"
            item = QListWidgetItem()
            item.setText(text)
            item.setData(Qt.ItemDataRole.UserRole, url)
            lw.addItem(item)
        layout.addWidget(lw)

        def open_from_history(item):
            url = item.data(Qt.ItemDataRole.UserRole)
            if url:
                q = QUrl(url)
                if is_safe_url(q):
                    self.add_new_tab(q)
                else:
                    self.status_label.setText("Небезопасный URL")
            dlg.accept()
        lw.itemDoubleClicked.connect(open_from_history)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(dlg.reject)
        layout.addWidget(bb)
        dlg.exec()

    def show_search(self):
        text, ok = QInputDialog.getText(self, "Поиск", "Введите запрос:")
        if ok and text:
            safe_text = sanitize_search_query(text)
            if safe_text:
                tmpl = SEARCH_ENGINES.get(self.current_engine, SEARCH_ENGINES["Google"])
                self.load_url(tmpl.replace("{query}", quote_plus(safe_text)))

    def toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def show_about(self):
        QMessageBox.about(self, "О программе",
            "Nostalgia Browser v0.8.5\n\n"
            "Безопасный браузер в стиле Windows 98\n"
            "© 2026 Nostalgia Project")

    def closeEvent(self, event):
        if self.tab_widget.count() > 1:
            reply = QMessageBox.question(self, "Выход", f"Закрыть {self.tab_widget.count()} вкладок?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        
        self._flush_history_queue()
        self._cleanup_security()
        self.save_settings()
        self.site_filter.save_lists()
        
        if hasattr(self, 'globe'):
            self.globe.stop()
        
        for w in list(self.loading_tabs.values()):
            w.stop()
        
        try:
            QApplication.instance().aboutToQuit.disconnect(self._cleanup_security)
        except TypeError:
            pass
        
        event.accept()


def main():
    QWebEngineUrlScheme.registerScheme(QWebEngineUrlScheme(b"nostalgia"))
    
    app = QApplication(sys.argv)
    app.setApplicationName("Nostalgia Browser")
    app.open_folder = lambda path: None
    
    font = QFont("MS Sans Serif", 8)
    if "Tahoma" in QFontDatabase.families():
        font = QFont("Tahoma", 8)
    app.setFont(font)
    
    browser = NostalgiaBrowser()
    apply_theme(app, browser.current_theme)
    app.open_folder = browser.open_folder
    browser.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
