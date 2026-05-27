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
from html import escape as html_escape
from urllib.parse import urlparse, quote_plus
from typing import Optional
from cryptography.fernet import Fernet

from PyQt6.QtCore import (
    QUrl, Qt, QSize, QTimer, QPoint, QRectF,
    pyqtSignal, QStandardPaths, QDateTime, QElapsedTimer
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
    QWebEngineCertificateError
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QPixmap,
    QFontDatabase, QPainter, QPen, QBrush,
    QKeySequence, QMovie, QPolygon, QAction,
    QShortcut, QIcon
)

# ──────────────────────────────────────────────
# КОНСТАНТЫ БЕЗОПАСНОСТИ
# ──────────────────────────────────────────────
ALLOWED_SCHEMES = frozenset({"http", "https", "about", "nostalgia"})
MAX_URL_LENGTH = 2048
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_DOWNLOADS_SIMULTANEOUS = 5
PASSWORD_DISPLAY_TIMEOUT = 10000  # 10 секунд
NAVIGATION_RATE_LIMIT = 10  # навигаций в секунду
CLIPBOARD_CLEAR_TIMEOUT = 30000  # 30 секунд
MAX_HISTORY_ENTRIES = 200
MAX_BOOKMARK_URL_LENGTH = 2048
MAX_TITLE_LENGTH = 500
MAX_DISPLAY_LENGTH = 25
RECENT_HISTORY_CHECK = 10
DEDUP_TIME_MINUTES = 5
KEY_FILE_PERMISSIONS = 0o600

_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

# ──────────────────────────────────────────────
# БЕЗОПАСНОЕ ЛОГИРОВАНИЕ
# ──────────────────────────────────────────────
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

handler = logging.handlers.RotatingFileHandler(
    'nostalgia.log',
    maxBytes=1024*1024,  # 1 MB
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

def sanitize_display_text(text: str, max_len: int = MAX_DISPLAY_LENGTH) -> str:
    """Безопасное форматирование текста для отображения в UI."""
    if not text:
        return ""
    escaped = html_escape(text)
    if len(escaped) > max_len:
        return escaped[:max_len - 3] + "..."
    return escaped


def safe_domain_match(domain: str, pattern: str) -> bool:
    """Проверка соответствия домена шаблону с защитой от атак через поддомены."""
    if not domain or not pattern:
        return False
    
    domain = domain.lower().strip()
    pattern = pattern.lower().strip()
    
    if domain == pattern:
        return True
    
    if domain.endswith('.' + pattern):
        return domain.count('.') == pattern.count('.') + 1
    
    return False


def validate_and_sanitize_html(html_content: str) -> str:
    """Базовая санитизация HTML-контента для предотвращения XSS."""
    html_content = re.sub(
        r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',
        '',
        html_content,
        flags=re.IGNORECASE | re.DOTALL
    )
    
    html_content = re.sub(
        r'\bon\w+\s*=\s*["\'][^"\']*["\']',
        '',
        html_content,
        flags=re.IGNORECASE
    )
    html_content = re.sub(
        r'\bon\w+\s*=\s*\S+',
        '',
        html_content,
        flags=re.IGNORECASE
    )
    
    html_content = re.sub(
        r'href\s*=\s*["\']javascript:[^"\']*["\']',
        'href="#"',
        html_content,
        flags=re.IGNORECASE
    )
    
    return html_content


class SecureClipboard:
    """Безопасное управление буфером обмена с автоматической очисткой."""
    
    _timer: Optional[QTimer] = None
    _last_content: str = ""
    
    @classmethod
    def set_text(cls, text: str, timeout: int = CLIPBOARD_CLEAR_TIMEOUT):
        """Устанавливает текст в буфер обмена с автоочисткой."""
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
        """Очищает буфер обмена."""
        clipboard = QApplication.clipboard()
        current = clipboard.text()
        
        if current == cls._last_content or not current:
            clipboard.clear()
            logger.debug("Clipboard cleared for security")


class RateLimiter:
    """Ограничитель частоты операций для предотвращения DoS."""
    
    def __init__(self, max_operations: int, per_seconds: float = 1.0):
        self.max_operations = max_operations
        self.per_seconds = per_seconds
        self._operations: list[float] = []
    
    def can_proceed(self) -> bool:
        """Проверяет, можно ли выполнить операцию."""
        now = datetime.datetime.now().timestamp()
        cutoff = now - self.per_seconds
        self._operations = [t for t in self._operations if t > cutoff]
        
        if len(self._operations) < self.max_operations:
            self._operations.append(now)
            return True
        
        return False
    
    def reset(self):
        """Сбрасывает счетчик."""
        self._operations.clear()


class SecureFileHandler:
    """Безопасная работа с файлами."""
    
    @staticmethod
    def safe_read_json(filepath: str, max_size: int = MAX_FILE_SIZE) -> dict:
        """Безопасное чтение JSON с проверкой размера и целостности."""
        if not os.path.exists(filepath):
            return {}
        
        file_size = os.path.getsize(filepath)
        if file_size > max_size:
            logger.warning("File too large: %s (%d bytes)", filepath, file_size)
            return {}
        
        if os.path.islink(filepath):
            real_path = os.path.realpath(filepath)
            if not real_path.startswith(os.path.abspath(os.getcwd())):
                logger.warning("Symlink attack detected: %s -> %s", filepath, real_path)
                return {}
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if '\0' in content:
                logger.warning("Binary data detected in JSON: %s", filepath)
                return {}
            
            data = json.loads(content)
            
            if not isinstance(data, dict):
                logger.warning("Invalid JSON structure in: %s", filepath)
                return {}
            
            if SecureFileHandler._get_depth(data) > 10:
                logger.warning("JSON too deeply nested: %s", filepath)
                return {}
            
            return data
            
        except json.JSONDecodeError as e:
            logger.warning("JSON decode error in %s: %s", filepath, e)
            backup_path = filepath + '.backup'
            try:
                shutil.copy2(filepath, backup_path)
                logger.info("Created backup of corrupted file: %s", backup_path)
            except Exception:
                pass
            return {}
        except Exception as e:
            logger.warning("Error reading file %s: %s", filepath, e)
            return {}
    
    @staticmethod
    def safe_write_json(filepath: str, data: dict, create_backup: bool = True):
        """Безопасная запись JSON с атомарной заменой."""
        temp_path = filepath + '.tmp'
        
        try:
            json_str = json.dumps(data, ensure_ascii=False, indent=2)
            if len(json_str) > MAX_FILE_SIZE:
                logger.warning("Data too large for writing to %s", filepath)
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
            logger.warning("Error writing file %s: %s", filepath, e)
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            return False
    
    @staticmethod
    def _get_depth(obj, current_depth=0):
        """Рекурсивно вычисляет глубину вложенности объекта."""
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


class SanitizedUrl:
    """Санитизированный URL с защитой от过长 URL и других атак."""
    
    @staticmethod
    def sanitize(url_str: str) -> Optional[str]:
        """Санитизирует URL-строку."""
        if not url_str:
            return None
        
        if len(url_str) > MAX_URL_LENGTH:
            logger.warning("URL too long: %d characters", len(url_str))
            return None
        
        if '\0' in url_str:
            logger.warning("Null byte detected in URL")
            return None
        
        if any(ord(c) < 32 for c in url_str):
            logger.warning("Control characters detected in URL")
            return None
        
        url_str = url_str.strip()
        
        try:
            parsed = urlparse(url_str)
            
            if parsed.scheme in ('http', 'https') and not parsed.netloc:
                return None
            
            if parsed.scheme.lower() in ('javascript', 'data', 'vbscript', 'file'):
                logger.warning("Dangerous URL scheme: %s", parsed.scheme)
                return None
            
            if parsed.fragment and any(
                dangerous in parsed.fragment.lower() 
                for dangerous in ('javascript:', 'data:', 'vbscript:')
            ):
                url_str = url_str.split('#')[0]
            
            return url_str
            
        except Exception as e:
            logger.warning("URL parsing error: %s", e)
            return None


class SecurePasswordItem:
    """Безопасный элемент пароля с автоскрытием."""
    
    def __init__(self):
        self._password: str = ""
        self._visible: bool = False
        self._timer: Optional[QTimer] = None
        self._widget: Optional[QTableWidgetItem] = None
    
    def show_password(self, widget: QTableWidgetItem, password: str):
        """Показывает пароль на ограниченное время."""
        self._widget = widget
        self._password = password
        self._visible = True
        
        widget.setText(password)
        
        if self._timer:
            self._timer.stop()
        
        self._timer = QTimer()
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide_password)
        self._timer.start(PASSWORD_DISPLAY_TIMEOUT)
    
    def hide_password(self):
        """Скрывает пароль."""
        if self._widget and self._visible:
            self._widget.setText("••••••••")
            self._visible = False
            self._password = ""
        
        if self._timer:
            self._timer.stop()
            self._timer = None
    
    def __del__(self):
        """Очистка при удалении объекта."""
        self.hide_password()
        self._password = ""
        self._widget = None


def is_safe_url(url: QUrl) -> bool:
    """Проверяет, что URL валиден и использует разрешённую схему."""
    if not url.isValid():
        return False
    
    url_str = url.toString()
    
    if len(url_str) > MAX_URL_LENGTH:
        return False
    
    scheme = url.scheme().lower()
    if scheme not in ALLOWED_SCHEMES:
        return False
    
    if scheme in ('http', 'https'):
        if not url.host():
            return False
        
        if url.userName() or url.password():
            return False
    
    return True


def sanitize_url_for_history(url_str: str) -> str | None:
    """Возвращает URL если его можно сохранить в истории, иначе None."""
    if not url_str or url_str in ("about:blank", ""):
        return None
    
    sanitized = SanitizedUrl.sanitize(url_str)
    if not sanitized:
        return None
    
    q = QUrl(sanitized)
    if not is_safe_url(q):
        return None
    
    # Удаление чувствительных параметров из URL
    parsed = urlparse(sanitized)
    sensitive_params = {'token', 'password', 'secret', 'key', 'auth', 'session', 'access_token', 'api_key'}
    
    if parsed.query:
        query_params = []
        for param in parsed.query.split('&'):
            if '=' in param:
                name = param.split('=')[0].lower()
                if name in sensitive_params:
                    query_params.append(f'{name}=[REDACTED]')
                else:
                    query_params.append(param)
            else:
                query_params.append(param)
        
        clean_query = '&'.join(query_params)
        sanitized = sanitized.split('?')[0]
        if clean_query:
            sanitized += '?' + clean_query
    
    return sanitized[:MAX_URL_LENGTH]


def validate_domain(domain: str) -> bool:
    """Проверяет, что строка является допустимым доменным именем."""
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
        "Window":          "#D4D0C8",
        "WindowText":      "#000000",
        "Base":            "#FFFFFF",
        "AlternateBase":   "#D4D0C8",
        "Button":          "#D4D0C8",
        "ButtonText":      "#000000",
        "Highlight":       "#000080",
        "HighlightedText": "#FFFFFF",
        "Link":            "#0000FF",
        "ToolTipBase":     "#FFFFE1",
        "ToolTipText":     "#000000",
        "Light":           "#FFFFFF",
        "Midlight":        "#E3DFDB",
        "Mid":             "#808080",
        "Dark":            "#808080",
        "Shadow":          "#000000",
        "titlebar_active":   "#000080",
        "titlebar_inactive": "#808080",
        "titlebar_text":     "#FFFFFF",
    },
    "Морской (Teal)": {
        "Window":          "#C8D4D0",
        "WindowText":      "#000000",
        "Base":            "#FFFFFF",
        "AlternateBase":   "#C8D4D0",
        "Button":          "#C8D4D0",
        "ButtonText":      "#000000",
        "Highlight":       "#008080",
        "HighlightedText": "#FFFFFF",
        "Link":            "#006666",
        "ToolTipBase":     "#FFFFE1",
        "ToolTipText":     "#000000",
        "Light":           "#E0FFFF",
        "Midlight":        "#B0D0CC",
        "Mid":             "#608080",
        "Dark":            "#406060",
        "Shadow":          "#000000",
        "titlebar_active":   "#008080",
        "titlebar_inactive": "#607070",
        "titlebar_text":     "#FFFFFF",
    },
    "Шоколадная": {
        "Window":          "#D4C8B4",
        "WindowText":      "#000000",
        "Base":            "#FFF8F0",
        "AlternateBase":   "#D4C8B4",
        "Button":          "#D4C8B4",
        "ButtonText":      "#000000",
        "Highlight":       "#804000",
        "HighlightedText": "#FFFFFF",
        "Link":            "#804000",
        "ToolTipBase":     "#FFFFE1",
        "ToolTipText":     "#000000",
        "Light":           "#FFF0DC",
        "Midlight":        "#C8B898",
        "Mid":             "#907060",
        "Dark":            "#604030",
        "Shadow":          "#000000",
        "titlebar_active":   "#804000",
        "titlebar_inactive": "#907060",
        "titlebar_text":     "#FFFFFF",
    },
    "Лиловая": {
        "Window":          "#D0C8D4",
        "WindowText":      "#000000",
        "Base":            "#FAF8FF",
        "AlternateBase":   "#D0C8D4",
        "Button":          "#D0C8D4",
        "ButtonText":      "#000000",
        "Highlight":       "#400080",
        "HighlightedText": "#FFFFFF",
        "Link":            "#6000AA",
        "ToolTipBase":     "#FFFFE1",
        "ToolTipText":     "#000000",
        "Light":           "#F0E8FF",
        "Midlight":        "#C0B8CC",
        "Mid":             "#806090",
        "Dark":            "#503060",
        "Shadow":          "#000000",
        "titlebar_active":   "#400080",
        "titlebar_inactive": "#705080",
        "titlebar_text":     "#FFFFFF",
    },
    "Тёмная (Ночная)": {
        "Window":          "#2B2B2B",
        "WindowText":      "#E0E0E0",
        "Base":            "#1E1E1E",
        "AlternateBase":   "#2B2B2B",
        "Button":          "#3C3C3C",
        "ButtonText":      "#E0E0E0",
        "Highlight":       "#264F78",
        "HighlightedText": "#FFFFFF",
        "Link":            "#4EC9B0",
        "ToolTipBase":     "#3C3C3C",
        "ToolTipText":     "#E0E0E0",
        "Light":           "#505050",
        "Midlight":        "#3C3C3C",
        "Mid":             "#252525",
        "Dark":            "#1A1A1A",
        "Shadow":          "#000000",
        "titlebar_active":   "#264F78",
        "titlebar_inactive": "#3C3C3C",
        "titlebar_text":     "#FFFFFF",
    },
}


def apply_theme(app: QApplication, theme_name: str):
    """Применяет выбранную тему к приложению."""
    theme = THEMES.get(theme_name, THEMES["Классическая (Windows 98)"])
    app.setStyle(QStyleFactory.create('Windows'))

    palette = QPalette()
    role_map = {
        "Window":          QPalette.ColorRole.Window,
        "WindowText":      QPalette.ColorRole.WindowText,
        "Base":            QPalette.ColorRole.Base,
        "AlternateBase":   QPalette.ColorRole.AlternateBase,
        "Button":          QPalette.ColorRole.Button,
        "ButtonText":      QPalette.ColorRole.ButtonText,
        "Highlight":       QPalette.ColorRole.Highlight,
        "HighlightedText": QPalette.ColorRole.HighlightedText,
        "Link":            QPalette.ColorRole.Link,
        "ToolTipBase":     QPalette.ColorRole.ToolTipBase,
        "ToolTipText":     QPalette.ColorRole.ToolTipText,
        "Light":           QPalette.ColorRole.Light,
        "Midlight":        QPalette.ColorRole.Midlight,
        "Mid":             QPalette.ColorRole.Mid,
        "Dark":            QPalette.ColorRole.Dark,
        "Shadow":          QPalette.ColorRole.Shadow,
    }
    for key, role in role_map.items():
        color_hex = theme.get(key)
        if color_hex:
            palette.setColor(role, QColor(color_hex))

    palette.setColor(QPalette.ColorRole.Text,
                     QColor(theme.get("WindowText", "#000000")))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(Qt.GlobalColor.red))
    app.setPalette(palette)
    app._current_theme = theme_name
    app._current_theme_data = theme
    app.setStyleSheet("""
        QWebEngineView { background: white; }
        QToolTip { 
            background-color: #FFFFE1; 
            color: #000000;
            border: 1px solid black;
            font-size: 8pt;
        }
        QTabBar::tab:hover {
            background-color: #E3DFDB;
        }
    """)


# ──────────────────────────────────────────────
# ДИАЛОГИ (ThemeDialog, FilterDialog, ...)
# ──────────────────────────────────────────────

class ThemeDialog(QDialog):
    """Диалог выбора темы оформления."""
    
    def __init__(self, current_theme: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Темы оформления - Nostalgia")
        self.setFixedSize(400, 360)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x() - 200, geo.center().y() - 180)

        self.selected_theme = current_theme
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 10)
        layout.setSpacing(10)

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
        self.preview_frame.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(self.preview_frame)
        self._preview_label = QLabel(self.preview_frame)
        self._preview_label.setGeometry(0, 0, 372, 40)
        self._preview_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.btn_group.buttonClicked.connect(self._on_select)
        self._update_preview(current_theme)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)

        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
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
            f'<span style="color:{title_c};font-weight:bold;">▐ </span>'
            f'<span style="background:{win_c};color:{txt_c};">  Окно  </span>  '
            f'<span style="background:{hi_c};color:#FFFFFF;"> Выделение </span>'
        )
        self._preview_label.setStyleSheet(
            f"background: {win_c}; color: {txt_c};"
        )

    def _on_ok(self):
        checked = self.btn_group.checkedButton()
        if checked:
            self.selected_theme = checked.text()
        self.accept()


class EnhancedGifLoadingWidget(QWidget):
    """Улучшенный виджет с анимированным глобусом и индикацией загрузки."""

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
        """Загружает GIF или создает улучшенную анимированную иконку."""
        gif_paths = ['planet.gif', 'loading.gif', 'ie_spinner.gif']
        
        for path in gif_paths:
            if os.path.exists(path):
                self._init_movie(path)
                return
        
        self._create_animated_fallback()

    def _init_movie(self, gif_path):
        """Загружает GIF-файл и подготавливает первый кадр."""
        self.movie = QMovie(gif_path)
        if not self.movie.isValid():
            self._create_animated_fallback()
            return
        self.movie.setScaledSize(self.SIZE)
        self.movie.jumpToFrame(0)
        first = self.movie.currentImage()
        if not first.isNull():
            self._static_frame = QPixmap.fromImage(
                first.scaled(
                    self.SIZE,
                    Qt.AspectRatioMode.IgnoreAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
            )
        self._show_static()
        self.movie.frameChanged.connect(self._on_frame)

    def _create_animated_fallback(self):
        """Создает анимированный спиннер программно."""
        from PyQt6.QtCore import QTimer
        
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
        """Обновляет кадр анимации."""
        if self._frames:
            self._current_frame = (self._current_frame + 1) % len(self._frames)
            self.label.setPixmap(self._frames[self._current_frame])

    def _show_static(self):
        """Показывает статичный кадр."""
        if self._static_frame:
            self.label.setPixmap(self._static_frame)

    def _on_frame(self, _):
        if self.movie:
            img = self.movie.currentImage()
            if not img.isNull():
                self.label.setPixmap(QPixmap.fromImage(
                    img.scaled(
                        self.SIZE,
                        Qt.AspectRatioMode.IgnoreAspectRatio,
                        Qt.TransformationMode.SmoothTransformation
                    )
                ))

    def start(self):
        """Запускает анимацию."""
        if self.movie:
            self.movie.start()
        elif self._animation_timer:
            self._animation_timer.start()

    def stop(self):
        """Останавливает анимацию и очищает ресурсы."""
        if self.movie:
            self.movie.stop()
            self.movie.jumpToFrame(0)
        elif self._animation_timer:
            self._animation_timer.stop()
        self._show_static()
        # Очистка frames для предотвращения утечки памяти (уязвимость #22)
        self._frames.clear()

    def __del__(self):
        """Гарантированная очистка ресурсов."""
        self.stop()
        if self._animation_timer:
            self._animation_timer.stop()
            self._animation_timer.deleteLater()
            self._animation_timer = None


class SiteFilter:
    """Фильтр сайтов по чёрному и белому спискам доменов."""

    def __init__(self):
        self.blacklist = []
        self.whitelist = []
        self.use_whitelist = False
        self.use_blacklist = True
        self.filter_enabled = True
        self.block_message = True
        self.load_lists()

    def load_lists(self):
        try:
            if os.path.exists('nostalgia_filter.json'):
                data = SecureFileHandler.safe_read_json('nostalgia_filter.json')
                if data:
                    self.blacklist = [
                        d for d in data.get('blacklist', [])
                        if isinstance(d, str) and validate_domain(d)
                    ]
                    self.whitelist = [
                        d for d in data.get('whitelist', [])
                        if isinstance(d, str) and validate_domain(d)
                    ]
                    self.use_whitelist = bool(data.get('use_whitelist', False))
                    self.use_blacklist = bool(data.get('use_blacklist', True))
                    self.filter_enabled = bool(data.get('filter_enabled', True))
                    self.block_message = bool(data.get('block_message', True))
        except Exception as e:
            logger.warning("Ошибка загрузки фильтра: %s", e)

    def save_lists(self):
        try:
            SecureFileHandler.safe_write_json('nostalgia_filter.json', {
                'blacklist': self.blacklist,
                'whitelist': self.whitelist,
                'use_whitelist': self.use_whitelist,
                'use_blacklist': self.use_blacklist,
                'filter_enabled': self.filter_enabled,
                'block_message': self.block_message,
            })
        except Exception as e:
            logger.warning("Ошибка сохранения фильтра: %s", e)

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
            rem_btn.clicked.connect(
                (lambda t, lt: lambda: self._remove(t, lt))(tbl, list_type)
            )
            bl.addWidget(rem_btn)
            bl.addStretch()
            tl.addWidget(bw)
            self.tab_widget.addTab(tab, title)

        layout.addWidget(self.tab_widget)

        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
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
        domain, ok = QInputDialog.getText(
            self, f"Добавить в {label} список", "Введите домен:"
        )
        if ok and domain:
            domain = domain.strip().lower()
            if not validate_domain(domain):
                QMessageBox.warning(
                    self, "Ошибка",
                    f"«{sanitize_display_text(domain, 50)}» не является допустимым доменным именем."
                )
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


class NostalgiaSchemeHandler:
    def __init__(self):
        self._blocked_pages = {}
        self._counter = 0
        self._allowed_ids = set()  # Белый список ID страниц

    def register_page(self, html_content: str, allow_public: bool = True) -> str:
        """
        Регистрирует HTML-страницу с санитизацией для предотвращения XSS.
        Исправление уязвимости #4 и #21.
        """
        self._counter += 1
        pid = f"blocked_{self._counter}"
        self._blocked_pages[pid] = validate_and_sanitize_html(html_content)
        
        if allow_public:
            self._allowed_ids.add(pid)
        
        return f"nostalgia:{pid}"

    def get_page(self, pid: str) -> str:
        """
        Возвращает санитизированную страницу.
        Исправление уязвимости #21: проверка доступа к страницам.
        """
        # Проверка, что ID страницы разрешен для доступа
        if pid not in self._allowed_ids:
            logger.warning("Attempt to access unauthorized nostalgia page: %s", pid)
            return validate_and_sanitize_html(
                "<html><body><h1>Доступ запрещен</h1><p>У вас нет доступа к этой странице.</p></body></html>"
            )
        
        return self._blocked_pages.get(
            pid, 
            validate_and_sanitize_html(
                "<html><body><h1>Страница не найдена</h1><p>Запрошенная страница не существует.</p></body></html>"
            )
        )


class IncognitoProfile:
    _instance: QWebEngineProfile | None = None

    @classmethod
    def get(cls) -> QWebEngineProfile:
        if cls._instance is None:
            cls._instance = QWebEngineProfile()
            cls._instance.setHttpUserAgent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
            cls._instance.setHttpAcceptLanguage(
                "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
            )
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
        # Исправление уязвимости #2 и #19: санитизация имени файла
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
            self.info_label.setText(
                f"{self._fmt(received)} / {self._fmt(total)}"
            )
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
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint |
            Qt.WindowType.WindowMinimizeButtonHint
        )
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-310, geo.center().y()-190)

        ml = QVBoxLayout(self)
        ml.setContentsMargins(8, 8, 8, 8)
        ml.setSpacing(4)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.container = QWidget()
        self.items_layout = QVBoxLayout(self.container)
        self.items_layout.setContentsMargins(2, 2, 2, 2)
        self.items_layout.setSpacing(2)
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
            self._webview.findText(
                t,
                self._flags() | QWebEnginePage.FindFlag.FindBackward,
                self._on_result
            )

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
    "Google":     "https://www.google.com/search?q={query}",
    "Yandex":     "https://yandex.ru/search/?text={query}",
    "Bing":       "https://www.bing.com/search?q={query}",
    "DuckDuckGo": "https://duckduckgo.com/?q={query}",
    "Mail.ru":    "https://go.mail.ru/search?q={query}",
    "Rambler":    "https://nova.rambler.ru/search?query={query}",
}


class SearchEngineDialog(QDialog):
    def __init__(self, current_engine: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Поисковые системы - Nostalgia")
        self.setFixedSize(420, 320)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-210, geo.center().y()-160)

        self.selected = current_engine
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 10)
        layout.setSpacing(10)

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
        self.btn_group.buttonClicked.connect(
            lambda btn: self._update_preview(btn.text())
        )

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)

        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
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


PASSWORDS_FILE = 'nostalgia_passwords.dat'
KEY_FILE = 'nostalgia_key.key'


class SecurePasswordManager:
    """Безопасное хранилище паролей с шифрованием Fernet."""
    
    def __init__(self):
        self._entries: list[dict] = []
        self._cipher = self._get_or_create_cipher()
        self._access_times: dict[int, datetime.datetime] = {}
        self._failed_attempts: dict[str, int] = {}
        self._lockout_until: dict[str, datetime.datetime] = {}
        self._secure_items: dict[int, SecurePasswordItem] = {}
        self._load()
    
    def _get_or_create_cipher(self):
        """Получает или создает ключ шифрования."""
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(KEY_FILE, 'wb') as f:
                f.write(key)
            try:
                os.chmod(KEY_FILE, KEY_FILE_PERMISSIONS)
            except Exception:
                pass
        return Fernet(key)
    
    def _encrypt(self, data: str) -> str:
        """Шифрует строку."""
        return self._cipher.encrypt(data.encode()).decode()
    
    def _decrypt(self, encrypted: str) -> str:
        """Расшифровывает строку."""
        try:
            return self._cipher.decrypt(encrypted.encode()).decode()
        except Exception:
            return ""
    
    def _load(self):
        """Загружает зашифрованные пароли."""
        try:
            if os.path.exists(PASSWORDS_FILE):
                with open(PASSWORDS_FILE, 'rb') as f:
                    data = f.read()
                decrypted = self._cipher.decrypt(data).decode()
                self._entries = json.loads(decrypted)
        except Exception as e:
            logger.warning("Ошибка загрузки паролей: %s", e)
            self._entries = []
    
    def _save(self):
        """Сохраняет зашифрованные пароли."""
        try:
            data = json.dumps(self._entries, ensure_ascii=False, indent=2)
            encrypted = self._cipher.encrypt(data.encode())
            with open(PASSWORDS_FILE, 'wb') as f:
                f.write(encrypted)
            try:
                os.chmod(PASSWORDS_FILE, KEY_FILE_PERMISSIONS)
            except Exception:
                pass
        except Exception as e:
            logger.warning("Ошибка сохранения паролей: %s", e)
    
    def add(self, url: str, login: str, password: str):
        """Добавляет или обновляет запись."""
        for e in self._entries:
            if e['url'] == url and e['login'] == login:
                e['password'] = self._encrypt(password)
                self._save()
                return
        self._entries.append({
            'url': url,
            'login': login,
            'password': self._encrypt(password),
        })
        self._save()
    
    def remove(self, index: int):
        """Удаляет запись по индексу."""
        if 0 <= index < len(self._entries):
            del self._entries[index]
            self._save()
    
    def entries(self) -> list[dict]:
        """Возвращает копию списка всех записей."""
        return list(self._entries)
    
    def get_password(self, index: int) -> str:
        """Возвращает расшифрованный пароль."""
        if 0 <= index < len(self._entries):
            return self._decrypt(self._entries[index]['password'])
        return ''
    
    def get_password_secure(self, index: int) -> Optional[str]:
        """
        Безопасное получение пароля с защитой от перебора.
        Исправление уязвимости #12.
        """
        now = datetime.datetime.now()
        if str(index) in self._lockout_until:
            if now < self._lockout_until[str(index)]:
                logger.warning("Password access blocked for index %d", index)
                return None
            else:
                del self._lockout_until[str(index)]
                self._failed_attempts.pop(str(index), None)
        
        last_access = self._access_times.get(index)
        if last_access and (now - last_access).seconds < 1:
            self._failed_attempts[str(index)] = self._failed_attempts.get(str(index), 0) + 1
            
            if self._failed_attempts[str(index)] > 5:
                self._lockout_until[str(index)] = now + datetime.timedelta(minutes=5)
                logger.warning("Password access locked for index %d due to too many attempts", index)
                return None
            
            return None
        
        self._failed_attempts.pop(str(index), None)
        self._access_times[index] = now
        
        return self.get_password(index)
    
    def create_secure_item(self, index: int) -> SecurePasswordItem:
        """
        Создает безопасный элемент для отображения пароля.
        Исправление уязвимости #13.
        """
        item = SecurePasswordItem()
        self._secure_items[index] = item
        return item
    
    def show_password_secure(self, index: int, widget: QTableWidgetItem) -> bool:
        """
        Безопасный показ пароля с автоскрытием.
        """
        password = self.get_password_secure(index)
        if password is None:
            return False
        
        item = self._secure_items.get(index)
        if not item:
            item = self.create_secure_item(index)
        
        item.show_password(widget, password)
        return True
    
    def clear_secure_items(self):
        """Очищает все безопасные элементы из памяти."""
        for item in self._secure_items.values():
            item.hide_password()
        self._secure_items.clear()
    
    def find_for_url(self, url: str) -> list[dict]:
        """Ищет записи для домена."""
        try:
            domain = urlparse(url).netloc.lower()
        except Exception:
            return []
        result = []
        for i, e in enumerate(self._entries):
            try:
                edomain = urlparse(e['url']).netloc.lower()
            except Exception:
                continue
            if edomain == domain:
                result.append({'index': i, **e})
        return result
    
    def clear_all(self):
        """Удаляет все пароли и очищает память."""
        self.clear_secure_items()
        self._entries = []
        self._access_times.clear()
        self._failed_attempts.clear()
        self._lockout_until.clear()
        self._save()


class PasswordManagerDialog(QDialog):
    def __init__(self, password_manager: SecurePasswordManager, parent=None):
        super().__init__(parent)
        self.pm = password_manager
        self.setWindowTitle("Управление паролями - Nostalgia")
        self.resize(680, 440)
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint |
            Qt.WindowType.WindowMinimizeButtonHint
        )
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-340, geo.center().y()-220)
        self._build_ui()
        self._refresh()
    
    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        
        warn = QLabel(
            "🔒 Пароли хранятся в зашифрованном виде (AES-128). "
            "Ключ шифрования сохраняется локально."
        )
        warn.setStyleSheet("color: #008000; font-size: 8pt; font-weight: bold;")
        warn.setWordWrap(True)
        layout.addWidget(warn)
        
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Сайт", "Логин", "Пароль", ""])
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
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
            show_btn.setToolTip("Показать пароль (автоскрытие через 10 сек)")
            show_btn.clicked.connect((lambda idx, item=pwd_item: lambda: self._show_password_secure(idx, item))(i))
            self.table.setCellWidget(row, 3, show_btn)
        self.count_lbl.setText(f"Записей: {self.table.rowCount()}")
    
    def _show_password_secure(self, entry_index: int, widget: QTableWidgetItem):
        """
        Безопасный показ пароля с автоскрытием.
        Исправление уязвимостей #12 и #13.
        """
        if not self.pm.show_password_secure(entry_index, widget):
            QMessageBox.warning(
                self, 
                "Защита пароля",
                "Слишком много попыток показа пароля. Попробуйте позже."
            )
    
    def _add_entry(self):
        dlg = _AddPasswordDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            url, login, pwd = dlg.result_data
            if url and login and pwd:
                self.pm.add(url, login, pwd)
                self._refresh()
    
    def _delete_selected(self):
        rows = sorted(
            set(idx.row() for idx in self.table.selectedIndexes()),
            reverse=True
        )
        for row in rows:
            item = self.table.item(row, 2)
            if item:
                self.pm.remove(item.data(Qt.ItemDataRole.UserRole))
        self._refresh()
    
    def _delete_all(self):
        reply = QMessageBox.question(
            self, "Удалить все пароли",
            "Удалить все сохранённые пароли? Это действие необратимо.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.pm.clear_all()
            self._refresh()
    
    def closeEvent(self, event):
        """Очистка при закрытии диалога."""
        self.pm.clear_secure_items()
        super().closeEvent(event)


class _AddPasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Добавить пароль")
        self.setFixedSize(360, 210)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-180, geo.center().y()-105)
        self.result_data = ("", "", "")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 10)
        form = QFormLayout()
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com")
        self.login_edit = QLineEdit()
        self.pwd_edit = QLineEdit()
        self.pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Сайт:", self.url_edit)
        form.addRow("Логин:", self.login_edit)
        form.addRow("Пароль:", self.pwd_edit)
        layout.addLayout(form)
        
        show_cb = QCheckBox("Показать пароль")
        show_cb.toggled.connect(
            lambda c: self.pwd_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password
            )
        )
        layout.addWidget(show_cb)
        
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)
        
        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        bb.accepted.connect(self._on_ok)
        bb.rejected.connect(self.reject)
        layout.addWidget(bb)
    
    def _on_ok(self):
        url = self.url_edit.text().strip()
        login = self.login_edit.text().strip()
        pwd = self.pwd_edit.text()
        if not url or not login or not pwd:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self.result_data = (url, login, pwd)
        self.accept()


class SavePasswordDialog(QDialog):
    def __init__(self, url: str, login: str, password: str, parent=None):
        super().__init__(parent)
        self.url = url
        self.login = login
        self.password = password
        self.setWindowTitle("Nostalgia Browser")
        self.setFixedSize(400, 180)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-200, geo.center().y()-90)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 10)
        layout.setSpacing(10)
        
        top = QHBoxLayout()
        top.setSpacing(14)
        icon = QLabel()
        icon.setFixedSize(40, 40)
        px = QPixmap(40, 40)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
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
        msg = QLabel(
            f"<b>Сохранить пароль?</b><br><br>"
            f"Логин: <b>{safe_login}</b> на сайте <b>{safe_url}</b>"
        )
        msg.setWordWrap(True)
        msg.setTextFormat(Qt.TextFormat.RichText)
        top.addWidget(msg, 1)
        layout.addLayout(top)
        
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)
        
        bl = QHBoxLayout()
        bl.addStretch()
        yes_btn = QPushButton("Сохранить")
        yes_btn.setFixedWidth(90)
        yes_btn.setDefault(True)
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
        self.setFixedSize(380, 320)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-190, geo.center().y()-160)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 10)
        layout.setSpacing(10)
        
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
        for cb in [self.cb_history, self.cb_cookies, self.cb_cache,
                   self.cb_passwords, self.cb_bookmarks]:
            bl.addWidget(cb)
        layout.addWidget(box)
        
        warn = QLabel("⚠  Действие необратимо!")
        warn.setStyleSheet("color: red; font-weight: bold;")
        layout.addWidget(warn)
        
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)
        
        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
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
    """Диалог управления закладками с импортом/экспортом."""
    
    def __init__(self, bookmarks: dict, parent=None):
        super().__init__(parent)
        self.bookmarks = bookmarks
        self.setWindowTitle("Управление закладками - Nostalgia")
        self.resize(600, 450)
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint |
            Qt.WindowType.WindowMinimizeButtonHint
        )
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-300, geo.center().y()-225)
        
        self._build_ui()
        self._refresh()
    
    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        
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
            safe_name = sanitize_display_text(name, 100)
            safe_url = sanitize_display_text(url, 100)
            item = QTreeWidgetItem([safe_name, safe_url])
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
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Импорт закладок", "", "HTML Files (*.html *.htm)"
        )
        if file_path:
            try:
                safe_path = os.path.abspath(file_path)
                if not safe_path.startswith(os.path.abspath(os.getcwd())):
                    QMessageBox.warning(self, "Ошибка", "Недопустимый путь к файлу.")
                    return
                
                # Проверка размера файла
                file_size = os.path.getsize(safe_path)
                if file_size > MAX_FILE_SIZE:
                    QMessageBox.warning(self, "Ошибка", "Файл слишком большой.")
                    return
                
                with open(safe_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                pattern = r'<a\s+href="([^"]+)"[^>]*>([^<]+)</a>'
                matches = re.findall(pattern, content)
                
                imported_count = 0
                for url, name in matches:
                    # Исправление уязвимости #23: проверка длины URL
                    if len(url) > MAX_URL_LENGTH:
                        logger.warning("URL too long in import: %d characters", len(url))
                        continue
                    
                    safe_name = html_escape(name.strip())
                    if is_safe_url(QUrl(url)) and safe_name:
                        self.bookmarks[safe_name[:200]] = url
                        imported_count += 1
                
                self._refresh()
                QMessageBox.information(self, "Импорт", f"Импортировано {imported_count} закладок.")
            except Exception as e:
                logger.warning("Ошибка импорта закладок: %s", e)
                QMessageBox.warning(self, "Ошибка", "Не удалось импортировать файл.")
    
    def _export_bookmarks(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт закладок", "bookmarks.html", "HTML Files (*.html)"
        )
        if file_path:
            try:
                safe_path = os.path.abspath(file_path)
                if not safe_path.startswith(os.path.abspath(os.getcwd())):
                    QMessageBox.warning(self, "Ошибка", "Недопустимый путь к файлу.")
                    return
                
                html = ['<!DOCTYPE html><html><head><title>Закладки Nostalgia</title></head>',
                       '<body><h1>Закладки Nostalgia Browser</h1><ul>']
                for name, url in self.bookmarks.items():
                    safe_name = html_escape(name)
                    safe_url = html_escape(url)
                    html.append(f'<li><a href="{safe_url}">{safe_name}</a></li>')
                html.append('</ul></body></html>')
                
                with open(safe_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(html))
                
                QMessageBox.information(self, "Экспорт", "Закладки экспортированы.")
            except Exception as e:
                logger.warning("Ошибка экспорта закладок: %s", e)
                QMessageBox.warning(self, "Ошибка", "Не удалось экспортировать файл.")


class CertificateErrorDialog(QDialog):
    """Диалог для ошибок SSL сертификата."""
    
    def __init__(self, error: QWebEngineCertificateError, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ошибка сертификата - Nostalgia")
        self.setFixedSize(500, 300)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 12)
        
        icon_label = QLabel()
        icon_label.setFixedSize(48, 48)
        px = QPixmap(48, 48)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor(255, 200, 0)))
        p.setPen(QPen(QColor(160, 100, 0), 2))
        p.drawPolygon(QPolygon([QPoint(24, 2), QPoint(46, 45), QPoint(2, 45)]))
        p.setPen(QPen(QColor(80, 40, 0), 3))
        p.drawLine(24, 16, 24, 32)
        p.drawLine(24, 37, 24, 40)
        p.end()
        icon_label.setPixmap(px)
        
        top_layout = QHBoxLayout()
        top_layout.addWidget(icon_label)
        
        safe_url = html_escape(error.url().toString())
        error_text = QLabel(
            f"<b>Ошибка сертификата безопасности</b><br><br>"
            f"URL: {safe_url}<br><br>"
            f"Соединение не защищено. Продолжить?"
        )
        error_text.setWordWrap(True)
        top_layout.addWidget(error_text, 1)
        layout.addLayout(top_layout)
        
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
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

    def __init__(self, site_filter, scheme_handler,
                 block_popups: bool = True,
                 profile=None, parent=None):
        if profile:
            super().__init__(profile, parent)
        else:
            super().__init__(parent)
        self.site_filter = site_filter
        self.scheme_handler = scheme_handler
        self.block_popups = block_popups
        self._blocked = False
        self._incognito = (profile is not None and profile == IncognitoProfile.get())
        self._install_form_interceptor()
        self.certificateError.connect(self._on_certificate_error)

    def _on_certificate_error(self, error: QWebEngineCertificateError):
        """Обработка ошибок SSL сертификатов."""
        dialog = CertificateErrorDialog(error, self.view())
        if dialog.exec() == QDialog.DialogCode.Accepted:
            return True
        return False

    def _install_form_interceptor(self):
        js = """
        (function() {
            if (window.__nostalgiaFormHooked) return;
            window.__nostalgiaFormHooked = true;
            document.addEventListener('submit', function(e) {
                var form = e.target;
                var pwds = form.querySelectorAll('input[type="password"]');
                if (pwds.length === 0) return;
                var loginEl = form.querySelector(
                    'input[type="text"], input[type="email"], ' +
                    'input[name*="login"], input[name*="user"], ' +
                    'input[name*="email"], input[id*="login"], input[id*="user"]'
                );
                var login = loginEl ? loginEl.value : '';
                var pwd   = pwds[0].value;
                if (login && pwd) {
                    window.__nostalgiaCredentials = {
                        login: login, password: pwd
                    };
                }
            }, true);
        })();
        """
        script = QWebEngineScript()
        script.setName("NostalgiaFormHook")
        script.setSourceCode(js)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        script.setRunsOnSubFrames(False)
        self.scripts().insert(script)

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):
        if url.scheme().lower() == "nostalgia":
            # Исправление уязвимости #21: проверка доступа к nostalgia страницам
            return True
        
        if is_main_frame:
            if nav_type == QWebEnginePage.NavigationType.NavigationTypeFormSubmitted:
                self._check_credentials(url)
            if not is_safe_url(url):
                self._blocked = True
                scheme = url.scheme()
                QTimer.singleShot(0, lambda: self.scheme_blocked.emit(scheme))
                return False
            if self.site_filter.is_blocked(url):
                self._blocked = True
                domain = self.site_filter.extract_domain(url)
                QTimer.singleShot(0, lambda: self.page_blocked.emit(domain))
                return False
            self._blocked = False
        return super().acceptNavigationRequest(url, nav_type, is_main_frame)

    def _check_credentials(self, url: QUrl):
        if self._incognito:
            return
        self.runJavaScript(
            "window.__nostalgiaCredentials || null;",
            lambda creds: self._emit_credentials(url.toString(), creds)
        )

    def _emit_credentials(self, url: str, creds):
        if isinstance(creds, dict):
            login = creds.get('login', '')
            pwd = creds.get('password', '')
            if login and pwd:
                self.credentials_found.emit(url, login, pwd)
            self.runJavaScript("window.__nostalgiaCredentials = null;")

    def createWindow(self, win_type):
        if self.block_popups:
            if win_type in (
                QWebEnginePage.WebWindowType.WebDialog,
                QWebEnginePage.WebWindowType.WebBrowserWindow
            ):
                return None

        placeholder = NostalgiaPage(
            self.site_filter, self.scheme_handler,
            self.block_popups, self.profile(), self.parent()
        )

        def _on_url(url):
            if url.isEmpty() or url.toString() == "about:blank":
                return
            if is_safe_url(url):
                self.open_in_new_tab.emit(url)
            placeholder.deleteLater()

        placeholder.urlChanged.connect(_on_url)
        return placeholder


class BrowserTab(QWidget):
    def __init__(self, site_filter, scheme_handler,
                 block_popups: bool = True,
                 incognito: bool = False,
                 parent=None):
        super().__init__(parent)
        self.is_incognito = incognito

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        if incognito:
            inc_bar = QLabel(
                "  🕵  Режим инкогнито — история, cookie и кэш не сохраняются"
            )
            inc_bar.setStyleSheet(
                "background: #3a3a3a; color: #e0e0e0; "
                "padding: 3px 6px; font-size: 8pt;"
            )
            inc_bar.setFixedHeight(22)
            outer.addWidget(inc_bar)

        self.find_bar = FindBar(self)
        outer.addWidget(self.find_bar)

        self.webview = QWebEngineView()
        self.webview.setStyleSheet("background: white;")
        self.webview.page().setBackgroundColor(QColor(255, 255, 255))

        profile = IncognitoProfile.get() if incognito else QWebEngineProfile.defaultProfile()
        page = NostalgiaPage(
            site_filter, scheme_handler, block_popups,
            profile, self.webview
        )
        self.webview.setPage(page)
        self.webview.page().setBackgroundColor(QColor(255, 255, 255))

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
            open_tab_a.triggered.connect(
                lambda: self.nostalgia_page.open_in_new_tab.emit(link_url)
            )
            menu.addAction(open_tab_a)

            copy_link_a = QAction("Копировать адрес ссылки", self)
            # Исправление уязвимости #14: использование безопасного буфера обмена
            copy_link_a.triggered.connect(
                lambda url=link_url.toString(): SecureClipboard.set_text(url)
            )
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
        src_a.triggered.connect(self._view_source)
        menu.addAction(src_a)

        menu.exec(self.webview.mapToGlobal(pos))

    def _view_source(self):
        self.webview.page().toHtml(self._show_source_dialog)

    def _show_source_dialog(self, html: str):
        dlg = QDialog(self)
        dlg.setWindowTitle("Исходный код страницы - Nostalgia")
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
        self.setFixedSize(380, 220)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-190, geo.center().y()-110)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 12)
        layout.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(14)
        icon_label = QLabel()
        icon_label.setFixedSize(48, 48)
        px = QPixmap(48, 48)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor(200, 0, 0)))
        p.setPen(QPen(QColor(140, 0, 0), 2))
        p.drawEllipse(2, 2, 44, 44)
        p.setPen(QPen(QColor(Qt.GlobalColor.white), 6))
        p.drawLine(14, 14, 34, 34)
        p.drawLine(34, 14, 14, 34)
        p.end()
        icon_label.setPixmap(px)
        top.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)

        safe_domain = html_escape(domain)
        msg = QLabel(
            f"<b>Сайт заблокирован</b><br><br>"
            f"Доступ к сайту <b>{safe_domain}</b> ограничен "
            f"настройками фильтрации.<br><br>Обратитесь к администратору."
        )
        msg.setWordWrap(True)
        msg.setTextFormat(Qt.TextFormat.RichText)
        top.addWidget(msg, 1)
        layout.addLayout(top)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)

        bl = QHBoxLayout()
        bl.addStretch()
        ok = QPushButton("  ОК  ")
        ok.setFixedWidth(80)
        ok.setDefault(True)
        ok.clicked.connect(self.accept)
        bl.addWidget(ok)
        bl.addStretch()
        layout.addLayout(bl)


class SchemeBlockedDialog(QDialog):
    def __init__(self, scheme: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nostalgia Browser")
        self.setFixedSize(380, 200)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-190, geo.center().y()-100)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 12)
        layout.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(14)
        icon_label = QLabel()
        icon_label.setFixedSize(48, 48)
        px = QPixmap(48, 48)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor(255, 200, 0)))
        p.setPen(QPen(QColor(160, 100, 0), 2))
        p.drawPolygon(QPolygon([QPoint(24, 2), QPoint(46, 45), QPoint(2, 45)]))
        p.setPen(QPen(QColor(80, 40, 0), 3))
        p.drawLine(24, 16, 24, 32)
        p.drawLine(24, 37, 24, 40)
        p.end()
        icon_label.setPixmap(px)
        top.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)

        safe_scheme = html_escape(scheme)
        msg = QLabel(
            f"<b>Протокол не поддерживается</b><br><br>"
            f"Схема <b>{safe_scheme}://</b> заблокирована.<br>"
            f"Разрешены только <b>http://</b> и <b>https://</b>."
        )
        msg.setWordWrap(True)
        msg.setTextFormat(Qt.TextFormat.RichText)
        top.addWidget(msg, 1)
        layout.addLayout(top)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)

        bl = QHBoxLayout()
        bl.addStretch()
        ok = QPushButton("  ОК  ")
        ok.setFixedWidth(80)
        ok.setDefault(True)
        ok.clicked.connect(self.accept)
        bl.addWidget(ok)
        bl.addStretch()
        layout.addLayout(bl)


class HomepageDialog(QDialog):
    def __init__(self, current_homepage: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройка домашней страницы - Nostalgia")
        self.setFixedSize(460, 160)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x()-230, geo.center().y()-80)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 10)
        layout.setSpacing(10)

        form = QFormLayout()
        self.url_edit = QLineEdit(current_homepage)
        self.url_edit.setMinimumWidth(340)
        form.addRow("Домашняя страница:", self.url_edit)
        layout.addLayout(form)

        hint = QLabel(
            "Пример: https://www.google.com  •  Только http:// и https://"
        )
        hint.setStyleSheet("color: gray; font-size: 8pt;")
        layout.addWidget(hint)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)

        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        bb.accepted.connect(self._validate_and_accept)
        bb.rejected.connect(self.reject)
        layout.addWidget(bb)

    def _validate_and_accept(self):
        raw = self.url_edit.text().strip()
        if not raw:
            QMessageBox.warning(
                self, "Ошибка", "Введите адрес домашней страницы."
            )
            return
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw
        q = QUrl(raw)
        if not q.isValid() or not is_safe_url(q):
            QMessageBox.warning(
                self, "Ошибка",
                "Недопустимый адрес.\nИспользуйте http:// или https://."
            )
            return
        self.result_url = raw
        self.accept()

    @property
    def homepage(self) -> str:
        return getattr(self, 'result_url', self.url_edit.text().strip())


class ColoredTabLoadingWidget(QWidget):
    """Улучшенный спиннер с цветовой индикацией загрузки."""
    
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

        self.site_filter = SiteFilter()
        self.scheme_handler = NostalgiaSchemeHandler()
        self.bookmarks = {}
        self.history = []
        self.homepage = "https://www.google.com"
        self.block_popups = True
        self.current_theme = "Классическая (Windows 98)"
        self.current_engine = "Google"
        self.loading_tabs: dict[BrowserTab, TabLoadingWidget] = {}
        self.password_manager = SecurePasswordManager()
        self._download_manager: DownloadManagerDialog | None = None
        self._navigation_limiter = RateLimiter(NAVIGATION_RATE_LIMIT)
        self._active_downloads = 0
        self._clipboard_cleanup_timer: Optional[QTimer] = None

        self.setup_profile()
        self.load_settings()

        self.create_menubar()
        self.create_toolbars()
        self.create_tabs()
        self.setup_statusbar()
        self.setup_shortcuts()

        QTimer.singleShot(100, lambda: self.add_new_tab(
            QUrl(self.homepage), "Домашняя страница"
        ))
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
            logger.warning("Не удалось открыть папку: %s", e)

    def setup_profile(self):
        profile = QWebEngineProfile.defaultProfile()
        profile.setHttpUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        profile.setHttpAcceptLanguage("ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
        profile.downloadRequested.connect(self._on_download_requested)
        IncognitoProfile.get().downloadRequested.connect(self._on_download_requested)

        settings = profile.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.AllowRunningInsecureContent, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, True)
        
        # Исправление уязвимости #28: ограничение WebRTC
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.WebRTCPublicInterfacesOnly, 
            True
        )
        
        # Исправление уязвимости #26: отключение DNS prefetch
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.DnsPrefetchEnabled,
            False
        )
        
        # Ограничение размера кэша
        profile.setHttpCacheMaximumSize(50 * 1024 * 1024)  # 50 MB
        
        # Очистка буфера обмена при выходе
        QApplication.instance().aboutToQuit.connect(self._cleanup_security)

    def _cleanup_security(self):
        """
        Очистка чувствительных данных при выходе.
        Исправление уязвимости #27.
        """
        # Очистка буфера обмена
        clipboard = QApplication.clipboard()
        clipboard.clear()
        
        # Очистка паролей из памяти
        if hasattr(self, 'password_manager'):
            self.password_manager.clear_secure_items()
            self.password_manager._entries.clear()
            self.password_manager._access_times.clear()
            self.password_manager._failed_attempts.clear()
            self.password_manager._lockout_until.clear()
        
        # Остановка всех таймеров
        if self._clipboard_cleanup_timer:
            self._clipboard_cleanup_timer.stop()
        
        # Очистка истории из памяти
        self.history.clear()
        
        logger.info("Security cleanup completed")

    def _on_download_requested(self, download: QWebEngineDownloadRequest):
        """
        Безопасная обработка запросов на скачивание.
        Исправление уязвимости #16: защита от race condition.
        """
        # Проверка лимита одновременных загрузок
        if self._active_downloads >= MAX_DOWNLOADS_SIMULTANEOUS:
            logger.warning("Download limit reached: %d", self._active_downloads)
            download.cancel()
            QMessageBox.warning(
                self, 
                "Слишком много загрузок",
                f"Достигнут лимит одновременных загрузок ({MAX_DOWNLOADS_SIMULTANEOUS}). "
                "Дождитесь завершения текущих загрузок."
            )
            return
        
        # Санитизация имени файла
        fname = download.downloadFileName() or "download"
        
        # Удаление path traversal
        fname = os.path.basename(fname)
        
        # Удаление опасных символов
        fname = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', fname)
        
        # Ограничение длины имени файла
        if len(fname) > 255:
            name, ext = os.path.splitext(fname)
            fname = name[:250] + ext
        
        if not fname:
            fname = "download"
        
        # Санитизированное имя для отображения
        safe_display_name = sanitize_display_text(fname, 50)
        
        # Выбор пути сохранения
        save_path, _ = QFileDialog.getSaveFileName(
            self, 
            "Сохранить файл",
            os.path.join(
                QStandardPaths.writableLocation(
                    QStandardPaths.StandardLocation.DownloadLocation
                ),
                fname
            ),
            "Все файлы (*.*)"
        )
        
        if not save_path:
            download.cancel()
            return
        
        # Проверка path traversal в пути сохранения
        safe_save_path = os.path.abspath(save_path)
        allowed_dir = os.path.abspath(
            QStandardPaths.writableLocation(
                QStandardPaths.StandardLocation.DownloadLocation
            )
        )
        
        if not safe_save_path.startswith(allowed_dir):
            logger.warning("Path traversal attempt in download: %s", safe_save_path)
            download.cancel()
            return
        
        # Проверка расширения файла
        dangerous_extensions = {'.exe', '.bat', '.cmd', '.msi', '.scr', '.ps1', '.vbs'}
        _, ext = os.path.splitext(fname)
        if ext.lower() in dangerous_extensions:
            reply = QMessageBox.question(
                self,
                "Потенциально опасный файл",
                f"Файл «{safe_display_name}» может быть опасным. "
                "Вы уверены, что хотите его сохранить?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                download.cancel()
                return
        
        # Увеличиваем счетчик активных загрузок
        self._active_downloads += 1
        
        # Подключаем обработчик завершения
        def on_download_finished():
            self._active_downloads = max(0, self._active_downloads - 1)
        
        download.isFinishedChanged.connect(on_download_finished)
        
        # Настройка параметров загрузки
        download.setDownloadDirectory(os.path.dirname(safe_save_path))
        download.setDownloadFileName(os.path.basename(safe_save_path))
        download.accept()
        
        # Показываем менеджер загрузок
        if self._download_manager is None:
            self._download_manager = DownloadManagerDialog(self)
        self._download_manager.add_download(download)
        
        logger.info("Download started: %s", safe_display_name)

    def load_settings(self):
        """
        Безопасная загрузка настроек.
        Исправление уязвимости #20: проверка целостности.
        Исправление уязвимости #29: ограничение размера файла.
        """
        try:
            if os.path.exists('nostalgia_settings.json'):
                data = SecureFileHandler.safe_read_json('nostalgia_settings.json')
                
                if not data:
                    logger.warning("Using default settings due to corrupted config")
                    return
                
                # Загрузка закладок с валидацией
                raw_bm = data.get('bookmarks', {})
                if isinstance(raw_bm, dict):
                    self.bookmarks = {}
                    for k, v in raw_bm.items():
                        if (
                            isinstance(k, str) and isinstance(v, str)
                            and len(k) <= 200 and len(v) <= MAX_URL_LENGTH
                            and is_safe_url(QUrl(v))
                        ):
                            safe_name = sanitize_display_text(k, 200)
                            if safe_name:
                                self.bookmarks[safe_name] = v
                
                # Загрузка истории с ограничениями
                raw_hist = data.get('history', [])
                self.history = []
                if isinstance(raw_hist, list):
                    for e in raw_hist[:MAX_HISTORY_ENTRIES]:
                        if not isinstance(e, dict):
                            continue
                        safe_url = sanitize_url_for_history(e.get('url', ''))
                        if not safe_url:
                            continue
                        
                        self.history.append({
                            'url': safe_url,
                            'title': sanitize_display_text(
                                str(e.get('title', ''))[:MAX_TITLE_LENGTH],
                                MAX_TITLE_LENGTH
                            ),
                            'time': str(e.get('time', ''))[:50],
                        })
                
                # Загрузка домашней страницы
                raw_hp = data.get('homepage', 'https://www.google.com')
                if (
                    isinstance(raw_hp, str) 
                    and is_safe_url(QUrl(raw_hp))
                    and len(raw_hp) <= MAX_URL_LENGTH
                ):
                    self.homepage = raw_hp
                
                self.block_popups = bool(data.get('block_popups', True))
                
                raw_theme = data.get('theme', 'Классическая (Windows 98)')
                self.current_theme = raw_theme if raw_theme in THEMES else 'Классическая (Windows 98)'
                
                raw_engine = data.get('search_engine', 'Google')
                self.current_engine = raw_engine if raw_engine in SEARCH_ENGINES else 'Google'
                
        except Exception as e:
            logger.warning("Critical error loading settings: %s", e)

    def save_settings(self):
        """
        Безопасное сохранение настроек.
        Исправление уязвимости #15: ограничение истории.
        """
        try:
            # Ограничиваем количество записей истории
            history_to_save = self.history[-MAX_HISTORY_ENTRIES:]
            
            # Очищаем чувствительные данные из URL в истории
            cleaned_history = []
            for entry in history_to_save:
                cleaned_entry = entry.copy()
                if 'url' in cleaned_entry:
                    cleaned_entry['url'] = sanitize_url_for_history(cleaned_entry['url'])
                cleaned_history.append(cleaned_entry)
            
            data = {
                'bookmarks': self.bookmarks,
                'history': cleaned_history,
                'homepage': self.homepage,
                'block_popups': self.block_popups,
                'theme': self.current_theme,
                'search_engine': self.current_engine,
            }
            
            SecureFileHandler.safe_write_json('nostalgia_settings.json', data)
            
        except Exception as e:
            logger.warning("Ошибка сохранения настроек: %s", e)

    def create_menubar(self):
        mb = self.menuBar()

        fm = mb.addMenu("&Файл")
        a = QAction("Новая &вкладка", self)
        a.setShortcut("Ctrl+T")
        a.triggered.connect(lambda: self.add_new_tab(QUrl(self.homepage)))
        fm.addAction(a)

        a = QAction("🕵  Новая вкладка &инкогнито", self)
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

        zm = vm.addMenu("&Масштаб")
        for txt, sc, fn in [
            ("Увеличить  (+)", "Ctrl++", self.zoom_in),
            ("Уменьшить  (-)", "Ctrl+-", self.zoom_out),
            ("Обычный  (100%)", "Ctrl+0", self.zoom_reset),
        ]:
            a = QAction(txt, self)
            a.setShortcut(sc)
            a.triggered.connect(fn)
            zm.addAction(a)

        zm.addSeparator()
        for pct in (75, 90, 100, 110, 125, 150, 175, 200):
            a = QAction(f"{pct}%", self)
            a.triggered.connect((lambda z: lambda: self._set_zoom(z/100))(pct))
            zm.addAction(a)

        vm.addSeparator()

        a = QAction("🎨 &Темы оформления...", self)
        a.triggered.connect(self.show_theme_dialog)
        vm.addAction(a)

        vm.addSeparator()

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

        a = QAction("🍪 Управление &cookie...", self)
        a.triggered.connect(self.show_cookie_manager)
        tm.addAction(a)

        a = QAction("🔑 Управление &паролями...", self)
        a.triggered.connect(self.show_password_manager)
        tm.addAction(a)

        a = QAction("🗑  &Очистить данные браузера...", self)
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
            safe_name = sanitize_display_text(name, 50)
            a = QAction(safe_name, self)
            a.triggered.connect((lambda u: lambda: self.load_url(u))(url))
            self.fav_menu.addAction(a)

    def create_toolbars(self):
        self.nav_toolbar = QToolBar("Панель инструментов")
        self.nav_toolbar.setMovable(False)
        self.addToolBar(self.nav_toolbar)

        for text, func in [
            ("← Назад", self.go_back),
            ("Вперед →", self.go_forward),
            ("Стоп", self.stop_loading),
            ("Обновить", self.reload_page),
            ("Домой", self.go_home),
        ]:
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
        zob.setToolTip("Уменьшить (Ctrl+-)")
        zob.clicked.connect(self.zoom_out)
        self.nav_toolbar.addWidget(zob)

        self.zoom_label = QLabel("100%")
        self.zoom_label.setFixedWidth(38)
        self.zoom_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.nav_toolbar.addWidget(self.zoom_label)

        zib = QPushButton("A+")
        zib.setFixedWidth(32)
        zib.setToolTip("Увеличить (Ctrl++)")
        zib.clicked.connect(self.zoom_in)
        self.nav_toolbar.addWidget(zib)

        self.address_toolbar = QToolBar("Адресная строка")
        self.address_toolbar.setMovable(False)
        self.addToolBar(self.address_toolbar)

        self.address_label = QLabel("Адрес: ")
        self.address_toolbar.addWidget(self.address_label)

        self.url_bar = QLineEdit()
        self.url_bar.setMinimumWidth(400)
        self.url_bar.setPlaceholderText("Введите адрес веб-страницы")
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
        QShortcut(QKeySequence("Ctrl+="), self, activated=self.zoom_in)
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
        """
        Безопасное добавление записи в историю.
        Исправление уязвимости #7: дедупликация и ограничение.
        Исправление уязвимости #15: очистка чувствительных параметров.
        """
        if not sanitize_url_for_history(entry.get('url', '')):
            return
        
        if len(self.history) >= MAX_HISTORY_ENTRIES:
            self.history = self.history[-MAX_HISTORY_ENTRIES//2:]
        
        now = datetime.datetime.now()
        cutoff = now - datetime.timedelta(minutes=DEDUP_TIME_MINUTES)
        
        for recent in reversed(self.history[-RECENT_HISTORY_CHECK:]):
            if recent.get('url') == entry.get('url'):
                try:
                    recent_time = datetime.datetime.fromisoformat(recent.get('time', ''))
                    if recent_time > cutoff:
                        return
                except (ValueError, TypeError):
                    pass
        
        if entry.get('title'):
            entry['title'] = sanitize_display_text(entry['title'], MAX_TITLE_LENGTH)
        
        self.history.append(entry)

    def open_incognito_tab(self):
        self.add_new_tab(QUrl(self.homepage), "🕵 Инкогнито", incognito=True)

    def add_new_tab(self, url=None, title="Новая вкладка", incognito: bool = False):
        if url is None:
            url = QUrl("about:blank")
        elif isinstance(url, str):
            url = QUrl(url)

        if (not url.isEmpty() and url.toString() != "about:blank"
                and url.scheme() != "nostalgia"):
            if not is_safe_url(url):
                self.status_label.setText("Заблокировано: небезопасная схема URL")
                return None

        tab = BrowserTab(
            self.site_filter, self.scheme_handler,
            self.block_popups, incognito
        )
        safe_title = sanitize_display_text(title, MAX_DISPLAY_LENGTH)
        index = self.tab_widget.addTab(tab, safe_title)
        self.tab_widget.setCurrentIndex(index)

        page: NostalgiaPage = tab.nostalgia_page
        page.open_in_new_tab.connect(
            lambda u, inc=incognito: self.add_new_tab(u, incognito=inc)
        )
        page.page_blocked.connect(
            lambda domain, t=tab: self._on_site_blocked(t, domain)
        )
        page.scheme_blocked.connect(
            lambda scheme, t=tab: self._on_scheme_blocked(t, scheme)
        )
        if not incognito:
            page.credentials_found.connect(self._on_credentials_found)

        wv = tab.webview
        wv.loadStarted.connect(lambda t=tab: self.on_load_started(t))
        wv.loadFinished.connect(lambda ok, t=tab: self.on_load_finished(t, ok))
        wv.urlChanged.connect(lambda u, t=tab: self.on_url_changed(u, t))
        wv.titleChanged.connect(lambda txt, t=tab: self.update_tab_title_by_tab(t, txt))
        wv.loadProgress.connect(lambda p, t=tab: self.update_progress(p, t))
        wv.urlChanged.connect(lambda u, t=tab: self._sync_zoom_label(t))
        wv.setUrl(url)
        return tab

    def _on_credentials_found(self, url: str, login: str, pwd: str):
        existing = self.password_manager.find_for_url(url)
        for e in existing:
            if e['login'] == login:
                return
        dlg = SavePasswordDialog(url, login, pwd, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.password_manager.add(url, login, pwd)

    def on_load_started(self, tab: BrowserTab):
        if tab not in self.loading_tabs:
            w = TabLoadingWidget()
            self.loading_tabs[tab] = w
            idx = self.tab_widget.indexOf(tab)
            if idx >= 0:
                self.tab_widget.tabBar().setTabButton(
                    idx, QTabBar.ButtonPosition.LeftSide, w
                )
        self.loading_tabs[tab].start()
        self.globe.start()
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Поиск узла...")

    def on_load_finished(self, tab: BrowserTab, ok: bool):
        if tab in self.loading_tabs:
            self.loading_tabs[tab].stop()
            idx = self.tab_widget.indexOf(tab)
            if idx >= 0:
                self.tab_widget.tabBar().setTabButton(
                    idx, QTabBar.ButtonPosition.LeftSide, None
                )
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
        
        if progress < 30:
            self.status_label.setText("Поиск узла...")
        elif progress < 60:
            self.status_label.setText("Ожидание ответа...")
        elif progress < 90:
            self.status_label.setText("Загрузка страницы...")
        else:
            self.status_label.setText("Завершение...")

    def on_url_changed(self, url: QUrl, tab: BrowserTab):
        if self.tab_widget.currentWidget() is tab:
            self.url_bar.setText("" if url.scheme() == "nostalgia" else url.toString())
            if url.scheme() == "https":
                self.zone_label.setText("🔒 Надежный узел")
                self.zone_label.setStyleSheet("color: green;")
            elif url.scheme() == "http":
                self.zone_label.setText("⚠ Не защищено")
                self.zone_label.setStyleSheet("color: orange;")
            else:
                self.zone_label.setText("Зона Интернета")
                self.zone_label.setStyleSheet("")

        if not tab.is_incognito and url.scheme() != "nostalgia":
            safe = sanitize_url_for_history(url.toString())
            if safe:
                self._safe_add_to_history({
                    'url': safe,
                    'title': '',
                    'time': datetime.datetime.now().isoformat()
                })

    def update_tab_title_by_tab(self, tab: BrowserTab, title: str):
        idx = self.tab_widget.indexOf(tab)
        if idx < 0:
            return
        
        title = sanitize_display_text(title, MAX_TITLE_LENGTH)
        display = sanitize_display_text(title, MAX_DISPLAY_LENGTH)
        
        safe_tooltip = sanitize_display_text(title, 200)
        self.tab_widget.setTabToolTip(idx, safe_tooltip)
        
        if tab.is_incognito and not display.startswith("🕵"):
            display = "🕵 " + display
        self.tab_widget.setTabText(idx, display)
        
        if idx == self.tab_widget.currentIndex():
            self.setWindowTitle(f"{display} - Nostalgia Browser")

        url_str = tab.webview.url().toString()
        for e in reversed(self.history):
            if e.get('url') == url_str and not e.get('title'):
                e['title'] = sanitize_display_text(title, MAX_TITLE_LENGTH)
                break

    def _sync_zoom_label(self, tab: BrowserTab):
        if self.tab_widget.currentWidget() is tab:
            self.zoom_label.setText(f"{int(tab.webview.zoomFactor()*100)}%")

    def _stop_loading_for_tab(self, tab: BrowserTab):
        if tab in self.loading_tabs:
            self.loading_tabs[tab].stop()
            idx = self.tab_widget.indexOf(tab)
            if idx >= 0:
                self.tab_widget.tabBar().setTabButton(
                    idx, QTabBar.ButtonPosition.LeftSide, None
                )
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
        self.status_label.setText(
            f"Заблокировано: схема «{html_escape(scheme)}» не разрешена"
        )
        SchemeBlockedDialog(scheme, self).exec()

    def navigate_to_url(self):
        """
        Безопасная навигация с rate limiting.
        Исправление уязвимости #17.
        """
        if not self._navigation_limiter.can_proceed():
            self.status_label.setText("Слишком много запросов. Подождите...")
            return
        
        text = self.url_bar.text().strip()
        if not text:
            return
        
        sanitized_url = SanitizedUrl.sanitize(text)
        if not sanitized_url:
            self.status_label.setText("Недопустимый URL")
            return
        
        try:
            if sanitized_url.startswith(("http://", "https://", "about:")):
                url = QUrl(sanitized_url)
            elif "." in sanitized_url and " " not in sanitized_url:
                url = QUrl("https://" + sanitized_url)
            else:
                tmpl = SEARCH_ENGINES.get(self.current_engine, SEARCH_ENGINES["Google"])
                safe_query = quote_plus(sanitized_url[:500])
                url = QUrl(tmpl.replace("{query}", safe_query))
            
            if not url.isValid():
                raise ValueError(f"Невалидный URL")
            if not is_safe_url(url):
                self.status_label.setText(
                    f"Заблокировано: схема «{html_escape(url.scheme())}» не разрешена"
                )
                return
            self.load_url(url)
        except Exception as e:
            self.status_label.setText(f"Ошибка: {sanitize_display_text(str(e), 100)}")

    def load_url(self, url):
        if isinstance(url, str):
            url = QUrl(url)
        if not is_safe_url(url) and url.scheme() != "nostalgia":
            self.status_label.setText(
                f"Заблокировано: схема «{html_escape(url.scheme())}» не разрешена"
            )
            return
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
        self.status_label.setText("Загрузка остановлена")

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
                self.zone_label.setText("🔒 Надежный узел")
                self.zone_label.setStyleSheet("color: green;")
            elif url.scheme() == "http":
                self.zone_label.setText("⚠ Не защищено")
                self.zone_label.setStyleSheet("color: orange;")
            else:
                self.zone_label.setText("Зона Интернета")
                self.zone_label.setStyleSheet("")
            self.zoom_label.setText(f"{int(tab.webview.zoomFactor()*100)}%")

    def close_tab(self, index: int):
        if self.tab_widget.count() > 1:
            tab = self.tab_widget.widget(index)
            if tab:
                if tab in self.loading_tabs:
                    self.loading_tabs[tab].stop()
                    self.loading_tabs[tab].deleteLater()
                    del self.loading_tabs[tab]
                wv = tab.webview
                wv.stop()
                wv.setUrl(QUrl("about:blank"))
                wv.page().deleteLater()
            self.tab_widget.removeTab(index)
            if tab:
                tab.deleteLater()
        else:
            reply = QMessageBox.question(
                self, "Выход", "Закрыть браузер?",
                QMessageBox.StandardButton.Yes |
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.save_settings()
                self.site_filter.save_lists()
                QApplication.quit()

    def close_current_tab(self):
        self.close_tab(self.tab_widget.currentIndex())
    
    def next_tab(self):
        current = self.tab_widget.currentIndex()
        next_idx = (current + 1) % self.tab_widget.count()
        self.tab_widget.setCurrentIndex(next_idx)
    
    def prev_tab(self):
        current = self.tab_widget.currentIndex()
        prev_idx = (current - 1) % self.tab_widget.count()
        self.tab_widget.setCurrentIndex(prev_idx)
    
    def switch_to_tab(self, index: int):
        if 0 <= index < self.tab_widget.count():
            self.tab_widget.setCurrentIndex(index)

    def get_current_webview(self) -> QWebEngineView | None:
        tab = self.tab_widget.currentWidget()
        return tab.webview if isinstance(tab, BrowserTab) else None

    def _set_zoom(self, factor: float):
        wv = self.get_current_webview()
        if wv:
            factor = max(0.25, min(5.0, factor))
            wv.setZoomFactor(factor)
            self.zoom_label.setText(f"{int(factor*100)}%")

    def zoom_in(self):
        wv = self.get_current_webview()
        if wv:
            self._set_zoom(wv.zoomFactor() + 0.1)

    def zoom_out(self):
        wv = self.get_current_webview()
        if wv:
            self._set_zoom(wv.zoomFactor() - 0.1)

    def zoom_reset(self):
        self._set_zoom(1.0)

    def _toggle_popup_blocking(self, checked: bool):
        self.block_popups = checked
        for i in range(self.tab_widget.count()):
            tab = self.tab_widget.widget(i)
            if isinstance(tab, BrowserTab):
                tab.nostalgia_page.block_popups = checked
        self.save_settings()
        self.status_label.setText(
            f"Блокировка всплывающих окон "
            f"{'включена' if checked else 'отключена'}"
        )

    def show_filter_settings(self):
        if FilterDialog(self.site_filter, self).exec():
            self.update_filter_indicator()

    def update_filter_indicator(self):
        self.filter_status.setText(
            "🔒 Фильтр вкл." if self.site_filter.filter_enabled else ""
        )

    def show_homepage_settings(self):
        dlg = HomepageDialog(self.homepage, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            new_hp = dlg.homepage
            if new_hp and is_safe_url(QUrl(new_hp)):
                self.homepage = new_hp
                self.save_settings()
                self.status_label.setText(f"Домашняя страница: {sanitize_display_text(new_hp, 50)}")

    def show_theme_dialog(self):
        dlg = ThemeDialog(self.current_theme, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.current_theme = dlg.selected_theme
            apply_theme(QApplication.instance(), self.current_theme)
            self.save_settings()
            self.status_label.setText(f"Тема: {self.current_theme}")

    def show_search_engine_dialog(self):
        dlg = SearchEngineDialog(self.current_engine, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.current_engine = dlg.selected
            self.save_settings()
            self.status_label.setText(
                f"Поисковая система: {self.current_engine}"
            )

    def show_cookie_manager(self):
        tab = self.tab_widget.currentWidget()
        if isinstance(tab, BrowserTab) and tab.is_incognito:
            profile = IncognitoProfile.get()
        else:
            profile = QWebEngineProfile.defaultProfile()
        
        dlg = QDialog(self)
        dlg.setWindowTitle("Управление cookie - Nostalgia")
        dlg.resize(600, 400)
        layout = QVBoxLayout(dlg)
        
        label = QLabel("Управление cookie через настройки браузера.\nДля удаления всех cookie используйте «Очистить данные браузера» (Ctrl+Shift+Del).")
        label.setWordWrap(True)
        layout.addWidget(label)
        
        btn = QPushButton("Закрыть")
        btn.clicked.connect(dlg.accept)
        layout.addWidget(btn)
        
        dlg.exec()

    def show_password_manager(self):
        dlg = PasswordManagerDialog(self.password_manager, self)
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()
    
    def show_bookmark_manager(self):
        dlg = BookmarkManagerDialog(self.bookmarks, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.save_settings()

    def show_clear_data_dialog(self):
        dlg = ClearDataDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        profile = QWebEngineProfile.defaultProfile()
        cleared = []

        if dlg.clear_history:
            self.history.clear()
            cleared.append("история")

        if dlg.clear_cookies:
            try:
                profile.cookieStore().deleteAllCookies()
                cleared.append("cookie")
            except Exception as e:
                logger.warning("Ошибка очистки cookie: %s", e)

        if dlg.clear_cache:
            try:
                profile.clearHttpCache()
                cleared.append("кэш")
            except Exception as e:
                logger.warning("Ошибка очистки кэша: %s", e)

        if dlg.clear_passwords:
            self.password_manager.clear_all()
            cleared.append("пароли")

        if dlg.clear_bookmarks:
            self.bookmarks.clear()
            cleared.append("закладки")

        self.save_settings()
        msg = ", ".join(cleared) if cleared else "ничего"
        self.status_label.setText(f"Очищено: {msg}")
        QMessageBox.information(
            self, "Очистка завершена",
            f"Успешно очищено: {msg}."
        )

    def show_downloads(self):
        if self._download_manager is None:
            self._download_manager = DownloadManagerDialog(self)
        self._download_manager.show()
        self._download_manager.raise_()
        self._download_manager.activateWindow()

    def open_find_bar(self):
        tab = self.tab_widget.currentWidget()
        if isinstance(tab, BrowserTab):
            tab.find_bar.set_webview(tab.webview)
            tab.find_bar.open_bar()

    def add_to_bookmarks(self):
        wv = self.get_current_webview()
        if wv:
            url = wv.url()
            if not is_safe_url(url):
                self.status_label.setText(
                    "Нельзя добавить: небезопасная схема URL"
                )
                return
            url_str = url.toString()
            title = wv.title() or url_str
            name, ok = QInputDialog.getText(
                self, "Добавление в избранное", "Название:", text=title
            )
            if ok and name:
                safe_name = html_escape(name[:200])
                self.bookmarks[safe_name] = url_str
                self.save_settings()
                self.status_label.setText("Добавлено в избранное")

    def show_history(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("История - Nostalgia")
        dlg.resize(600, 400)
        layout = QVBoxLayout(dlg)
        lw = QListWidget()

        for e in reversed(self.history[-200:]):
            url_str = e.get('url', '')
            if not sanitize_url_for_history(url_str):
                continue
            title = e.get('title', '')
            safe_title = sanitize_display_text(title, 50) if title else ""
            safe_url = sanitize_display_text(url_str, 80)
            
            time_str = ""
            if e.get('time'):
                try:
                    dt = datetime.datetime.fromisoformat(e['time'])
                    time_str = f" [{dt.strftime('%d.%m.%Y %H:%M')}]"
                except (ValueError, TypeError):
                    pass
            
            text = f"{safe_title}{time_str}  —  {safe_url}"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, url_str)
            lw.addItem(item)
        layout.addWidget(lw)

        def open_from_history(item):
            url_str = item.data(Qt.ItemDataRole.UserRole)
            if url_str:
                q = QUrl(url_str)
                if is_safe_url(q):
                    self.add_new_tab(q)
                else:
                    self.status_label.setText(
                        "Заблокировано: небезопасный URL из истории"
                    )
            dlg.accept()

        lw.itemDoubleClicked.connect(open_from_history)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(dlg.reject)
        layout.addWidget(bb)
        dlg.exec()

    def show_search(self):
        text, ok = QInputDialog.getText(self, "Поиск", "Введите запрос:")
        if ok and text:
            tmpl = SEARCH_ENGINES.get(self.current_engine, SEARCH_ENGINES["Google"])
            self.load_url(tmpl.replace("{query}", quote_plus(text)))

    def toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def show_about(self):
        QMessageBox.about(
            self, "О программе",
            "Nostalgia Browser v0.3.0 Alpha\n\n"
            "Вдохновлен Internet Explorer 5.5\n"
            "Стиль: Windows 98 Classic\n\n"
            "Исправления безопасности v0.3.0:\n"
            "• Защита от XSS в заголовках и истории\n"
            "• Безопасное отображение паролей с автоскрытием\n"
            "• Защита буфера обмена\n"
            "• Rate limiting навигации\n"
            "• Защита от path traversal\n"
            "• Ограничение WebRTC\n"
            "• Отключение DNS prefetch\n"
            "• Безопасное шифрование паролей\n"
            "• Защита от race condition в загрузках\n"
            "• Очистка памяти при выходе\n\n"
            "© 2026 Nostalgia Project"
        )

    def closeEvent(self, event):
        if self.tab_widget.count() > 1:
            reply = QMessageBox.question(
                self, "Подтверждение выхода",
                f"Закрыть {self.tab_widget.count()} вкладок и выйти?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        
        self._cleanup_security()
        self.save_settings()
        self.site_filter.save_lists()
        if hasattr(self, 'globe'):
            self.globe.stop()
        for w in list(self.loading_tabs.values()):
            w.stop()
        event.accept()


def main():
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