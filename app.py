import os
import json
import time
import uuid
import base64
import hashlib
import requests
import streamlit as st
import streamlit.components.v1 as components
import google.generativeai as genai
from datetime import datetime, timedelta
from collections import defaultdict
from cryptography.fernet import Fernet
from streamlit_cookies_controller import CookieController

try:
    from google.api_core import exceptions as google_exceptions
except Exception:
    google_exceptions = None

# ==========================================
# 0. VERSION & HẰNG SỐ
# ==========================================
APP_VERSION = "1.12.0"

ADMIN_USERNAME = "Admin"
ADMIN_PASSWORD = "7428"

TEST_USERNAME = "test"
TEST_PASSWORD = "testsoftware"

SYSTEM_CONFIG_KEY = "__system_config__"
TRAFFIC_LOG_KEY = "__traffic_log__"
BUG_REPORTS_KEY = "__bug_reports__"
TRAFFIC_RETENTION_DAYS = 30
BUG_REPORTS_MAX = 50

VN_TZ_OFFSET = timedelta(hours=7)
VERSION_SCAN_INTERVAL = 60

# Smart draft
SMART_DRAFT_MIN_WORDS = 20
SMART_DRAFT_INTERVAL_SEC = 5
SMART_DRAFT_IDLE_SEC = 20
COOKIE_DRAFT = "LTTP_chat_draft"
COOKIE_DRAFT_TS = "LTTP_draft_ts"

# Bug report
BR_COOKIE_PREFIX = "LTTP_br_"
BR_META_COOKIE = "LTTP_br_meta"
BR_CHUNK_SIZE = 3000
BR_MAX_CHUNKS = 20

# Streaming
STREAM_UPDATE_INTERVAL = 0.05

# Typing speed modes
TYPING_MODE_SMOOTH = "smooth"
TYPING_MODE_CONTROLLED = "controlled"
TYPING_MODE_INSTANT = "instant"
DEFAULT_TYPING_MODE = TYPING_MODE_SMOOTH
DEFAULT_TYPING_CPS = 30

def vn_now() -> datetime:
    return datetime.utcnow() + VN_TZ_OFFSET

# ==========================================
# 1. CẤU HÌNH TRANG & SECRETS
# ==========================================
st.set_page_config(
    page_title="LTTP AI Online",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

DB_FILE = "users_db.json"
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", "")
GITHUB_REPO = st.secrets.get("GITHUB_REPO", "")

MASTER_SECRET = st.secrets.get("ENCRYPTION_SECRET", "LTTPAI_Master_Secret_Key_2026")
FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(MASTER_SECRET.encode()).digest())
cipher = Fernet(FERNET_KEY)

API_KEY_1 = st.secrets.get("GEMINI_API_KEY_1", "").strip()
API_KEY_2 = st.secrets.get("GEMINI_API_KEY_2", "").strip()
SECRET_API_KEYS = [k for k in [API_KEY_1, API_KEY_2] if k]

cookies = CookieController()
COOKIE_MAX_AGE = 30 * 24 * 60 * 60

device_id = cookies.get("LTTP_device_id")
if not device_id:
    device_id = str(uuid.uuid4())
    cookies.set("LTTP_device_id", device_id, max_age=COOKIE_MAX_AGE)

DEFAULT_MODEL = "gemini-3.5-flash"

FAILOVER_MODEL_CHAIN = [
    "gemini-3.5-flash", "gemini-3.5-flash-lite", "gemini-3.6-flash",
    "gemini-3.7-flash", "gemini-3.8-flash", "gemini-2.5-flash",
    "gemini-2.5-flash-lite", "gemini-2.0-flash", "gemini-1.5-flash",
]

FALLBACK_MODELS = [
    "gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.6-flash",
    "gemini-3.5-flash", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite",
    "gemini-3.1-pro-preview", "gemini-2.5-flash", "gemini-2.5-flash-lite",
    "gemini-2.5-pro", "gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro",
]

LEGACY_MODEL_MAP = {
    "gemini-2.5-flash": "gemini-3.5-flash", "gemini-2.5-pro": "gemini-3.5-flash",
    "gemini-2.0-flash": "gemini-3.5-flash", "gemini-1.5-flash": "gemini-3.5-flash",
    "gemini-1.5-pro": "gemini-3.5-flash", "gemini-1.0-pro": "gemini-3.5-flash",
    "gemini-pro": "gemini-3.5-flash",
}

RATE_LIMIT_RETRY_DELAY = 60

DISCLAIMER = {
    "vi": "Lưu ý kiểm tra thông tin của A.I trước khi xác nhận thông tin.",
    "en": "Please verify A.I information before confirming any facts.",
}

UPDATE_NOTICE = {
    "vi": "🔄 Phần mềm vừa được cập nhật",
    "en": "🔄 Software just got updated",
}

REBOOT_NOTICE = {
    "vi": {
        "title": "Đã có phiên bản mới!",
        "desc": "Vui lòng tải lại trang (F5 hoặc Ctrl+R) để cập nhật lên phiên bản mới nhất.",
        "button": "Tải lại ngay",
        "later": "Để sau",
    },
    "en": {
        "title": "New version available!",
        "desc": "Please reload the page (F5 or Ctrl+R) to update to the latest version.",
        "button": "Reload now",
        "later": "Later",
    },
}

# ==========================================
# 2. CUSTOM CSS
# ==========================================
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        font-weight: 800; font-size: 2.5rem; margin-bottom: 0.2rem;
    }
    .ai-loading-box {
        display: flex; align-items: center; gap: 12px;
        padding: 12px 18px;
        background: rgba(102, 126, 234, 0.08);
        border: 1px solid rgba(102, 126, 234, 0.2);
        border-radius: 12px; margin-bottom: 15px;
    }
    .spinner {
        width: 22px; height: 22px;
        border: 3px solid rgba(102, 126, 234, 0.2);
        border-top: 3px solid #667eea;
        border-radius: 50%; animation: spin 0.8s linear infinite;
    }
    .ai-loading-text {
        color: #667eea; font-weight: 600; font-size: 0.95rem;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 50%, #667eea 100%);
        background-size: 200% auto;
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        animation: shine 2s linear infinite;
    }
    .typing-cursor {
        display: inline-block;
        width: 8px; height: 1.1em;
        background: #667eea; margin-left: 2px; vertical-align: text-bottom;
        animation: blink 1s step-end infinite;
    }
    @keyframes blink {
        0%, 100% { opacity: 1; }
        50% { opacity: 0; }
    }
    .pulse-dot {
        width: 8px; height: 8px; background-color: #10b981;
        border-radius: 50%; display: inline-block;
        box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
        animation: pulse 1.6s infinite; margin-right: 6px;
    }
    .rate-limit-box {
        padding: 14px 18px;
        background: rgba(251, 191, 36, 0.1);
        border: 1px solid rgba(251, 191, 36, 0.35);
        border-radius: 12px; margin-bottom: 15px;
    }
    .rate-limit-text { color: #fbbf24; font-weight: 600; font-size: 0.95rem; }
    .rate-limit-countdown { color: #f59e0b; font-weight: 800; font-size: 1.1rem; }

    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    @keyframes shine { to { background-position: 200% center; } }
    @keyframes pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }
    .user-card {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 10px 14px; border-radius: 10px; margin-bottom: 12px;
    }
    .stButton button { width: 100%; }
    .status-badge {
        display: inline-block; padding: 2px 8px;
        border-radius: 6px; font-size: 0.75rem;
        font-weight: 600; margin-left: 6px;
    }
    .badge-ready { background: rgba(16, 185, 129, 0.15); color: #10b981; }
    .badge-missing { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
    .badge-admin { background: rgba(251, 191, 36, 0.15); color: #fbbf24; }
    .badge-guest { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
    .badge-test { background: rgba(168, 85, 247, 0.15); color: #a855f7; }
    .badge-bug { background: rgba(239, 68, 68, 0.15); color: #ef4444; }

    .ai-disclaimer {
        font-size: 0.78rem; font-style: italic;
        color: rgba(148, 163, 184, 0.85);
        margin-top: 6px; padding-top: 6px;
        border-top: 1px dashed rgba(148, 163, 184, 0.25);
    }
    .update-notice {
        padding: 8px 14px;
        background: linear-gradient(90deg, rgba(102, 126, 234, 0.15), rgba(118, 75, 162, 0.15));
        border: 1px solid rgba(102, 126, 234, 0.3);
        border-radius: 10px; font-size: 0.85rem;
        font-weight: 600; color: #667eea;
        text-align: center; margin-bottom: 10px;
    }
    .reboot-banner {
        padding: 14px 20px;
        background: linear-gradient(90deg, #f59e0b, #f97316);
        color: #fff; border-radius: 12px;
        margin-bottom: 14px;
        box-shadow: 0 4px 16px rgba(249, 115, 22, 0.35);
        animation: rebootPulse 2s ease-in-out infinite;
    }
    .reboot-banner-title {
        font-size: 1.05rem; font-weight: 800;
        margin-bottom: 4px;
    }
    .reboot-banner-desc { font-size: 0.9rem; opacity: 0.95; }
    @keyframes rebootPulse {
        0%, 100% { box-shadow: 0 4px 16px rgba(249, 115, 22, 0.35); }
        50% { box-shadow: 0 4px 24px rgba(249, 115, 22, 0.65); }
    }

    .announcement-banner {
        padding: 16px 20px;
        background: linear-gradient(135deg, rgba(102, 126, 234, 0.12), rgba(118, 75, 162, 0.12));
        border: 1px solid rgba(102, 126, 234, 0.4);
        border-left: 5px solid #667eea;
        border-radius: 12px;
        margin-bottom: 16px;
        animation: announcementIn 0.5s ease-out;
    }
    .announcement-header {
        display: flex; align-items: center; gap: 8px;
        font-size: 1.05rem; font-weight: 800;
        color: #667eea; margin-bottom: 8px;
    }
    .announcement-body {
        font-size: 0.95rem; color: #e2e8f0;
        line-height: 1.6; white-space: pre-wrap; word-break: break-word;
    }
    .announcement-meta {
        margin-top: 10px; font-size: 0.75rem;
        color: #94a3b8; font-style: italic;
        border-top: 1px dashed rgba(148, 163, 184, 0.25);
        padding-top: 8px;
    }
    @keyframes announcementIn {
        from { opacity: 0; transform: translateY(-8px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .maintenance-banner {
        padding: 18px 22px;
        background: linear-gradient(90deg, rgba(239, 68, 68, 0.15), rgba(220, 38, 38, 0.1));
        border: 1px solid rgba(239, 68, 68, 0.4);
        border-radius: 12px; margin-bottom: 16px;
        text-align: center; color: #ef4444;
        font-weight: 600; font-size: 1rem;
    }
    .maintenance-note {
        margin-top: 14px; padding: 12px 16px;
        background: rgba(251, 191, 36, 0.1);
        border-left: 4px solid #fbbf24;
        border-radius: 8px;
        font-size: 0.95rem; color: #fbbf24;
        font-style: italic; text-align: left;
    }
    .test-notice {
        padding: 12px 18px;
        background: linear-gradient(90deg, rgba(168, 85, 247, 0.15), rgba(139, 92, 246, 0.1));
        border: 1px solid rgba(168, 85, 247, 0.4);
        border-radius: 12px; margin-bottom: 16px;
        color: #a855f7; font-size: 0.88rem;
        font-weight: 600; text-align: center;
    }
    .admin-panel {
        padding: 16px;
        background: rgba(251, 191, 36, 0.05);
        border: 1px solid rgba(251, 191, 36, 0.25);
        border-radius: 12px; margin-bottom: 16px;
    }
    .stat-card {
        padding: 14px 18px;
        background: rgba(102, 126, 234, 0.08);
        border: 1px solid rgba(102, 126, 234, 0.2);
        border-radius: 10px; text-align: center;
    }
    .stat-value {
        font-size: 1.8rem; font-weight: 800; color: #667eea;
        line-height: 1.1;
    }
    .stat-label {
        font-size: 0.8rem; color: #94a3b8;
        margin-top: 4px; font-weight: 500;
    }
    .guest-banner {
        padding: 10px 14px;
        background: rgba(148, 163, 184, 0.1);
        border: 1px solid rgba(148, 163, 184, 0.3);
        border-radius: 10px; font-size: 0.85rem;
        color: #94a3b8; text-align: center;
        margin-bottom: 12px;
    }
    .traffic-row {
        padding: 6px 10px; margin: 3px 0;
        background: rgba(255,255,255,0.03);
        border-radius: 6px; font-size: 0.88rem;
        font-family: monospace;
    }
    .draft-banner {
        padding: 10px 14px; margin-bottom: 12px;
        background: rgba(251, 191, 36, 0.08);
        border: 1px solid rgba(251, 191, 36, 0.3);
        border-radius: 10px;
        font-size: 0.85rem; color: #fbbf24;
    }
    .draft-preview {
        padding: 8px 12px; margin-top: 6px;
        background: rgba(0,0,0,0.15);
        border-radius: 6px;
        font-family: monospace; font-size: 0.82rem;
        color: #e2e8f0;
        max-height: 80px; overflow-y: auto;
        white-space: pre-wrap; word-break: break-word;
    }
    .bug-report-card {
        padding: 14px 16px; margin-bottom: 12px;
        background: rgba(239, 68, 68, 0.05);
        border: 1px solid rgba(239, 68, 68, 0.25);
        border-radius: 10px;
    }
    .bug-report-meta {
        font-size: 0.8rem; color: #94a3b8;
        margin-bottom: 8px;
    }
    .bug-report-text {
        font-size: 0.9rem; color: #e2e8f0;
        padding: 8px 12px;
        background: rgba(0,0,0,0.15);
        border-radius: 6px;
        white-space: pre-wrap; word-break: break-word;
        margin-top: 6px;
    }
    .bug-report-reply {
        margin-top: 8px;
        padding: 8px 12px;
        background: rgba(16, 185, 129, 0.08);
        border-left: 3px solid #10b981;
        border-radius: 6px;
        font-size: 0.88rem;
        color: #10b981;
    }

    /* Ngăn browser tự anchor scroll khi content thay đổi */
    html, body, [data-testid="stAppViewContainer"], section.main {
        overflow-anchor: none !important;
    }
    
    .typing-mode-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 600;
        background: rgba(102, 126, 234, 0.15);
        color: #667eea;
        margin-left: 6px;
    }

    section[data-testid="stChatInput"] button[aria-label*="upload" i],
    section[data-testid="stChatInput"] button[aria-label*="Attach" i],
    section[data-testid="stChatInput"] button[aria-label*="file" i],
    div[data-testid="stChatInput"] button[aria-label*="upload" i],
    div[data-testid="stChatInput"] button[aria-label*="Attach" i],
    div[data-testid="stChatInput"] button[aria-label*="file" i],
    [data-testid="stChatInputFileUpload"],
    [data-testid="stChatInputFiles"],
    [data-testid="stChatInputAttachment"],
    [data-testid="stChatInput"] input[type="file"] {
        display: none !important;
        visibility: hidden !important;
        width: 0 !important; height: 0 !important;
        opacity: 0 !important;
        pointer-events: none !important;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 3. HÀM TIỆN ÍCH
# ==========================================
def encrypt_key(raw_key: str) -> str:
    if not raw_key:
        return ""
    try:
        return cipher.encrypt(raw_key.encode('utf-8')).decode('utf-8')
    except Exception:
        return ""

def decrypt_key(encrypted_key: str) -> str:
    if not encrypted_key:
        return ""
    try:
        return cipher.decrypt(encrypted_key.encode('utf-8')).decode('utf-8')
    except Exception:
        return ""

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def mask_device(did: str) -> str:
    if not did or len(did) < 12:
        return "unknown"
    return f"{did[:6]}...{did[-4:]}"

def count_words(text: str) -> int:
    if not text:
        return 0
    return len(text.strip().split())

def is_temporary_session() -> bool:
    return bool(st.session_state.get("is_temporary", False))

def safe_save_db(data: dict) -> tuple:
    if is_temporary_session():
        return True, "Temporary session - not saved"
    return GitHubStorage.save_db(data)

# ==========================================
# 4. JAVASCRIPT INJECTION
# ==========================================
def inject_js(js_code: str, height: int = 0):
    html_template = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head><meta charset=\"utf-8\"></head>\n"
        "<body style=\"margin:0;padding:0;\">\n"
        "<script>\n"
        "(function() {\n"
        "    try {\n"
        "        const w = window.parent || window;\n"
        "        const d = w.document;\n"
        "        __JS_CODE__\n"
        "    } catch (e) {\n"
        "        console.warn('LTTP JS error:', e);\n"
        "    }\n"
        "})();\n"
        "</script>\n"
        "</body>\n"
        "</html>"
    )
    html = html_template.replace("__JS_CODE__", js_code)
    components.html(html, height=height, scrolling=False)


def inject_version_scanner():
    js = (
        'const CURRENT_VERSION = "' + APP_VERSION + '";\n'
        'const SCAN_INTERVAL_MS = ' + str(VERSION_SCAN_INTERVAL * 1000) + ';\n'
        'const COOKIE_NAME = "LTTP_app_version";\n'
        '\n'
        'function getCookie(name) {\n'
        '    const value = "; " + d.cookie;\n'
        '    const parts = value.split("; " + name + "=");\n'
        '    if (parts.length === 2) return parts.pop().split(";").shift();\n'
        '    return null;\n'
        '}\n'
        '\n'
        'function checkVersion() {\n'
        '    try {\n'
        '        const cached = getCookie(COOKIE_NAME);\n'
        '        if (cached && cached !== CURRENT_VERSION) {\n'
        '            if (!d.getElementById("lttp-reboot-banner-injected")) {\n'
        '                const banner = d.createElement("div");\n'
        '                banner.id = "lttp-reboot-banner-injected";\n'
        '                banner.style.cssText = "position:fixed;top:10px;left:50%;transform:translateX(-50%);z-index:999999;padding:14px 24px;background:linear-gradient(90deg,#f59e0b,#f97316);color:white;border-radius:12px;box-shadow:0 6px 24px rgba(249,115,22,0.55);font-family:sans-serif;max-width:90vw;";\n'
        '                banner.innerHTML = "<div style=\\"font-weight:800;font-size:1.05rem;margin-bottom:4px;\\">🚀 Đã có phiên bản mới!</div><div style=\\"font-size:0.9rem;margin-bottom:10px;opacity:0.95;\\">Vui lòng tải lại trang để cập nhật.</div><button onclick=\\"location.reload()\\" style=\\"background:white;color:#f97316;border:none;padding:8px 20px;border-radius:8px;font-weight:700;cursor:pointer;font-size:0.9rem;\\">Tải lại ngay</button>";\n'
        '                d.body.appendChild(banner);\n'
        '            }\n'
        '        }\n'
        '    } catch (e) {}\n'
        '}\n'
        '\n'
        'setTimeout(checkVersion, 3000);\n'
        'setInterval(checkVersion, SCAN_INTERVAL_MS);\n'
    )
    inject_js(js)


def inject_scroll_guard():
    js = (
        'if (!window.__lttp_scroll_guard_installed) {\n'
        '    window.__lttp_scroll_guard_installed = true;\n'
        '    window.__lttp_scroll_lock = false;\n'
        '    \n'
        '    const origScrollIntoView = Element.prototype.scrollIntoView;\n'
        '    Element.prototype.scrollIntoView = function() {\n'
        '        if (window.__lttp_scroll_lock) return;\n'
        '        return origScrollIntoView.apply(this, arguments);\n'
        '    };\n'
        '    \n'
        '    function getScrollContainer() {\n'
        '        let el = d.querySelector("section.main");\n'
        '        if (el) return el;\n'
        '        el = d.querySelector("[data-testid=\\"stAppViewContainer\\"]");\n'
        '        if (el) return el;\n'
        '        return d.scrollingElement || d.documentElement;\n'
        '    }\n'
        '    \n'
        '    function updateLock() {\n'
        '        const c = getScrollContainer();\n'
        '        if (!c) return;\n'
        '        const atBottom = (c.scrollHeight - c.scrollTop - c.clientHeight) < 150;\n'
        '        window.__lttp_scroll_lock = !atBottom;\n'
        '    }\n'
        '    \n'
        '    let ticking = false;\n'
        '    d.addEventListener("scroll", function() {\n'
        '        if (ticking) return;\n'
        '        ticking = true;\n'
        '        requestAnimationFrame(function() {\n'
        '            updateLock();\n'
        '            ticking = false;\n'
        '        });\n'
        '    }, true);\n'
        '    \n'
        '    setInterval(updateLock, 500);\n'
        '}\n'
    )
    inject_js(js)


def inject_smart_draft_tracker(enabled, min_words, interval_sec, idle_sec):
    if not enabled:
        js_clear = (
            'd.cookie = "' + COOKIE_DRAFT + '=; max-age=0; path=/";\n'
            'd.cookie = "' + COOKIE_DRAFT_TS + '=; max-age=0; path=/";\n'
        )
        inject_js(js_clear)
        return

    js = (
        'const MIN_WORDS = ' + str(min_words) + ';\n'
        'const INTERVAL_MS = ' + str(interval_sec * 1000) + ';\n'
        'const IDLE_MS = ' + str(idle_sec * 1000) + ';\n'
        'const DRAFT_COOKIE = "' + COOKIE_DRAFT + '";\n'
        'const TS_COOKIE = "' + COOKIE_DRAFT_TS + '";\n'
        '\n'
        'let lastSavedText = "";\n'
        'let lastIdleSavedText = "";\n'
        'let typingTimer = null;\n'
        'let periodicTimer = null;\n'
        'let currentTextarea = null;\n'
        '\n'
        'function countWords(s) {\n'
        '    if (!s) return 0;\n'
        '    return s.trim().split(/\\s+/).filter(Boolean).length;\n'
        '}\n'
        '\n'
        'function saveDraft(text) {\n'
        '    try {\n'
        '        const encoded = encodeURIComponent(text);\n'
        '        const trimmed = encoded.length > 3500 ? encoded.slice(0, 3500) : encoded;\n'
        '        d.cookie = DRAFT_COOKIE + "=" + trimmed + "; path=/; max-age=86400";\n'
        '        d.cookie = TS_COOKIE + "=" + Date.now() + "; path=/; max-age=86400";\n'
        '        lastSavedText = text;\n'
        '    } catch (e) {}\n'
        '}\n'
        '\n'
        'function attachToTextarea() {\n'
        '    const candidates = d.querySelectorAll(\n'
        '        "textarea[data-testid=\\"stChatInputTextArea\\"], " +\n'
        '        "section[data-testid=\\"stChatInput\\"] textarea, " +\n'
        '        "div[data-testid=\\"stChatInput\\"] textarea, " +\n'
        '        "textarea[aria-label*=\\"chat\\" i], " +\n'
        '        "textarea[placeholder]"\n'
        '    );\n'
        '    let ta = null;\n'
        '    for (const c of candidates) {\n'
        '        if (c.offsetParent !== null) { ta = c; break; }\n'
        '    }\n'
        '    if (!ta || ta === currentTextarea) return;\n'
        '    \n'
        '    currentTextarea = ta;\n'
        '    const handler = function() {\n'
        '        const text = ta.value || "";\n'
        '        const words = countWords(text);\n'
        '        \n'
        '        if (typingTimer) clearTimeout(typingTimer);\n'
        '        if (periodicTimer) { clearInterval(periodicTimer); periodicTimer = null; }\n'
        '        \n'
        '        if (words > MIN_WORDS) {\n'
        '            periodicTimer = setInterval(function() {\n'
        '                const cur = ta.value || "";\n'
        '                if (cur && cur !== lastSavedText) {\n'
        '                    saveDraft(cur);\n'
        '                }\n'
        '            }, INTERVAL_MS);\n'
        '        }\n'
        '        \n'
        '        typingTimer = setTimeout(function() {\n'
        '            const cur = ta.value || "";\n'
        '            if (cur && cur !== lastIdleSavedText) {\n'
        '                saveDraft(cur);\n'
        '                lastIdleSavedText = cur;\n'
        '            }\n'
        '        }, IDLE_MS);\n'
        '    };\n'
        '    \n'
        '    ta.removeEventListener("input", ta._lttpHandler);\n'
        '    ta._lttpHandler = handler;\n'
        '    ta.addEventListener("input", handler);\n'
        '}\n'
        '\n'
        'attachToTextarea();\n'
        'setInterval(attachToTextarea, 2000);\n'
    )
    inject_js(js)


def clear_draft_cookie_via_js():
    js_clear = (
        'd.cookie = "' + COOKIE_DRAFT + '=; max-age=0; path=/";\n'
        'd.cookie = "' + COOKIE_DRAFT_TS + '=; max-age=0; path=/";\n'
    )
    inject_js(js_clear)


def inject_screenshot_capture(max_chunks: int):
    js = (
        'if (typeof html2canvas === "undefined") {\n'
        '    const s = d.createElement("script");\n'
        '    s.src = "https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js";\n'
        '    d.head.appendChild(s);\n'
        '}\n'
        '\n'
        'window.__lttp_do_screenshot = function() {\n'
        '    try {\n'
        '        if (typeof html2canvas === "undefined") {\n'
        '            setTimeout(window.__lttp_do_screenshot, 500);\n'
        '            return;\n'
        '        }\n'
        '        html2canvas(d.body, {\n'
        '            backgroundColor: "#0e1117",\n'
        '            scale: 1,\n'
        '            logging: false,\n'
        '            useCORS: true,\n'
        '            allowTaint: true,\n'
        '            windowWidth: d.documentElement.clientWidth,\n'
        '            windowHeight: d.documentElement.clientHeight\n'
        '        }).then(function(canvas) {\n'
        '            const targetWidth = 480;\n'
        '            const scale = targetWidth / canvas.width;\n'
        '            const targetHeight = Math.round(canvas.height * scale);\n'
        '            \n'
        '            const off = d.createElement("canvas");\n'
        '            off.width = targetWidth;\n'
        '            off.height = targetHeight;\n'
        '            const ctx = off.getContext("2d");\n'
        '            ctx.drawImage(canvas, 0, 0, targetWidth, targetHeight);\n'
        '            \n'
        '            const dataUrl = off.toDataURL("image/jpeg", 0.4);\n'
        '            const b64 = dataUrl.split(",")[1];\n'
        '            \n'
        '            const CHUNK_SIZE = ' + str(BR_CHUNK_SIZE) + ';\n'
        '            const chunks = [];\n'
        '            for (let i = 0; i < b64.length; i += CHUNK_SIZE) {\n'
        '                chunks.push(b64.slice(i, i + CHUNK_SIZE));\n'
        '            }\n'
        '            \n'
        '            for (let i = 0; i < ' + str(max_chunks) + '; i++) {\n'
        '                d.cookie = "' + BR_COOKIE_PREFIX + '" + i + "=; max-age=0; path=/";\n'
        '            }\n'
        '            d.cookie = "' + BR_META_COOKIE + '=; max-age=0; path=/";\n'
        '            \n'
        '            const maxToStore = Math.min(chunks.length, ' + str(max_chunks) + ');\n'
        '            for (let i = 0; i < maxToStore; i++) {\n'
        '                d.cookie = "' + BR_COOKIE_PREFIX + '" + i + "=" + chunks[i] + "; path=/; max-age=300";\n'
        '            }\n'
        '            d.cookie = "' + BR_META_COOKIE + '=" + maxToStore + "; path=/; max-age=300";\n'
        '        }).catch(function(err) {\n'
        '            console.warn("Screenshot error:", err);\n'
        '        });\n'
        '    } catch (e) {\n'
        '        console.warn("Screenshot outer error:", e);\n'
        '    }\n'
        '};\n'
        '\n'
        'window.__lttp_do_screenshot();\n'
    )
    inject_js(js)


def read_bug_report_screenshot():
    try:
        meta = cookies.get(BR_META_COOKIE)
        if not meta:
            return None
        try:
            n = int(meta)
        except Exception:
            return None
        if n <= 0 or n > BR_MAX_CHUNKS:
            return None

        parts = []
        for i in range(n):
            c = cookies.get(BR_COOKIE_PREFIX + str(i))
            if not c:
                return None
            parts.append(c)

        b64 = "".join(parts)
        if not b64:
            return None
        return b64
    except Exception:
        return None


def clear_bug_report_cookies():
    try:
        cookies.set(BR_META_COOKIE, "", max_age=0)
        for i in range(BR_MAX_CHUNKS):
            cookies.set(BR_COOKIE_PREFIX + str(i), "", max_age=0)
    except Exception:
        pass


def get_saved_draft():
    try:
        raw = cookies.get(COOKIE_DRAFT)
        ts = cookies.get(COOKIE_DRAFT_TS)
        if raw:
            from urllib.parse import unquote
            text = unquote(raw)
            return text, ts
    except Exception:
        pass
    return None, None

# ==========================================
# 5. LỖI 429
# ==========================================
def is_rate_limit_error(error: Exception) -> bool:
    if google_exceptions is not None:
        try:
            if isinstance(error, google_exceptions.ResourceExhausted):
                return True
            if isinstance(error, google_exceptions.TooManyRequests):
                return True
            if hasattr(error, "code"):
                try:
                    code_str = str(error.code).upper()
                    if "429" in code_str or "RESOURCE_EXHAUSTED" in code_str:
                        return True
                except Exception:
                    pass
        except Exception:
            pass
    if getattr(error, "status_code", None) == 429:
        return True
    if getattr(error, "code", None) == 429:
        return True
    err_str = str(error).lower()
    keywords = ["429", "quota", "rate limit", "rate_limit",
                "resource_exhausted", "resource exhausted",
                "too many requests", "exceeded your current quota"]
    return any(k in err_str for k in keywords)

# ==========================================
# 6. GỌI GEMINI VỚI FAILOVER (STREAMING + TYPING MODES)
# ==========================================
def _build_model_chain(preferred_model: str) -> list:
    chain = [preferred_model]
    for m in FAILOVER_MODEL_CHAIN:
        if m not in chain:
            chain.append(m)
    return chain


def stream_gemini_with_failover(
    prompt_inputs, api_keys, preferred_model,
    system_instruction=None, generation_config=None, lang="en",
    ui_placeholder=None,
    typing_mode=TYPING_MODE_SMOOTH,
    typing_cps=DEFAULT_TYPING_CPS,
):
    """
    Generator streaming với failover + kiểm soát tốc độ gõ.
    
    typing_mode:
      - smooth: hiện ngay khi có chunk
      - controlled: đệm chunk, release theo tốc độ typing_cps ký tự/giây
      - instant: đợi response xong hết rồi yield 1 lần
    """
    if not api_keys:
        yield "", True, "no_api_keys"
        return

    model_chain = _build_model_chain(preferred_model)
    last_error = None
    saw_rate_limit = False
    saw_other_error = False

    for model_name in model_chain:
        for api_k in api_keys:
            accumulated = ""
            got_first_chunk = False

            use_stream = (typing_mode != TYPING_MODE_INSTANT)

            try:
                genai.configure(api_key=api_k)
                model = genai.GenerativeModel(
                    model_name=model_name,
                    system_instruction=system_instruction if system_instruction else None,
                    generation_config=generation_config or {}
                )

                if not use_stream:
                    # === INSTANT: non-stream, đợi xong hết ===
                    res = model.generate_content(prompt_inputs)
                    text = getattr(res, "text", None)
                    if text:
                        if ui_placeholder is not None:
                            ui_placeholder.markdown(text, unsafe_allow_html=True)
                        yield text, True, None
                        return
                    else:
                        saw_other_error = True
                        last_error = "Empty response"
                        continue

                # === SMOOTH / CONTROLLED: dùng stream ===
                response = model.generate_content(prompt_inputs, stream=True)

                display_buffer = ""
                pending_buffer = ""
                last_release_time = time.time()
                chars_per_sec = max(1, int(typing_cps))

                for chunk in response:
                    try:
                        chunk_text = getattr(chunk, "text", None)
                    except Exception:
                        chunk_text = None
                    if not chunk_text:
                        continue

                    got_first_chunk = True
                    accumulated += chunk_text

                    if typing_mode == TYPING_MODE_SMOOTH:
                        if ui_placeholder is not None:
                            display = accumulated + '<span class="typing-cursor"></span>'
                            ui_placeholder.markdown(display, unsafe_allow_html=True)
                        yield accumulated, False, None
                    else:
                        # CONTROLLED
                        pending_buffer += chunk_text
                        now = time.time()
                        elapsed = now - last_release_time
                        chars_to_release = int(elapsed * chars_per_sec)

                        if chars_to_release > 0:
                            release = pending_buffer[:chars_to_release]
                            pending_buffer = pending_buffer[chars_to_release:]
                            display_buffer += release
                            last_release_time = now
                            if ui_placeholder is not None:
                                disp = display_buffer + '<span class="typing-cursor"></span>'
                                ui_placeholder.markdown(disp, unsafe_allow_html=True)
                            yield display_buffer, False, None
                        else:
                            if ui_placeholder is not None:
                                disp = display_buffer + '<span class="typing-cursor"></span>'
                                ui_placeholder.markdown(disp, unsafe_allow_html=True)
                            yield display_buffer, False, None

                # Release nốt pending còn lại với tốc độ cps
                if typing_mode == TYPING_MODE_CONTROLLED and pending_buffer:
                    while pending_buffer:
                        now = time.time()
                        elapsed = now - last_release_time
                        chars_to_release = int(elapsed * chars_per_sec)
                        if chars_to_release <= 0:
                            time.sleep(1.0 / chars_per_sec)
                            continue
                        release = pending_buffer[:chars_to_release]
                        pending_buffer = pending_buffer[chars_to_release:]
                        display_buffer += release
                        last_release_time = now
                        if ui_placeholder is not None:
                            disp = display_buffer + '<span class="typing-cursor"></span>'
                            ui_placeholder.markdown(disp, unsafe_allow_html=True)
                        yield display_buffer, False, None

                if accumulated:
                    if ui_placeholder is not None:
                        ui_placeholder.markdown(accumulated, unsafe_allow_html=True)
                    yield accumulated, True, None
                    return
                else:
                    saw_other_error = True
                    last_error = "Empty response"
                    continue

            except Exception as ex:
                last_error = str(ex)
                if got_first_chunk and accumulated:
                    if is_rate_limit_error(ex):
                        yield accumulated, True, "rate_limit_partial"
                    else:
                        yield accumulated, True, last_error
                    return

                if is_rate_limit_error(ex):
                    saw_rate_limit = True
                    continue
                else:
                    saw_other_error = True
                    continue

    if saw_rate_limit and not saw_other_error:
        yield "", True, "rate_limit"
    elif saw_rate_limit and saw_other_error:
        if last_error and is_rate_limit_error(Exception(last_error)):
            yield "", True, "rate_limit"
        else:
            yield "", True, last_error or "unknown_error"
    else:
        yield "", True, last_error or "unknown_error"


def call_gemini_with_failover(
    prompt_inputs, api_keys, preferred_model,
    system_instruction=None, generation_config=None, lang="en",
):
    if not api_keys:
        return None, "no_api_keys"
    model_chain = _build_model_chain(preferred_model)
    last_error = None
    saw_rate_limit = False
    saw_other_error = False

    for model_name in model_chain:
        for api_k in api_keys:
            try:
                genai.configure(api_key=api_k)
                model = genai.GenerativeModel(
                    model_name=model_name,
                    system_instruction=system_instruction if system_instruction else None,
                    generation_config=generation_config or {}
                )
                res = model.generate_content(prompt_inputs)
                text = getattr(res, "text", None)
                if text:
                    return text, None
                saw_other_error = True
                last_error = "Empty response"
                continue
            except Exception as ex:
                last_error = str(ex)
                if is_rate_limit_error(ex):
                    saw_rate_limit = True
                    continue
                else:
                    saw_other_error = True
                    continue

    if saw_rate_limit and not saw_other_error:
        return None, "rate_limit"
    if saw_rate_limit and saw_other_error:
        if last_error and is_rate_limit_error(Exception(last_error)):
            return None, "rate_limit"
        return None, last_error or "unknown_error"
    return None, last_error or "unknown_error"


def render_rate_limit_and_retry(lang="en"):
    if lang == "vi":
        title = "⏳ Hệ thống đang nhận quá nhiều yêu cầu"
        subtitle = "Vui lòng thử lại sau. Hệ thống sẽ tự động gửi lại câu hỏi của bạn."
    else:
        title = "⏳ System is receiving too many requests"
        subtitle = "Please try again later. Your question will be automatically retried."
    box = st.empty()
    total = RATE_LIMIT_RETRY_DELAY
    for remaining in range(total, 0, -1):
        box.markdown("""
        <div class="rate-limit-box">
            <div class="rate-limit-text">__T__</div>
            <div style="margin-top:6px; font-size:0.9rem; opacity:0.85;">__S__</div>
            <div style="margin-top:8px;"><span class="rate-limit-countdown">__R__s</span></div>
        </div>
        """.replace("__T__", title).replace("__S__", subtitle).replace("__R__", str(remaining)),
        unsafe_allow_html=True)
        time.sleep(1)
    box.empty()
    st.rerun()

# ==========================================
# 7. MIGRATION
# ==========================================
def migrate_user_data(db_data: dict) -> tuple:
    migrated = False

    if SYSTEM_CONFIG_KEY not in db_data:
        db_data[SYSTEM_CONFIG_KEY] = {
            "maintenance_mode": False,
            "maintenance_note": "",
            "announcement": {
                "enabled": False, "title": "", "body": "", "updated_at": ""
            }
        }
        migrated = True
    else:
        cfg = db_data[SYSTEM_CONFIG_KEY]
        if not isinstance(cfg, dict):
            db_data[SYSTEM_CONFIG_KEY] = {
                "maintenance_mode": False,
                "maintenance_note": "",
                "announcement": {
                    "enabled": False, "title": "", "body": "", "updated_at": ""
                }
            }
            migrated = True
        else:
            if "whitelist_users" in cfg:
                del cfg["whitelist_users"]
                migrated = True
            for k, dv in [("maintenance_mode", False), ("maintenance_note", "")]:
                if k not in cfg:
                    cfg[k] = dv
                    migrated = True
            if "announcement" not in cfg:
                cfg["announcement"] = {
                    "enabled": False, "title": "", "body": "", "updated_at": ""
                }
                migrated = True
            else:
                ann = cfg["announcement"]
                if not isinstance(ann, dict):
                    cfg["announcement"] = {
                        "enabled": False, "title": "", "body": "", "updated_at": ""
                    }
                    migrated = True
                else:
                    for k, dv in [("enabled", False), ("title", ""),
                                  ("body", ""), ("updated_at", "")]:
                        if k not in ann:
                            ann[k] = dv
                            migrated = True

    if TRAFFIC_LOG_KEY not in db_data:
        db_data[TRAFFIC_LOG_KEY] = {}
        migrated = True

    if BUG_REPORTS_KEY not in db_data:
        db_data[BUG_REPORTS_KEY] = []
        migrated = True

    for username, uinfo in db_data.items():
        if username in (SYSTEM_CONFIG_KEY, TRAFFIC_LOG_KEY, BUG_REPORTS_KEY):
            continue
        if not isinstance(uinfo, dict):
            continue
        for k, dv in [("custom_instructions", ""), ("chats", {}),
                      ("remembered_devices", []), ("language", "en")]:
            if k not in uinfo:
                uinfo[k] = dv
                migrated = True
        if "preferences" not in uinfo:
            uinfo["preferences"] = {
                "model": DEFAULT_MODEL, "temperature": 0.7,
                "top_p": 0.95, "top_k": 40,
                "smart_draft": True,
                "typing_mode": DEFAULT_TYPING_MODE,
                "typing_cps": DEFAULT_TYPING_CPS
            }
            migrated = True
        else:
            prefs = uinfo["preferences"]
            if not isinstance(prefs, dict):
                prefs = {}
                uinfo["preferences"] = prefs
                migrated = True
            for k, dv in [("model", DEFAULT_MODEL), ("temperature", 0.7),
                          ("top_p", 0.95), ("top_k", 40),
                          ("smart_draft", True),
                          ("typing_mode", DEFAULT_TYPING_MODE),
                          ("typing_cps", DEFAULT_TYPING_CPS)]:
                if k not in prefs:
                    prefs[k] = dv
                    migrated = True
            old_model = prefs.get("model", "")
            if old_model in LEGACY_MODEL_MAP:
                prefs["model"] = LEGACY_MODEL_MAP[old_model]
                migrated = True

        if "draft" in uinfo:
            del uinfo["draft"]
            migrated = True

        for cid, chat in uinfo.get("chats", {}).items():
            if not isinstance(chat, dict):
                continue
            for k, dv in [("title", "Conversation"), ("messages", []),
                          ("summary", "")]:
                if k not in chat:
                    chat[k] = dv
                    migrated = True
            if "created_at" not in chat:
                chat["created_at"] = datetime.now().isoformat()
                migrated = True
            if "updated_at" not in chat:
                chat["updated_at"] = chat.get("created_at", datetime.now().isoformat())
                migrated = True

        if "api_keys" in uinfo:
            del uinfo["api_keys"]
            migrated = True

    return db_data, migrated

# ==========================================
# 8. TRAFFIC HELPERS
# ==========================================
def _today_vn_str() -> str:
    return vn_now().strftime("%Y-%m-%d")

def _now_vn_iso() -> str:
    return vn_now().strftime("%Y-%m-%d %H:%M:%S")

def _prune_traffic_log(traffic: dict) -> dict:
    if not isinstance(traffic, dict):
        return {}
    cutoff = vn_now() - timedelta(days=TRAFFIC_RETENTION_DAYS)
    cutoff_str = cutoff.strftime("%Y-%m-%d")
    return {k: v for k, v in traffic.items() if k >= cutoff_str}

def record_traffic(db_data: dict, user_label: str, role: str) -> bool:
    traffic = db_data.get(TRAFFIC_LOG_KEY, {})
    if not isinstance(traffic, dict):
        traffic = {}
    today = _today_vn_str()
    if today not in traffic:
        traffic[today] = {"visits": []}
    day_data = traffic[today]
    if "visits" not in day_data:
        day_data["visits"] = []

    if role in ("user", "guest"):
        for v in day_data["visits"]:
            if v.get("device") == device_id and v.get("role") == role:
                return False

    day_data["visits"].append({
        "time": _now_vn_iso(),
        "label": user_label,
        "role": role,
        "device": device_id,
    })
    traffic[today] = day_data
    db_data[TRAFFIC_LOG_KEY] = _prune_traffic_log(traffic)
    return True

# ==========================================
# 9. BUG REPORT HELPERS
# ==========================================
def add_bug_report(db_data: dict, report: dict) -> bool:
    reports = db_data.get(BUG_REPORTS_KEY, [])
    if not isinstance(reports, list):
        reports = []
    reports.insert(0, report)
    if len(reports) > BUG_REPORTS_MAX:
        reports = reports[:BUG_REPORTS_MAX]
    db_data[BUG_REPORTS_KEY] = reports
    return True


def delete_bug_report(db_data: dict, report_id: str) -> bool:
    reports = db_data.get(BUG_REPORTS_KEY, [])
    if not isinstance(reports, list):
        return False
    new_reports = [r for r in reports if r.get("id") != report_id]
    if len(new_reports) == len(reports):
        return False
    db_data[BUG_REPORTS_KEY] = new_reports
    return True


def reply_bug_report(db_data: dict, report_id: str, reply_text: str, admin_name: str) -> bool:
    reports = db_data.get(BUG_REPORTS_KEY, [])
    if not isinstance(reports, list):
        return False
    for r in reports:
        if r.get("id") == report_id:
            r["reply"] = reply_text
            r["replied_at"] = _now_vn_iso()
            r["replied_by"] = admin_name
            db_data[BUG_REPORTS_KEY] = reports
            return True
    return False


def get_user_bug_reports(db_data: dict, username: str) -> list:
    reports = db_data.get(BUG_REPORTS_KEY, [])
    if not isinstance(reports, list):
        return []
    return [r for r in reports if r.get("user") == username]

# ==========================================
# 10. GITHUB STORAGE
# ==========================================
class GitHubStorage:
    _cache = None
    _cache_time = 0
    CACHE_DURATION = 5
    _migration_checked = False

    @staticmethod
    def get_api_headers():
        return {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }

    @staticmethod
    def _is_cache_valid():
        return (GitHubStorage._cache is not None and
                (time.time() - GitHubStorage._cache_time) < GitHubStorage.CACHE_DURATION)

    @staticmethod
    def load_db(force_refresh=False) -> dict:
        if not force_refresh and GitHubStorage._is_cache_valid():
            return GitHubStorage._cache
        if not GITHUB_TOKEN or not GITHUB_REPO:
            st.error("⚠️ Missing GITHUB_TOKEN or GITHUB_REPO in Secrets!")
            return {}

        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{DB_FILE}"
        try:
            res = requests.get(
                url, headers=GitHubStorage.get_api_headers(),
                params={"nocache": int(time.time())}, timeout=8
            )
            if res.status_code == 200:
                content_b64 = res.json().get("content", "")
                decoded = base64.b64decode(content_b64.encode('utf-8')).decode('utf-8')
                data = json.loads(decoded)

                if not GitHubStorage._migration_checked:
                    data, was_migrated = migrate_user_data(data)
                    GitHubStorage._migration_checked = True
                    if was_migrated:
                        GitHubStorage._cache = data
                        GitHubStorage._cache_time = time.time()
                        GitHubStorage.save_db(data)

                GitHubStorage._cache = data
                GitHubStorage._cache_time = time.time()
                return data
            elif res.status_code == 404:
                data = {
                    SYSTEM_CONFIG_KEY: {
                        "maintenance_mode": False,
                        "maintenance_note": "",
                        "announcement": {
                            "enabled": False, "title": "", "body": "", "updated_at": ""
                        }
                    },
                    TRAFFIC_LOG_KEY: {},
                    BUG_REPORTS_KEY: []
                }
                GitHubStorage._cache = data
                GitHubStorage._cache_time = time.time()
                return data
            else:
                st.error(f"GitHub read error (HTTP {res.status_code})")
                return GitHubStorage._cache if GitHubStorage._cache is not None else {}
        except requests.exceptions.Timeout:
            return GitHubStorage._cache if GitHubStorage._cache is not None else {}
        except Exception as e:
            st.error(f"GitHub API error: {e}")
            return GitHubStorage._cache if GitHubStorage._cache is not None else {}

    @staticmethod
    def save_db(data: dict) -> tuple:
        if not GITHUB_TOKEN or not GITHUB_REPO:
            return False, "Missing GitHub Token/Repo configuration."
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{DB_FILE}"
        headers = GitHubStorage.get_api_headers()
        sha = None
        try:
            res_get = requests.get(url, headers=headers, timeout=5)
            if res_get.status_code == 200:
                sha = res_get.json().get("sha")
        except Exception:
            pass

        json_bytes = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
        content_b64 = base64.b64encode(json_bytes).decode('utf-8')
        payload = {
            "message": f"Update users_db.json - {_now_vn_iso()} (VN)",
            "content": content_b64
        }
        if sha:
            payload["sha"] = sha

        try:
            res_put = requests.put(url, headers=headers, json=payload, timeout=10)
            if res_put.status_code in [200, 201]:
                GitHubStorage._cache = data
                GitHubStorage._cache_time = time.time()
                return True, "Saved successfully!"
            else:
                return False, f"GitHub error (HTTP {res_put.status_code})"
        except requests.exceptions.Timeout:
            return False, "Timeout saving to GitHub"
        except Exception as e:
            return False, f"Save error: {e}"

# ==========================================
# 11. HÀM AI PHỤ
# ==========================================
def generate_chat_title(user_prompt, api_keys, model_name, lang="en"):
    try:
        if lang == "vi":
            prompt = ("Hãy tạo 1 tiêu đề cực kỳ ngắn gọn (từ 2 đến 5 từ, không đặt trong dấu ngoặc kép, không dùng markdown) "
                      f"tóm tắt chủ đề của câu hỏi sau:\n\"{user_prompt}\"")
        else:
            prompt = ("Generate an extremely short title (2-5 words, no quotes, no markdown) "
                      f"summarizing the topic of this question:\n\"{user_prompt}\"")
        text, err = call_gemini_with_failover(
            prompt_inputs=[prompt], api_keys=api_keys,
            preferred_model=model_name, lang=lang
        )
        if text:
            title = text.strip().replace('"', '').replace("'", "")
            return title[:35] if title else user_prompt[:25]
        return user_prompt[:25] + "..." if len(user_prompt) > 25 else user_prompt
    except Exception:
        return user_prompt[:25] + "..." if len(user_prompt) > 25 else user_prompt


def generate_summary(older_messages, existing_summary, api_keys, model_name, lang="en"):
    try:
        text_to_summarize = ""
        if existing_summary:
            prefix = "Bối cảnh tóm tắt trước đó" if lang == "vi" else "Previous summary context"
            text_to_summarize += f"{prefix}:\n{existing_summary}\n\n"
        limited = older_messages[-15:] if len(older_messages) > 15 else older_messages
        for m in limited:
            rl = ("Người dùng" if lang == "vi" else "User") if m["role"] == "user" else "AI"
            c = m['content'][:500] + "..." if len(m['content']) > 500 else m['content']
            text_to_summarize += f"- {rl}: {c}\n"
        if lang == "vi":
            prompt = ("Hãy tóm tắt ngắn gọn và đúc kết các ý chính, thông tin quan trọng của đoạn hội thoại sau "
                      "thành 1 đoạn văn (dưới 150 từ) để làm bối cảnh cho các câu hỏi tiếp theo:\n\n" + text_to_summarize)
        else:
            prompt = ("Briefly summarize the key points and important information from the following conversation "
                      "into one paragraph (under 150 words) to serve as context for follow-up questions:\n\n" + text_to_summarize)
        text, err = call_gemini_with_failover(
            prompt_inputs=[prompt], api_keys=api_keys,
            preferred_model=model_name, lang=lang
        )
        if text:
            return text.strip()
        parts = [existing_summary] if existing_summary else []
        for m in older_messages[-10:]:
            r = "User" if m["role"] == "user" else "AI"
            parts.append(f"{r}: {m['content'][:50]}...")
        return " | ".join(parts)
    except Exception:
        parts = [existing_summary] if existing_summary else []
        for m in older_messages[-10:]:
            r = "User" if m["role"] == "user" else "AI"
            parts.append(f"{r}: {m['content'][:50]}...")
        return " | ".join(parts)

# ==========================================
# 12. i18n
# ==========================================
TRANSLATIONS = {
    "en": {
        "app_title": "⚡ LTTP AI Online",
        "app_subtitle": "Multi-purpose AI System with GitHub Sync",
        "login_tab": "🔑 Login", "register_tab": "📝 Register",
        "username": "Username:", "password": "Password:",
        "confirm_password": "Confirm password:",
        "remember_device": "📌 Remember this device (30 days)",
        "login_btn": "Login", "register_btn": "Create account",
        "fill_all": "⚠️ Please fill in all fields.",
        "pass_min": "❌ Password must be at least 6 characters.",
        "pass_mismatch": "❌ Passwords do not match.",
        "username_taken": "❌ Username is already taken.",
        "register_success": "🎉 Registration successful! Please switch to Login tab.",
        "login_fail": "❌ Invalid username or password!",
        "login_success": "Login successful!",
        "auto_login": "Auto-login successful! Welcome",
        "logout_btn": "🚪 Logout",
        "new_chat_btn": "➕ New Conversation",
        "chat_list": "💬 Conversations",
        "no_chats": "No conversations yet.",
        "delete_chat_tooltip": "Delete conversation",
        "chat_deleted": "Conversation deleted!",
        "memory_title": "🧠 Persistent Memory / AI Instructions",
        "memory_desc": "AI will always remember and follow these rules in every conversation.",
        "memory_placeholder": "Example: You are a professional Python programming assistant.",
        "save_memory_btn": "💾 Save Memory",
        "memory_saved": "Memory saved!",
        "api_title": "🔑 API Keys & Model",
        "api_from_secrets": "API Keys are loaded from Streamlit Secrets",
        "api_status_ready": "Ready", "api_status_missing": "Missing",
        "model_select": "Select AI model:",
        "gen_config": "🎨 How A.I responds",
        "temperature": "Creativity level",
        "temperature_help": "**Creativity level** — how imaginative the A.I is.\n\n- **Low:** Safe, sticks to facts.\n- **Medium:** Balanced — default.\n- **High:** Creative.\n\n👉 *Tip:* Raise if repetitive; lower if it invents facts.",
        "top_p": "Diversity",
        "top_p_help": "**Diversity** — how many word choices the A.I considers.\n\n- **Low:** Predictable.\n- **High:** Rich.\n\n👉 Keep at 0.95.",
        "top_k": "Focus level",
        "top_k_help": "**Focus level** — candidate words per step.\n\n- **Low:** Tight.\n- **High:** Varied.\n\n👉 Keep at 40.",
        "save_params": "💾 Save settings",
        "params_saved": "Settings saved!",
        "reset_params": "↺ Defaults",
        "reset_params_toast": "Reset to defaults!",
        "t_level_safe": "Safe, sticks to facts",
        "t_level_balanced": "Balanced — recommended",
        "t_level_creative": "Creative, imaginative",
        "p_level_predictable": "Predictable, safe",
        "p_level_varied": "Rich, varied",
        "k_level_focused": "Very focused, concise",
        "k_level_balanced": "Balanced — recommended",
        "k_level_varied": "Highly varied",
        "chat_placeholder": "Ask LTTP AI anything...",
        "current_chat": "Currently in", "model_label": "Model",
        "new_chat": "New Conversation",
        "no_api_key": "⚠️ No Gemini API Keys found in Secrets!",
        "ai_thinking": "LTTP AI is thinking...",
        "ai_typing": "LTTP AI is typing...",
        "ai_error": "❌ Could not generate AI response.",
        "device_id": "Device ID", "online": "Online", "language": "🌐 Language",
        "guest_btn": "👤 Continue as Guest",
        "guest_mode": "Guest Mode",
        "guest_banner": "You are using Guest Mode. Chats are not saved.",
        "maintenance_title": "🚧 System under maintenance",
        "maintenance_desc": "We are temporarily pausing the system. Please come back later.",
        "maintenance_login_expander": "🔧 Maintenance access",
        "maintenance_login_test_hint": "Use test account to verify during maintenance",
        "admin_panel": "🛡️ Admin Panel",
        "admin_logged_in": "Logged in as Administrator",
        "maintenance_toggle": "System Maintenance Mode",
        "maintenance_on": "🔴 Pause System",
        "maintenance_off": "🟢 Resume System",
        "maintenance_note_label": "Maintenance note (optional):",
        "maintenance_note_placeholder": "e.g. We are upgrading servers.",
        "save_maintenance_note": "💾 Save Maintenance Note",
        "maintenance_note_saved": "Maintenance note saved!",
        "sys_status": "System Status",
        "sys_running": "🟢 Running", "sys_paused": "🔴 Paused",
        "admin_logout": "🚪 Exit Admin Mode",
        "announcement_panel_title": "📢 Announcement Board",
        "announcement_panel_desc": "This message will be shown to ALL users.",
        "announcement_title_label": "Title (optional)",
        "announcement_title_placeholder": "e.g. Scheduled maintenance tonight",
        "announcement_body_label": "Message content",
        "announcement_body_placeholder": "Write something to display to all users.",
        "announcement_send_btn": "📤 Send to all users",
        "announcement_update_btn": "💾 Update announcement",
        "announcement_clear_btn": "🗑️ Clear announcement",
        "announcement_sent_toast": "Announcement updated!",
        "announcement_cleared_toast": "Announcement cleared!",
        "announcement_preview": "Preview:",
        "announcement_current_status": "Current status",
        "announcement_status_on": "🟢 Live",
        "announcement_status_off": "⚪ Off",
        "announcement_default_title": "📢 Announcement",
        "announcement_updated_at": "Last updated",
        "test_mode_label": "🔧 TEST SESSION",
        "test_banner": "You are in TEST mode. All actions are stored in RAM only.",
        "test_logout": "🚪 Exit Test Session",
        "test_only_in_maintenance": "❌ Test account can only be used during maintenance.",
        "test_login_success": "Test mode activated! Session is temporary.",
        "test_badge": "TEST",
        "traffic_title": "📊 Traffic Analytics",
        "traffic_desc": "Visitor log (Vietnam time, GMT+7)",
        "traffic_today": "Today", "traffic_7d": "Last 7 days",
        "traffic_30d": "Last 30 days",
        "traffic_unique": "Unique visitors",
        "traffic_by_role": "By role",
        "traffic_chart_title": "Visits per day (last 14 days)",
        "traffic_recent": "Recent visits",
        "traffic_no_data": "No traffic data yet.",
        "traffic_role_user": "Users", "traffic_role_guest": "Guests",
        "traffic_role_admin": "Admin",
        "traffic_current_time": "Current VN time",
        "settings_title": "⚙️ Settings",
        "smart_draft_label": "Smart Message Saving",
        "smart_draft_help": "Auto-saves your draft:\n• >20 words → save every 5s\n• Idle 20s → save once",
        "smart_draft_on": "✅ Enabled",
        "smart_draft_off": "❌ Disabled",
        "draft_restored_title": "📝 Unsent draft found",
        "draft_restored_desc": "You have a saved draft:",
        "draft_restore_btn": "📋 Copy to clipboard",
        "draft_discard_btn": "🗑️ Discard draft",
        "draft_discarded_toast": "Draft discarded",
        "draft_copied_toast": "Draft copied to clipboard!",
        "typing_mode_label": "Typing speed",
        "typing_mode_help": (
            "Choose how A.I's response appears:\n\n"
            "• **Smooth** — text appears as fast as A.I generates it (default).\n"
            "• **Controlled** — text is revealed at a fixed characters-per-second speed.\n"
            "• **Instant** — no typing effect; the full answer appears at once when ready.\n\n"
            "👉 Pick **Instant** if you prefer to read the whole answer immediately."
        ),
        "typing_mode_smooth": "🌊 Smooth",
        "typing_mode_controlled": "⌨️ Controlled",
        "typing_mode_instant": "⚡ Instant",
        "typing_cps_label": "Typing speed (chars/second):",
        "typing_mode_saved": "Typing mode saved!",
        "bug_report_btn": "🐛 Report a Bug",
        "bug_report_title": "🐛 Bug Report",
        "bug_report_desc": "Help us improve! Describe what went wrong. A screenshot is automatically attached.",
        "bug_report_text_label": "Describe the bug (optional):",
        "bug_report_text_placeholder": "e.g. When I pressed X, the page showed error Y...",
        "bug_report_screenshot_label": "Screenshot (auto-captured):",
        "bug_report_capture_btn": "📸 Capture screenshot",
        "bug_report_submit_btn": "📤 Send report",
        "bug_report_cancel_btn": "✖ Cancel",
        "bug_report_success": "Report sent! Admin will review soon.",
        "bug_report_error": "Failed to send report. Please try again.",
        "bug_report_no_screenshot": "No screenshot captured. You can still send text-only report.",
        "bug_report_my_reports": "📬 My Reports",
        "bug_report_no_reports": "You have no reports yet.",
        "bug_report_reply_from_admin": "Admin reply:",
        "bug_report_sent_at": "Sent at",
        "bug_report_admin_title": "🐛 Bug Reports (Admin)",
        "bug_report_admin_desc": "User-submitted bug reports with screenshots. Max 50 kept.",
        "bug_report_admin_empty": "No bug reports yet.",
        "bug_report_admin_reply_label": "Reply to user:",
        "bug_report_admin_reply_placeholder": "e.g. Thanks, we will fix this in the next version.",
        "bug_report_admin_reply_btn": "📤 Send reply",
        "bug_report_admin_delete_btn": "🗑️ Delete report",
        "bug_report_admin_reply_saved": "Reply sent!",
        "bug_report_admin_deleted": "Report deleted!",
        "bug_report_from_user": "From",
        "bug_report_view_screenshot": "View screenshot",
        "bug_report_status_replied": "✅ Replied",
        "bug_report_status_pending": "⏳ Awaiting reply",
    },
    "vi": {
        "app_title": "⚡ LTTP AI Online",
        "app_subtitle": "Hệ thống Trí tuệ Nhân tạo Đa Năng Đồng bộ GitHub",
        "login_tab": "🔑 Đăng nhập", "register_tab": "📝 Đăng ký",
        "username": "Tên đăng nhập:", "password": "Mật khẩu:",
        "confirm_password": "Xác nhận mật khẩu:",
        "remember_device": "📌 Ghi nhớ thiết bị này (30 ngày)",
        "login_btn": "Đăng nhập", "register_btn": "Tạo tài khoản mới",
        "fill_all": "⚠️ Vui lòng điền đầy đủ thông tin.",
        "pass_min": "❌ Mật khẩu phải có ít nhất 6 ký tự.",
        "pass_mismatch": "❌ Mật khẩu xác nhận không khớp.",
        "username_taken": "❌ Tên đăng nhập đã được sử dụng.",
        "register_success": "🎉 Đăng ký thành công! Hãy chuyển qua tab Đăng nhập.",
        "login_fail": "❌ Mật khẩu hoặc tên đăng nhập không chính xác!",
        "login_success": "Đăng nhập thành công!",
        "auto_login": "Tự động đăng nhập thành công! Xin chào",
        "logout_btn": "🚪 Đăng xuất",
        "new_chat_btn": "➕ Cuộc trò chuyện mới",
        "chat_list": "💬 Danh sách trò chuyện",
        "no_chats": "Chưa có cuộc trò chuyện nào.",
        "delete_chat_tooltip": "Xóa cuộc trò chuyện",
        "chat_deleted": "Đã xóa cuộc trò chuyện!",
        "memory_title": "🧠 Bộ nhớ cố định / Chỉ dẫn AI",
        "memory_desc": "AI sẽ luôn ghi nhớ và tuân thủ các quy tắc này trong mọi cuộc trò chuyện.",
        "memory_placeholder": "Ví dụ: Bạn là trợ lý lập trình Python chuyên nghiệp.",
        "save_memory_btn": "💾 Lưu ghi nhớ cố định",
        "memory_saved": "Đã ghi nhớ thông tin!",
        "api_title": "🔑 API Keys & Model",
        "api_from_secrets": "API Keys được nạp từ Streamlit Secrets",
        "api_status_ready": "Sẵn sàng", "api_status_missing": "Thiếu",
        "model_select": "Chọn mô hình AI:",
        "gen_config": "🎨 Cách A.I trả lời",
        "temperature": "Mức độ sáng tạo",
        "temperature_help": "**Mức độ sáng tạo** — A.I bay bổng đến mức nào.\n\n- **Thấp:** An toàn.\n- **Trung bình:** Cân bằng.\n- **Cao:** Sáng tạo.\n\n👉 Tăng nếu lặp; giảm nếu bịa.",
        "top_p": "Mức độ đa dạng",
        "top_p_help": "**Mức độ đa dạng** — số lựa chọn từ.\n\n- **Thấp:** Dễ đoán.\n- **Cao:** Phong phú.\n\n👉 Giữ 0.95.",
        "top_k": "Mức độ tập trung",
        "top_k_help": "**Mức độ tập trung** — số từ mỗi bước.\n\n- **Thấp:** Gọn.\n- **Cao:** Đa dạng.\n\n👉 Giữ 40.",
        "save_params": "💾 Lưu cài đặt",
        "params_saved": "Đã lưu cài đặt!",
        "reset_params": "↺ Mặc định",
        "reset_params_toast": "Đã khôi phục mặc định!",
        "t_level_safe": "An toàn, bám sát sự thật",
        "t_level_balanced": "Cân bằng — khuyên dùng",
        "t_level_creative": "Sáng tạo, bay bổng",
        "p_level_predictable": "Dễ đoán, an toàn",
        "p_level_varied": "Đa dạng, phong phú",
        "k_level_focused": "Rất tập trung, gọn gàng",
        "k_level_balanced": "Cân bằng — khuyên dùng",
        "k_level_varied": "Đa dạng cao",
        "chat_placeholder": "Hỏi LTTP AI bất cứ điều gì...",
        "current_chat": "Đang trò chuyện trong", "model_label": "Mô hình",
        "new_chat": "Cuộc trò chuyện mới",
        "no_api_key": "⚠️ Không tìm thấy Gemini API Key trong Secrets!",
        "ai_thinking": "LTTP AI đang suy nghĩ...",
        "ai_typing": "LTTP AI đang gõ...",
        "ai_error": "❌ Không thể tạo phản hồi từ AI.",
        "device_id": "Device ID", "online": "Online", "language": "🌐 Ngôn ngữ",
        "guest_btn": "👤 Tiếp tục với tư cách Khách",
        "guest_mode": "Chế độ Khách",
        "guest_banner": "Bạn đang dùng chế độ Khách. Cuộc trò chuyện không được lưu.",
        "maintenance_title": "🚧 Hệ thống đang bảo trì",
        "maintenance_desc": "Chúng tôi tạm thời ngừng hệ thống. Vui lòng quay lại sau.",
        "maintenance_login_expander": "🔧 Truy cập bảo trì",
        "maintenance_login_test_hint": "Dùng tài khoản test để kiểm tra khi đang bảo trì",
        "admin_panel": "🛡️ Bảng điều khiển Admin",
        "admin_logged_in": "Đã đăng nhập với quyền Quản trị viên",
        "maintenance_toggle": "Chế độ Bảo trì Hệ thống",
        "maintenance_on": "🔴 Tạm ngừng hệ thống",
        "maintenance_off": "🟢 Mở lại hệ thống",
        "maintenance_note_label": "Lời chú thích bảo trì:",
        "maintenance_note_placeholder": "Ví dụ: Đang nâng cấp máy chủ.",
        "save_maintenance_note": "💾 Lưu lời chú thích",
        "maintenance_note_saved": "Đã lưu lời chú thích!",
        "sys_status": "Trạng thái hệ thống",
        "sys_running": "🟢 Đang chạy", "sys_paused": "🔴 Đang tạm ngừng",
        "admin_logout": "🚪 Thoát chế độ Admin",
        "announcement_panel_title": "📢 Bảng thông tin",
        "announcement_panel_desc": "Thông báo này hiển thị cho TẤT CẢ người dùng.",
        "announcement_title_label": "Tiêu đề (không bắt buộc)",
        "announcement_title_placeholder": "Ví dụ: Bảo trì tối nay",
        "announcement_body_label": "Nội dung thông báo",
        "announcement_body_placeholder": "Nhập nội dung gửi đến mọi người.",
        "announcement_send_btn": "📤 Gửi đến toàn bộ người dùng",
        "announcement_update_btn": "💾 Cập nhật thông báo",
        "announcement_clear_btn": "🗑️ Xóa thông báo",
        "announcement_sent_toast": "Đã cập nhật bảng thông tin!",
        "announcement_cleared_toast": "Đã xóa bảng thông tin!",
        "announcement_preview": "Xem trước:",
        "announcement_current_status": "Trạng thái",
        "announcement_status_on": "🟢 Đang hiển thị",
        "announcement_status_off": "⚪ Đang tắt",
        "announcement_default_title": "📢 Thông báo",
        "announcement_updated_at": "Cập nhật lúc",
        "test_mode_label": "🔧 PHIÊN TEST",
        "test_banner": "Bạn đang ở chế độ TEST. Mọi thao tác chỉ lưu RAM.",
        "test_logout": "🚪 Thoát phiên Test",
        "test_only_in_maintenance": "❌ Tài khoản test chỉ dùng được khi bảo trì.",
        "test_login_success": "Đã bật Test! Phiên tạm thời.",
        "test_badge": "TEST",
        "traffic_title": "📊 Lưu lượng truy cập",
        "traffic_desc": "Nhật ký (giờ Việt Nam, GMT+7)",
        "traffic_today": "Hôm nay", "traffic_7d": "7 ngày qua",
        "traffic_30d": "30 ngày qua",
        "traffic_unique": "Người truy cập riêng",
        "traffic_by_role": "Theo vai trò",
        "traffic_chart_title": "Lượt/ngày (14 ngày qua)",
        "traffic_recent": "Truy cập gần đây",
        "traffic_no_data": "Chưa có dữ liệu.",
        "traffic_role_user": "Người dùng", "traffic_role_guest": "Khách",
        "traffic_role_admin": "Admin",
        "traffic_current_time": "Giờ VN hiện tại",
        "settings_title": "⚙️ Cài đặt",
        "smart_draft_label": "Lưu tin nhắn thông minh",
        "smart_draft_help": "Tự động lưu nháp:\n• >20 từ → lưu mỗi 5s\n• Ngừng 20s → lưu 1 lần",
        "smart_draft_on": "✅ Đang bật",
        "smart_draft_off": "❌ Đang tắt",
        "draft_restored_title": "📝 Có tin nhắn nháp",
        "draft_restored_desc": "Bạn có nháp đã lưu:",
        "draft_restore_btn": "📋 Sao chép",
        "draft_discard_btn": "🗑️ Xóa nháp",
        "draft_discarded_toast": "Đã xóa nháp",
        "draft_copied_toast": "Đã sao chép!",
        "typing_mode_label": "Tốc độ gõ",
        "typing_mode_help": (
            "Chọn cách câu trả lời của A.I xuất hiện:\n\n"
            "• **Mượt mà** — chữ hiện nhanh như A.I tạo ra (mặc định).\n"
            "• **Kiểm soát** — chữ hiện đều theo tốc độ ký tự/giây.\n"
            "• **Hiện ngay** — không có hiệu ứng gõ, câu trả lời hiện một lần khi xong.\n\n"
            "👉 Chọn **Hiện ngay** để đọc toàn bộ tức thì."
        ),
        "typing_mode_smooth": "🌊 Mượt mà",
        "typing_mode_controlled": "⌨️ Kiểm soát",
        "typing_mode_instant": "⚡ Hiện ngay",
        "typing_cps_label": "Tốc độ gõ (ký tự/giây):",
        "typing_mode_saved": "Đã lưu chế độ gõ!",
        "bug_report_btn": "🐛 Báo cáo lỗi",
        "bug_report_title": "🐛 Báo cáo lỗi",
        "bug_report_desc": "Giúp chúng tôi cải thiện! Mô tả lỗi bạn gặp. Ảnh chụp màn hình sẽ được tự động đính kèm.",
        "bug_report_text_label": "Mô tả lỗi (không bắt buộc):",
        "bug_report_text_placeholder": "Ví dụ: Khi tôi bấm X thì hiện lỗi Y...",
        "bug_report_screenshot_label": "Ảnh chụp màn hình (tự động):",
        "bug_report_capture_btn": "📸 Chụp màn hình",
        "bug_report_submit_btn": "📤 Gửi báo cáo",
        "bug_report_cancel_btn": "✖ Hủy",
        "bug_report_success": "Đã gửi báo cáo! Admin sẽ xem sớm.",
        "bug_report_error": "Gửi báo cáo thất bại. Thử lại sau.",
        "bug_report_no_screenshot": "Chưa có ảnh chụp. Vẫn có thể gửi báo cáo bằng chữ.",
        "bug_report_my_reports": "📬 Báo cáo của tôi",
        "bug_report_no_reports": "Bạn chưa có báo cáo nào.",
        "bug_report_reply_from_admin": "Phản hồi từ Admin:",
        "bug_report_sent_at": "Gửi lúc",
        "bug_report_admin_title": "🐛 Báo cáo lỗi (Admin)",
        "bug_report_admin_desc": "Báo cáo lỗi từ người dùng kèm ảnh chụp. Giữ tối đa 50.",
        "bug_report_admin_empty": "Chưa có báo cáo lỗi nào.",
        "bug_report_admin_reply_label": "Phản hồi người dùng:",
        "bug_report_admin_reply_placeholder": "Ví dụ: Cảm ơn, chúng tôi sẽ sửa trong bản tới.",
        "bug_report_admin_reply_btn": "📤 Gửi phản hồi",
        "bug_report_admin_delete_btn": "🗑️ Xóa báo cáo",
        "bug_report_admin_reply_saved": "Đã gửi phản hồi!",
        "bug_report_admin_deleted": "Đã xóa báo cáo!",
        "bug_report_from_user": "Từ",
        "bug_report_view_screenshot": "Xem ảnh chụp",
        "bug_report_status_replied": "✅ Đã phản hồi",
        "bug_report_status_pending": "⏳ Chờ phản hồi",
    }
}

def t(key: str, lang: str = "en") -> str:
    return TRANSLATIONS.get(lang, TRANSLATIONS["en"]).get(key, key)

# ==========================================
# 13. SESSION STATE
# ==========================================
for k, dv in [("user", None), ("is_admin", False), ("is_guest", False),
              ("is_temporary", False),
              ("current_chat_id", None), ("messages", []), ("db_data", {}),
              ("last_save_time", 0), ("language", "en"),
              ("pending_retry_prompt", None), ("seen_version", None),
              ("guest_chats", {}), ("guest_memory", ""),
              ("test_chats", {}), ("test_memory", ""),
              ("traffic_recorded", False),
              ("version_mismatch", False),
              ("reboot_banner_dismissed", False),
              ("draft_last_saved_hash", ""),
              ("bug_report_open", False),
              ("bug_report_text", "")]:
    if k not in st.session_state:
        st.session_state[k] = dv

if "guest_prefs" not in st.session_state:
    st.session_state.guest_prefs = {
        "model": DEFAULT_MODEL, "temperature": 0.7,
        "top_p": 0.95, "top_k": 40, "smart_draft": True,
        "typing_mode": DEFAULT_TYPING_MODE,
        "typing_cps": DEFAULT_TYPING_CPS
    }

if "test_prefs" not in st.session_state:
    st.session_state.test_prefs = {
        "model": DEFAULT_MODEL, "temperature": 0.7,
        "top_p": 0.95, "top_k": 40, "smart_draft": True,
        "typing_mode": DEFAULT_TYPING_MODE,
        "typing_cps": DEFAULT_TYPING_CPS
    }

# ==========================================
# 14. VERSION CHECK
# ==========================================
def _init_version_cookie():
    try:
        cached_ver = cookies.get("LTTP_app_version")
        if not cached_ver:
            cookies.set("LTTP_app_version", APP_VERSION, max_age=COOKIE_MAX_AGE)
            st.session_state.version_mismatch = False
        elif cached_ver != APP_VERSION:
            st.session_state.version_mismatch = True
            cookies.set("LTTP_app_version", APP_VERSION, max_age=COOKIE_MAX_AGE)
        else:
            st.session_state.version_mismatch = False
    except Exception:
        st.session_state.version_mismatch = False


_init_version_cookie()
inject_version_scanner()
inject_scroll_guard()

_seen_ver = cookies.get("LTTP_seen_version")
if _seen_ver:
    st.session_state.seen_version = _seen_ver

db_data = GitHubStorage.load_db()
st.session_state.db_data = db_data

system_config = db_data.get(SYSTEM_CONFIG_KEY, {
    "maintenance_mode": False, "maintenance_note": "",
    "announcement": {"enabled": False, "title": "", "body": "", "updated_at": ""}
})
maintenance_mode = system_config.get("maintenance_mode", False)
maintenance_note = system_config.get("maintenance_note", "").strip()

_ann_cfg = system_config.get("announcement", {}) or {}
announcement = {
    "enabled": bool(_ann_cfg.get("enabled", False)),
    "title": str(_ann_cfg.get("title", "")),
    "body": str(_ann_cfg.get("body", "")),
    "updated_at": str(_ann_cfg.get("updated_at", "")),
}

# ==========================================
# 15. AUTO-LOGIN
# ==========================================
if (not st.session_state.user
        and not st.session_state.is_admin
        and not st.session_state.is_guest
        and not st.session_state.is_temporary
        and device_id and db_data):
    for username, uinfo in db_data.items():
        if username in (SYSTEM_CONFIG_KEY, TRAFFIC_LOG_KEY, BUG_REPORTS_KEY):
            continue
        if not isinstance(uinfo, dict):
            continue
        if device_id in uinfo.get("remembered_devices", []):
            st.session_state.user = username
            st.session_state.language = uinfo.get("language", "en")
            st.toast(f"{t('auto_login', st.session_state.language)} {username}", icon="⚡")
            break

# ==========================================
# 16. RECORD TRAFFIC
# ==========================================
def _try_record_traffic_once():
    if st.session_state.traffic_recorded:
        return
    if is_temporary_session():
        st.session_state.traffic_recorded = True
        return
    role = label = None
    if st.session_state.is_admin:
        role, label = "admin", "Admin"
    elif st.session_state.user:
        role, label = "user", st.session_state.user
    elif st.session_state.is_guest:
        role, label = "guest", "guest"
    if role:
        db = GitHubStorage.load_db()
        if record_traffic(db, label, role):
            GitHubStorage.save_db(db)
        st.session_state.traffic_recorded = True

_try_record_traffic_once()

# ==========================================
# 17. UPDATE NOTICE
# ==========================================
def _show_update_notice_if_needed():
    current_lang = st.session_state.language
    if st.session_state.seen_version != APP_VERSION:
        try:
            cookies.set("LTTP_seen_version", APP_VERSION, max_age=COOKIE_MAX_AGE)
        except Exception:
            pass
        st.session_state.seen_version = APP_VERSION
        st.markdown(
            f'<div class="update-notice">{UPDATE_NOTICE.get(current_lang, UPDATE_NOTICE["en"])} • v{APP_VERSION}</div>',
            unsafe_allow_html=True
        )

# ==========================================
# 18. REBOOT BANNER
# ==========================================
def render_reboot_banner_if_needed():
    if not st.session_state.get("version_mismatch", False):
        return
    if st.session_state.get("reboot_banner_dismissed", False):
        return

    lang = st.session_state.get("language", "en")
    notice = REBOOT_NOTICE.get(lang, REBOOT_NOTICE["en"])

    st.markdown(f"""
    <div class="reboot-banner">
        <div class="reboot-banner-title">🚀 {notice['title']}</div>
        <div class="reboot-banner-desc">{notice['desc']}</div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button(f"🔄 {notice['button']}", use_container_width=True, key="reboot_now_btn"):
            inject_js("location.reload();")
    with col2:
        if st.button(f"⏸️ {notice['later']}", use_container_width=True, key="reboot_later_btn"):
            st.session_state.reboot_banner_dismissed = True
            st.rerun()

# ==========================================
# 19. ANNOUNCEMENT
# ==========================================
def render_announcement_banner():
    if not announcement.get("enabled"):
        return
    body = announcement.get("body", "").strip()
    title = announcement.get("title", "").strip()
    updated = announcement.get("updated_at", "").strip()
    lang = st.session_state.get("language", "en")

    if not body and not title:
        return

    display_title = title if title else t("announcement_default_title", lang)

    meta_html = ""
    if updated:
        meta_html = f'<div class="announcement-meta">🕐 {t("announcement_updated_at", lang)}: {updated}</div>'

    safe_title = (display_title
                  .replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;"))
    safe_body = (body
                 .replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;"))

    st.markdown(f"""
    <div class="announcement-banner">
        <div class="announcement-header">📢 {safe_title}</div>
        <div class="announcement-body">{safe_body}</div>
        {meta_html}
    </div>
    """, unsafe_allow_html=True)

# ==========================================
# 20. TEST BANNER
# ==========================================
def render_test_banner():
    if not is_temporary_session():
        return
    lang = st.session_state.get("language", "en")
    st.markdown(
        f'<div class="test-notice">{t("test_banner", lang)}</div>',
        unsafe_allow_html=True
    )

# ==========================================
# 21. BUG REPORT DIALOG
# ==========================================
@st.dialog("🐛")
def bug_report_dialog():
    lang = st.session_state.get("language", "en")
    st.markdown(f"### {t('bug_report_title', lang)}")
    st.caption(t("bug_report_desc", lang))

    st.markdown(f"**{t('bug_report_screenshot_label', lang)}**")
    col_cap, col_clear = st.columns([1, 1])
    with col_cap:
        if st.button(t("bug_report_capture_btn", lang), use_container_width=True, key="bug_capture_btn"):
            inject_screenshot_capture(BR_MAX_CHUNKS)
            time.sleep(1.2)
            st.rerun()
    with col_clear:
        if st.button("🗑️", use_container_width=True, key="bug_clear_ss_btn", help="Clear screenshot"):
            clear_bug_report_cookies()
            st.rerun()

    b64 = read_bug_report_screenshot()
    if b64:
        try:
            st.image("data:image/jpeg;base64," + b64, caption="Preview (240-360p)", width=320)
        except Exception:
            st.caption("⚠️ Preview error.")
    else:
        st.caption(t("bug_report_no_screenshot", lang))

    bug_text = st.text_area(
        t("bug_report_text_label", lang),
        value=st.session_state.get("bug_report_text", ""),
        height=120,
        placeholder=t("bug_report_text_placeholder", lang),
        key="bug_dialog_text"
    )

    col_send, col_cancel = st.columns(2)
    with col_send:
        if st.button(t("bug_report_submit_btn", lang), use_container_width=True, type="primary", key="bug_submit_btn"):
            final_b64 = read_bug_report_screenshot()

            if not final_b64 and not bug_text.strip():
                st.error("⚠️ Vui lòng chụp ảnh hoặc nhập mô tả." if lang == "vi" else "⚠️ Please capture or describe the bug.")
            else:
                report = {
                    "id": str(uuid.uuid4()),
                    "user": st.session_state.get("user") or ("guest" if st.session_state.get("is_guest") else "test"),
                    "role": "guest" if st.session_state.get("is_guest") else ("test" if is_temporary_session() else "user"),
                    "device": mask_device(device_id),
                    "time": _now_vn_iso(),
                    "text": bug_text.strip(),
                    "screenshot_b64": final_b64 or "",
                    "reply": "",
                    "replied_at": "",
                    "replied_by": "",
                }
                if is_temporary_session():
                    st.session_state.setdefault("test_bug_reports", []).insert(0, report)
                    st.success(t("bug_report_success", lang))
                else:
                    db = GitHubStorage.load_db(force_refresh=True)
                    add_bug_report(db, report)
                    ok, msg = safe_save_db(db)
                    if ok:
                        st.success(t("bug_report_success", lang))
                    else:
                        st.error(t("bug_report_error", lang) + f" {msg}")

                clear_bug_report_cookies()
                st.session_state.bug_report_open = False
                time.sleep(1.0)
                st.rerun()

    with col_cancel:
        if st.button(t("bug_report_cancel_btn", lang), use_container_width=True, key="bug_cancel_btn"):
            clear_bug_report_cookies()
            st.session_state.bug_report_open = False
            st.rerun()

# ==========================================
# 22. AUTH UI
# ==========================================
def render_auth_ui():
    lang = st.session_state.language
    _show_update_notice_if_needed()
    render_reboot_banner_if_needed()
    render_announcement_banner()

    col_lang_left, col_lang_right = st.columns([5, 1])
    with col_lang_right:
        lc = st.selectbox("🌐", ["en", "vi"], index=0 if lang == "en" else 1,
                          format_func=lambda x: "🇬🇧 EN" if x == "en" else "🇻🇳 VI",
                          key="auth_lang_selector", label_visibility="collapsed")
        if lc != lang:
            st.session_state.language = lc
            st.rerun()

    st.markdown(f"<h1 class='main-header' style='text-align: center;'>{t('app_title', lang)}</h1>", unsafe_allow_html=True)
    st.caption(f"<p style='text-align: center;'>{t('app_subtitle', lang)}</p>", unsafe_allow_html=True)
    st.divider()

    _, col, _ = st.columns([1, 1.8, 1])
    with col:
        st.caption(f"🆔 {t('device_id', lang)}: `{mask_device(device_id)}`")
        tab_login, tab_register = st.tabs([t("login_tab", lang), t("register_tab", lang)])

        with tab_login:
            with st.form("login_form"):
                u_name = st.text_input(t("username", lang)).strip()
                u_pass = st.text_input(t("password", lang), type="password")
                remember_me = st.checkbox(t("remember_device", lang), value=True)
                if st.form_submit_button(t("login_btn", lang), use_container_width=True):
                    if u_name == ADMIN_USERNAME and u_pass == ADMIN_PASSWORD:
                        st.session_state.is_admin = True
                        st.session_state.user = None
                        st.session_state.is_guest = False
                        st.session_state.is_temporary = False
                        st.session_state.current_chat_id = None
                        st.session_state.messages = []
                        st.session_state.traffic_recorded = False
                        st.toast("🛡️ Admin mode activated", icon="🛡️")
                        st.rerun()
                    elif u_name.lower() == TEST_USERNAME and u_pass == TEST_PASSWORD:
                        st.error(t("test_only_in_maintenance", lang))
                    else:
                        u_name_lower = u_name.lower()
                        db = GitHubStorage.load_db(force_refresh=True)
                        if (u_name_lower in db
                                and u_name_lower not in (SYSTEM_CONFIG_KEY, TRAFFIC_LOG_KEY, BUG_REPORTS_KEY)
                                and isinstance(db[u_name_lower], dict)
                                and db[u_name_lower].get("password") == hash_password(u_pass)):
                            st.session_state.user = u_name_lower
                            st.session_state.is_admin = False
                            st.session_state.is_guest = False
                            st.session_state.is_temporary = False
                            st.session_state.current_chat_id = None
                            st.session_state.messages = []
                            st.session_state.language = db[u_name_lower].get("language", "en")
                            st.session_state.traffic_recorded = False
                            if remember_me:
                                db[u_name_lower].setdefault("remembered_devices", [])
                                if device_id not in db[u_name_lower]["remembered_devices"]:
                                    db[u_name_lower]["remembered_devices"].append(device_id)
                                    GitHubStorage.save_db(db)
                            st.toast(t("login_success", st.session_state.language), icon="✅")
                            st.rerun()
                        else:
                            st.error(t("login_fail", lang))

        with tab_register:
            with st.form("register_form"):
                reg_u = st.text_input(t("username", lang)).strip().lower()
                reg_p = st.text_input(t("password", lang), type="password")
                reg_p2 = st.text_input(t("confirm_password", lang), type="password")
                if st.form_submit_button(t("register_btn", lang), use_container_width=True):
                    if not reg_u or not reg_p:
                        st.warning(t("fill_all", lang))
                    elif reg_u in (ADMIN_USERNAME.lower(), TEST_USERNAME.lower(),
                                   SYSTEM_CONFIG_KEY.lower(), TRAFFIC_LOG_KEY.lower(),
                                   BUG_REPORTS_KEY.lower()):
                        st.error("❌ Reserved username.")
                    elif len(reg_p) < 6:
                        st.error(t("pass_min", lang))
                    elif reg_p != reg_p2:
                        st.error(t("pass_mismatch", lang))
                    else:
                        db = GitHubStorage.load_db(force_refresh=True)
                        if reg_u in db:
                            st.error(t("username_taken", lang))
                        else:
                            db[reg_u] = {
                                "password": hash_password(reg_p),
                                "custom_instructions": "",
                                "chats": {},
                                "remembered_devices": [device_id],
                                "language": "en",
                                "preferences": {
                                    "model": DEFAULT_MODEL, "temperature": 0.7,
                                    "top_p": 0.95, "top_k": 40,
                                    "smart_draft": True,
                                    "typing_mode": DEFAULT_TYPING_MODE,
                                    "typing_cps": DEFAULT_TYPING_CPS
                                }
                            }
                            ok, msg = GitHubStorage.save_db(db)
                            if ok:
                                st.success(t("register_success", lang))
                            else:
                                st.error(f"❌ {msg}")

        st.markdown("---")
        if st.button(t("guest_btn", lang), use_container_width=True, type="secondary"):
            st.session_state.is_guest = True
            st.session_state.user = None
            st.session_state.is_admin = False
            st.session_state.is_temporary = False
            st.session_state.current_chat_id = None
            st.session_state.messages = []
            st.session_state.guest_chats = {}
            st.session_state.guest_prefs = {
                "model": DEFAULT_MODEL, "temperature": 0.7,
                "top_p": 0.95, "top_k": 40, "smart_draft": True,
                "typing_mode": DEFAULT_TYPING_MODE,
                "typing_cps": DEFAULT_TYPING_CPS
            }
            st.session_state.guest_memory = ""
            st.session_state.traffic_recorded = False
            st.rerun()

# ==========================================
# 23. TRAFFIC ANALYTICS
# ==========================================
def _render_traffic_analytics(lang: str, traffic: dict):
    st.markdown(f"### {t('traffic_title', lang)}")
    st.caption(f"{t('traffic_desc', lang)} • {t('traffic_current_time', lang)}: **{_now_vn_iso()}**")

    if not isinstance(traffic, dict) or not traffic:
        st.info(t("traffic_no_data", lang))
        return

    today = _today_vn_str()
    d7 = (vn_now() - timedelta(days=6)).strftime("%Y-%m-%d")
    d30 = (vn_now() - timedelta(days=29)).strftime("%Y-%m-%d")

    total_7d = total_30d = today_count = 0
    unique_devices = set()
    role_counts = {"user": 0, "guest": 0, "admin": 0}

    for date_str, day in traffic.items():
        if not isinstance(day, dict):
            continue
        visits = day.get("visits", [])
        if not isinstance(visits, list):
            continue
        n = len(visits)
        if date_str >= d30:
            total_30d += n
        if date_str >= d7:
            total_7d += n
        if date_str == today:
            today_count = n
        for v in visits:
            dev = v.get("device")
            role = v.get("role", "user")
            if dev:
                unique_devices.add(dev)
            if role in role_counts:
                role_counts[role] += 1

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="stat-card"><div class="stat-value">{today_count}</div><div class="stat-label">{t("traffic_today", lang)}</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="stat-card"><div class="stat-value">{total_7d}</div><div class="stat-label">{t("traffic_7d", lang)}</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="stat-card"><div class="stat-value">{total_30d}</div><div class="stat-label">{t("traffic_30d", lang)}</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="stat-card"><div class="stat-value">{len(unique_devices)}</div><div class="stat-label">{t("traffic_unique", lang)}</div></div>', unsafe_allow_html=True)

    st.markdown(f"#### {t('traffic_chart_title', lang)}")
    chart_data = {}
    for i in range(13, -1, -1):
        d = (vn_now() - timedelta(days=i)).strftime("%Y-%m-%d")
        day = traffic.get(d, {})
        visits = day.get("visits", []) if isinstance(day, dict) else []
        chart_data[d] = len(visits) if isinstance(visits, list) else 0

    try:
        import pandas as pd
        df = pd.DataFrame({"visits": list(chart_data.values())}, index=list(chart_data.keys()))
        st.bar_chart(df, use_container_width=True)
    except Exception:
        for d, n in chart_data.items():
            st.markdown(f"<div class='traffic-row'>{d}: {'█' * min(n, 50)} ({n})</div>", unsafe_allow_html=True)

    st.markdown(f"#### {t('traffic_by_role', lang)}")
    rc1, rc2, rc3 = st.columns(3)
    with rc1:
        st.markdown(f'<div class="stat-card"><div class="stat-value">{role_counts["user"]}</div><div class="stat-label">👤 {t("traffic_role_user", lang)}</div></div>', unsafe_allow_html=True)
    with rc2:
        st.markdown(f'<div class="stat-card"><div class="stat-value">{role_counts["guest"]}</div><div class="stat-label">👥 {t("traffic_role_guest", lang)}</div></div>', unsafe_allow_html=True)
    with rc3:
        st.markdown(f'<div class="stat-card"><div class="stat-value">{role_counts["admin"]}</div><div class="stat-label">🛡️ {t("traffic_role_admin", lang)}</div></div>', unsafe_allow_html=True)

    with st.expander(f"📋 {t('traffic_recent', lang)}", expanded=False):
        all_visits = []
        for date_str, day in traffic.items():
            if not isinstance(day, dict):
                continue
            for v in day.get("visits", []):
                if isinstance(v, dict):
                    all_visits.append(v)
        all_visits.sort(key=lambda x: x.get("time", ""), reverse=True)
        recent = all_visits[:100]
        if not recent:
            st.caption(t("traffic_no_data", lang))
        else:
            for v in recent:
                ts = v.get("time", "?")
                lbl = v.get("label", "?")
                role = v.get("role", "?")
                dev = mask_device(v.get("device", ""))
                icon = {"user": "👤", "guest": "👥", "admin": "🛡️"}.get(role, "❓")
                st.markdown(f"<div class='traffic-row'>{icon} <b>{ts}</b> — {lbl} <span style='opacity:0.5'>({dev})</span></div>", unsafe_allow_html=True)

# ==========================================
# 24. ADMIN PANEL
# ==========================================
def render_admin_panel():
    lang = st.session_state.language
    _show_update_notice_if_needed()
    render_reboot_banner_if_needed()

    st.markdown(f"<h1 class='main-header'>{t('admin_panel', lang)}</h1>", unsafe_allow_html=True)
    st.caption(f"🛡️ {t('admin_logged_in', lang)} • VN: {_now_vn_iso()}")
    st.divider()

    db = GitHubStorage.load_db(force_refresh=True)
    cfg = db.get(SYSTEM_CONFIG_KEY, {
        "maintenance_mode": False, "maintenance_note": "",
        "announcement": {"enabled": False, "title": "", "body": "", "updated_at": ""}
    })
    cur_maint = cfg.get("maintenance_mode", False)
    cur_note = cfg.get("maintenance_note", "")

    cur_ann = cfg.get("announcement", {}) or {}
    ann_enabled = bool(cur_ann.get("enabled", False))
    ann_title = str(cur_ann.get("title", ""))
    ann_body = str(cur_ann.get("body", ""))
    ann_updated = str(cur_ann.get("updated_at", ""))

    # 1. ANNOUNCEMENT
    st.markdown('<div class="admin-panel">', unsafe_allow_html=True)
    st.subheader(t("announcement_panel_title", lang))
    st.caption(t("announcement_panel_desc", lang))

    if ann_enabled:
        st.markdown(f"**{t('announcement_current_status', lang)}:** {t('announcement_status_on', lang)}")
    else:
        st.markdown(f"**{t('announcement_current_status', lang)}:** {t('announcement_status_off', lang)}")
    if ann_updated:
        st.caption(f"🕐 {t('announcement_updated_at', lang)}: {ann_updated}")

    ann_title_input = st.text_input(
        t("announcement_title_label", lang),
        value=ann_title,
        placeholder=t("announcement_title_placeholder", lang),
        key="admin_ann_title"
    )
    ann_body_input = st.text_area(
        t("announcement_body_label", lang),
        value=ann_body,
        height=140,
        placeholder=t("announcement_body_placeholder", lang),
        key="admin_ann_body"
    )

    if ann_body_input.strip():
        st.markdown(f"**{t('announcement_preview', lang)}**")
        preview_title = ann_title_input.strip() or t("announcement_default_title", lang)
        st.markdown(f"""
        <div class="announcement-banner" style="margin-top:6px;">
            <div class="announcement-header">📢 {preview_title}</div>
            <div class="announcement-body">{ann_body_input}</div>
        </div>
        """, unsafe_allow_html=True)

    acol1, acol2 = st.columns(2)
    with acol1:
        send_label = t("announcement_update_btn", lang) if ann_enabled else t("announcement_send_btn", lang)
        if st.button(send_label, use_container_width=True, type="primary", key="admin_ann_send"):
            if not ann_body_input.strip() and not ann_title_input.strip():
                st.warning("⚠️ Vui lòng nhập tiêu đề hoặc nội dung." if lang == "vi" else "⚠️ Please enter a title or content.")
            else:
                cfg["announcement"] = {
                    "enabled": True,
                    "title": ann_title_input.strip(),
                    "body": ann_body_input.strip(),
                    "updated_at": _now_vn_iso()
                }
                db[SYSTEM_CONFIG_KEY] = cfg
                ok, msg = GitHubStorage.save_db(db)
                if ok:
                    st.toast(t("announcement_sent_toast", lang), icon="📢")
                    time.sleep(0.4)
                    st.rerun()
                else:
                    st.error(f"Error: {msg}")
    with acol2:
        if st.button(t("announcement_clear_btn", lang), use_container_width=True, key="admin_ann_clear"):
            cfg["announcement"] = {
                "enabled": False, "title": "", "body": "",
                "updated_at": _now_vn_iso()
            }
            db[SYSTEM_CONFIG_KEY] = cfg
            ok, msg = GitHubStorage.save_db(db)
            if ok:
                st.toast(t("announcement_cleared_toast", lang), icon="🗑️")
                time.sleep(0.4)
                st.rerun()
            else:
                st.error(f"Error: {msg}")
    st.markdown('</div>', unsafe_allow_html=True)

    # 2. MAINTENANCE
    status_text = t("sys_paused", lang) if cur_maint else t("sys_running", lang)
    st.markdown(f"**{t('sys_status', lang)}:** {status_text}")

    st.markdown('<div class="admin-panel">', unsafe_allow_html=True)
    st.subheader(t("maintenance_toggle", lang))
    col_a, col_b = st.columns(2)
    with col_a:
        if st.button(t("maintenance_on", lang), use_container_width=True, disabled=cur_maint, key="admin_maint_on"):
            cfg["maintenance_mode"] = True
            db[SYSTEM_CONFIG_KEY] = cfg
            ok, msg = GitHubStorage.save_db(db)
            if ok:
                st.toast("🔴 System paused", icon="🔴")
                time.sleep(0.3)
                st.rerun()
            else:
                st.error(f"Error: {msg}")
    with col_b:
        if st.button(t("maintenance_off", lang), use_container_width=True, disabled=not cur_maint, key="admin_maint_off"):
            cfg["maintenance_mode"] = False
            db[SYSTEM_CONFIG_KEY] = cfg
            ok, msg = GitHubStorage.save_db(db)
            if ok:
                st.toast("🟢 System resumed", icon="🟢")
                time.sleep(0.3)
                st.rerun()
            else:
                st.error(f"Error: {msg}")

    st.markdown(f"**{t('maintenance_note_label', lang)}**")
    note_input = st.text_area("Note:", value=cur_note, height=100,
                              placeholder=t("maintenance_note_placeholder", lang),
                              key="admin_maint_note", label_visibility="collapsed")
    if st.button(t("save_maintenance_note", lang), use_container_width=True, key="admin_save_note"):
        cfg["maintenance_note"] = note_input.strip()
        db[SYSTEM_CONFIG_KEY] = cfg
        ok, msg = GitHubStorage.save_db(db)
        if ok:
            st.toast(t("maintenance_note_saved", lang), icon="💾")
            time.sleep(0.3)
            st.rerun()
        else:
            st.error(f"Error: {msg}")
    st.markdown('</div>', unsafe_allow_html=True)

    # 3. BUG REPORTS
    st.markdown('<div class="admin-panel">', unsafe_allow_html=True)
    st.subheader(t("bug_report_admin_title", lang))
    st.caption(t("bug_report_admin_desc", lang))
    reports = db.get(BUG_REPORTS_KEY, [])
    if not isinstance(reports, list):
        reports = []
    if not reports:
        st.caption(t("bug_report_admin_empty", lang))
    else:
        reports_sorted = sorted(reports, key=lambda x: x.get("time", ""), reverse=True)
        for rpt in reports_sorted:
            rid = rpt.get("id", "")
            uname = rpt.get("user", "?")
            role = rpt.get("role", "user")
            rtime = rpt.get("time", "?")
            rtext = rpt.get("text", "").strip()
            ss = rpt.get("screenshot_b64", "")
            reply = rpt.get("reply", "")
            replied_at = rpt.get("replied_at", "")
            replied_by = rpt.get("replied_by", "")

            with st.container():
                status_badge = t("bug_report_status_replied", lang) if reply else t("bug_report_status_pending", lang)
                st.markdown(f"""
                <div class="bug-report-card">
                    <div class="bug-report-meta">
                        🐛 <b>#{rid[:8]}</b> • {t('bug_report_from_user', lang)}: <b>{uname}</b> ({role}) • {t('bug_report_sent_at', lang)}: <b>{rtime}</b> • {status_badge}
                    </div>
                """, unsafe_allow_html=True)

                if rtext:
                    st.markdown(f'<div class="bug-report-text">{rtext}</div>', unsafe_allow_html=True)

                if reply:
                    st.markdown(
                        f'<div class="bug-report-reply">💬 <b>{t("bug_report_reply_from_admin", lang)}</b> '
                        f'({replied_by}, {replied_at}):<br>{reply}</div>',
                        unsafe_allow_html=True
                    )

                st.markdown('</div>', unsafe_allow_html=True)

                if ss:
                    with st.expander(t("bug_report_view_screenshot", lang), expanded=False):
                        try:
                            st.image("data:image/jpeg;base64," + ss, caption=f"#{rid[:8]}", width=480)
                        except Exception:
                            st.caption("⚠️ Không đọc được ảnh." if lang == "vi" else "⚠️ Cannot read image.")

                reply_key = f"reply_text_{rid}"
                reply_input = st.text_area(
                    t("bug_report_admin_reply_label", lang),
                    value=reply,
                    height=80,
                    placeholder=t("bug_report_admin_reply_placeholder", lang),
                    key=reply_key
                )
                cr1, cr2 = st.columns(2)
                with cr1:
                    if st.button(t("bug_report_admin_reply_btn", lang), use_container_width=True, key=f"reply_send_{rid}"):
                        if not reply_input.strip():
                            st.warning("⚠️ Empty reply." if lang == "en" else "⚠️ Phản hồi trống.")
                        else:
                            db2 = GitHubStorage.load_db(force_refresh=True)
                            ok_r = reply_bug_report(db2, rid, reply_input.strip(), "Admin")
                            if ok_r:
                                ok2, msg2 = GitHubStorage.save_db(db2)
                                if ok2:
                                    st.toast(t("bug_report_admin_reply_saved", lang), icon="✅")
                                    time.sleep(0.4)
                                    st.rerun()
                                else:
                                    st.error(f"Error: {msg2}")
                            else:
                                st.error("Report not found.")
                with cr2:
                    if st.button(t("bug_report_admin_delete_btn", lang), use_container_width=True, key=f"reply_del_{rid}"):
                        db2 = GitHubStorage.load_db(force_refresh=True)
                        ok_d = delete_bug_report(db2, rid)
                        if ok_d:
                            ok2, msg2 = GitHubStorage.save_db(db2)
                            if ok2:
                                st.toast(t("bug_report_admin_deleted", lang), icon="🗑️")
                                time.sleep(0.4)
                                st.rerun()
                            else:
                                st.error(f"Error: {msg2}")
                        else:
                            st.error("Report not found.")

                st.markdown("---")
    st.markdown('</div>', unsafe_allow_html=True)

    # 4. TRAFFIC
    st.markdown('<div class="admin-panel">', unsafe_allow_html=True)
    _render_traffic_analytics(lang, db.get(TRAFFIC_LOG_KEY, {}))
    st.markdown('</div>', unsafe_allow_html=True)

    with st.expander("📋 Existing users", expanded=False):
        user_list = [u for u in db.keys()
                     if u not in (SYSTEM_CONFIG_KEY, TRAFFIC_LOG_KEY, BUG_REPORTS_KEY)
                     and isinstance(db[u], dict)]
        if user_list:
            for u in sorted(user_list):
                st.markdown(f"- `{u}`")
        else:
            st.caption("No users yet.")

    st.divider()
    if st.button(t("admin_logout", lang), use_container_width=True, key="admin_logout"):
        st.session_state.is_admin = False
        st.session_state.user = None
        st.session_state.is_guest = False
        st.session_state.is_temporary = False
        st.session_state.traffic_recorded = False
        st.rerun()

# ==========================================
# 25. MAINTENANCE SCREEN
# ==========================================
def render_maintenance_screen():
    lang = st.session_state.language
    render_reboot_banner_if_needed()

    db = GitHubStorage.load_db(force_refresh=True)
    cfg = db.get(SYSTEM_CONFIG_KEY, {})
    note = cfg.get("maintenance_note", "").strip()

    st.markdown(f"<h1 class='main-header' style='text-align: center;'>{t('app_title', lang)}</h1>", unsafe_allow_html=True)

    note_html = f'<div class="maintenance-note">💬 {note}</div>' if note else ""

    st.markdown(f"""
    <div class="maintenance-banner">
        <div style="font-size: 1.8rem; margin-bottom: 8px;">🚧</div>
        <div style="font-size: 1.2rem; font-weight: 800;">{t('maintenance_title', lang)}</div>
        <div style="margin-top: 10px; font-size: 0.95rem; opacity: 0.9;">{t('maintenance_desc', lang)}</div>
        {note_html}
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    with st.expander(t("maintenance_login_expander", lang), expanded=False):
        st.caption(t("maintenance_login_test_hint", lang))
        with st.form("maintenance_access_form"):
            m_user = st.text_input("Username:", key="maint_u")
            m_pass = st.text_input("Password:", type="password", key="maint_p")
            if st.form_submit_button("Login", use_container_width=True):
                if m_user == ADMIN_USERNAME and m_pass == ADMIN_PASSWORD:
                    st.session_state.is_admin = True
                    st.session_state.user = None
                    st.session_state.is_guest = False
                    st.session_state.is_temporary = False
                    st.session_state.traffic_recorded = False
                    st.rerun()
                elif m_user.lower() == TEST_USERNAME and m_pass == TEST_PASSWORD:
                    st.session_state.user = TEST_USERNAME
                    st.session_state.is_admin = False
                    st.session_state.is_guest = False
                    st.session_state.is_temporary = True
                    st.session_state.current_chat_id = None
                    st.session_state.messages = []
                    st.session_state.test_chats = {}
                    st.session_state.test_memory = ""
                    st.session_state.test_prefs = {
                        "model": DEFAULT_MODEL, "temperature": 0.7,
                        "top_p": 0.95, "top_k": 40, "smart_draft": True,
                        "typing_mode": DEFAULT_TYPING_MODE,
                        "typing_cps": DEFAULT_TYPING_CPS
                    }
                    st.session_state.traffic_recorded = True
                    st.toast(t("test_login_success", lang), icon="🔧")
                    st.rerun()
                else:
                    st.error("❌ Sai thông tin đăng nhập." if lang == "vi" else "❌ Invalid credentials.")

# ==========================================
# 26. ROUTING
# ==========================================
if st.session_state.is_admin:
    render_admin_panel()
    st.stop()

if maintenance_mode:
    if is_temporary_session():
        pass
    else:
        render_maintenance_screen()
        st.stop()

if not maintenance_mode and is_temporary_session():
    st.session_state.user = None
    st.session_state.is_temporary = False
    st.session_state.current_chat_id = None
    st.session_state.messages = []
    st.session_state.test_chats = {}
    st.session_state.test_memory = ""
    st.warning(t("test_only_in_maintenance", st.session_state.language))
    st.stop()

if not st.session_state.user and not st.session_state.is_guest:
    render_auth_ui()
    st.stop()

# ==========================================
# 27. LOAD USER / GUEST / TEST DATA
# ==========================================
is_guest = st.session_state.is_guest
is_test = is_temporary_session()
lang = st.session_state.language

if is_test:
    user_data = {
        "custom_instructions": st.session_state.test_memory,
        "chats": st.session_state.test_chats,
        "remembered_devices": [],
        "language": lang,
        "preferences": st.session_state.test_prefs
    }
    user_chats = st.session_state.test_chats
elif is_guest:
    user_data = {
        "custom_instructions": st.session_state.guest_memory,
        "chats": st.session_state.guest_chats,
        "remembered_devices": [],
        "language": lang,
        "preferences": st.session_state.guest_prefs
    }
    user_chats = st.session_state.guest_chats
else:
    user_data = db_data.get(st.session_state.user, {})
    user_data.setdefault("custom_instructions", "")
    user_data.setdefault("chats", {})
    user_data.setdefault("remembered_devices", [])
    user_data.setdefault("language", "en")
    user_data.setdefault("preferences", {})
    user_data["preferences"].setdefault("model", DEFAULT_MODEL)
    user_data["preferences"].setdefault("temperature", 0.7)
    user_data["preferences"].setdefault("top_p", 0.95)
    user_data["preferences"].setdefault("top_k", 40)
    user_data["preferences"].setdefault("smart_draft", True)
    user_data["preferences"].setdefault("typing_mode", DEFAULT_TYPING_MODE)
    user_data["preferences"].setdefault("typing_cps", DEFAULT_TYPING_CPS)
    st.session_state.language = user_data.get("language", "en")
    lang = st.session_state.language
    user_chats = user_data["chats"]

if st.session_state.current_chat_id and st.session_state.current_chat_id not in user_chats:
    st.session_state.current_chat_id = None
    st.session_state.messages = []

# ==========================================
# 28. SIDEBAR
# ==========================================
with st.sidebar:
    if is_test or is_guest:
        lc = st.selectbox(t("language", lang), ["en", "vi"],
                          index=0 if lang == "en" else 1,
                          format_func=lambda x: "🇬🇧 English" if x == "en" else "🇻🇳 Tiếng Việt",
                          key="sidebar_lang_temp")
        if lc != lang:
            st.session_state.language = lc
            st.rerun()
    else:
        lc = st.selectbox(t("language", lang), ["en", "vi"],
                          index=0 if lang == "en" else 1,
                          format_func=lambda x: "🇬🇧 English" if x == "en" else "🇻🇳 Tiếng Việt",
                          key="sidebar_lang")
        if lc != lang:
            user_data["language"] = lc
            db_data[st.session_state.user] = user_data
            safe_save_db(db_data)
            st.session_state.language = lc
            st.rerun()

    if is_test:
        st.markdown(f"""
        <div class="user-card">
            <div style="font-weight: 700; font-size: 1.1rem; color: #a855f7;">🔧 {st.session_state.user}</div>
            <div style="font-size: 0.8rem; opacity: 0.7;"><span class="pulse-dot"></span>{t('online', lang)} | {t('device_id', lang)}: {mask_device(device_id)}</div>
            <span class="status-badge badge-test">{t('test_badge', lang)}</span>
        </div>
        """, unsafe_allow_html=True)
    elif is_guest:
        st.markdown(f"""
        <div class="user-card">
            <div style="font-weight: 700; font-size: 1.1rem; color: #94a3b8;">👤 {t('guest_mode', lang)}</div>
            <div style="font-size: 0.8rem; opacity: 0.7;"><span class="pulse-dot"></span>{t('online', lang)} | {t('device_id', lang)}: {mask_device(device_id)}</div>
            <span class="status-badge badge-guest">GUEST</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="user-card">
            <div style="font-weight: 700; font-size: 1.1rem; color: #667eea;">👤 {st.session_state.user}</div>
            <div style="font-size: 0.8rem; opacity: 0.7;"><span class="pulse-dot"></span>{t('online', lang)} | {t('device_id', lang)}: {mask_device(device_id)}</div>
        </div>
        """, unsafe_allow_html=True)

    if st.button(t("bug_report_btn", lang), use_container_width=True, key="bug_report_open_btn"):
        st.session_state.bug_report_open = True
        st.rerun()

    if not is_test and not is_guest:
        with st.expander(t("bug_report_my_reports", lang), expanded=False):
            my_reports = get_user_bug_reports(db_data, st.session_state.user)
            if not my_reports:
                st.caption(t("bug_report_no_reports", lang))
            else:
                for rpt in my_reports[:10]:
                    rtime = rpt.get("time", "?")
                    rtext = rpt.get("text", "").strip()
                    reply = rpt.get("reply", "")
                    replied_at = rpt.get("replied_at", "")
                    status = t("bug_report_status_replied", lang) if reply else t("bug_report_status_pending", lang)
                    st.markdown(f"**{rtime}** • {status}")
                    if rtext:
                        st.caption(f"💬 {rtext[:120]}" + ("..." if len(rtext) > 120 else ""))
                    if reply:
                        st.markdown(
                            f'<div class="bug-report-reply">💬 <b>{t("bug_report_reply_from_admin", lang)}</b> '
                            f'({replied_at}):<br>{reply}</div>',
                            unsafe_allow_html=True
                        )
                    st.markdown("---")

    logout_label = t("test_logout", lang) if is_test else t("logout_btn", lang)
    if st.button(logout_label, use_container_width=True, key="logout_btn"):
        if not is_guest and not is_test:
            db = GitHubStorage.load_db(force_refresh=True)
            u = db.get(st.session_state.user, {})
            if device_id in u.get("remembered_devices", []):
                u["remembered_devices"].remove(device_id)
                db[st.session_state.user] = u
                GitHubStorage.save_db(db)
        st.session_state.user = None
        st.session_state.is_guest = False
        st.session_state.is_temporary = False
        st.session_state.current_chat_id = None
        st.session_state.messages = []
        st.session_state.test_chats = {}
        st.session_state.test_memory = ""
        st.session_state.traffic_recorded = False
        st.rerun()

    st.divider()
    if st.button(t("new_chat_btn", lang), type="primary", use_container_width=True, key="new_chat_btn"):
        st.session_state.current_chat_id = None
        st.session_state.messages = []
        st.rerun()

    st.subheader(t("chat_list", lang))
    if not user_chats:
        st.caption(t("no_chats", lang))
    else:
        sorted_ids = sorted(user_chats.keys(),
                            key=lambda cid: user_chats[cid].get("updated_at", ""),
                            reverse=True)[:50]
        for cid in sorted_ids:
            item = user_chats.get(cid, {})
            title = item.get("title", t("new_chat", lang))
            active = (cid == st.session_state.current_chat_id)
            label = f"📌 {title}" if active else f"💬 {title}"
            cc, cd = st.columns([0.8, 0.2])
            if cc.button(label, key=f"sel_{cid}", use_container_width=True):
                st.session_state.current_chat_id = cid
                st.session_state.messages = user_chats[cid].get("messages", [])
                st.rerun()
            if cd.button("🗑️", key=f"del_{cid}", help=t("delete_chat_tooltip", lang)):
                if cid in user_chats:
                    del user_chats[cid]
                    if is_test:
                        st.session_state.test_chats = user_chats
                    elif is_guest:
                        st.session_state.guest_chats = user_chats
                    else:
                        user_data["chats"] = user_chats
                        db_data[st.session_state.user] = user_data
                        safe_save_db(db_data)
                    if st.session_state.current_chat_id == cid:
                        st.session_state.current_chat_id = None
                        st.session_state.messages = []
                    st.toast(t("chat_deleted", lang), icon="🗑️")
                    time.sleep(0.3)
                    st.rerun()

    st.divider()

    with st.expander(t("settings_title", lang), expanded=False):
        # Smart Draft
        col_lbl, col_help = st.columns([0.85, 0.15])
        with col_lbl:
            st.markdown(f"**{t('smart_draft_label', lang)}**")
        with col_help:
            with st.popover("❓"):
                st.markdown(t("smart_draft_help", lang))

        smart_draft_val = st.toggle(
            t("smart_draft_label", lang),
            value=bool(user_data["preferences"].get("smart_draft", True)),
            key="smart_draft_toggle",
            label_visibility="collapsed"
        )

        if smart_draft_val != user_data["preferences"].get("smart_draft", True):
            user_data["preferences"]["smart_draft"] = smart_draft_val
            if is_test:
                st.session_state.test_prefs["smart_draft"] = smart_draft_val
            elif is_guest:
                st.session_state.guest_prefs["smart_draft"] = smart_draft_val
            else:
                db_data[st.session_state.user] = user_data
                safe_save_db(db_data)
            st.toast(
                t("smart_draft_on", lang) if smart_draft_val else t("smart_draft_off", lang),
                icon="💾"
            )

        status_txt = t("smart_draft_on", lang) if smart_draft_val else t("smart_draft_off", lang)
        st.caption(f"→ {status_txt}")

        if not smart_draft_val:
            clear_draft_cookie_via_js()

        st.markdown("---")

        # Typing mode
        tcol1, tcol2 = st.columns([0.85, 0.15])
        with tcol1:
            st.markdown(f"**⌨️ {t('typing_mode_label', lang)}**")
        with tcol2:
            with st.popover("❓", use_container_width=True):
                st.markdown(t("typing_mode_help", lang))

        typing_mode_options = [
            TYPING_MODE_SMOOTH,
            TYPING_MODE_CONTROLLED,
            TYPING_MODE_INSTANT,
        ]
        typing_mode_labels = {
            TYPING_MODE_SMOOTH: t("typing_mode_smooth", lang),
            TYPING_MODE_CONTROLLED: t("typing_mode_controlled", lang),
            TYPING_MODE_INSTANT: t("typing_mode_instant", lang),
        }
        current_mode = user_data["preferences"].get("typing_mode", DEFAULT_TYPING_MODE)
        try:
            default_idx = typing_mode_options.index(current_mode)
        except ValueError:
            default_idx = 0

        selected_mode = st.radio(
            t("typing_mode_label", lang),
            options=typing_mode_options,
            index=default_idx,
            format_func=lambda x: typing_mode_labels.get(x, x),
            key="typing_mode_radio",
            label_visibility="collapsed"
        )

        if selected_mode == TYPING_MODE_CONTROLLED:
            new_cps = st.slider(
                t("typing_cps_label", lang),
                min_value=5, max_value=120,
                value=int(user_data["preferences"].get("typing_cps", DEFAULT_TYPING_CPS)),
                step=5,
                key="typing_cps_slider"
            )
        else:
            new_cps = user_data["preferences"].get("typing_cps", DEFAULT_TYPING_CPS)

        old_mode = user_data["preferences"].get("typing_mode", DEFAULT_TYPING_MODE)
        old_cps = user_data["preferences"].get("typing_cps", DEFAULT_TYPING_CPS)
        if selected_mode != old_mode or new_cps != old_cps:
            user_data["preferences"]["typing_mode"] = selected_mode
            user_data["preferences"]["typing_cps"] = new_cps
            if is_test:
                st.session_state.test_prefs["typing_mode"] = selected_mode
                st.session_state.test_prefs["typing_cps"] = new_cps
            elif is_guest:
                st.session_state.guest_prefs["typing_mode"] = selected_mode
                st.session_state.guest_prefs["typing_cps"] = new_cps
            else:
                db_data[st.session_state.user] = user_data
                safe_save_db(db_data)
            st.toast(t("typing_mode_saved", lang), icon="⌨️")

    st.divider()

    with st.expander(t("memory_title", lang), expanded=False):
        st.caption(t("memory_desc", lang))
        mem = st.text_area("Memory:", value=user_data.get("custom_instructions", ""),
                           height=120, placeholder=t("memory_placeholder", lang),
                           key="sidebar_memory_ta")
        if st.button(t("save_memory_btn", lang), use_container_width=True, key="sidebar_save_mem"):
            if is_test:
                st.session_state.test_memory = mem.strip()
                user_data["custom_instructions"] = mem.strip()
            elif is_guest:
                st.session_state.guest_memory = mem.strip()
                user_data["custom_instructions"] = mem.strip()
            else:
                user_data["custom_instructions"] = mem.strip()
                db_data[st.session_state.user] = user_data
                safe_save_db(db_data)
            st.toast(t("memory_saved", lang), icon="🧠")
            time.sleep(0.3)
            st.rerun()

    st.subheader(t("api_title", lang))
    st.caption(t("api_from_secrets", lang))
    for i, key in enumerate([API_KEY_1, API_KEY_2], start=1):
        if key:
            masked = f"{key[:6]}...{key[-4:]}" if len(key) > 10 else "••••••••"
            st.markdown(f"**Key {i}:** `{masked}` <span class='status-badge badge-ready'>{t('api_status_ready', lang)}</span>", unsafe_allow_html=True)
        else:
            st.markdown(f"**Key {i}:** *Not configured* <span class='status-badge badge-missing'>{t('api_status_missing', lang)}</span>", unsafe_allow_html=True)

    available_models = FALLBACK_MODELS.copy()
    if SECRET_API_KEYS:
        try:
            genai.configure(api_key=SECRET_API_KEYS[0])
            dyn = []
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    dyn.append(m.name.replace("models/", ""))
            if dyn:
                available_models = list(dict.fromkeys(dyn + FALLBACK_MODELS))
        except Exception:
            pass

    saved_model = user_data["preferences"].get("model", DEFAULT_MODEL)
    if saved_model not in available_models:
        saved_model = DEFAULT_MODEL
        user_data["preferences"]["model"] = saved_model
        if not is_guest and not is_test:
            db_data[st.session_state.user] = user_data

    try:
        midx = available_models.index(saved_model)
    except ValueError:
        midx = 0

    sel_model = st.selectbox(t("model_select", lang), available_models, index=midx, key="sidebar_model_sel")
    if sel_model != user_data["preferences"].get("model"):
        user_data["preferences"]["model"] = sel_model
        if is_test:
            st.session_state.test_prefs["model"] = sel_model
        elif is_guest:
            st.session_state.guest_prefs["model"] = sel_model
        else:
            db_data[st.session_state.user] = user_data
            safe_save_db(db_data)

    with st.expander(t("gen_config", lang), expanded=False):
        tcol1, tcol2 = st.columns([0.85, 0.15])
        with tcol1:
            st.markdown(f"**🎨 {t('temperature', lang)}**")
        with tcol2:
            with st.popover("❓", use_container_width=True):
                st.markdown(t("temperature_help", lang))
        temperature = st.slider(
            t("temperature", lang), 0.0, 1.0,
            float(user_data["preferences"].get("temperature", 0.7)), 0.05,
            key="sidebar_temp", label_visibility="collapsed"
        )
        if temperature <= 0.3:
            st.caption("🟦 " + t("t_level_safe", lang))
        elif temperature <= 0.7:
            st.caption("🟩 " + t("t_level_balanced", lang))
        else:
            st.caption("🟧 " + t("t_level_creative", lang))

        st.markdown("---")

        tcol1, tcol2 = st.columns([0.85, 0.15])
        with tcol1:
            st.markdown(f"**🌈 {t('top_p', lang)}**")
        with tcol2:
            with st.popover("❓", use_container_width=True):
                st.markdown(t("top_p_help", lang))
        top_p = st.slider(
            t("top_p", lang), 0.0, 1.0,
            float(user_data["preferences"].get("top_p", 0.95)), 0.05,
            key="sidebar_topp", label_visibility="collapsed"
        )
        if top_p <= 0.7:
            st.caption("🟦 " + t("p_level_predictable", lang))
        else:
            st.caption("🟩 " + t("p_level_varied", lang))

        st.markdown("---")

        tcol1, tcol2 = st.columns([0.85, 0.15])
        with tcol1:
            st.markdown(f"**🎯 {t('top_k', lang)}**")
        with tcol2:
            with st.popover("❓", use_container_width=True):
                st.markdown(t("top_k_help", lang))
        top_k = st.number_input(
            t("top_k", lang), 1, 100,
            int(user_data["preferences"].get("top_k", 40)),
            key="sidebar_topk", label_visibility="collapsed"
        )
        if top_k <= 20:
            st.caption("🟦 " + t("k_level_focused", lang))
        elif top_k <= 60:
            st.caption("🟩 " + t("k_level_balanced", lang))
        else:
            st.caption("🟧 " + t("k_level_varied", lang))

        st.markdown("---")

        bcol1, bcol2 = st.columns(2)
        with bcol1:
            if st.button(t("save_params", lang), use_container_width=True, key="sidebar_save_params", type="primary"):
                user_data["preferences"]["temperature"] = temperature
                user_data["preferences"]["top_p"] = top_p
                user_data["preferences"]["top_k"] = top_k
                if is_test:
                    st.session_state.test_prefs = user_data["preferences"]
                elif is_guest:
                    st.session_state.guest_prefs = user_data["preferences"]
                else:
                    db_data[st.session_state.user] = user_data
                    safe_save_db(db_data)
                st.toast(t("params_saved", lang), icon="💾")
                time.sleep(0.3)
                st.rerun()
        with bcol2:
            if st.button(t("reset_params", lang), use_container_width=True, key="sidebar_reset_params"):
                user_data["preferences"]["temperature"] = 0.7
                user_data["preferences"]["top_p"] = 0.95
                user_data["preferences"]["top_k"] = 40
                if is_test:
                    st.session_state.test_prefs = user_data["preferences"]
                elif is_guest:
                    st.session_state.guest_prefs = user_data["preferences"]
                else:
                    db_data[st.session_state.user] = user_data
                    safe_save_db(db_data)
                st.toast(t("reset_params_toast", lang), icon="🔄")
                time.sleep(0.3)
                st.rerun()

# ==========================================
# 29. SMART DRAFT
# ==========================================
smart_draft_enabled = bool(user_data["preferences"].get("smart_draft", True))
inject_smart_draft_tracker(
    enabled=smart_draft_enabled,
    min_words=SMART_DRAFT_MIN_WORDS,
    interval_sec=SMART_DRAFT_INTERVAL_SEC,
    idle_sec=SMART_DRAFT_IDLE_SEC
)

draft_text, draft_ts = get_saved_draft()

# ==========================================
# 30. BUG REPORT DIALOG TRIGGER
# ==========================================
if st.session_state.get("bug_report_open", False):
    bug_report_dialog()

# ==========================================
# 31. MAIN CHAT
# ==========================================
_show_update_notice_if_needed()
render_reboot_banner_if_needed()
render_announcement_banner()
render_test_banner()

st.markdown(f"<h1 class='main-header'>{t('app_title', lang)}</h1>", unsafe_allow_html=True)

if not SECRET_API_KEYS:
    st.warning(t("no_api_key", lang))
    st.stop()

if is_guest:
    st.markdown(f'<div class="guest-banner">👤 {t("guest_banner", lang)}</div>', unsafe_allow_html=True)

current_title = t("new_chat", lang)
if st.session_state.current_chat_id and st.session_state.current_chat_id in user_chats:
    current_title = user_chats[st.session_state.current_chat_id].get("title", "Chat")

typing_mode_now = user_data["preferences"].get("typing_mode", DEFAULT_TYPING_MODE)
if typing_mode_now == TYPING_MODE_INSTANT:
    typing_badge = '⚡ Instant'
elif typing_mode_now == TYPING_MODE_CONTROLLED:
    typing_badge = f'⌨️ {user_data["preferences"].get("typing_cps", DEFAULT_TYPING_CPS)} cps'
else:
    typing_badge = '🌊 Smooth'

st.caption(f"📌 {t('current_chat', lang)}: **{current_title}** | {t('model_label', lang)}: `{sel_model}` <span class='typing-mode-badge'>{typing_badge}</span>", unsafe_allow_html=True)

if smart_draft_enabled and draft_text and len(draft_text.strip()) > 0:
    st.markdown(f"""
    <div class="draft-banner">
        <b>{t('draft_restored_title', lang)}</b><br>
        <span style="opacity:0.85;">{t('draft_restored_desc', lang)}</span>
        <div class="draft-preview">{draft_text}</div>
    </div>
    """, unsafe_allow_html=True)

    dc1, dc2, _ = st.columns([1, 1, 2])
    with dc1:
        if st.button(t("draft_restore_btn", lang), use_container_width=True, key="draft_restore_btn"):
            safe_text = json.dumps(draft_text)
            inject_js(
                '(function() {\n'
                '    const txt = ' + safe_text + ';\n'
                '    if (navigator.clipboard && navigator.clipboard.writeText) {\n'
                '        navigator.clipboard.writeText(txt).catch(function(){});\n'
                '    } else {\n'
                '        const ta = d.createElement("textarea");\n'
                '        ta.value = txt;\n'
                '        d.body.appendChild(ta);\n'
                '        ta.select();\n'
                '        try { d.execCommand("copy"); } catch(e){}\n'
                '        d.body.removeChild(ta);\n'
                '    }\n'
                '})();\n'
            )
            st.toast(t("draft_copied_toast", lang), icon="📋")
    with dc2:
        if st.button(t("draft_discard_btn", lang), use_container_width=True, key="draft_discard_btn"):
            clear_draft_cookie_via_js()
            st.toast(t("draft_discarded_toast", lang), icon="🗑️")
            time.sleep(0.3)
            st.rerun()

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])
        if msg["role"] == "assistant":
            st.markdown(f'<div class="ai-disclaimer">✍️ {DISCLAIMER.get(lang, DISCLAIMER["en"])}</div>', unsafe_allow_html=True)

# ==========================================
# 32. XỬ LÝ PROMPT
# ==========================================
def _process_prompt(user_prompt):
    clear_draft_cookie_via_js()

    st.session_state.messages.append({"role": "user", "content": user_prompt})
    with st.chat_message("user"):
        st.markdown(user_prompt)

    if not st.session_state.current_chat_id:
        st.session_state.current_chat_id = str(uuid.uuid4())
        user_chats[st.session_state.current_chat_id] = {
            "title": t("new_chat", lang),
            "messages": [],
            "summary": "",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        if is_test:
            st.session_state.test_chats = user_chats
        elif is_guest:
            st.session_state.guest_chats = user_chats

    chat_data = user_chats[st.session_state.current_chat_id]
    chat_summary = chat_data.get("summary", "")

    if len(st.session_state.messages) > 10:
        older = st.session_state.messages[:-6]
        try:
            chat_summary = generate_summary(older, chat_summary, SECRET_API_KEYS, sel_model, lang)
            chat_data["summary"] = chat_summary
        except Exception:
            pass

    system_instruction = user_data.get("custom_instructions", "")
    if chat_summary:
        label = "[BỐI CẢNH LỊCH SỬ ĐÃ TÓM TẮT]" if lang == "vi" else "[SUMMARIZED HISTORY CONTEXT]"
        system_instruction += f"\n\n{label}: {chat_summary}"

    content_inputs = []
    recent = st.session_state.messages[-6:]
    hist = ""
    for m in recent[:-1]:
        r = ("Người dùng" if lang == "vi" else "User") if m["role"] == "user" else "AI"
        hist += f"{r}: {m['content']}\n"

    if hist:
        if lang == "vi":
            full_prompt = f"Lịch sử hội thoại gần đây:\n{hist}\nCâu hỏi mới: {user_prompt}"
        else:
            full_prompt = f"Recent conversation history:\n{hist}\nNew question: {user_prompt}"
    else:
        full_prompt = user_prompt
    content_inputs.append(full_prompt)

    final_text = ""
    final_err = None

    with st.chat_message("assistant"):
        ai_placeholder = st.empty()
        ai_placeholder.markdown(f"""
        <div class="ai-loading-box">
            <div class="spinner"></div>
            <div class="ai-loading-text">{t('ai_typing', lang)}</div>
        </div>
        """, unsafe_allow_html=True)

        typing_mode_use = user_data["preferences"].get("typing_mode", DEFAULT_TYPING_MODE)
        typing_cps_use = user_data["preferences"].get("typing_cps", DEFAULT_TYPING_CPS)

        for text_so_far, done, err in stream_gemini_with_failover(
            prompt_inputs=content_inputs,
            api_keys=SECRET_API_KEYS,
            preferred_model=sel_model,
            system_instruction=system_instruction if system_instruction else None,
            generation_config={
                "temperature": temperature, "top_p": top_p, "top_k": top_k
            },
            lang=lang,
            ui_placeholder=ai_placeholder,
            typing_mode=typing_mode_use,
            typing_cps=typing_cps_use,
        ):
            if text_so_far:
                final_text = text_so_far

            if done:
                final_err = err
                break

        if final_text:
            ai_placeholder.markdown(final_text)
            st.markdown(
                f'<div class="ai-disclaimer">✍️ {DISCLAIMER.get(lang, DISCLAIMER["en"])}</div>',
                unsafe_allow_html=True
            )
            st.session_state.messages.append({"role": "assistant", "content": final_text})

            if final_err == "rate_limit_partial":
                st.warning(
                    "⚠️ Phản hồi có thể chưa đầy đủ (bị giới hạn giữa chừng)."
                    if lang == "vi" else
                    "⚠️ Response may be incomplete (rate-limited mid-stream)."
                )

        elif final_err == "rate_limit":
            st.session_state.pending_retry_prompt = user_prompt
            if (st.session_state.messages and
                    st.session_state.messages[-1]["role"] == "user" and
                    st.session_state.messages[-1]["content"] == user_prompt):
                st.session_state.messages.pop()
            render_rate_limit_and_retry(lang)
            return

        else:
            error_msg = f"{t('ai_error', lang)} Error: {str(final_err)[:150] if final_err else 'Unknown'}"
            st.error(error_msg)
            st.session_state.messages.append({"role": "assistant", "content": error_msg})

    if final_text:
        if len(chat_data.get("messages", [])) == 0:
            try:
                chat_data["title"] = generate_chat_title(user_prompt, SECRET_API_KEYS, sel_model, lang)
            except Exception:
                chat_data["title"] = user_prompt[:30] + "..." if len(user_prompt) > 30 else user_prompt

        chat_data["messages"] = st.session_state.messages
        chat_data["updated_at"] = datetime.now().isoformat()
        user_chats[st.session_state.current_chat_id] = chat_data

        if is_test:
            st.session_state.test_chats = user_chats
        elif is_guest:
            st.session_state.guest_chats = user_chats
        else:
            user_data["chats"] = user_chats
            db_data[st.session_state.user] = user_data
            if time.time() - st.session_state.last_save_time > 1:
                safe_save_db(db_data)
                st.session_state.last_save_time = time.time()

        st.rerun()


if st.session_state.pending_retry_prompt:
    pending = st.session_state.pending_retry_prompt
    st.session_state.pending_retry_prompt = None
    _process_prompt(pending)
elif user_prompt := st.chat_input(t("chat_placeholder", lang)):
    _process_prompt(user_prompt)
