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
APP_VERSION = "1.11.0"

ADMIN_USERNAME = "Admin"
ADMIN_PASSWORD = "7428"

TEST_USERNAME = "test"
TEST_PASSWORD = "testsoftware"

SYSTEM_CONFIG_KEY = "__system_config__"
TRAFFIC_LOG_KEY = "__traffic_log__"
BUG_REPORTS_KEY = "__bug_reports__"
TRAFFIC_RETENTION_DAYS = 30
BUG_REPORTS_MAX = 50  # Giữ tối đa 50 report gần nhất

VN_TZ_OFFSET = timedelta(hours=7)
VERSION_SCAN_INTERVAL = 60

# Smart draft constants
SMART_DRAFT_MIN_WORDS = 20
SMART_DRAFT_INTERVAL_SEC = 5
SMART_DRAFT_IDLE_SEC = 20
COOKIE_DRAFT = "LTTP_chat_draft"
COOKIE_DRAFT_TS = "LTTP_draft_ts"
COOKIE_DRAFT_ENABLED = "LTTP_draft_enabled"

# Bug report cookie chunk settings
BR_COOKIE_PREFIX = "LTTP_br_"
BR_COOKIE_META = "LTTP_br_meta"  # {chunks: N, ts: ..., text: ...}
BR_CHUNK_SIZE = 3000  # ký tự mỗi chunk
BR_MAX_CHUNKS = 15  # tối đa 15 chunks = 45KB base64 (đủ cho ảnh 240p)

# Streaming update interval
STREAM_UPDATE_INTERVAL = 0.05

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

    /* Ẩn nút attach trong chat_input */
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
        return True, "Temporary session - not saved to database"
    return GitHubStorage.save_db(data)

# ==========================================
# 4. JAVASCRIPT INJECTION
# ==========================================
def inject_js(js_code: str, height: int = 0):
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="margin:0;padding:0;">
    <script>
    (function() {{
        try {{
            const w = window.parent || window;
            const d = w.document;
            {js_code}
        }} catch (e) {{
            console.warn("LTTP JS error:", e);
        }}
    }})();
    </script>
    </body>
    </html>
    """
    components.html(html, height=height, scrolling=False)


def inject_version_scanner():
    js = f"""
    const CURRENT_VERSION = "{APP_VERSION}";
    const SCAN_INTERVAL_MS = {VERSION_SCAN_INTERVAL * 1000};
    const COOKIE_NAME = "LTTP_app_version";
    
    function getCookie(name) {{
        const value = `; ${{d.cookie}}`;
        const parts = value.split(`; ${{name}}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }}
    
    function checkVersion() {{
        try {{
            const cached = getCookie(COOKIE_NAME);
            if (cached && cached !== CURRENT_VERSION) {{
                if (!d.getElementById('lttp-reboot-banner-injected')) {{
                    const banner = d.createElement('div');
                    banner.id = 'lttp-reboot-banner-injected';
                    banner.style.cssText = 'position:fixed;top:10px;left:50%;transform:translateX(-50%);z-index:999999;padding:14px 24px;background:linear-gradient(90deg,#f59e0b,#f97316);color:white;border-radius:12px;box-shadow:0 6px 24px rgba(249,115,22,0.55);font-family:sans-serif;max-width:90vw;';
                    banner.innerHTML = '<div style="font-weight:800;font-size:1.05rem;margin-bottom:4px;">🚀 Đã có phiên bản mới!</div><div style="font-size:0.9rem;margin-bottom:10px;opacity:0.95;">Vui lòng tải lại trang để cập nhật.</div><button onclick="location.reload()" style="background:white;color:#f97316;border:none;padding:8px 20px;border-radius:8px;font-weight:700;cursor:pointer;font-size:0.9rem;">Tải lại ngay</button>';
                    d.body.appendChild(banner);
                }}
            }}
        }} catch (e) {{}}
    }}
    
    setTimeout(checkVersion, 3000);
    setInterval(checkVersion, SCAN_INTERVAL_MS);
    """
    inject_js(js)


def inject_smart_draft_tracker(enabled: bool, min_words: int,
                                interval_sec: int, idle_sec: int):
    if not enabled:
        js = f"""
        d.cookie = "{COOKIE_DRAFT}=; max-age=0; path=/";
        d.cookie = "{COOKIE_DRAFT_TS}=; max-age=0; path=/";
        """
        inject_js(js)
        return

    js = f"""
    const MIN_WORDS = {min_words};
    const INTERVAL_MS = {interval_sec * 1000};
    const IDLE_MS = {idle_sec * 1000};
    const DRAFT_COOKIE = "{COOKIE_DRAFT}";
    const TS_COOKIE = "{COOKIE_DRAFT_TS}";
    
    let lastSavedText = "";
    let lastIdleSavedText = "";
    let typingTimer = null;
    let periodicTimer = null;
    let currentTextarea = null;
    
    function countWords(s) {{
        if (!s) return 0;
        return s.trim().split(/\\s+/).filter(Boolean).length;
    }}
    
    function saveDraft(text, reason) {{
        try {{
            const encoded = encodeURIComponent(text);
            const trimmed = encoded.length > 3500 ? encoded.slice(0, 3500) : encoded;
            d.cookie = `${{DRAFT_COOKIE}}=${{trimmed}}; path=/; max-age=86400`;
            d.cookie = `${{TS_COOKIE}}=${{Date.now()}}; path=/; max-age=86400`;
            lastSavedText = text;
        }} catch (e) {{}}
    }}
    
    function attachToTextarea() {{
        const candidates = d.querySelectorAll(
            'textarea[data-testid="stChatInputTextArea"], ' +
            'section[data-testid="stChatInput"] textarea, ' +
            'div[data-testid="stChatInput"] textarea, ' +
            'textarea[aria-label*="chat" i], textarea[placeholder]'
        );
        let ta = null;
        for (const c of candidates) {{
            if (c.offsetParent !== null) {{ ta = c; break; }}
        }}
        if (!ta || ta === currentTextarea) return;
        
        currentTextarea = ta;
        const handler = function() {{
            const text = ta.value || "";
            const words = countWords(text);
            
            if (typingTimer) clearTimeout(typingTimer);
            if (periodicTimer) {{ clearInterval(periodicTimer); periodicTimer = null; }}
            
            if (words > MIN_WORDS) {{
                periodicTimer = setInterval(function() {{
                    const cur = ta.value || "";
                    if (cur && cur !== lastSavedText) {{
                       
