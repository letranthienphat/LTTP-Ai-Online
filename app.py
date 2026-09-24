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
APP_VERSION = "1.8.1"

ADMIN_USERNAME = "Admin"
ADMIN_PASSWORD = "7428"

SYSTEM_CONFIG_KEY = "__system_config__"
TRAFFIC_LOG_KEY = "__traffic_log__"
TRAFFIC_RETENTION_DAYS = 30

VN_TZ_OFFSET = timedelta(hours=7)
VERSION_SCAN_INTERVAL = 60

# Smart draft constants
SMART_DRAFT_MIN_WORDS = 20
SMART_DRAFT_INTERVAL_SEC = 5
SMART_DRAFT_IDLE_SEC = 20
COOKIE_DRAFT = "LTTP_chat_draft"
COOKIE_DRAFT_TS = "LTTP_draft_ts"
COOKIE_DRAFT_ENABLED = "LTTP_draft_enabled"

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

# ==========================================
# 4. JAVASCRIPT INJECTION
# ==========================================
def inject_js(js_code: str, height: int = 0):
    """Chèn JavaScript an toàn qua iframe của st.components.v1.html."""
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
    
    function clearDraft() {{
        try {{
            d.cookie = `${{DRAFT_COOKIE}}=; path=/; max-age=0`;
            d.cookie = `${{TS_COOKIE}}=; path=/; max-age=0`;
            lastSavedText = "";
            lastIdleSavedText = "";
        }} catch (e) {{}}
    }}
    
    function attachToTextarea() {{
        const candidates = d.querySelectorAll(
            'textarea[data-testid="stChatInputTextArea"], ' +
            'section[data-testid="stChatInput"] textarea, ' +
            'div[data-testid="stChatInput"] textarea, ' +
            'textarea[aria-label*="chat" i], ' +
            'textarea[placeholder]'
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
                        saveDraft(cur, "periodic");
                    }}
                }}, INTERVAL_MS);
            }}
            
            typingTimer = setTimeout(function() {{
                const cur = ta.value || "";
                if (cur && cur !== lastIdleSavedText) {{
                    saveDraft(cur, "idle");
                    lastIdleSavedText = cur;
                }}
            }}, IDLE_MS);
        }};
        
        ta.removeEventListener("input", ta._lttpHandler);
        ta._lttpHandler = handler;
        ta.addEventListener("input", handler);
    }}
    
    attachToTextarea();
    setInterval(attachToTextarea, 2000);
    """
    inject_js(js)


def clear_draft_cookie_via_js():
    js = f"""
    d.cookie = "{COOKIE_DRAFT}=; max-age=0; path=/";
    d.cookie = "{COOKIE_DRAFT_TS}=; max-age=0; path=/";
    """
    inject_js(js)

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
# 6. GỌI GEMINI VỚI FAILOVER
# ==========================================
def _build_model_chain(preferred_model: str) -> list:
    chain = [preferred_model]
    for m in FAILOVER_MODEL_CHAIN:
        if m not in chain:
            chain.append(m)
    return chain


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
        box.markdown(f"""
        <div class="rate-limit-box">
            <div class="rate-limit-text">{title}</div>
            <div style="margin-top:6px; font-size:0.9rem; opacity:0.85;">{subtitle}</div>
            <div style="margin-top:8px;"><span class="rate-limit-countdown">{remaining}s</span></div>
        </div>
        """, unsafe_allow_html=True)
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
            "whitelist_users": [],
            "maintenance_note": ""
        }
        migrated = True
    else:
        cfg = db_data[SYSTEM_CONFIG_KEY]
        if not isinstance(cfg, dict):
            db_data[SYSTEM_CONFIG_KEY] = {
                "maintenance_mode": False,
                "whitelist_users": [],
                "maintenance_note": ""
            }
            migrated = True
        else:
            for k, dv in [("maintenance_mode", False), ("whitelist_users", []),
                          ("maintenance_note", "")]:
                if k not in cfg:
                    cfg[k] = dv
                    migrated = True

    if TRAFFIC_LOG_KEY not in db_data:
        db_data[TRAFFIC_LOG_KEY] = {}
        migrated = True

    for username, uinfo in db_data.items():
        if username in (SYSTEM_CONFIG_KEY, TRAFFIC_LOG_KEY):
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
                "smart_draft": True
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
                          ("smart_draft", True)]:
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
# 9. GITHUB STORAGE
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
                        "whitelist_users": [],
                        "maintenance_note": ""
                    },
                    TRAFFIC_LOG_KEY: {}
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
# 10. HÀM AI PHỤ
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
# 11. i18n
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
        "temperature_help": (
            "**Creativity level** — how imaginative the A.I is.\n\n"
            "- **Low (0.0–0.3):** A.I answers safely, sticks to facts. Good for math, coding, factual questions.\n"
            "- **Medium (0.4–0.7):** Balanced — the default. Good for most everyday questions.\n"
            "- **High (0.8–1.0):** A.I is creative, surprising, more varied wording. Good for stories, brainstorming, marketing copy.\n\n"
            "👉 *Tip:* If the A.I keeps repeating itself, raise this value. If it invents facts, lower it."
        ),
        "top_p": "Diversity",
        "top_p_help": (
            "**Diversity** — how many different words the A.I may consider when writing.\n\n"
            "- **Low (0.5–0.7):** A.I picks only the most obvious words → predictable, safe answers.\n"
            "- **High (0.9–1.0):** A.I considers many word choices → richer, more surprising answers.\n\n"
            "👉 *Tip:* Keep at **0.95** unless you have a specific reason to change."
        ),
        "top_k": "Focus level",
        "top_k_help": (
            "**Focus level** — how many candidate words the A.I considers at each step.\n\n"
            "- **Low (10–20):** Very focused, tight answers. Good for short, direct replies.\n"
            "- **Medium (40):** Balanced — the default.\n"
            "- **High (80–100):** A.I considers many options → more varied but sometimes less coherent answers.\n\n"
            "👉 *Tip:* Keep at **40** for everyday use."
        ),
        "save_params": "💾 Save settings",
        "params_saved": "Settings saved!",
        "reset_params": "↺ Defaults",
        "reset_params_toast": "Reset to defaults!",
        # Gợi ý mức
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
        "ai_error": "❌ Could not generate AI response.",
        "device_id": "Device ID", "online": "Online", "language": "🌐 Language",
        "guest_btn": "👤 Continue as Guest",
        "guest_mode": "Guest Mode",
        "guest_banner": "You are using Guest Mode. Chats are not saved.",
        "maintenance_title": "🚧 System under maintenance",
        "maintenance_desc": "We are temporarily pausing the system. Please come back later.",
        "admin_panel": "🛡️ Admin Panel",
        "admin_logged_in": "Logged in as Administrator",
        "maintenance_toggle": "System Maintenance Mode",
        "maintenance_on": "🔴 Pause System",
        "maintenance_off": "🟢 Resume System",
        "maintenance_note_label": "Maintenance note (optional):",
        "maintenance_note_placeholder": "e.g. We are upgrading servers. Back in 30 minutes.",
        "save_maintenance_note": "💾 Save Maintenance Note",
        "maintenance_note_saved": "Maintenance note saved!",
        "whitelist_title": "Whitelist (allowed during maintenance)",
        "whitelist_desc": "One username per line.",
        "save_whitelist": "💾 Save Whitelist",
        "whitelist_saved": "Whitelist saved!",
        "sys_status": "System Status",
        "sys_running": "🟢 Running", "sys_paused": "🔴 Paused",
        "admin_logout": "🚪 Exit Admin Mode",
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
        "smart_draft_help": (
            "Automatically saves what you are typing so you never lose it:\n\n"
            "• **Periodic save:** If your draft exceeds 20 words, it will be auto-saved every 5 seconds.\n"
            "• **Idle save:** If you stop typing for 20 seconds, the current text will be saved once.\n\n"
            "Saved drafts are restored when you return to the app. Disable if you don't want this behavior."
        ),
        "smart_draft_on": "✅ Enabled",
        "smart_draft_off": "❌ Disabled",
        "smart_draft_saved_toast": "Draft saved",
        "draft_restored_title": "📝 Unsent draft found",
        "draft_restored_desc": "You have a saved draft from a previous session. Click to restore:",
        "draft_restore_btn": "📋 Copy to clipboard",
        "draft_discard_btn": "🗑️ Discard draft",
        "draft_discarded_toast": "Draft discarded",
        "draft_copied_toast": "Draft copied to clipboard!",
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
        "temperature_help": (
            "**Mức độ sáng tạo** — A.I trả lời bay bổng, tưởng tượng đến mức nào.\n\n"
            "- **Thấp (0.0–0.3):** A.I trả lời an toàn, bám sát sự thật. Phù hợp cho toán, lập trình, câu hỏi kiến thức.\n"
            "- **Trung bình (0.4–0.7):** Cân bằng — mức mặc định. Phù hợp cho hầu hết câu hỏi hằng ngày.\n"
            "- **Cao (0.8–1.0):** A.I sáng tạo, bất ngờ, dùng nhiều từ ngữ đa dạng. Phù hợp viết truyện, brainstorm, viết quảng cáo.\n\n"
            "👉 *Mẹo:* Nếu A.I cứ lặp đi lặp lại, hãy tăng giá trị này. Nếu A.I bịa đặt thông tin, hãy giảm xuống."
        ),
        "top_p": "Mức độ đa dạng",
        "top_p_help": (
            "**Mức độ đa dạng** — A.I cân nhắc bao nhiêu từ khác nhau khi viết.\n\n"
            "- **Thấp (0.5–0.7):** A.I chỉ chọn những từ rõ ràng nhất → câu trả lời dễ đoán, an toàn.\n"
            "- **Cao (0.9–1.0):** A.I cân nhắc nhiều lựa chọn từ ngữ → câu trả lời phong phú, bất ngờ hơn.\n\n"
            "👉 *Mẹo:* Giữ ở **0.95** trừ khi bạn có lý do cụ thể để đổi."
        ),
        "top_k": "Mức độ tập trung",
        "top_k_help": (
            "**Mức độ tập trung** — A.I xem xét bao nhiêu từ tiềm năng ở mỗi bước.\n\n"
            "- **Thấp (10–20):** Rất tập trung, câu trả lời gọn gàng. Phù hợp cho câu trả lời ngắn, trực tiếp.\n"
            "- **Trung bình (40):** Cân bằng — mức mặc định.\n"
            "- **Cao (80–100):** A.I xem xét nhiều lựa chọn → đa dạng hơn nhưng đôi khi kém mạch lạc.\n\n"
            "👉 *Mẹo:* Giữ ở **40** cho sử dụng hằng ngày."
        ),
        "save_params": "💾 Lưu cài đặt",
        "params_saved": "Đã lưu cài đặt!",
        "reset_params": "↺ Mặc định",
        "reset_params_toast": "Đã khôi phục mặc định!",
        # Gợi ý mức
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
        "ai_error": "❌ Không thể tạo phản hồi từ AI.",
        "device_id": "Device ID", "online": "Online", "language": "🌐 Ngôn ngữ",
        "guest_btn": "👤 Tiếp tục với tư cách Khách",
        "guest_mode": "Chế độ Khách",
        "guest_banner": "Bạn đang dùng chế độ Khách. Cuộc trò chuyện không được lưu.",
        "maintenance_title": "🚧 Hệ thống đang bảo trì",
        "maintenance_desc": "Chúng tôi tạm thời ngừng hệ thống. Vui lòng quay lại sau.",
        "admin_panel": "🛡️ Bảng điều khiển Admin",
        "admin_logged_in": "Đã đăng nhập với quyền Quản trị viên",
        "maintenance_toggle": "Chế độ Bảo trì Hệ thống",
        "maintenance_on": "🔴 Tạm ngừng hệ thống",
        "maintenance_off": "🟢 Mở lại hệ thống",
        "maintenance_note_label": "Lời chú thích bảo trì (có thể để trống):",
        "maintenance_note_placeholder": "Ví dụ: Chúng tôi đang nâng cấp máy chủ. Quay lại sau 30 phút.",
        "save_maintenance_note": "💾 Lưu lời chú thích",
        "maintenance_note_saved": "Đã lưu lời chú thích!",
        "whitelist_title": "Danh sách được phép (truy cập khi bảo trì)",
        "whitelist_desc": "Mỗi dòng 1 tên người dùng.",
        "save_whitelist": "💾 Lưu danh sách",
        "whitelist_saved": "Đã lưu danh sách!",
        "sys_status": "Trạng thái hệ thống",
        "sys_running": "🟢 Đang chạy", "sys_paused": "🔴 Đang tạm ngừng",
        "admin_logout": "🚪 Thoát chế độ Admin",
        "traffic_title": "📊 Lưu lượng truy cập",
        "traffic_desc": "Nhật ký truy cập (giờ Việt Nam, GMT+7)",
        "traffic_today": "Hôm nay", "traffic_7d": "7 ngày qua",
        "traffic_30d": "30 ngày qua",
        "traffic_unique": "Người truy cập riêng biệt",
        "traffic_by_role": "Theo vai trò",
        "traffic_chart_title": "Lượt truy cập mỗi ngày (14 ngày qua)",
        "traffic_recent": "Truy cập gần đây",
        "traffic_no_data": "Chưa có dữ liệu truy cập.",
        "traffic_role_user": "Người dùng", "traffic_role_guest": "Khách",
        "traffic_role_admin": "Admin",
        "traffic_current_time": "Giờ VN hiện tại",
        "settings_title": "⚙️ Cài đặt",
        "smart_draft_label": "Lưu tin nhắn thông minh",
        "smart_draft_help": (
            "Tự động lưu những gì bạn đang nhập để không bao giờ mất:\n\n"
            "• **Lưu định kỳ:** Nếu bạn nhập trên 20 từ, tin nhắn sẽ được tự động lưu mỗi 5 giây.\n"
            "• **Lưu khi ngừng nhập:** Nếu bạn không nhập gì trong 20 giây, nội dung hiện tại sẽ được lưu một lần.\n\n"
            "Tin nhắn nháp sẽ được khôi phục khi bạn quay lại. Tắt nếu bạn không muốn dùng."
        ),
        "smart_draft_on": "✅ Đang bật",
        "smart_draft_off": "❌ Đang tắt",
        "smart_draft_saved_toast": "Đã lưu nháp",
        "draft_restored_title": "📝 Có tin nhắn nháp chưa gửi",
        "draft_restored_desc": "Bạn có tin nhắn nháp từ phiên trước. Bấm để khôi phục:",
        "draft_restore_btn": "📋 Sao chép vào clipboard",
        "draft_discard_btn": "🗑️ Xóa nháp",
        "draft_discarded_toast": "Đã xóa nháp",
        "draft_copied_toast": "Đã sao chép vào clipboard!",
    }
}

def t(key: str, lang: str = "en") -> str:
    return TRANSLATIONS.get(lang, TRANSLATIONS["en"]).get(key, key)

# ==========================================
# 12. SESSION STATE
# ==========================================
for k, dv in [("user", None), ("is_admin", False), ("is_guest", False),
              ("current_chat_id", None), ("messages", []), ("db_data", {}),
              ("last_save_time", 0), ("language", "en"),
              ("pending_retry_prompt", None), ("seen_version", None),
              ("guest_chats", {}), ("guest_memory", ""),
              ("traffic_recorded", False),
              ("version_mismatch", False),
              ("reboot_banner_dismissed", False),
              ("draft_last_saved_hash", "")]:
    if k not in st.session_state:
        st.session_state[k] = dv

if "guest_prefs" not in st.session_state:
    st.session_state.guest_prefs = {
        "model": DEFAULT_MODEL, "temperature": 0.7,
        "top_p": 0.95, "top_k": 40,
        "smart_draft": True
    }

# ==========================================
# 13. VERSION CHECK
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

_seen_ver = cookies.get("LTTP_seen_version")
if _seen_ver:
    st.session_state.seen_version = _seen_ver

db_data = GitHubStorage.load_db()
st.session_state.db_data = db_data

system_config = db_data.get(SYSTEM_CONFIG_KEY, {
    "maintenance_mode": False, "whitelist_users": [], "maintenance_note": ""
})
maintenance_mode = system_config.get("maintenance_mode", False)
maintenance_note = system_config.get("maintenance_note", "").strip()
whitelist_users = [u.strip().lower() for u in system_config.get("whitelist_users", []) if u.strip()]

# ==========================================
# 14. AUTO-LOGIN
# ==========================================
if (not st.session_state.user
        and not st.session_state.is_admin
        and not st.session_state.is_guest
        and device_id and db_data):
    for username, uinfo in db_data.items():
        if username in (SYSTEM_CONFIG_KEY, TRAFFIC_LOG_KEY):
            continue
        if not isinstance(uinfo, dict):
            continue
        if device_id in uinfo.get("remembered_devices", []):
            st.session_state.user = username
            st.session_state.language = uinfo.get("language", "en")
            st.toast(f"{t('auto_login', st.session_state.language)} {username}", icon="⚡")
            break

# ==========================================
# 15. RECORD TRAFFIC
# ==========================================
def _try_record_traffic_once():
    if st.session_state.traffic_recorded:
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
# 16. UPDATE NOTICE
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
# 17. REBOOT BANNER
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
# 18. AUTH UI
# ==========================================
def render_auth_ui():
    lang = st.session_state.language
    _show_update_notice_if_needed()
    render_reboot_banner_if_needed()

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
                        st.session_state.current_chat_id = None
                        st.session_state.messages = []
                        st.session_state.traffic_recorded = False
                        st.toast("🛡️ Admin mode activated", icon="🛡️")
                        st.rerun()
                    else:
                        u_name_lower = u_name.lower()
                        db = GitHubStorage.load_db(force_refresh=True)
                        if (u_name_lower in db
                                and u_name_lower not in (SYSTEM_CONFIG_KEY, TRAFFIC_LOG_KEY)
                                and isinstance(db[u_name_lower], dict)
                                and db[u_name_lower].get("password") == hash_password(u_pass)):
                            st.session_state.user = u_name_lower
                            st.session_state.is_admin = False
                            st.session_state.is_guest = False
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
                    elif reg_u in (ADMIN_USERNAME.lower(), SYSTEM_CONFIG_KEY.lower(), TRAFFIC_LOG_KEY.lower()):
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
                                    "smart_draft": True
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
            st.session_state.current_chat_id = None
            st.session_state.messages = []
            st.session_state.guest_chats = {}
            st.session_state.guest_prefs = {
                "model": DEFAULT_MODEL, "temperature": 0.7,
                "top_p": 0.95, "top_k": 40,
                "smart_draft": True
            }
            st.session_state.guest_memory = ""
            st.session_state.traffic_recorded = False
            st.rerun()

# ==========================================
# 19. TRAFFIC ANALYTICS
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
# 20. ADMIN PANEL
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
        "maintenance_mode": False, "whitelist_users": [], "maintenance_note": ""
    })
    cur_maint = cfg.get("maintenance_mode", False)
    cur_wl = cfg.get("whitelist_users", [])
    cur_note = cfg.get("maintenance_note", "")

    status_text = t("sys_paused", lang) if cur_maint else t("sys_running", lang)
    st.markdown(f"**{t('sys_status', lang)}:** {status_text}")

    st.markdown('<div class="admin-panel">', unsafe_allow_html=True)
    st.subheader(t("maintenance_toggle", lang))
    col_a, col_b = st.columns(2)
    with col_a:
        if st.button(t("maintenance_on", lang), use_container_width=True, disabled=cur_maint):
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
        if st.button(t("maintenance_off", lang), use_container_width=True, disabled=not cur_maint):
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
    if st.button(t("save_maintenance_note", lang), use_container_width=True):
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

    st.markdown('<div class="admin-panel">', unsafe_allow_html=True)
    st.subheader(t("whitelist_title", lang))
    st.caption(t("whitelist_desc", lang))
    wl_text = st.text_area("Whitelist:", value="\n".join(cur_wl), height=180,
                           placeholder="user1\nuser2\nuser3", key="admin_wl_textarea")
    if st.button(t("save_whitelist", lang), use_container_width=True, type="primary"):
        new_wl = [line.strip().lower() for line in wl_text.splitlines() if line.strip()]
        seen = set()
        new_wl_unique = []
        for u in new_wl:
            if u not in seen:
                seen.add(u)
                new_wl_unique.append(u)
        cfg["whitelist_users"] = new_wl_unique
        db[SYSTEM_CONFIG_KEY] = cfg
        ok, msg = GitHubStorage.save_db(db)
        if ok:
            st.toast(t("whitelist_saved", lang), icon="💾")
            time.sleep(0.3)
            st.rerun()
        else:
            st.error(f"Error: {msg}")
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="admin-panel">', unsafe_allow_html=True)
    _render_traffic_analytics(lang, db.get(TRAFFIC_LOG_KEY, {}))
    st.markdown('</div>', unsafe_allow_html=True)

    with st.expander("📋 Existing users", expanded=False):
        user_list = [u for u in db.keys()
                     if u not in (SYSTEM_CONFIG_KEY, TRAFFIC_LOG_KEY)
                     and isinstance(db[u], dict)]
        if user_list:
            for u in sorted(user_list):
                st.markdown(f"- `{u}`")
        else:
            st.caption("No users yet.")

    st.divider()
    if st.button(t("admin_logout", lang), use_container_width=True):
        st.session_state.is_admin = False
        st.session_state.user = None
        st.session_state.is_guest = False
        st.session_state.traffic_recorded = False
        st.rerun()

# ==========================================
# 21. MAINTENANCE SCREEN
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
    with st.expander("🛡️ Admin login", expanded=False):
        with st.form("admin_login_during_maint"):
            a_user = st.text_input("Username:", key="maint_admin_u")
            a_pass = st.text_input("Password:", type="password", key="maint_admin_p")
            if st.form_submit_button("Login as Admin"):
                if a_user == ADMIN_USERNAME and a_pass == ADMIN_PASSWORD:
                    st.session_state.is_admin = True
                    st.session_state.user = None
                    st.session_state.is_guest = False
                    st.session_state.traffic_recorded = False
                    st.rerun()
                else:
                    st.error("❌ Invalid admin credentials.")

# ==========================================
# 22. ROUTING
# ==========================================
if st.session_state.is_admin:
    render_admin_panel()
    st.stop()

if maintenance_mode:
    current_user = st.session_state.user
    if not (current_user and current_user.lower() in whitelist_users):
        render_maintenance_screen()
        st.stop()

if not st.session_state.user and not st.session_state.is_guest:
    render_auth_ui()
    st.stop()

# ==========================================
# 23. LOAD USER / GUEST DATA
# ==========================================
is_guest = st.session_state.is_guest
lang = st.session_state.language

if is_guest:
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
    st.session_state.language = user_data.get("language", "en")
    lang = st.session_state.language
    user_chats = user_data["chats"]

if st.session_state.current_chat_id and st.session_state.current_chat_id not in user_chats:
    st.session_state.current_chat_id = None
    st.session_state.messages = []

# ==========================================
# 24. SIDEBAR
# ==========================================
with st.sidebar:
    if not is_guest:
        lc = st.selectbox(t("language", lang), ["en", "vi"],
                          index=0 if lang == "en" else 1,
                          format_func=lambda x: "🇬🇧 English" if x == "en" else "🇻🇳 Tiếng Việt",
                          key="sidebar_lang")
        if lc != lang:
            user_data["language"] = lc
            db_data[st.session_state.user] = user_data
            GitHubStorage.save_db(db_data)
            st.session_state.language = lc
            st.rerun()
    else:
        lc = st.selectbox(t("language", lang), ["en", "vi"],
                          index=0 if lang == "en" else 1,
                          format_func=lambda x: "🇬🇧 English" if x == "en" else "🇻🇳 Tiếng Việt",
                          key="sidebar_lang_guest")
        if lc != lang:
            st.session_state.language = lc
            st.rerun()

    if is_guest:
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

    if st.button(t("logout_btn", lang), use_container_width=True):
        if not is_guest:
            db = GitHubStorage.load_db(force_refresh=True)
            u = db.get(st.session_state.user, {})
            if device_id in u.get("remembered_devices", []):
                u["remembered_devices"].remove(device_id)
                db[st.session_state.user] = u
                GitHubStorage.save_db(db)
        st.session_state.user = None
        st.session_state.is_guest = False
        st.session_state.current_chat_id = None
        st.session_state.messages = []
        st.session_state.traffic_recorded = False
        st.rerun()

    st.divider()
    if st.button(t("new_chat_btn", lang), type="primary", use_container_width=True):
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
                    if is_guest:
                        st.session_state.guest_chats = user_chats
                    else:
                        user_data["chats"] = user_chats
                        db_data[st.session_state.user] = user_data
                        GitHubStorage.save_db(db_data)
                    if st.session_state.current_chat_id == cid:
                        st.session_state.current_chat_id = None
                        st.session_state.messages = []
                    st.toast(t("chat_deleted", lang), icon="🗑️")
                    time.sleep(0.3)
                    st.rerun()

    st.divider()

    # ============================
    # SETTINGS EXPANDER
    # ============================
    with st.expander(t("settings_title", lang), expanded=False):
        # === SMART DRAFT ===
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
            if is_guest:
                st.session_state.guest_prefs["smart_draft"] = smart_draft_val
            else:
                db_data[st.session_state.user] = user_data
                GitHubStorage.save_db(db_data)
            st.toast(
                t("smart_draft_on", lang) if smart_draft_val else t("smart_draft_off", lang),
                icon="💾"
            )

        status_txt = t("smart_draft_on", lang) if smart_draft_val else t("smart_draft_off", lang)
        st.caption(f"→ {status_txt}")

        if not smart_draft_val:
            clear_draft_cookie_via_js()

    st.divider()

    with st.expander(t("memory_title", lang), expanded=False):
        st.caption(t("memory_desc", lang))
        mem = st.text_area("Memory:", value=user_data.get("custom_instructions", ""),
                           height=120, placeholder=t("memory_placeholder", lang),
                           key="sidebar_memory_ta")
        if st.button(t("save_memory_btn", lang), use_container_width=True, key="sidebar_save_mem"):
            if is_guest:
                st.session_state.guest_memory = mem.strip()
                user_data["custom_instructions"] = mem.strip()
            else:
                user_data["custom_instructions"] = mem.strip()
                db_data[st.session_state.user] = user_data
                GitHubStorage.save_db(db_data)
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
        if not is_guest:
            db_data[st.session_state.user] = user_data

    try:
        midx = available_models.index(saved_model)
    except ValueError:
        midx = 0

    sel_model = st.selectbox(t("model_select", lang), available_models, index=midx, key="sidebar_model_sel")
    if sel_model != user_data["preferences"].get("model"):
        user_data["preferences"]["model"] = sel_model
        if is_guest:
            st.session_state.guest_prefs["model"] = sel_model
        else:
            db_data[st.session_state.user] = user_data
            GitHubStorage.save_db(db_data)

    # ============================
    # GENERATION SETTINGS - NGÔN NGỮ PHỔ THÔNG
    # ============================
    with st.expander(t("gen_config", lang), expanded=False):
        # === Mức độ sáng tạo ===
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

        # === Mức độ đa dạng ===
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

        # === Mức độ tập trung ===
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

        # === Nút lưu + khôi phục mặc định ===
        bcol1, bcol2 = st.columns(2)
        with bcol1:
            if st.button(t("save_params", lang), use_container_width=True, key="sidebar_save_params", type="primary"):
                user_data["preferences"]["temperature"] = temperature
                user_data["preferences"]["top_p"] = top_p
                user_data["preferences"]["top_k"] = top_k
                if is_guest:
                    st.session_state.guest_prefs = user_data["preferences"]
                else:
                    db_data[st.session_state.user] = user_data
                    GitHubStorage.save_db(db_data)
                st.toast(t("params_saved", lang), icon="💾")
                time.sleep(0.3)
                st.rerun()
        with bcol2:
            if st.button(t("reset_params", lang), use_container_width=True, key="sidebar_reset_params"):
                user_data["preferences"]["temperature"] = 0.7
                user_data["preferences"]["top_p"] = 0.95
                user_data["preferences"]["top_k"] = 40
                if is_guest:
                    st.session_state.guest_prefs = user_data["preferences"]
                else:
                    db_data[st.session_state.user] = user_data
                    GitHubStorage.save_db(db_data)
                st.toast(t("reset_params_toast", lang), icon="↺")
                time.sleep(0.3)
                st.rerun()

# ==========================================
# 25. SMART DRAFT: INJECT TRACKER
# ==========================================
smart_draft_enabled = bool(user_data["preferences"].get("smart_draft", True))
inject_smart_draft_tracker(
    enabled=smart_draft_enabled,
    min_words=SMART_DRAFT_MIN_WORDS,
    interval_sec=SMART_DRAFT_INTERVAL_SEC,
    idle_sec=SMART_DRAFT_IDLE_SEC
)


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

draft_text, draft_ts = get_saved_draft()

# ==========================================
# 26. MAIN CHAT
# ==========================================
_show_update_notice_if_needed()
render_reboot_banner_if_needed()

st.markdown(f"<h1 class='main-header'>{t('app_title', lang)}</h1>", unsafe_allow_html=True)

if not SECRET_API_KEYS:
    st.warning(t("no_api_key", lang))
    st.stop()

if is_guest:
    st.markdown(f'<div class="guest-banner">👤 {t("guest_banner", lang)}</div>', unsafe_allow_html=True)

current_title = t("new_chat", lang)
if st.session_state.current_chat_id and st.session_state.current_chat_id in user_chats:
    current_title = user_chats[st.session_state.current_chat_id].get("title", "Chat")

st.caption(f"📌 {t('current_chat', lang)}: **{current_title}** | {t('model_label', lang)}: `{sel_model}`")

# === DRAFT RESTORE BANNER ===
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
            inject_js(f"""
            (function() {{
                const txt = {safe_text};
                if (navigator.clipboard && navigator.clipboard.writeText) {{
                    navigator.clipboard.writeText(txt).catch(function(){{}});
                }} else {{
                    const ta = d.createElement('textarea');
                    ta.value = txt;
                    d.body.appendChild(ta);
                    ta.select();
                    try {{ d.execCommand('copy'); }} catch(e){{}}
                    d.body.removeChild(ta);
                }}
            }})();
            """)
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
# 27. XỬ LÝ PROMPT
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
        if is_guest:
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

    response_text = None
    err_type = None

    with st.chat_message("assistant"):
        ph = st.empty()
        ph.markdown(f"""
        <div class="ai-loading-box">
            <div class="spinner"></div>
            <div class="ai-loading-text">{t('ai_thinking', lang)}</div>
        </div>
        """, unsafe_allow_html=True)

        response_text, err_type = call_gemini_with_failover(
            prompt_inputs=content_inputs, api_keys=SECRET_API_KEYS,
            preferred_model=sel_model,
            system_instruction=system_instruction if system_instruction else None,
            generation_config={
                "temperature": temperature, "top_p": top_p, "top_k": top_k
            }, lang=lang
        )
        ph.empty()

        if response_text:
            st.markdown(response_text)
            st.markdown(f'<div class="ai-disclaimer">✍️ {DISCLAIMER.get(lang, DISCLAIMER["en"])}</div>', unsafe_allow_html=True)
            st.session_state.messages.append({"role": "assistant", "content": response_text})
        elif err_type == "rate_limit":
            st.session_state.pending_retry_prompt = user_prompt
            if (st.session_state.messages and
                    st.session_state.messages[-1]["role"] == "user" and
                    st.session_state.messages[-1]["content"] == user_prompt):
                st.session_state.messages.pop()
            render_rate_limit_and_retry(lang)
        else:
            error_msg = f"{t('ai_error', lang)} Error: {str(err_type)[:150] if err_type else 'Unknown'}"
            st.error(error_msg)
            st.session_state.messages.append({"role": "assistant", "content": error_msg})

    if response_text:
        if len(chat_data.get("messages", [])) == 0:
            try:
                chat_data["title"] = generate_chat_title(user_prompt, SECRET_API_KEYS, sel_model, lang)
            except Exception:
                chat_data["title"] = user_prompt[:30] + "..." if len(user_prompt) > 30 else user_prompt

        chat_data["messages"] = st.session_state.messages
        chat_data["updated_at"] = datetime.now().isoformat()
        user_chats[st.session_state.current_chat_id] = chat_data

        if is_guest:
            st.session_state.guest_chats = user_chats
        else:
            user_data["chats"] = user_chats
            db_data[st.session_state.user] = user_data
            if time.time() - st.session_state.last_save_time > 1:
                GitHubStorage.save_db(db_data)
                st.session_state.last_save_time = time.time()

        st.rerun()


if st.session_state.pending_retry_prompt:
    pending = st.session_state.pending_retry_prompt
    st.session_state.pending_retry_prompt = None
    _process_prompt(pending)
elif user_prompt := st.chat_input(t("chat_placeholder", lang)):
    _process_prompt(user_prompt)
