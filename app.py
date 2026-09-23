import os
import json
import time
import uuid
import base64
import hashlib
import requests
import streamlit as st
import google.generativeai as genai
from datetime import datetime
from cryptography.fernet import Fernet
from streamlit_cookies_controller import CookieController

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
    "gemini-3.5-flash",
    "gemini-3.6-flash",
    "gemini-3.7-flash",
    "gemini-3.8-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-2.5-flash",
]

FALLBACK_MODELS = [
    "gemini-3.8-flash",
    "gemini-3.7-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-3.1-pro-preview",
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
]

LEGACY_MODEL_MAP = {
    "gemini-2.5-flash": "gemini-3.5-flash",
    "gemini-2.5-pro": "gemini-3.5-flash",
    "gemini-2.0-flash": "gemini-3.5-flash",
    "gemini-1.5-flash": "gemini-3.5-flash",
    "gemini-1.5-pro": "gemini-3.5-flash",
    "gemini-1.0-pro": "gemini-3.5-flash",
    "gemini-pro": "gemini-3.5-flash",
}

RATE_LIMIT_RETRY_DELAY = 60

# Câu chú thích ở cuối mỗi phản hồi AI
DISCLAIMER = {
    "vi": "_Lưu ý kiểm tra thông tin của A.I trước khi xác nhận thông tin._",
    "en": "_Please verify A.I information before confirming any facts._",
}

# ==========================================
# 2. CUSTOM CSS
# ==========================================
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        font-size: 2.5rem;
        margin-bottom: 0.2rem;
    }
    
    .ai-loading-box {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 18px;
        background: rgba(102, 126, 234, 0.08);
        border: 1px solid rgba(102, 126, 234, 0.2);
        border-radius: 12px;
        margin-bottom: 15px;
        animation: fadeIn 0.3s ease-in-out;
    }

    .spinner {
        width: 22px;
        height: 22px;
        border: 3px solid rgba(102, 126, 234, 0.2);
        border-top: 3px solid #667eea;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
    }

    .ai-loading-text {
        color: #667eea;
        font-weight: 600;
        font-size: 0.95rem;
        letter-spacing: 0.3px;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 50%, #667eea 100%);
        background-size: 200% auto;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: shine 2s linear infinite;
    }

    .pulse-dot {
        width: 8px;
        height: 8px;
        background-color: #10b981;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
        animation: pulse 1.6s infinite;
        margin-right: 6px;
    }

    .rate-limit-box {
        padding: 14px 18px;
        background: rgba(251, 191, 36, 0.1);
        border: 1px solid rgba(251, 191, 36, 0.35);
        border-radius: 12px;
        margin-bottom: 15px;
        animation: fadeIn 0.3s ease-in-out;
    }
    .rate-limit-text {
        color: #fbbf24;
        font-weight: 600;
        font-size: 0.95rem;
    }
    .rate-limit-countdown {
        color: #f59e0b;
        font-weight: 800;
        font-size: 1.1rem;
    }

    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    @keyframes shine { to { background-position: 200% center; } }
    @keyframes pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

    .user-card {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 10px 14px;
        border-radius: 10px;
        margin-bottom: 12px;
    }
    
    .stButton button { width: 100%; }
    
    .status-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-left: 6px;
    }
    .badge-ready { background: rgba(16, 185, 129, 0.15); color: #10b981; }
    .badge-missing { background: rgba(239, 68, 68, 0.15); color: #ef4444; }

    /* Chú thích cuối phản hồi AI - chữ nhỏ, in nghiêng */
    .ai-disclaimer {
        font-size: 0.78rem;
        font-style: italic;
        color: rgba(148, 163, 184, 0.85);
        margin-top: 6px;
        padding-top: 6px;
        border-top: 1px dashed rgba(148, 163, 184, 0.25);
        letter-spacing: 0.1px;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 3. HÀM MÃ HÓA & MẬT KHẨU
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

# ==========================================
# 4. PHÁT HIỆN LỖI 429 / RATE LIMIT
# ==========================================
def is_rate_limit_error(error: Exception) -> bool:
    err_str = str(error).lower()
    keywords = [
        "429", "quota", "rate limit", "rate_limit",
        "resource_exhausted", "too many requests",
        "exceeded", "resource exhausted",
    ]
    return any(k in err_str for k in keywords)

# ==========================================
# 5. HÀM GỌI GEMINI VỚI FAILOVER TỰ ĐỘNG
# ==========================================
def _build_model_chain(preferred_model: str) -> list:
    chain = [preferred_model]
    for m in FAILOVER_MODEL_CHAIN:
        if m not in chain:
            chain.append(m)
    return chain


def call_gemini_with_failover(
    prompt_inputs: list,
    api_keys: list,
    preferred_model: str,
    system_instruction: str = None,
    generation_config: dict = None,
    lang: str = "en",
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

    if saw_rate_limit:
        return None, "rate_limit"
    return None, last_error or "unknown_error"


def render_rate_limit_and_retry(lang: str = "en"):
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
            <div style="margin-top:8px;">
                <span class="rate-limit-countdown">{remaining}s</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        time.sleep(1)

    box.empty()
    st.rerun()

# ==========================================
# 6. MIGRATION DỮ LIỆU CŨ
# ==========================================
def migrate_user_data(db_data: dict) -> tuple:
    migrated = False
    
    for username, uinfo in db_data.items():
        if not isinstance(uinfo, dict):
            continue
        
        if "custom_instructions" not in uinfo:
            uinfo["custom_instructions"] = ""
            migrated = True
        if "chats" not in uinfo:
            uinfo["chats"] = {}
            migrated = True
        if "remembered_devices" not in uinfo:
            uinfo["remembered_devices"] = []
            migrated = True
        if "language" not in uinfo:
            uinfo["language"] = "en"
            migrated = True
        
        if "preferences" not in uinfo:
            uinfo["preferences"] = {
                "model": DEFAULT_MODEL,
                "temperature": 0.7,
                "top_p": 0.95,
                "top_k": 40
            }
            migrated = True
        else:
            prefs = uinfo["preferences"]
            if not isinstance(prefs, dict):
                prefs = {}
                uinfo["preferences"] = prefs
                migrated = True
            if "model" not in prefs:
                prefs["model"] = DEFAULT_MODEL
                migrated = True
            if "temperature" not in prefs:
                prefs["temperature"] = 0.7
                migrated = True
            if "top_p" not in prefs:
                prefs["top_p"] = 0.95
                migrated = True
            if "top_k" not in prefs:
                prefs["top_k"] = 40
                migrated = True
            
            old_model = prefs.get("model", "")
            if old_model in LEGACY_MODEL_MAP:
                prefs["model"] = LEGACY_MODEL_MAP[old_model]
                migrated = True
        
        for cid, chat in uinfo.get("chats", {}).items():
            if not isinstance(chat, dict):
                continue
            if "title" not in chat:
                chat["title"] = "Conversation"
                migrated = True
            if "messages" not in chat:
                chat["messages"] = []
                migrated = True
            if "summary" not in chat:
                chat["summary"] = ""
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
# 7. GITHUB STORAGE
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
                url, 
                headers=GitHubStorage.get_api_headers(), 
                params={"nocache": int(time.time())}, 
                timeout=8
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
                GitHubStorage._cache = {}
                GitHubStorage._cache_time = time.time()
                return {}
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
            "message": f"Update users_db.json - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
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
# 8. HÀM AI PHỤ (ĐẶT TÊN & TÓM TẮT)
# ==========================================
def generate_chat_title(user_prompt: str, api_keys: list, model_name: str, lang: str = "en") -> str:
    try:
        if lang == "vi":
            prompt = (
                "Hãy tạo 1 tiêu đề cực kỳ ngắn gọn (từ 2 đến 5 từ, không đặt trong dấu ngoặc kép, không dùng markdown) "
                f"tóm tắt chủ đề của câu hỏi sau:\n\"{user_prompt}\""
            )
        else:
            prompt = (
                "Generate an extremely short title (2-5 words, no quotes, no markdown) "
                f"summarizing the topic of this question:\n\"{user_prompt}\""
            )
        text, err = call_gemini_with_failover(
            prompt_inputs=[prompt],
            api_keys=api_keys,
            preferred_model=model_name,
            lang=lang
        )
        if text:
            title = text.strip().replace('"', '').replace("'", "")
            return title[:35] if title else user_prompt[:25]
        return user_prompt[:25] + "..." if len(user_prompt) > 25 else user_prompt
    except Exception:
        return user_prompt[:25] + "..." if len(user_prompt) > 25 else user_prompt


def generate_summary(older_messages: list, existing_summary: str, api_keys: list, model_name: str, lang: str = "en") -> str:
    try:
        text_to_summarize = ""
        if existing_summary:
            prefix = "Bối cảnh tóm tắt trước đó" if lang == "vi" else "Previous summary context"
            text_to_summarize += f"{prefix}:\n{existing_summary}\n\n"
        
        limited_messages = older_messages[-15:] if len(older_messages) > 15 else older_messages
        
        for m in limited_messages:
            if lang == "vi":
                role_label = "Người dùng" if m["role"] == "user" else "AI"
            else:
                role_label = "User" if m["role"] == "user" else "AI"
            content = m['content'][:500] + "..." if len(m['content']) > 500 else m['content']
            text_to_summarize += f"- {role_label}: {content}\n"
        
        if lang == "vi":
            prompt = (
                "Hãy tóm tắt ngắn gọn và đúc kết các ý chính, thông tin quan trọng của đoạn hội thoại sau "
                "thành 1 đoạn văn (dưới 150 từ) để làm bối cảnh cho các câu hỏi tiếp theo:\n\n"
                f"{text_to_summarize}"
            )
        else:
            prompt = (
                "Briefly summarize the key points and important information from the following conversation "
                "into one paragraph (under 150 words) to serve as context for follow-up questions:\n\n"
                f"{text_to_summarize}"
            )
        
        text, err = call_gemini_with_failover(
            prompt_inputs=[prompt],
            api_keys=api_keys,
            preferred_model=model_name,
            lang=lang
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
# 9. i18n
# ==========================================
TRANSLATIONS = {
    "en": {
        "app_title": "⚡ LTTP AI Online",
        "app_subtitle": "Multi-purpose AI System with GitHub Sync",
        "login_tab": "🔑 Login",
        "register_tab": "📝 Register",
        "username": "Username:",
        "password": "Password:",
        "confirm_password": "Confirm password:",
        "remember_device": "📌 Remember this device (30 days)",
        "login_btn": "Login",
        "register_btn": "Create account",
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
        "memory_placeholder": "Example: You are a professional Python programming assistant. Always respond in English.",
        "save_memory_btn": "💾 Save Memory",
        "memory_saved": "Memory saved!",
        "api_title": "🔑 API Keys & Model",
        "api_from_secrets": "API Keys are loaded from Streamlit Secrets",
        "api_status_ready": "Ready",
        "api_status_missing": "Missing",
        "model_select": "Select AI model:",
        "gen_config": "⚙️ Generation Parameters",
        "temperature": "Temperature (creativity):",
        "top_p": "Top P:",
        "top_k": "Top K:",
        "save_params": "💾 Save Parameters",
        "params_saved": "Parameters saved!",
        "chat_placeholder": "Ask LTTP AI anything...",
        "current_chat": "Currently in",
        "model_label": "Model",
        "new_chat": "New Conversation",
        "no_api_key": "⚠️ No Gemini API Keys found in Secrets! Please add GEMINI_API_KEY_1 and GEMINI_API_KEY_2 to Streamlit Secrets.",
        "ai_thinking": "LTTP AI is thinking and composing a response...",
        "ai_error": "❌ Could not generate AI response.",
        "device_id": "Device ID",
        "online": "Online",
        "language": "🌐 Language",
    },
    "vi": {
        "app_title": "⚡ LTTP AI Online",
        "app_subtitle": "Hệ thống Trí tuệ Nhân tạo Đa Năng Đồng bộ GitHub",
        "login_tab": "🔑 Đăng nhập",
        "register_tab": "📝 Đăng ký",
        "username": "Tên đăng nhập:",
        "password": "Mật khẩu:",
        "confirm_password": "Xác nhận mật khẩu:",
        "remember_device": "📌 Ghi nhớ thiết bị này (30 ngày)",
        "login_btn": "Đăng nhập",
        "register_btn": "Tạo tài khoản mới",
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
        "memory_placeholder": "Ví dụ: Bạn là trợ lý lập trình Python chuyên nghiệp. Luôn trả lời bằng Tiếng Việt.",
        "save_memory_btn": "💾 Lưu ghi nhớ cố định",
        "memory_saved": "Đã ghi nhớ thông tin!",
        "api_title": "🔑 API Keys & Model",
        "api_from_secrets": "API Keys được nạp từ Streamlit Secrets",
        "api_status_ready": "Sẵn sàng",
        "api_status_missing": "Thiếu",
        "model_select": "Chọn mô hình AI:",
        "gen_config": "⚙️ Cấu hình tham số sinh",
        "temperature": "Temperature (Độ sáng tạo):",
        "top_p": "Top P:",
        "top_k": "Top K:",
        "save_params": "💾 Lưu tham số",
        "params_saved": "Đã lưu tham số!",
        "chat_placeholder": "Hỏi LTTP AI bất cứ điều gì...",
        "current_chat": "Đang trò chuyện trong",
        "model_label": "Mô hình",
        "new_chat": "Cuộc trò chuyện mới",
        "no_api_key": "⚠️ Không tìm thấy Gemini API Key trong Secrets! Vui lòng thêm GEMINI_API_KEY_1 và GEMINI_API_KEY_2 vào Streamlit Secrets.",
        "ai_thinking": "LTTP AI đang suy nghĩ và tổng hợp câu trả lời...",
        "ai_error": "❌ Không thể tạo phản hồi từ AI.",
        "device_id": "Device ID",
        "online": "Online",
        "language": "🌐 Ngôn ngữ",
    }
}

def t(key: str, lang: str = "en") -> str:
    return TRANSLATIONS.get(lang, TRANSLATIONS["en"]).get(key, key)

# ==========================================
# 10. SESSION STATE
# ==========================================
if "user" not in st.session_state:
    st.session_state.user = None
if "current_chat_id" not in st.session_state:
    st.session_state.current_chat_id = None
if "messages" not in st.session_state:
    st.session_state.messages = []
if "db_data" not in st.session_state:
    st.session_state.db_data = {}
if "last_save_time" not in st.session_state:
    st.session_state.last_save_time = 0
if "language" not in st.session_state:
    st.session_state.language = "en"
if "pending_retry_prompt" not in st.session_state:
    st.session_state.pending_retry_prompt = None

db_data = GitHubStorage.load_db()
st.session_state.db_data = db_data

if not st.session_state.user and device_id and db_data:
    for username, uinfo in db_data.items():
        remembered_devices = uinfo.get("remembered_devices", [])
        if device_id in remembered_devices:
            st.session_state.user = username
            st.session_state.language = uinfo.get("language", "en")
            st.toast(f"{t('auto_login', st.session_state.language)} {username}", icon="⚡")
            break

# ==========================================
# 11. AUTH UI
# ==========================================
def render_auth_ui():
    lang = st.session_state.language
    
    col_lang_left, col_lang_right = st.columns([5, 1])
    with col_lang_right:
        lang_choice = st.selectbox(
            "🌐",
            ["en", "vi"],
            index=0 if lang == "en" else 1,
            format_func=lambda x: "🇬🇧 EN" if x == "en" else "🇻🇳 VI",
            key="auth_lang_selector",
            label_visibility="collapsed"
        )
        if lang_choice != lang:
            st.session_state.language = lang_choice
            st.rerun()
    
    st.markdown(f"<h1 class='main-header' style='text-align: center;'>{t('app_title', lang)}</h1>", unsafe_allow_html=True)
    st.caption(f"<p style='text-align: center;'>{t('app_subtitle', lang)}</p>", unsafe_allow_html=True)
    st.divider()
    
    _, col, _ = st.columns([1, 1.8, 1])

    with col:
        st.caption(f"🆔 {t('device_id', lang)}: `{device_id[:8]}...{device_id[-4:]}`")
        tab_login, tab_register = st.tabs([t("login_tab", lang), t("register_tab", lang)])
        
        with tab_login:
            with st.form("login_form"):
                u_name = st.text_input(t("username", lang)).strip().lower()
                u_pass = st.text_input(t("password", lang), type="password")
                remember_me = st.checkbox(t("remember_device", lang), value=True)
                
                if st.form_submit_button(t("login_btn", lang), use_container_width=True):
                    db = GitHubStorage.load_db(force_refresh=True)
                    if u_name in db and db[u_name]["password"] == hash_password(u_pass):
                        st.session_state.user = u_name
                        st.session_state.current_chat_id = None
                        st.session_state.messages = []
                        st.session_state.language = db[u_name].get("language", "en")
                        
                        if remember_me:
                            db[u_name].setdefault("remembered_devices", [])
                            if device_id not in db[u_name]["remembered_devices"]:
                                db[u_name]["remembered_devices"].append(device_id)
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
                                    "model": DEFAULT_MODEL,
                                    "temperature": 0.7,
                                    "top_p": 0.95,
                                    "top_k": 40
                                }
                            }
                            ok, msg = GitHubStorage.save_db(db)
                            if ok:
                                st.success(t("register_success", lang))
                            else:
                                st.error(f"❌ {msg}")

if not st.session_state.user:
    render_auth_ui()
    st.stop()

# ==========================================
# 12. TẢI DỮ LIỆU TÀI KHOẢN
# ==========================================
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

st.session_state.language = user_data.get("language", "en")
lang = st.session_state.language

user_chats = user_data["chats"]

if st.session_state.current_chat_id and st.session_state.current_chat_id not in user_chats:
    st.session_state.current_chat_id = None
    st.session_state.messages = []

# ==========================================
# 13. SIDEBAR
# ==========================================
with st.sidebar:
    lang_choice = st.selectbox(
        t("language", lang),
        ["en", "vi"],
        index=0 if lang == "en" else 1,
        format_func=lambda x: "🇬🇧 English" if x == "en" else "🇻🇳 Tiếng Việt",
        key="sidebar_lang"
    )
    if lang_choice != lang:
        user_data["language"] = lang_choice
        db_data[st.session_state.user] = user_data
        GitHubStorage.save_db(db_data)
        st.session_state.language = lang_choice
        st.rerun()
    
    st.markdown(f"""
    <div class="user-card">
        <div style="font-weight: 700; font-size: 1.1rem; color: #667eea;">👤 {st.session_state.user}</div>
        <div style="font-size: 0.8rem; opacity: 0.7;"><span class="pulse-dot"></span>{t('online', lang)} | {t('device_id', lang)}: {device_id[:6]}...</div>
    </div>
    """, unsafe_allow_html=True)

    if st.button(t("logout_btn", lang), use_container_width=True):
        db = GitHubStorage.load_db(force_refresh=True)
        user = db.get(st.session_state.user, {})
        if device_id in user.get("remembered_devices", []):
            user["remembered_devices"].remove(device_id)
            db[st.session_state.user] = user
            GitHubStorage.save_db(db)

        st.session_state.user = None
        st.session_state.current_chat_id = None
        st.session_state.messages = []
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
        sorted_chat_ids = sorted(
            user_chats.keys(), 
            key=lambda cid: user_chats[cid].get("updated_at", ""), 
            reverse=True
        )
        display_ids = sorted_chat_ids[:50]
        
        for cid in display_ids:
            chat_item = user_chats.get(cid, {})
            title = chat_item.get("title", t("new_chat", lang))
            
            is_active = (cid == st.session_state.current_chat_id)
            btn_label = f"📌 {title}" if is_active else f"💬 {title}"
            
            col_select, col_del = st.columns([0.8, 0.2])
            
            if col_select.button(btn_label, key=f"select_{cid}", use_container_width=True):
                st.session_state.current_chat_id = cid
                st.session_state.messages = user_chats[cid].get("messages", [])
                st.rerun()

            if col_del.button("🗑️", key=f"del_{cid}", help=t("delete_chat_tooltip", lang)):
                if cid in user_chats:
                    del user_chats[cid]
                    user_data["chats"] = user_chats
                    db_data[st.session_state.user] = user_data
                    
                    ok, msg = GitHubStorage.save_db(db_data)
                    
                    if st.session_state.current_chat_id == cid:
                        st.session_state.current_chat_id = None
                        st.session_state.messages = []
                    
                    if ok:
                        st.toast(t("chat_deleted", lang), icon="🗑️")
                    else:
                        st.error(f"Error: {msg}")
                    time.sleep(0.3)
                    st.rerun()

    st.divider()

    with st.expander(t("memory_title", lang), expanded=False):
        st.caption(t("memory_desc", lang))
        memory_text = st.text_area(
            "Memory:" if lang == "en" else "Ghi nhớ:", 
            value=user_data.get("custom_instructions", ""), 
            height=120,
            placeholder=t("memory_placeholder", lang)
        )
        if st.button(t("save_memory_btn", lang), use_container_width=True):
            user_data["custom_instructions"] = memory_text.strip()
            db_data[st.session_state.user] = user_data
            ok, msg = GitHubStorage.save_db(db_data)
            if ok:
                st.toast(t("memory_saved", lang), icon="🧠")
                time.sleep(0.3)
                st.rerun()
            else:
                st.error(f"Error: {msg}")

    st.subheader(t("api_title", lang))
    st.caption(t("api_from_secrets", lang))
    
    for i, key in enumerate([API_KEY_1, API_KEY_2], start=1):
        if key:
            masked = f"{key[:6]}...{key[-4:]}" if len(key) > 10 else "••••••••"
            st.markdown(
                f"**Key {i}:** `{masked}` "
                f"<span class='status-badge badge-ready'>{t('api_status_ready', lang)}</span>",
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"**Key {i}:** *Not configured* "
                f"<span class='status-badge badge-missing'>{t('api_status_missing', lang)}</span>",
                unsafe_allow_html=True
            )

    available_models = FALLBACK_MODELS.copy()
    
    if SECRET_API_KEYS:
        try:
            genai.configure(api_key=SECRET_API_KEYS[0])
            dynamic_models = []
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    name = m.name.replace("models/", "")
                    dynamic_models.append(name)
            if dynamic_models:
                merged = list(dict.fromkeys(dynamic_models + FALLBACK_MODELS))
                available_models = merged
        except Exception:
            pass

    saved_model = user_data["preferences"].get("model", DEFAULT_MODEL)
    
    if saved_model not in available_models:
        saved_model = DEFAULT_MODEL
        user_data["preferences"]["model"] = saved_model
        db_data[st.session_state.user] = user_data
    
    try:
        model_index = available_models.index(saved_model)
    except ValueError:
        model_index = 0

    selected_model = st.selectbox(t("model_select", lang), available_models, index=model_index)
    
    if selected_model != user_data["preferences"].get("model"):
        user_data["preferences"]["model"] = selected_model
        db_data[st.session_state.user] = user_data
        GitHubStorage.save_db(db_data)

    with st.expander(t("gen_config", lang), expanded=False):
        temperature = st.slider(
            t("temperature", lang), 0.0, 1.0, 
            float(user_data["preferences"].get("temperature", 0.7)), 0.05
        )
        top_p = st.slider(
            t("top_p", lang), 0.0, 1.0, 
            float(user_data["preferences"].get("top_p", 0.95)), 0.05
        )
        top_k = st.number_input(
            t("top_k", lang), min_value=1, max_value=100, 
            value=int(user_data["preferences"].get("top_k", 40))
        )
        
        if st.button(t("save_params", lang), use_container_width=True):
            user_data["preferences"]["temperature"] = temperature
            user_data["preferences"]["top_p"] = top_p
            user_data["preferences"]["top_k"] = top_k
            db_data[st.session_state.user] = user_data
            ok, msg = GitHubStorage.save_db(db_data)
            if ok:
                st.toast(t("params_saved", lang), icon="⚙️")
                time.sleep(0.3)
                st.rerun()

# ==========================================
# 14. MAIN CHAT UI
# ==========================================
st.markdown(f"<h1 class='main-header'>{t('app_title', lang)}</h1>", unsafe_allow_html=True)

if not SECRET_API_KEYS:
    st.warning(t("no_api_key", lang))
    st.stop()

current_title = t("new_chat", lang)
if st.session_state.current_chat_id and st.session_state.current_chat_id in user_chats:
    current_title = user_chats[st.session_state.current_chat_id].get("title", "Chat")

st.caption(f"📌 {t('current_chat', lang)}: **{current_title}** | {t('model_label', lang)}: `{selected_model}`")

# Hiển thị lịch sử tin nhắn
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])
        # Thêm disclaimer dưới mỗi tin nhắn assistant
        if msg["role"] == "assistant":
            st.markdown(
                f'<div class="ai-disclaimer">{DISCLAIMER.get(lang, DISCLAIMER["en"])}</div>',
                unsafe_allow_html=True
            )

# ==========================================
# 15. XỬ LÝ PROMPT VÀ PHẢN HỒI AI
# ==========================================
def _process_prompt(user_prompt):
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

    chat_data = user_chats[st.session_state.current_chat_id]
    chat_summary = chat_data.get("summary", "")

    if len(st.session_state.messages) > 10:
        older_msgs = st.session_state.messages[:-6]
        try:
            chat_summary = generate_summary(
                older_msgs, chat_summary, SECRET_API_KEYS, selected_model, lang
            )
            chat_data["summary"] = chat_summary
        except Exception:
            pass

    system_instruction = user_data.get("custom_instructions", "")
    if chat_summary:
        label = "[BỐI CẢNH LỊCH SỬ ĐÃ TÓM TẮT]" if lang == "vi" else "[SUMMARIZED HISTORY CONTEXT]"
        system_instruction += f"\n\n{label}: {chat_summary}"

    content_inputs = []
    
    recent_msgs = st.session_state.messages[-6:]
    formatted_history = ""
    for m in recent_msgs[:-1]:
        r = ("Người dùng" if lang == "vi" else "User") if m["role"] == "user" else "AI"
        formatted_history += f"{r}: {m['content']}\n"
    
    if formatted_history:
        if lang == "vi":
            full_prompt = f"Lịch sử hội thoại gần đây:\n{formatted_history}\nCâu hỏi mới: {user_prompt}"
        else:
            full_prompt = f"Recent conversation history:\n{formatted_history}\nNew question: {user_prompt}"
    else:
        full_prompt = user_prompt

    content_inputs.append(full_prompt)

    response_text = None
    err_type = None
    
    with st.chat_message("assistant"):
        loading_placeholder = st.empty()
        loading_placeholder.markdown(f"""
        <div class="ai-loading-box">
            <div class="spinner"></div>
            <div class="ai-loading-text">{t('ai_thinking', lang)}</div>
        </div>
        """, unsafe_allow_html=True)

        response_text, err_type = call_gemini_with_failover(
            prompt_inputs=content_inputs,
            api_keys=SECRET_API_KEYS,
            preferred_model=selected_model,
            system_instruction=system_instruction if system_instruction else None,
            generation_config={
                "temperature": temperature,
                "top_p": top_p,
                "top_k": top_k
            },
            lang=lang
        )

        loading_placeholder.empty()

        if response_text:
            st.markdown(response_text)
            # Chú thích cuối phản hồi AI - chữ nhỏ in nghiêng
            st.markdown(
                f'<div class="ai-disclaimer">{DISCLAIMER.get(lang, DISCLAIMER["en"])}</div>',
                unsafe_allow_html=True
            )
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
                new_title = generate_chat_title(user_prompt, SECRET_API_KEYS, selected_model, lang)
                chat_data["title"] = new_title
            except Exception:
                chat_data["title"] = user_prompt[:30] + "..." if len(user_prompt) > 30 else user_prompt

        chat_data["messages"] = st.session_state.messages
        chat_data["updated_at"] = datetime.now().isoformat()
        user_chats[st.session_state.current_chat_id] = chat_data
        user_data["chats"] = user_chats
        db_data[st.session_state.user] = user_data

        current_time = time.time()
        if current_time - st.session_state.last_save_time > 1:
            GitHubStorage.save_db(db_data)
            st.session_state.last_save_time = current_time
        
        st.rerun()


if st.session_state.pending_retry_prompt:
    pending = st.session_state.pending_retry_prompt
    st.session_state.pending_retry_prompt = None
    _process_prompt(pending)

elif user_prompt := st.chat_input(t("chat_placeholder", lang)):
    _process_prompt(user_prompt)
