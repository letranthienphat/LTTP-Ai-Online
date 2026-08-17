import os
import json
import time
import uuid
import base64
import hashlib
import requests
import streamlit as st
import google.generativeai as genai
from PIL import Image
from datetime import datetime
from cryptography.fernet import Fernet
from streamlit_cookies_controller import CookieController

# ==========================================
# 1. CẤU HÌNH TRANG & SECRETS
# ==========================================
st.set_page_config(
    page_title="Nexus AI Online",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

DB_FILE = "users_db.json"
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", "")
GITHUB_REPO = st.secrets.get("GITHUB_REPO", "")

MASTER_SECRET = st.secrets.get("ENCRYPTION_SECRET", "NexusAI_Master_Secret_Key_2026")
FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(MASTER_SECRET.encode()).digest())
cipher = Fernet(FERNET_KEY)

cookies = CookieController()
COOKIE_MAX_AGE = 30 * 24 * 60 * 60

device_id = cookies.get("nexus_device_id")
if not device_id:
    device_id = str(uuid.uuid4())
    cookies.set("nexus_device_id", device_id, max_age=COOKIE_MAX_AGE)

# ==========================================
# 2. CUSTOM CSS - HIỆU ỨNG ĐỒ HỌA & UI
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
</style>
""", unsafe_allow_html=True)

# ==========================================
# 3. HÀM MÃ HÓA & MẬT KHẨU
# ==========================================
def encrypt_key(raw_key: str) -> str:
    if not raw_key: return ""
    return cipher.encrypt(raw_key.encode('utf-8')).decode('utf-8')

def decrypt_key(encrypted_key: str) -> str:
    if not encrypted_key: return ""
    try:
        return cipher.decrypt(encrypted_key.encode('utf-8')).decode('utf-8')
    except Exception:
        return ""

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ==========================================
# 4. QUẢN LÝ DỮ LIỆU ĐỒNG BỘ GITHUB API
# ==========================================
class GitHubStorage:
    @staticmethod
    def get_api_headers():
        return {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }

    @staticmethod
    def load_db() -> dict:
        if not GITHUB_TOKEN or not GITHUB_REPO:
            st.error("⚠️ Thiếu GITHUB_TOKEN hoặc GITHUB_REPO trong Streamlit Secrets!")
            return {}

        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{DB_FILE}"
        try:
            res = requests.get(
                url, 
                headers=GitHubStorage.get_api_headers(), 
                params={"nocache": time.time()}, 
                timeout=10
            )
            if res.status_code == 200:
                content_b64 = res.json().get("content", "")
                decoded = base64.b64decode(content_b64.encode('utf-8')).decode('utf-8')
                return json.loads(decoded)
            elif res.status_code == 404:
                return {}
            else:
                st.error(f"Lỗi đọc GitHub (HTTP {res.status_code})")
                return {}
        except Exception as e:
            st.error(f"Lỗi kết nối GitHub API: {e}")
            return {}

    @staticmethod
    def save_db(data: dict) -> tuple[bool, str]:
        if not GITHUB_TOKEN or not GITHUB_REPO:
            return False, "Thiếu cấu hình GitHub Token/Repo trong Secrets."

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
            "message": "Update users_db.json (Chats, Keys, Memory & Devices)",
            "content": content_b64
        }
        if sha:
            payload["sha"] = sha

        try:
            res_put = requests.put(url, headers=headers, json=payload, timeout=10)
            if res_put.status_code in [200, 201]:
                return True, "Đã lưu thành công lên GitHub!"
            else:
                return False, f"Lỗi GitHub (HTTP {res_put.status_code})"
        except Exception as e:
            return False, f"Lỗi lưu GitHub: {e}"

# ==========================================
# 5. HÀM XỬ LÝ AI (Đặt tên & Tóm tắt)
# ==========================================
def generate_chat_title(user_prompt: str, api_key: str, model_name: str) -> str:
    """Tự động đặt tên ngắn gọn cho cuộc trò chuyện bằng AI"""
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        prompt = (
            "Hãy tạo 1 tiêu đề cực kỳ ngắn gọn (từ 2 đến 5 từ, không đặt trong dấu ngoặc kép, không dùng markdown) "
            f"tóm tắt chủ đề của câu hỏi sau:\n\"{user_prompt}\""
        )
        res = model.generate_content(prompt)
        title = res.text.strip().replace('"', '').replace("'", "")
        return title[:35] if title else user_prompt[:25]
    except Exception:
        return user_prompt[:25] + "..." if len(user_prompt) > 25 else user_prompt

def generate_summary(older_messages: list, existing_summary: str, api_key: str, model_name: str) -> str:
    """Tóm tắt lịch sử hội thoại cũ để tiết kiệm context window"""
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        
        text_to_summarize = ""
        if existing_summary:
            text_to_summarize += f"Bối cảnh tóm tắt trước đó:\n{existing_summary}\n\nCác tin nhắn mới phát sinh:\n"
        
        for m in older_messages:
            role_label = "Người dùng" if m["role"] == "user" else "AI"
            text_to_summarize += f"- {role_label}: {m['content']}\n"
            
        prompt = (
            "Hãy tóm tắt ngắn gọn và đúc kết các ý chính, thông tin quan trọng của đoạn hội thoại sau "
            "thành 1 đoạn văn (dưới 150 từ) để làm bối cảnh cho các câu hỏi tiếp theo:\n\n"
            f"{text_to_summarize}"
        )
        
        res = model.generate_content(prompt)
        return res.text.strip()
    except Exception:
        parts = [existing_summary] if existing_summary else []
        for m in older_messages:
            r = "User" if m["role"] == "user" else "AI"
            parts.append(f"{r}: {m['content'][:50]}...")
        return " | ".join(parts)

# ==========================================
# 6. KHỞI TẠO SESSION STATE & DỮ LIỆU
# ==========================================
if "user" not in st.session_state:
    st.session_state.user = None
if "current_chat_id" not in st.session_state:
    st.session_state.current_chat_id = None
if "messages" not in st.session_state:
    st.session_state.messages = []

db_data = GitHubStorage.load_db()

# Tự động đăng nhập bằng Device Cookie
if not st.session_state.user and device_id and db_data:
    for username, uinfo in db_data.items():
        remembered_devices = uinfo.get("remembered_devices", [])
        if device_id in remembered_devices:
            st.session_state.user = username
            st.toast(f"Tự động đăng nhập thành công! Xin chào {username}", icon="⚡")
            break

# UI Đăng nhập / Đăng ký
def render_auth_ui():
    st.markdown("<h1 class='main-header' style='text-align: center;'>⚡ Nexus AI Online</h1>", unsafe_allow_html=True)
    st.caption("<p style='text-align: center;'>Hệ thống Trí tuệ Nhân tạo Đa Năng Đồng bộ GitHub</p>", unsafe_allow_html=True)
    st.divider()
    
    _, col, _ = st.columns([1, 1.8, 1])

    with col:
        st.caption(f"🆔 Device ID: `{device_id[:8]}...{device_id[-4:]}`")
        tab_login, tab_register = st.tabs(["🔑 Đăng nhập", "📝 Đăng ký"])
        
        with tab_login:
            with st.form("login_form"):
                u_name = st.text_input("Tên đăng nhập:").strip().lower()
                u_pass = st.text_input("Mật khẩu:", type="password")
                remember_me = st.checkbox("📌 Ghi nhớ thiết bị này (30 ngày)", value=True)
                
                if st.form_submit_button("Đăng nhập", use_container_width=True):
                    db = GitHubStorage.load_db()
                    if u_name in db and db[u_name]["password"] == hash_password(u_pass):
                        st.session_state.user = u_name
                        st.session_state.current_chat_id = None
                        st.session_state.messages = []
                        
                        if remember_me:
                            db[u_name].setdefault("remembered_devices", [])
                            if device_id not in db[u_name]["remembered_devices"]:
                                db[u_name]["remembered_devices"].append(device_id)
                                GitHubStorage.save_db(db)
                        
                        st.toast("Đăng nhập thành công!", icon="✅")
                        st.rerun()
                    else:
                        st.error("❌ Mật khẩu hoặc tên đăng nhập không chính xác!")

        with tab_register:
            with st.form("register_form"):
                reg_u = st.text_input("Tạo tên đăng nhập:").strip().lower()
                reg_p = st.text_input("Tạo mật khẩu:", type="password")
                reg_p2 = st.text_input("Xác nhận mật khẩu:", type="password")
                if st.form_submit_button("Tạo tài khoản mới", use_container_width=True):
                    if not reg_u or not reg_p:
                        st.warning("⚠️ Vui lòng điền đầy đủ thông tin.")
                    elif reg_p != reg_p2:
                        st.error("❌ Mật khẩu xác nhận không khớp.")
                    else:
                        db = GitHubStorage.load_db()
                        if reg_u in db:
                            st.error("❌ Tên đăng nhập đã được sử dụng.")
                        else:
                            db[reg_u] = {
                                "password": hash_password(reg_p),
                                "api_keys": [],
                                "custom_instructions": "",
                                "chats": {},
                                "remembered_devices": [device_id]
                            }
                            ok, msg = GitHubStorage.save_db(db)
                            if ok:
                                st.success("🎉 Đăng ký thành công! Hãy chuyển qua tab Đăng nhập.")
                            else:
                                st.error(f"❌ {msg}")

if not st.session_state.user:
    render_auth_ui()
    st.stop()

# ==========================================
# 7. TẢI DỮ LIỆU TÀI KHOẢN
# ==========================================
user_data = db_data.get(st.session_state.user, {})
user_data.setdefault("api_keys", [])
user_data.setdefault("custom_instructions", "")
user_data.setdefault("chats", {})
user_data.setdefault("remembered_devices", [])

encrypted_keys = user_data["api_keys"]
user_chats = user_data["chats"]
active_api_keys = [decrypt_key(k) for k in encrypted_keys if decrypt_key(k)]

if st.session_state.current_chat_id and st.session_state.current_chat_id not in user_chats:
    st.session_state.current_chat_id = None
    st.session_state.messages = []

# ==========================================
# 8. SIDEBAR CHÍNH
# ==========================================
with st.sidebar:
    st.markdown(f"""
    <div class="user-card">
        <div style="font-weight: 700; font-size: 1.1rem; color: #667eea;">👤 {st.session_state.user}</div>
        <div style="font-size: 0.8rem; opacity: 0.7;"><span class="pulse-dot"></span>Online | Device: {device_id[:6]}...</div>
    </div>
    """, unsafe_allow_html=True)

    if st.button("🚪 Đăng xuất", use_container_width=True):
        if device_id in user_data["remembered_devices"]:
            user_data["remembered_devices"].remove(device_id)
            db_data[st.session_state.user] = user_data
            GitHubStorage.save_db(db_data)

        st.session_state.user = None
        st.session_state.current_chat_id = None
        st.session_state.messages = []
        st.rerun()

    st.divider()

    # --- NÚT TẠO CHAT MỚI ---
    if st.button("➕ Cuộc trò chuyện mới", type="primary", use_container_width=True):
        st.session_state.current_chat_id = None
        st.session_state.messages = []
        st.rerun()

    # --- DANH SÁCH CHAT ---
    st.subheader("💬 Danh sách trò chuyện")
    if not user_chats:
        st.caption("Chưa có cuộc trò chuyện nào.")
    else:
        sorted_chat_ids = sorted(
            user_chats.keys(), 
            key=lambda cid: user_chats[cid].get("updated_at", ""), 
            reverse=True
        )

        for cid in sorted_chat_ids:
            chat_item = user_chats.get(cid, {})
            title = chat_item.get("title", "Hội thoại mới")
            
            is_active = (cid == st.session_state.current_chat_id)
            btn_label = f"📌 {title}" if is_active else f"💬 {title}"
            
            col_select, col_del = st.columns([0.8, 0.2])
            
            if col_select.button(btn_label, key=f"select_{cid}", use_container_width=True):
                st.session_state.current_chat_id = cid
                st.session_state.messages = user_chats[cid].get("messages", [])
                st.rerun()

            if col_del.button("🗑️", key=f"del_{cid}", help="Xóa cuộc trò chuyện"):
                if cid in user_chats:
                    del user_chats[cid]
                    user_data["chats"] = user_chats
                    db_data[st.session_state.user] = user_data
                    
                    ok, msg = GitHubStorage.save_db(db_data)
                    
                    if st.session_state.current_chat_id == cid:
                        st.session_state.current_chat_id = None
                        st.session_state.messages = []
                    
                    if ok:
                        st.toast("Đã xóa cuộc trò chuyện!", icon="🗑️")
                    else:
                        st.error(f"Lỗi: {msg}")
                    time.sleep(0.3)
                    st.rerun()

    st.divider()

    # --- QUẢN LÝ BỘ NHỚ CỐ ĐỊNH (SYSTEM INSTRUCTION) ---
    with st.expander("🧠 Bộ nhớ cố định / Chỉ dẫn AI", expanded=False):
        st.caption("AI sẽ luôn ghi nhớ và tuân thủ các quy tắc này trong mọi cuộc trò chuyện.")
        memory_text = st.text_area(
            "Nhập ghi nhớ của bạn:", 
            value=user_data.get("custom_instructions", ""), 
            height=120,
            placeholder="Ví dụ: Bạn là trợ lý lập trình Python chuyên nghiệp. Luôn trả lời bằng Tiếng Việt."
        )
        if st.button("💾 Lưu ghi nhớ cố định", use_container_width=True):
            user_data["custom_instructions"] = memory_text.strip()
            db_data[st.session_state.user] = user_data
            ok, msg = GitHubStorage.save_db(db_data)
            if ok:
                st.toast("Đã ghi nhớ thông tin!", icon="🧠")
                time.sleep(0.3)
                st.rerun()
            else:
                st.error(f"Lỗi lưu: {msg}")

    # --- QUẢN LÝ API KEY & MODEL SELECTION ---
    st.subheader("🔑 Quản lý API Key & Model")
    
    if active_api_keys:
        for idx, raw_k in enumerate(active_api_keys):
            col_k, col_del_k = st.columns([0.8, 0.2])
            masked = f"{raw_k[:6]}...{raw_k[-4:]}" if len(raw_k) > 10 else "••••••••"
            col_k.code(masked)
            if col_del_k.button("❌", key=f"del_key_{idx}"):
                user_data["api_keys"].pop(idx)
                db_data[st.session_state.user] = user_data
                GitHubStorage.save_db(db_data)
                st.toast("Đã xóa API Key!", icon="🗑️")
                time.sleep(0.3)
                st.rerun()

    new_key_input = st.text_input("Thêm Gemini API Key mới:", type="password")
    if st.button("💾 Lưu API Key", use_container_width=True):
        clean_k = new_key_input.strip()
        if clean_k and clean_k not in active_api_keys:
            user_data["api_keys"].append(encrypt_key(clean_k))
            db_data[st.session_state.user] = user_data
            ok, msg = GitHubStorage.save_db(db_data)
            if ok:
                st.success("🎉 Đã lưu API Key thành công!")
                time.sleep(0.5)
                st.rerun()

    # Quét danh sách Model có sẵn từ API Key
    available_models = []
    if active_api_keys:
        try:
            genai.configure(api_key=active_api_keys[0])
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    name = m.name.replace('models/', '')
                    available_models.append(name)
        except Exception:
            pass

    if not available_models:
        available_models = ["gemini-3.7-flash", "gemini-2.5-flash", "gemini-1.5-flash", "gemini-1.5-pro"]

    # Đặt mặc định chọn `gemini-3.7-flash` nếu có trong danh sách
    default_index = 0
    target_default = "gemini-3.7-flash"
    for idx, model_name in enumerate(available_models):
        if target_default in model_name:
            default_index = idx
            break

    selected_model = st.selectbox(
        "Chọn Phiên bản Gemini:", 
        options=available_models,
        index=default_index
    )

# ==========================================
# 9. KHUNG CHAT CHÍNH (Xử lý Đa phương tiện)
# ==========================================
st.markdown("<h1 class='main-header'>⚡ Nexus AI Online</h1>", unsafe_allow_html=True)

current_chat_title = "Cuộc trò chuyện mới"
current_summary = ""

if st.session_state.current_chat_id and st.session_state.current_chat_id in user_chats:
    chat_obj = user_chats.get(st.session_state.current_chat_id, {})
    current_chat_title = chat_obj.get("title", "Cuộc trò chuyện")
    current_summary = chat_obj.get("summary", "")

st.caption(f"Đang mở: **{current_chat_title}** | Model: **{selected_model}**")

if current_summary:
    with st.expander("📝 Bối cảnh hội thoại cũ (Đã tóm tắt)", expanded=False):
        st.info(current_summary)

if not active_api_keys:
    st.warning("👈 Vui lòng thêm ít nhất 1 Gemini API Key ở Sidebar để bắt đầu trò chuyện.")
    st.stop()

# Hiển thị lịch sử tin nhắn
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        if msg.get("image_bytes"):
            st.image(msg["image_bytes"], caption=msg.get("file_name", "Ảnh đính kèm"), use_column_width=True)
        if msg.get("file_info"):
            st.info(f"📄 File đính kèm: `{msg['file_info']}`")
        st.write(msg["content"])

# --- BỘ TẢI FILE / HÌNH ẢNH ĐÍNH KÈM ---
with st.expander("📎 Đính kèm Hình ảnh hoặc File văn bản (Tùy chọn)", expanded=False):
    uploaded_file = st.file_uploader(
        "Tải lên hình ảnh (PNG, JPG, WEBP) hoặc file văn bản/code (TXT, MD, PY, JSON...)",
        type=["png", "jpg", "jpeg", "webp", "txt", "md", "py", "json", "csv"]
    )

# Nhập tin nhắn mới
if prompt := st.chat_input("Nhập câu hỏi của bạn cho Nexus AI..."):
    image_data = None
    file_content_text = ""
    file_name = ""
    image_bytes = None

    if uploaded_file is not None:
        file_name = uploaded_file.name
        file_type = uploaded_file.type
        
        # Xử lý File Ảnh
        if file_type.startswith("image/"):
            image_bytes = uploaded_file.getvalue()
            image_data = Image.open(uploaded_file)
        # Xử lý File Văn bản / Code
        else:
            try:
                file_content_text = uploaded_file.getvalue().decode("utf-8")
            except Exception:
                file_content_text = str(uploaded_file.getvalue())

    # Tạo tin nhắn của người dùng
    user_msg = {
        "role": "user",
        "content": prompt,
        "image_bytes": image_bytes,
        "file_info": file_name if (file_name and not image_bytes) else None
    }
    
    st.session_state.messages.append(user_msg)
    
    with st.chat_message("user"):
        if image_bytes:
            st.image(image_bytes, caption=file_name, use_column_width=True)
        if file_name and not image_bytes:
            st.info(f"📄 File đính kèm: `{file_name}`")
        st.write(prompt)

    # Khởi tạo ID cuộc trò chuyện mới nếu chưa có
    is_new_chat = False
    if not st.session_state.current_chat_id:
        is_new_chat = True
        new_cid = f"chat_{uuid.uuid4().hex[:8]}"
        st.session_state.current_chat_id = new_cid
        user_chats[new_cid] = {
            "title": "Đang tạo tiêu đề...",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": "",
            "summarized_count": 0,
            "messages": []
        }
    
    cid = st.session_state.current_chat_id
    chat_info = user_chats[cid]

    # Xử lý tóm tắt nếu quá 6 tin nhắn
    total_msgs = len(st.session_state.messages)
    if total_msgs > 6:
        older_msgs = st.session_state.messages[:-6]
        summarized_count = chat_info.get("summarized_count", 0)
        
        if len(older_msgs) > summarized_count:
            unsummarized_msgs = older_msgs[summarized_count:]
            updated_summary = generate_summary(
                unsummarized_msgs, 
                chat_info.get("summary", ""), 
                active_api_keys[0], 
                selected_model
            )
            chat_info["summary"] = updated_summary
            chat_info["summarized_count"] = len(older_msgs)
            current_summary = updated_summary

    recent_messages = st.session_state.messages[-6:] if total_msgs > 6 else st.session_state.messages

    # --- TỔNG HỢP SYSTEM INSTRUCTIONS (Ghi nhớ cố định + Tóm tắt) ---
    sys_parts = []
    custom_mem = user_data.get("custom_instructions", "").strip()
    if custom_mem:
        sys_parts.append(f"Quy tắc & Ghi nhớ cố định từ người dùng:\n{custom_mem}")
    if current_summary:
        sys_parts.append(f"Bối cảnh các lượt trò chuyện trước đó:\n{current_summary}")

    full_sys_instruction = "\n\n".join(sys_parts) if sys_parts else None

    # --- KHUNG AI PHẢN HỒI KÈM HIỆU ỨNG LOADING ---
    with st.chat_message("assistant"):
        loading_placeholder = st.empty()
        loading_placeholder.markdown("""
        <div class="ai-loading-box">
            <div class="spinner"></div>
            <div class="ai-loading-text">Nexus AI đang phân tích và soạn câu trả lời...</div>
        </div>
        """, unsafe_allow_html=True)
        
        placeholder = st.empty()
        full_response = ""
        success = False

        for current_key in active_api_keys:
            try:
                genai.configure(api_key=current_key)
                
                model_engine = genai.GenerativeModel(
                    selected_model, 
                    system_instruction=full_sys_instruction
                )

                # Chuẩn bị nội dung gửi đi (Prompt + Ảnh / File văn bản)
                content_parts = []
                if image_data:
                    content_parts.append(image_data)
                if file_content_text:
                    content_parts.append(f"\n--- NỘI DUNG FILE ĐÍNH KÈM ({file_name}) ---\n{file_content_text}\n--- KẾT THÚC FILE ---\n")
                
                content_parts.append(prompt)

                # Nếu có ảnh/file thì gọi trực tiếp generate_content; nếu thoại thuần túy thì dùng chat_session
                if image_data or file_content_text:
                    response = model_engine.generate_content(content_parts, stream=True)
                else:
                    chat_history = []
                    for m in recent_messages[:-1]:
                        role = "model" if m["role"] == "assistant" else "user"
                        chat_history.append({"role": role, "parts": [m["content"]]})

                    chat_session = model_engine.start_chat(history=chat_history)
                    response = chat_session.send_message(prompt, stream=True)

                is_first_chunk = True
                for chunk in response:
                    if chunk.text:
                        if is_first_chunk:
                            loading_placeholder.empty()
                            is_first_chunk = False

                        full_response += chunk.text
                        placeholder.markdown(full_response + "▌")

                placeholder.markdown(full_response)
                success = True
                break
            except Exception:
                pass

        loading_placeholder.empty()

        if success and full_response:
            st.session_state.messages.append({"role": "assistant", "content": full_response})
            
            # Tự động đặt tên trò chuyện bằng AI nếu là lượt thoại đầu tiên
            if is_new_chat or chat_info.get("title") == "Đang tạo tiêu đề...":
                ai_title = generate_chat_title(prompt, active_api_keys[0], selected_model)
                chat_info["title"] = ai_title
            
            # Cập nhật & lưu dữ liệu
            chat_info["messages"] = st.session_state.messages
            chat_info["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            user_chats[cid] = chat_info
            user_data["chats"] = user_chats
            db_data[st.session_state.user] = user_data
            
            GitHubStorage.save_db(db_data)
            
            # Cập nhật lại UI nếu có thay đổi tiêu đề
            if is_new_chat:
                time.sleep(0.3)
                st.rerun()
        else:
            st.error("❌ Không thể tạo phản hồi từ AI. Vui lòng kiểm tra lại API Key hoặc File đính kèm.")
