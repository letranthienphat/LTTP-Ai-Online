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
                    available_models.append(m.name.replace("models/", ""))
        except Exception:
            available_models = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"]

    if not available_models:
        available_models = ["gemini-1.5-flash", "gemini-1.5-pro"]

    selected_model = st.selectbox("Chọn mô hình AI:", available_models, index=0)

    # --- THAM SỐ CẤU HÌNH SINH VĂN BẢN ---
    with st.expander("⚙️ Cấu hình tham số sinh", expanded=False):
        temperature = st.slider("Temperature (Độ sáng tạo):", 0.0, 1.0, 0.7, 0.05)
        top_p = st.slider("Top P:", 0.0, 1.0, 0.95, 0.05)
        top_k = st.number_input("Top K:", min_value=1, max_value=100, value=40)

# ==========================================
# 9. GIAO DIỆN CHAT CHÍNH (MAIN UI)
# ==========================================
st.markdown("<h1 class='main-header'>⚡ Nexus AI Workspace</h1>", unsafe_allow_html=True)

if not active_api_keys:
    st.warning("⚠️ Vui lòng thêm ít nhất một **Gemini API Key** ở thanh bên trái để bắt đầu trò chuyện!")
    st.stop()

# Hiển thị tiêu đề chat hiện tại
current_title = "Cuộc trò chuyện mới"
if st.session_state.current_chat_id and st.session_state.current_chat_id in user_chats:
    current_title = user_chats[st.session_state.current_chat_id].get("title", "Cuộc trò chuyện")

st.caption(f"📌 Đang trò chuyện trong: **{current_title}** | Mô hình: `{selected_model}`")

# Upload file / hình ảnh đính kèm
uploaded_file = st.file_uploader("📎 Đính kèm hình ảnh (tùy chọn):", type=["png", "jpg", "jpeg", "webp"])
image_input = None
if uploaded_file:
    image_input = Image.open(uploaded_file)
    st.image(image_input, caption="Hình ảnh đã tải lên", width=250)

# Hiển thị lịch sử tin nhắn
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# ==========================================
# 10. XỬ LÝ NHẬP LIỆU VÀ PHẢN HỒI AI
# ==========================================
if user_prompt := st.chat_input("Hỏi Nexus AI bất cứ điều gì..."):
    # 1. Thêm tin nhắn người dùng vào UI
    st.session_state.messages.append({"role": "user", "content": user_prompt})
    with st.chat_message("user"):
        st.markdown(user_prompt)

    # 2. Khởi tạo Chat ID mới nếu chưa có
    if not st.session_state.current_chat_id:
        st.session_state.current_chat_id = str(uuid.uuid4())
        user_chats[st.session_state.current_chat_id] = {
            "title": "Cuộc trò chuyện mới",
            "messages": [],
            "summary": "",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }

    chat_data = user_chats[st.session_state.current_chat_id]
    chat_summary = chat_data.get("summary", "")

    # 3. Tự động nén/tóm tắt bối cảnh cũ nếu hội thoại dài (> 10 tin nhắn)
    if len(st.session_state.messages) > 10:
        older_msgs = st.session_state.messages[:-6]
        chat_summary = generate_summary(
            older_msgs, 
            chat_summary, 
            active_api_keys[0], 
            selected_model
        )
        chat_data["summary"] = chat_summary

    # 4. Tạo System Instruction tổng hợp
    system_instruction = user_data.get("custom_instructions", "")
    if chat_summary:
        system_instruction += f"\n\n[BỐI CẢNH LỊCH SỬ ĐÃ TÓM TẮT]: {chat_summary}"

    # 5. Gọi AI sinh phản hồi (Xoay vòng API Key nếu gặp lỗi Quota)
    response_text = ""
    success = False
    
    with st.chat_message("assistant"):
        loading_placeholder = st.empty()
        loading_placeholder.markdown("""
        <div class="ai-loading-box">
            <div class="spinner"></div>
            <div class="ai-loading-text">Nexus AI đang suy nghĩ và tổng hợp câu trả lời...</div>
        </div>
        """, unsafe_allow_html=True)

        for api_k in active_api_keys:
            try:
                genai.configure(api_key=api_k)
                model = genai.GenerativeModel(
                    model_name=selected_model,
                    system_instruction=system_instruction if system_instruction else None,
                    generation_config={
                        "temperature": temperature,
                        "top_p": top_p,
                        "top_k": top_k
                    }
                )

                # Chuẩn bị danh sách nội dung gửi tới mô hình
                content_inputs = []
                if image_input:
                    content_inputs.append(image_input)
                
                # Bổ sung các tin nhắn gần nhất làm context
                recent_msgs = st.session_state.messages[-6:]
                formatted_history = ""
                for m in recent_msgs[:-1]:
                    r = "Người dùng" if m["role"] == "user" else "AI"
                    formatted_history += f"{r}: {m['content']}\n"
                
                if formatted_history:
                    full_prompt = f"Lịch sử hội thoại gần đây:\n{formatted_history}\nCâu hỏi mới: {user_prompt}"
                else:
                    full_prompt = user_prompt

                content_inputs.append(full_prompt)

                res = model.generate_content(content_inputs)
                response_text = res.text
                success = True
                break
            except Exception as ex:
                st.warning(f"⚠️ API Key gặp sự cố hoặc vượt giới hạn: {ex}. Đang thử Key tiếp theo...")
                continue

        loading_placeholder.empty()

        if success:
            st.markdown(response_text)
            st.session_state.messages.append({"role": "assistant", "content": response_text})
        else:
            error_msg = "❌ Không thể tạo phản hồi từ AI. Vui lòng kiểm tra lại API Key hoặc quota của bạn."
            st.error(error_msg)
            st.session_state.messages.append({"role": "assistant", "content": error_msg})

    # 6. Tự động tạo tiêu đề nếu đây là lượt trao đổi đầu tiên
    if len(chat_data.get("messages", [])) == 0:
        new_title = generate_chat_title(user_prompt, active_api_keys[0], selected_model)
        chat_data["title"] = new_title

    # 7. Lưu và đồng bộ trạng thái cuộc trò chuyện lên GitHub Storage
    chat_data["messages"] = st.session_state.messages
    chat_data["updated_at"] = datetime.now().isoformat()
    user_chats[st.session_state.current_chat_id] = chat_data
    user_data["chats"] = user_chats
    db_data[st.session_state.user] = user_data

    GitHubStorage.save_db(db_data)
    st.rerun()
