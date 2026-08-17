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
    /* Gradient Header */
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        font-size: 2.5rem;
        margin-bottom: 0.2rem;
    }
    
    /* Custom Loading Spinner & Text */
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

    /* Status Pulse Dot */
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

    /* Keyframe Animations */
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }

    @keyframes shine {
        to { background-position: 200% center; }
    }

    @keyframes pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(4px); }
        to { opacity: 1; transform: translateY(0); }
    }

    /* Style Thẻ Thông Tin Sidebar */
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
            "message": "Update users_db.json (Chats, Keys & Devices)",
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
# 5. HÀM TÓM TẮT HỘI THOẠI CŨ
# ==========================================
def generate_summary(older_messages: list, existing_summary: str, api_key: str, model_name: str) -> str:
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
user_data.setdefault("chats", {})
user_data.setdefault("remembered_devices", [])

encrypted_keys = user_data["api_keys"]
user_chats = user_data["chats"]
active_api_keys = [decrypt_key(k) for k in encrypted_keys if decrypt_key(k)]

# Kiểm tra an toàn trạng thái cuộc trò chuyện hiện tại
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

    st.subheader("💬 Danh sách trò chuyện")
    
    # --- DANH SÁCH & XÓA CHAT (ĐÃ SỬA LỖI KEYERROR) ---
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

    # --- QUẢN LÝ API KEY ---
    st.subheader("🔑 Quản lý API Key (AES-256)")
    
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

    available_models = []
    if active_api_keys:
        try:
            genai.configure(api_key=active_api_keys[0])
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    available_models.append(m.name.replace('models/', ''))
        except Exception:
            pass

    selected_model = st.selectbox(
        "Chọn Model Gemini:", 
        options=available_models if available_models else ["gemini-1.5-flash"]
    )

# ==========================================
# 9. KHUNG CHAT CHÍNH VỚI HIỆU ỨNG LOADING
# ==========================================
st.markdown("<h1 class='main-header'>⚡ Nexus AI Online</h1>", unsafe_allow_html=True)

current_chat_title = "Cuộc trò chuyện mới"
current_summary = ""

# Lấy thông tin chat an toàn từ dictionary
if st.session_state.current_chat_id and st.session_state.current_chat_id in user_chats:
    chat_obj = user_chats.get(st.session_state.current_chat_id, {})
    current_chat_title = chat_obj.get("title", "Cuộc trò chuyện")
    current_summary = chat_obj.get("summary", "")

st.caption(f"Đang mở: **{current_chat_title}** | Tài khoản: **{st.session_state.user}**")

# Hiển thị bối cảnh tóm tắt nếu có
if current_summary:
    with st.expander("📝 Bối cảnh hội thoại cũ (Đã tóm tắt tiết kiệm Token)", expanded=False):
        st.info(current_summary)

if not active_api_keys:
    st.warning("👈 Vui lòng thêm ít nhất 1 Gemini API Key ở Sidebar để bắt đầu trò chuyện.")
    st.stop()

# Hiển thị lịch sử tin nhắn
for msg in st.session_state.messages:
    st.chat_message(msg["role"]).write(msg["content"])

# Nhập tin nhắn mới
if prompt := st.chat_input("Nhập câu hỏi của bạn cho Nexus AI..."):
    st.chat_message("user").write(prompt)
    st.session_state.messages.append({"role": "user", "content": prompt})

    # Tạo Chat ID mới nếu đang ở giao diện chat mới
    if not st.session_state.current_chat_id:
        new_cid = f"chat_{uuid.uuid4().hex[:8]}"
        st.session_state.current_chat_id = new_cid
        chat_title = prompt[:30] + "..." if len(prompt) > 30 else prompt
        user_chats[new_cid] = {
            "title": chat_title,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": "",
            "summarized_count": 0,
            "messages": st.session_state.messages
        }
    
    cid = st.session_state.current_chat_id
    
    # Kiểm tra và lấy chat_info an toàn
    if cid not in user_chats:
        user_chats[cid] = {
            "title": prompt[:30] + "..." if len(prompt) > 30 else prompt,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": "",
            "summarized_count": 0,
            "messages": st.session_state.messages
        }
    
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

    # --- KHUNG AI PHẢN HỒI KÈM HIỆU ỨNG LOADING VÒNG XOAY ---
    with st.chat_message("assistant"):
        loading_placeholder = st.empty()
        loading_placeholder.markdown("""
        <div class="ai-loading-box">
            <div class="spinner"></div>
            <div class="ai-loading-text">Nexus AI đang soạn câu trả lời cho bạn...</div>
        </div>
        """, unsafe_allow_html=True)
        
        placeholder = st.empty()
        full_response = ""
        success = False

        for current_key in active_api_keys:
            try:
                genai.configure(api_key=current_key)
                
                sys_instruction = None
                if current_summary:
                    sys_instruction = (
                        "Bối cảnh các lượt trò chuyện trước đó đã được tóm tắt như sau:\n"
                        f"{current_summary}\n\n"
                        "Hãy tiếp tục phản hồi dựa trên bối cảnh trên và 6 tin nhắn gần nhất."
                    )
                
                model_engine = genai.GenerativeModel(
                    selected_model, 
                    system_instruction=sys_instruction
                )

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
            
            # Cập nhật & lưu đồng bộ GitHub
            chat_info["messages"] = st.session_state.messages
            chat_info["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            user_chats[cid] = chat_info
            user_data["chats"] = user_chats
            db_data[st.session_state.user] = user_data
            
            GitHubStorage.save_db(db_data)
        else:
            st.error("❌ Không thể tạo phản hồi từ AI. Vui lòng kiểm tra lại API Key.")
