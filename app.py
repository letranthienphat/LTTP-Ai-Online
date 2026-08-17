import os
import json
import time
import base64
import uuid
import threading
import urllib.request
import urllib.error
import streamlit as st
import requests

# ==========================================
# CẤU HÌNH TRANG & CUSTOM CSS (UI/UX SMOOTHING)
# ==========================================
st.set_page_config(
    page_title="Nexus AI Gateway",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Tối ưu giao diện đồ họa & hiệu ứng mượt
st.markdown("""
<style>
    /* Chuyển cảnh mượt cho toàn bộ ứng dụng */
    * {
        transition: background-color 0.25s ease, border-color 0.25s ease, box-shadow 0.25s ease;
    }

    /* Hiệu ứng mờ dần (Fade In) khi hiển thị phần tử mới */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .element-container, .stChatMessage, .stButton {
        animation: fadeIn 0.35s ease-out forwards;
    }

    /* Tối ưu nút bấm (Buttons) */
    div.stButton > button {
        border-radius: 10px !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        font-weight: 500 !important;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
    }

    div.stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15) !important;
    }

    div.stButton > button:active {
        transform: translateY(0) !important;
    }

    /* Tối ưu ô nhập liệu */
    .stTextInput input, .stTextArea textarea {
        border-radius: 10px !important;
        transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
    }

    .stTextInput input:focus, .stTextArea textarea:focus {
        box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.3) !important;
    }

    /* Card hiển thị trạng thái người dùng */
    .user-card {
        padding: 12px 16px;
        background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(168, 85, 247, 0.1) 100%);
        border: 1px solid rgba(168, 85, 247, 0.2);
        border-radius: 12px;
        margin-bottom: 12px;
    }

    /* Thanh cuộn mượt */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-thumb {
        background: rgba(156, 163, 175, 0.3);
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(156, 163, 175, 0.5);
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# CẤU HÌNH CƠ SỞ
# ==========================================
def get_admin_secret(key, default=""):
    try:
        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass
    return os.getenv(key, default)

GITHUB_TOKEN = get_admin_secret("GITHUB_TOKEN", "")
GITHUB_REPO = get_admin_secret("GITHUB_REPO", "username/repository-name")
GITHUB_FILE_PATH = "data/users_encrypted.json"
MAX_GUEST_LIMIT = 100

# ==========================================
# MODULE MÃ HÓA BASE64 (UTF-8 SAFE)
# ==========================================
def encode_data(data_str: str) -> str:
    return base64.b64encode(data_str.encode('utf-8')).decode('utf-8')

def decode_data(b64_str: str) -> str:
    try:
        return base64.b64decode(b64_str.encode('utf-8')).decode('utf-8')
    except Exception:
        return "{}"

# ==========================================
# BỘ QUẢN LÝ RAM & ĐỒNG BỘ CHỐNG LỖI 409
# ==========================================
class GlobalRAMDatabase:
    _lock = threading.Lock()
    _users_cache = None

    @staticmethod
    def _headers():
        return {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "NexusAIGateway",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }

    @classmethod
    def _get_fresh_sha_and_data(cls):
        """Lấy dữ liệu tươi từ GitHub, triệt tiêu CDN Cache bằng UUID"""
        if not GITHUB_TOKEN:
            return {}, None, "Chưa cấu hình GITHUB_TOKEN!"

        cache_buster = uuid.uuid4().hex
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}?nocache={cache_buster}"
        
        req = urllib.request.Request(url, headers=cls._headers())
        try:
            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode('utf-8'))
                sha = res_data.get("sha")
                content_b64 = res_data.get("content", "").replace("\n", "").replace("\r", "")
                raw_json_str = decode_data(content_b64)
                users = json.loads(raw_json_str) if raw_json_str else {}
                return users, sha, None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {}, None, None
            return {}, None, f"Lỗi HTTP ({e.code}): {e.reason}"
        except Exception as e:
            return {}, None, str(e)

    @classmethod
    def get_users_db(cls, force_reload=False):
        """Đọc dữ liệu từ RAM. Chỉ tải lại nếu chưa có cache hoặc yêu cầu cưỡng chế"""
        with cls._lock:
            if cls._users_cache is None or force_reload:
                users, _, err = cls._get_fresh_sha_and_data()
                if not err or "404" in str(err):
                    cls._users_cache = users
            return cls._users_cache.copy() if cls._users_cache else {}

    @classmethod
    def update_user_in_ram(cls, username, user_payload):
        """Cập nhật dữ liệu tức thì trên RAM (Không tốn thời gian chờ)"""
        with cls._lock:
            if cls._users_cache is None:
                cls._users_cache = {}
            cls._users_cache[username] = user_payload

    @classmethod
    def sync_ram_to_github(cls, max_retries=3):
        """Đồng bộ dữ liệu từ RAM lên GitHub với cơ chế xử lý 409 chủ động"""
        with cls._lock:
            if not cls._users_cache:
                return True, "RAM trống."

            if not GITHUB_TOKEN:
                return False, "Chưa cấu hình GITHUB_TOKEN!"

            for attempt in range(max_retries):
                _, fresh_sha, _ = cls._get_fresh_sha_and_data()

                json_str = json.dumps(cls._users_cache, ensure_ascii=False)
                content_b64 = encode_data(json_str)

                url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
                payload = {
                    "message": f"Update user data (Sync #{attempt + 1})",
                    "content": content_b64
                }
                if fresh_sha:
                    payload["sha"] = fresh_sha

                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(url, data=data, headers=cls._headers(), method="PUT")

                try:
                    with urllib.request.urlopen(req) as response:
                        if response.status in (200, 201):
                            return True, "Đã lưu thành công lên GitHub!"
                except urllib.error.HTTPError as e:
                    if e.code == 409:
                        time.sleep(1.0 * (attempt + 1))
                        continue
                    else:
                        return False, f"Lỗi GitHub API ({e.code}): {e.reason}"
                except Exception as e:
                    return False, f"Lỗi hệ thống: {str(e)}"

            return True, "Đã lưu tạm vào RAM server."

# ==========================================
# MODULE AI ENGINE (GROQ -> GEMINI -> FALLBACK)
# ==========================================
class AutoAIEngine:
    @staticmethod
    def generate_response(prompt: str, system_instruction: str = "", groq_key: str = "", gemini_key: str = "") -> str:
        if groq_key.strip():
            try:
                url = "https://api.groq.com/openai/v1/chat/completions"
                messages = []
                if system_instruction:
                    messages.append({"role": "system", "content": system_instruction})
                messages.append({"role": "user", "content": prompt})

                payload = {
                    "model": "llama-3.3-70b-versatile",
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 2048,
                }
                headers = {
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {groq_key.strip()}'
                }
                res = requests.post(url, json=payload, headers=headers, timeout=20)
                if res.status_code == 200:
                    return res.json()['choices'][0]['message']['content']
            except Exception:
                pass

        if gemini_key.strip():
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key.strip()}"
                combined_prompt = f"{system_instruction}\n\n{prompt}" if system_instruction else prompt
                payload = {"contents": [{"parts": [{"text": combined_prompt}]}]}
                headers = {'Content-Type': 'application/json'}
                res = requests.post(url, json=payload, headers=headers, timeout=20)
                if res.status_code == 200:
                    return res.json()['candidates'][0]['content']['parts'][0]['text']
            except Exception:
                pass

        return "⚠️ **Không thể kết nối API AI!** Vui lòng kiểm tra lại **Groq API Key** hoặc **Gemini API Key** bên thanh Sidebar."

    @staticmethod
    def generate_title(chat_messages: list, groq_key: str = "", gemini_key: str = "") -> str:
        conversation_text = "\n".join([f"{m['role']}: {m['content']}" for m in chat_messages if m['role'] != 'system'])
        prompt = f"Dựa trên nội dung cuộc hội thoại sau, hãy đặt một tiêu đề ngắn gọn (từ 2 đến 5 từ). Chỉ trả về duy nhất chuỗi tiêu đề:\n\n{conversation_text}"
        response = AutoAIEngine.generate_response(prompt, "", groq_key, gemini_key)
        clean_title = response.strip().replace('"', '').replace("'", "").replace("\n", "")[:40]
        return clean_title if clean_title and "Không thể kết nối" not in clean_title else "Cuộc trò chuyện mới"

# ==========================================
# KHỞI TẠO SESSION STATE & DỮ LIỆU
# ==========================================
if "user" not in st.session_state:
    st.session_state.user = None
if "user_data" not in st.session_state:
    st.session_state.user_data = {"groq_key": "", "gemini_key": "", "memory": "", "chats": []}
if "current_chat_id" not in st.session_state:
    st.session_state.current_chat_id = None
if "guest_timestamps" not in st.session_state:
    st.session_state.guest_timestamps = []
if "temp_guest_groq" not in st.session_state:
    st.session_state.temp_guest_groq = ""
if "temp_guest_gemini" not in st.session_state:
    st.session_state.temp_guest_gemini = ""

query_params = st.query_params
if st.session_state.user is None and "session_token" in query_params:
    saved_token = query_params["session_token"]
    try:
        decoded_user = decode_data(saved_token)
        if decoded_user:
            users_db = GlobalRAMDatabase.get_users_db()
            if decoded_user in users_db:
                st.session_state.user = decoded_user
                st.session_state.user_data = users_db[decoded_user]
                if "chats" not in st.session_state.user_data:
                    st.session_state.user_data["chats"] = []
    except Exception:
        pass

def save_user_state_to_ram():
    if st.session_state.user:
        GlobalRAMDatabase.update_user_in_ram(st.session_state.user, st.session_state.user_data)

def create_new_chat():
    chat_id = str(int(time.time() * 1000))
    new_chat = {
        "id": chat_id,
        "title": "Cuộc trò chuyện mới",
        "title_set": False,
        "messages": []
    }
    if st.session_state.user:
        st.session_state.user_data["chats"].insert(0, new_chat)
        st.session_state.current_chat_id = chat_id
        save_user_state_to_ram()
    else:
        if "guest_chats" not in st.session_state:
            st.session_state.guest_chats = []
        st.session_state.guest_chats.insert(0, new_chat)
        st.session_state.current_chat_id = chat_id
    st.rerun()

def get_active_chats():
    if st.session_state.user:
        return st.session_state.user_data.get("chats", [])
    return st.session_state.get("guest_chats", [])

def get_current_chat():
    chats = get_active_chats()
    for c in chats:
        if c["id"] == st.session_state.current_chat_id:
            return c
    return None

def check_guest_limit() -> bool:
    now = time.time()
    st.session_state.guest_timestamps = [t for t in st.session_state.guest_timestamps if now - t < 3600]
    return len(st.session_state.guest_timestamps) < MAX_GUEST_LIMIT

if not get_active_chats():
    create_new_chat()

if st.session_state.current_chat_id is None and get_active_chats():
    st.session_state.current_chat_id = get_active_chats()[0]["id"]

# ==========================================
# GIAO DIỆN THANH SIDEBAR
# ==========================================
with st.sidebar:
    st.title("🤖 Nexus AI Gateway")

    # Hiển thị thẻ người dùng
    if st.session_state.user:
        st.markdown(f"""
        <div class="user-card">
            <span style="font-size: 0.9em; opacity: 0.8;">Tài khoản đăng nhập</span><br>
            <strong style="font-size: 1.1em;">👤 {st.session_state.user}</strong>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚪 Đăng xuất", use_container_width=True):
            save_user_state_to_ram()
            GlobalRAMDatabase.sync_ram_to_github()
            st.session_state.user = None
            st.session_state.user_data = {"groq_key": "", "gemini_key": "", "memory": "", "chats": []}
            st.query_params.clear()
            st.rerun()
    else:
        st.info("👤 **Chế độ: Khách (Guest)**")
        guest_used = len([t for t in st.session_state.guest_timestamps if time.time() - t < 3600])
        st.progress(guest_used / MAX_GUEST_LIMIT)
        st.caption(f"Lượt chat 1h qua: **{guest_used}/{MAX_GUEST_LIMIT}**")

        tab_login, tab_reg = st.tabs(["Đăng nhập", "Đăng ký"])

        with tab_login:
            login_u = st.text_input("Tài khoản", key="l_u")
            login_p = st.text_input("Mật khẩu", type="password", key="l_p")
            remember_me = st.checkbox("Ghi nhớ đăng nhập", value=True)
            if st.button("🔑 Đăng nhập", use_container_width=True):
                users_db = GlobalRAMDatabase.get_users_db(force_reload=True)
                if login_u in users_db and users_db[login_u].get("password") == login_p:
                    st.session_state.user = login_u
                    st.session_state.user_data = users_db[login_u]
                    if "chats" not in st.session_state.user_data:
                        st.session_state.user_data["chats"] = []

                    if remember_me:
                        st.query_params["session_token"] = encode_data(login_u)
                    st.toast("Đăng nhập thành công!", icon="✅")
                    st.rerun()
                else:
                    st.error("Tài khoản hoặc mật khẩu không đúng!")

        with tab_reg:
            reg_u = st.text_input("Tài khoản mới", key="r_u")
            reg_p = st.text_input("Mật khẩu mới", type="password", key="r_p")
            if st.button("✨ Tạo tài khoản", use_container_width=True):
                if not reg_u or not reg_p:
                    st.warning("Vui lòng nhập đủ thông tin.")
                else:
                    users_db = GlobalRAMDatabase.get_users_db(force_reload=True)
                    if reg_u in users_db:
                        st.error("Tài khoản đã tồn tại!")
                    else:
                        new_user_payload = {
                            "password": reg_p,
                            "groq_key": "",
                            "gemini_key": "",
                            "memory": "",
                            "chats": []
                        }
                        GlobalRAMDatabase.update_user_in_ram(reg_u, new_user_payload)
                        success, msg = GlobalRAMDatabase.sync_ram_to_github()
                        
                        if success:
                            st.session_state.user = reg_u
                            st.session_state.user_data = new_user_payload
                            st.query_params["session_token"] = encode_data(reg_u)
                            st.toast("Đăng ký thành công!", icon="✅")
                            st.rerun()
                        else:
                            st.error(f"Đăng ký thất bại: {msg}")

    st.markdown("---")

    # Cấu hình API Keys trong Expander gọn gàng
    with st.expander("🔑 Cấu hình API Keys", expanded=True if st.session_state.user else False):
        if st.session_state.user:
            current_groq = st.session_state.user_data.get("groq_key", "")
            current_gemini = st.session_state.user_data.get("gemini_key", "")

            input_groq = st.text_input("Groq Key", value=current_groq, type="password")
            input_gemini = st.text_input("Gemini Key", value=current_gemini, type="password")

            if st.button("💾 Lưu API Keys", use_container_width=True):
                st.session_state.user_data["groq_key"] = input_groq.strip()
                st.session_state.user_data["gemini_key"] = input_gemini.strip()
                save_user_state_to_ram()

                success, msg = GlobalRAMDatabase.sync_ram_to_github()
                if success:
                    st.toast("Đã lưu API Keys!", icon="✅")
                else:
                    st.toast("Đã lưu tạm trên RAM", icon="⚡")
        else:
            st.session_state.temp_guest_groq = st.text_input("Groq Key (Tạm thời)", type="password", value=st.session_state.temp_guest_groq)
            st.session_state.temp_guest_gemini = st.text_input("Gemini Key (Tạm thời)", type="password", value=st.session_state.temp_guest_gemini)

    # Bộ nhớ AI trong Expander
    if st.session_state.user:
        with st.expander("🧠 Bộ nhớ AI (Memory)"):
            current_mem = st.session_state.user_data.get("memory", "")
            input_mem = st.text_area("Ghi nhớ của AI:", value=current_mem, height=90)

            if st.button("💾 Lưu Bộ Nhớ", use_container_width=True):
                st.session_state.user_data["memory"] = input_mem
                save_user_state_to_ram()
                success, msg = GlobalRAMDatabase.sync_ram_to_github()
                if success:
                    st.toast("Đã lưu bộ nhớ!", icon="✅")
                else:
                    st.toast("Đã lưu tạm trên RAM", icon="⚡")

    st.markdown("---")

    # Danh sách cuộc trò chuyện
    st.subheader("💬 Cuộc trò chuyện")
    if st.button("➕ Tạo hội thoại mới", use_container_width=True):
        create_new_chat()

    chats_list = get_active_chats()
    for chat in chats_list:
        col_title, col_del = st.columns([0.82, 0.18])
        with col_title:
            btn_style = "primary" if chat["id"] == st.session_state.current_chat_id else "secondary"
            if st.button(f"💬 {chat['title']}", key=f"btn_{chat['id']}", type=btn_style, use_container_width=True):
                st.session_state.current_chat_id = chat["id"]
                st.rerun()
        with col_del:
            if st.button("🗑️", key=f"del_{chat['id']}"):
                chats_list.remove(chat)
                if st.session_state.user:
                    save_user_state_to_ram()
                if st.session_state.current_chat_id == chat["id"]:
                    st.session_state.current_chat_id = chats_list[0]["id"] if chats_list else None
                st.rerun()

# ==========================================
# KHU VỰC KHUNG CHAT CHÍNH (MAIN AREA)
# ==========================================
active_chat = get_current_chat()

if active_chat:
    st.title(f"💬 {active_chat['title']}")

    # Render danh sách tin nhắn
    for msg in active_chat["messages"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if prompt := st.chat_input("Nhập tin nhắn của bạn..."):
        if st.session_state.user is None:
            if not check_guest_limit():
                st.error("⚠️ Bạn đã dùng hết 100 lượt chat cho Khách trong 1 giờ qua! Vui lòng Đăng nhập để tiếp tục.")
                st.stop()
            st.session_state.guest_timestamps.append(time.time())

        active_chat["messages"].append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        if st.session_state.user:
            active_groq = st.session_state.user_data.get("groq_key", "")
            active_gemini = st.session_state.user_data.get("gemini_key", "")
            system_mem = st.session_state.user_data.get("memory", "")
        else:
            active_groq = st.session_state.temp_guest_groq
            active_gemini = st.session_state.temp_guest_gemini
            system_mem = ""

        with st.chat_message("assistant"):
            with st.spinner("Đang suy nghĩ..."):
                response_text = AutoAIEngine.generate_response(prompt, system_mem, active_groq, active_gemini)
                st.markdown(response_text)

        active_chat["messages"].append({"role": "assistant", "content": response_text})

        # Tự động đặt tên tiêu đề ở tin nhắn thứ 3
        user_msg_count = sum(1 for m in active_chat["messages"] if m["role"] == "user")
        if user_msg_count == 3 and not active_chat.get("title_set", False):
            with st.spinner("Đang tự động đặt tên cuộc trò chuyện..."):
                new_title = AutoAIEngine.generate_title(active_chat["messages"], active_groq, active_gemini)
                if new_title:
                    active_chat["title"] = new_title
                    active_chat["title_set"] = True

        # Lưu ngay vào RAM (Zero latency & không bị gián đoạn giao diện)
        if st.session_state.user:
            save_user_state_to_ram()

        st.rerun()
