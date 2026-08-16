import os
import json
import time
import base64
import urllib.request
import urllib.error
import streamlit as st
import requests

# ==========================================
# CẤU HÌNH HỆ THỐNG & GITHUB DATABASE
# ==========================================
st.set_page_config(page_title="Nexus AI Gateway", page_icon="🤖", layout="wide")

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
    """Mã hóa chuỗi JSON sang Base64 chuẩn UTF-8"""
    return base64.b64encode(data_str.encode('utf-8')).decode('utf-8')

def decode_data(b64_str: str) -> str:
    """Giải mã chuỗi Base64 về JSON"""
    try:
        return base64.b64decode(b64_str.encode('utf-8')).decode('utf-8')
    except Exception:
        return "{}"

# ==========================================
# GITHUB DATABASE MANAGER (FIX 409 CONFLICT)
# ==========================================
class GitHubDB:
    @staticmethod
    def _headers():
        return {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "NexusAIGateway",
            "Cache-Control": "no-cache"
        }

    @classmethod
    def get_latest_sha(cls):
        """Lấy mã SHA trực tiếp từ GitHub server (Bỏ qua CDN Cache)"""
        if not GITHUB_TOKEN:
            return None
        # Thêm timestamp query parameter để chống GitHub CDN Cache SHA cũ
        timestamp = int(time.time() * 1000)
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}?t={timestamp}"
        req = urllib.request.Request(url, headers=cls._headers())
        try:
            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode('utf-8'))
                return res_data.get("sha")
        except Exception:
            return None

    @classmethod
    def load_users(cls):
        """Đọc dữ liệu người dùng từ GitHub DB"""
        if not GITHUB_TOKEN:
            return {}, None
        timestamp = int(time.time() * 1000)
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}?t={timestamp}"
        req = urllib.request.Request(url, headers=cls._headers())
        try:
            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode('utf-8'))
                sha = res_data.get("sha")
                content_b64 = res_data.get("content", "").replace("\n", "").replace("\r", "")
                raw_json_str = decode_data(content_b64)
                users = json.loads(raw_json_str)
                return users, sha
        except urllib.error.HTTPError as e:
            return {}, None
        except Exception:
            return {}, None

    @classmethod
    def save_users(cls, users_dict, max_retries=3):
        """Lưu dữ liệu lên GitHub với cơ chế xử lý lỗi 409 Conflict triệt để"""
        if not GITHUB_TOKEN:
            return False, "Chưa cấu hình GITHUB_TOKEN trong Streamlit Secrets!"

        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
        json_str = json.dumps(users_dict, ensure_ascii=False)
        content_b64 = encode_data(json_str)

        for attempt in range(max_retries):
            # Lấy SHA tươi mới nhất ngay trước khi gửi request
            fresh_sha = cls.get_latest_sha()
            
            payload = {
                "message": f"Update DB (attempt {attempt + 1})",
                "content": content_b64
            }
            if fresh_sha:
                payload["sha"] = fresh_sha

            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers=cls._headers(), method="PUT")

            try:
                with urllib.request.urlopen(req) as response:
                    if response.status in (200, 201):
                        res_data = json.loads(response.read().decode('utf-8'))
                        # Cập nhật SHA mới vừa lưu vào session_state
                        new_sha = res_data.get("content", {}).get("sha")
                        if new_sha:
                            st.session_state.db_sha = new_sha
                        return True, "Lưu dữ liệu thành công!"
            except urllib.error.HTTPError as e:
                if e.code == 409 and attempt < max_retries - 1:
                    # Nếu dính lỗi 409 Conflict, tạm dừng tăng dần để chờ GitHub xử lý xong commit trước
                    time.sleep(1.0 * (attempt + 1))
                    continue
                else:
                    return False, f"Lỗi GitHub API ({e.code}): {e.reason}"
            except Exception as e:
                return False, f"Lỗi hệ thống: {str(e)}"

        return False, "Lưu thất bại sau nhiều lần thử lại do xung đột dữ liệu."

# ==========================================
# MODULE AI ENGINE (Groq -> Gemini -> Fallback)
# ==========================================
class AutoAIEngine:
    @staticmethod
    def generate_response(prompt: str, system_instruction: str = "", groq_key: str = "", gemini_key: str = "") -> str:
        # 1. Thử gọi Groq API
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

        # 2. Thử gọi Gemini API
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
# KHỞI TẠO SESSION STATE & TỰ ĐỘNG ĐĂNG NHẬP
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
if "db_sha" not in st.session_state:
    st.session_state.db_sha = None

# Tự động đăng nhập qua Query Token
query_params = st.query_params
if st.session_state.user is None and "session_token" in query_params:
    saved_token = query_params["session_token"]
    try:
        decoded_user = decode_data(saved_token)
        if decoded_user:
            users, sha = GitHubDB.load_users()
            if decoded_user in users:
                st.session_state.user = decoded_user
                st.session_state.user_data = users[decoded_user]
                st.session_state.db_sha = sha
                if "chats" not in st.session_state.user_data:
                    st.session_state.user_data["chats"] = []
    except Exception:
        pass

# ==========================================
# HÀM TRỢ GIÚP ĐỒNG BỘ DỮ LIỆU SAFETY
# ==========================================
def save_current_user_to_db():
    if st.session_state.user:
        users, _ = GitHubDB.load_users()
        users[st.session_state.user] = st.session_state.user_data
        success, msg = GitHubDB.save_users(users)
        return success, msg
    return False, "Chưa đăng nhập"

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
        save_current_user_to_db()
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

    # --- KHU VỰC ĐĂNG NHẬP / ĐĂNG XUẤT ---
    if st.session_state.user:
        st.success(f"👤 **{st.session_state.user}**")
        if st.button("Đăng xuất", use_container_width=True):
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
            if st.button("Đăng nhập", use_container_width=True):
                users, sha = GitHubDB.load_users()
                if login_u in users and users[login_u].get("password") == login_p:
                    st.session_state.user = login_u
                    st.session_state.user_data = users[login_u]
                    st.session_state.db_sha = sha
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
            if st.button("Tạo tài khoản", use_container_width=True):
                if not reg_u or not reg_p:
                    st.warning("Vui lòng nhập đủ thông tin.")
                else:
                    users, _ = GitHubDB.load_users()
                    if reg_u in users:
                        st.error("Tài khoản đã tồn tại!")
                    else:
                        new_user_payload = {
                            "password": reg_p,
                            "groq_key": "",
                            "gemini_key": "",
                            "memory": "",
                            "chats": []
                        }
                        users[reg_u] = new_user_payload
                        success, msg = GitHubDB.save_users(users)
                        if success:
                            st.session_state.user = reg_u
                            st.session_state.user_data = new_user_payload
                            st.query_params["session_token"] = encode_data(reg_u)
                            st.toast("Đăng ký thành công!", icon="✅")
                            st.rerun()
                        else:
                            st.error(f"Đăng ký thất bại: {msg}")

    st.markdown("---")

    # --- KHU VỰC CẤU HÌNH API KEYS ---
    st.subheader("🔑 Cấu hình API Keys")
    if st.session_state.user:
        current_groq = st.session_state.user_data.get("groq_key", "")
        current_gemini = st.session_state.user_data.get("gemini_key", "")

        input_groq = st.text_input("Groq API Key", value=current_groq, type="password")
        input_gemini = st.text_input("Gemini API Key", value=current_gemini, type="password")

        if st.button("💾 Lưu API Keys", use_container_width=True):
            st.session_state.user_data["groq_key"] = input_groq.strip()
            st.session_state.user_data["gemini_key"] = input_gemini.strip()

            success, msg = save_current_user_to_db()
            if success:
                st.toast("Đã lưu API Keys thành công!", icon="✅")
            else:
                st.error(f"Lỗi lưu API Keys: {msg}")
    else:
        st.caption("Khách có thể nhập API Key tạm thời:")
        st.session_state.temp_guest_groq = st.text_input("Groq Key (Tạm thời)", type="password", value=st.session_state.temp_guest_groq)
        st.session_state.temp_guest_gemini = st.text_input("Gemini Key (Tạm thời)", type="password", value=st.session_state.temp_guest_gemini)

    st.markdown("---")

    # --- KHU VỰC MỤC GHI NHỚ (MEMORY) ---
    st.subheader("🧠 Bộ nhớ AI (Memory)")
    if st.session_state.user:
        current_mem = st.session_state.user_data.get("memory", "")
        input_mem = st.text_area("AI sẽ luôn ghi nhớ những điều này:", value=current_mem, height=100)
        if input_mem != current_mem:
            st.session_state.user_data["memory"] = input_mem
            save_current_user_to_db()
    else:
        st.caption("Tính năng Ghi nhớ dành riêng cho tài khoản Đăng nhập.")

    st.markdown("---")

    # --- KHU VỰC DANH SÁCH CUỘC HỘI THOẠI ---
    st.subheader("💬 Cuộc trò chuyện")
    if st.button("➕ Tạo hội thoại mới", use_container_width=True):
        create_new_chat()

    chats_list = get_active_chats()
    for chat in chats_list:
        col_title, col_del = st.columns([0.85, 0.15])
        with col_title:
            btn_style = "primary" if chat["id"] == st.session_state.current_chat_id else "secondary"
            if st.button(f"💬 {chat['title']}", key=f"btn_{chat['id']}", type=btn_style, use_container_width=True):
                st.session_state.current_chat_id = chat["id"]
                st.rerun()
        with col_del:
            if st.button("🗑️", key=f"del_{chat['id']}"):
                chats_list.remove(chat)
                if st.session_state.user:
                    save_current_user_to_db()
                if st.session_state.current_chat_id == chat["id"]:
                    st.session_state.current_chat_id = chats_list[0]["id"] if chats_list else None
                st.rerun()

# ==========================================
# KHU VỰC KHUNG CHAT CHÍNH (MAIN AREA)
# ==========================================
active_chat = get_current_chat()

if active_chat:
    st.header(f"💬 {active_chat['title']}")

    # Hiển thị lịch sử hội thoại
    for msg in active_chat["messages"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Xử lý khi người dùng nhập tin nhắn
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

        # Đổi tên tự động sau 3 lượt gửi câu hỏi của User
        user_msg_count = sum(1 for m in active_chat["messages"] if m["role"] == "user")
        if user_msg_count == 3 and not active_chat.get("title_set", False):
            with st.spinner("Đang tự động đặt tên cuộc trò chuyện..."):
                new_title = AutoAIEngine.generate_title(active_chat["messages"], active_groq, active_gemini)
                if new_title:
                    active_chat["title"] = new_title
                    active_chat["title_set"] = True

        # ĐỒNG BỘ NGHỆ AN DỮ LIỆU
        if st.session_state.user:
            save_current_user_to_db()

        st.rerun()
