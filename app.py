import os
import json
import time
import base64
import urllib.request
import urllib.error
from datetime import datetime
import streamlit as st
import requests

# ==========================================
# CẤU HÌNH BẢO MẬT (Lấy từ Streamlit Secrets)
# ==========================================
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", os.getenv("GITHUB_TOKEN", ""))
GITHUB_REPO = st.secrets.get("GITHUB_REPO", os.getenv("GITHUB_REPO", "username/your-repo-name"))
GITHUB_FILE_PATH = "data/users_encrypted.json"

# --- API KEYS (Lấy từ Streamlit Secrets) ---
# Bạn có thể set cả Groq và Gemini, hoặc chỉ một trong hai
GROQ_API_KEY = st.secrets.get("GROQ_API_KEY", os.getenv("GROQ_API_KEY", ""))
GEMINI_API_KEY = st.secrets.get("GEMINI_API_KEY", os.getenv("GEMINI_API_KEY", ""))

MAX_GUEST_LIMIT = 100

# ==========================================
# MODULE MÃ HÓA & GITHUB DB
# ==========================================
def xor_encrypt_decrypt(data_str: str, key: str = "SecretKey123") -> str:
    out = []
    for i, char in enumerate(data_str):
        key_c = key[i % len(key)]
        out.append(chr(ord(char) ^ ord(key_c)))
    return "".join(out)

def encode_to_hex(data_str: str) -> str:
    encrypted = xor_encrypt_decrypt(data_str)
    return encrypted.encode('utf-8').hex()

def decode_from_hex(hex_str: str) -> str:
    try:
        raw_str = bytes.fromhex(hex_str).decode('utf-8')
        return xor_encrypt_decrypt(raw_str)
    except Exception:
        return "{}"

class GitHubDB:
    @staticmethod
    def _headers():
        return {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "StreamlitCloudApp"
        }

    @classmethod
    def load_users(cls):
        if not GITHUB_TOKEN:
            st.error("⚠️ Chưa cấu hình GITHUB_TOKEN trong Streamlit Secrets!")
            return {}, None
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
        req = urllib.request.Request(url, headers=cls._headers())
        try:
            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode('utf-8'))
                sha = res_data.get("sha")
                content_b64 = res_data.get("content", "")
                raw_hex = base64.b64decode(content_b64).decode('utf-8').strip()
                decrypted_json_str = decode_from_hex(raw_hex)
                users = json.loads(decrypted_json_str)
                return users, sha
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {}, None
            return {}, None
        except Exception:
            return {}, None

    @classmethod
    def save_users(cls, users_dict, sha=None):
        if not GITHUB_TOKEN:
            st.error("⚠️ Chưa cấu hình GITHUB_TOKEN trong Streamlit Secrets!")
            return False
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
        json_str = json.dumps(users_dict, ensure_ascii=False)
        hex_data = encode_to_hex(json_str)
        content_b64 = base64.b64encode(hex_data.encode('utf-8')).decode('utf-8')
        
        payload = {
            "message": "Update user database via Streamlit Cloud",
            "content": content_b64
        }
        if sha:
            payload["sha"] = sha
            
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers=cls._headers(), method="PUT")
        try:
            with urllib.request.urlopen(req) as response:
                return response.status in (200, 201)
        except Exception as e:
            st.error(f"Lỗi kết nối GitHub: {e}")
            return False

# ==========================================
# MODULE TỰ ĐỘNG CHỌN MODEL AI (Groq -> Gemini -> Fallback)
# ==========================================
class AutoAIEngine:
    @staticmethod
    def generate_response(prompt: str, system_instruction: str = "") -> str:
        """Tự động chọn Model theo thứ tự ưu tiên: Groq -> Gemini -> Fallback"""
        
        # 1. Thử gọi Groq API (Ưu tiên hàng đầu)
        if GROQ_API_KEY:
            try:
                url = "https://api.groq.com/openai/v1/chat/completions"
                messages = []
                if system_instruction:
                    messages.append({"role": "system", "content": system_instruction})
                messages.append({"role": "user", "content": prompt})
                
                payload = {
                    "model": "llama3-70b-8192",  # Hoặc "mixtral-8x7b-32768", "gemma2-9b-it"
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 1024,
                }
                headers = {
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {GROQ_API_KEY}'
                }
                response = requests.post(url, json=payload, headers=headers, timeout=15)
                if response.status_code == 200:
                    return response.json()['choices'][0]['message']['content']
                else:
                    st.warning(f"Groq API Error: {response.status_code}")
            except Exception as e:
                st.warning(f"Groq API Exception: {str(e)}")

        # 2. Thử gọi Google Gemini API
        if GEMINI_API_KEY:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"
                payload = {
                    "contents": [{
                        "parts": [{"text": f"{system_instruction}\n\n{prompt}" if system_instruction else prompt}]
                    }]
                }
                headers = {'Content-Type': 'application/json'}
                response = requests.post(url, json=payload, headers=headers, timeout=15)
                if response.status_code == 200:
                    return response.json()['candidates'][0]['content']['parts'][0]['text']
                else:
                    st.warning(f"Gemini API Error: {response.status_code}")
            except Exception as e:
                st.warning(f"Gemini API Exception: {str(e)}")

        # 3. Fallback Engine
        return f"[Cloud AI Engine] Phản hồi tự động cho câu hỏi: '{prompt}'. (Vui lòng cấu hình GROQ_API_KEY hoặc GEMINI_API_KEY trong Streamlit Secrets để dùng AI thật)."

    @staticmethod
    def generate_title(prompt: str) -> str:
        """Sử dụng AI để đặt tiêu đề chat"""
        title_prompt = f"Dựa trên câu hỏi sau đây, hãy đặt một tiêu đề ngắn gọn, súc tích (từ 2 đến 5 từ) cho cuộc hội thoại. Chỉ trả ra tiêu đề thuần túy, không dấu ngoặc kép hoặc giải thích.\n\nCâu hỏi: {prompt}"
        response = AutoAIEngine.generate_response(title_prompt)
        # Làm sạch response để chỉ lấy tiêu đề
        return response.strip().replace('"', '').replace("'", "")[:50]

# ==========================================
# KHỞI TẠO SESSION STATE
# ==========================================
if "messages" not in st.session_state:
    st.session_state.messages = []

if "user" not in st.session_state:
    st.session_state.user = None

if "guest_timestamps" not in st.session_state:
    st.session_state.guest_timestamps = []

if "chat_title" not in st.session_state:
    st.session_state.chat_title = "Cuộc trò chuyện mới"

if "memory" not in st.session_state:
    st.session_state.memory = ""

if "title_set" not in st.session_state:
    st.session_state.title_set = False

def check_guest_limit() -> bool:
    now = time.time()
    st.session_state.guest_timestamps = [t for t in st.session_state.guest_timestamps if now - t < 3600]
    return len(st.session_state.guest_timestamps) < MAX_GUEST_LIMIT

def clear_chat():
    st.session_state.messages = []
    st.session_state.chat_title = "Cuộc trò chuyện mới"
    st.session_state.title_set = False
    st.rerun()

# ==========================================
# GIAO DIỆN STREAMLIT WEB APP
# ==========================================
st.set_page_config(page_title="Nexus AI Gateway", page_icon="🤖", layout="wide")

# Sidebar
with st.sidebar:
    st.title("🤖 Nexus AI Gateway")
    
    # Phần xác thực người dùng
    if st.session_state.user:
        st.success(f"👤 **{st.session_state.user}**")
        st.caption("Trạng thái: Đã đăng nhập")
        if st.button("Đăng xuất", use_container_width=True):
            st.session_state.user = None
            st.rerun()
    else:
        st.info("👤 **Chế độ: Khách (Guest)**")
        guest_count = len([t for t in st.session_state.guest_timestamps if time.time() - t < 3600])
        st.progress(guest_count / MAX_GUEST_LIMIT)
        st.caption(f"Lượt chat 1h qua: **{guest_count}/{MAX_GUEST_LIMIT}**")

        st.markdown("---")
        tab_login, tab_reg = st.tabs(["Đăng nhập", "Đăng ký"])

        with tab_login:
            login_user = st.text_input("Tài khoản", key="login_u")
            login_pass = st.text_input("Mật khẩu", type="password", key="login_p")
            if st.button("Đăng nhập", use_container_width=True):
                users, _ = GitHubDB.load_users()
                if login_user in users and users[login_user] == login_pass:
                    st.session_state.user = login_user
                    st.success("Đăng nhập thành công!")
                    st.rerun()
                else:
                    st.error("Tài khoản hoặc mật khẩu không chính xác!")

        with tab_reg:
            reg_user = st.text_input("Tài khoản mới", key="reg_u")
            reg_pass = st.text_input("Mật khẩu mới", type="password", key="reg_p")
            if st.button("Tạo tài khoản", use_container_width=True):
                if not reg_user or not reg_pass:
                    st.warning("Vui lòng điền đầy đủ thông tin.")
                else:
                    users, sha = GitHubDB.load_users()
                    if reg_user in users:
                        st.error("Tài khoản đã tồn tại!")
                    else:
                        users[reg_user] = reg_pass
                        if GitHubDB.save_users(users, sha):
                            st.session_state.user = reg_user
                            st.success("Đăng ký thành công & Lưu dữ liệu GitHub!")
                            st.rerun()
                        else:
                            st.error("Không thể ghi dữ liệu lên GitHub DB.")

    st.markdown("---")
    
    # Phần Memory (Ghi nhớ)
    st.subheader("🧠 Ghi nhớ (Memory)")
    st.caption("AI sẽ luôn ghi nhớ những thông tin này.")
    memory_input = st.text_area(
        "Nhập thông tin bạn muốn AI luôn nhớ:",
        value=st.session_state.memory,
        height=100,
        key="memory_input"
    )
    if memory_input != st.session_state.memory:
        st.session_state.memory = memory_input
    
    # Nút tạo chat mới
    if st.button("➕ Tạo cuộc trò chuyện mới", use_container_width=True):
        clear_chat()

# Chat chính
st.header(f"💬 {st.session_state.chat_title}")

# Hiển thị lịch sử chat
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Xử lý nhập tin nhắn
if prompt := st.chat_input("Nhập câu hỏi của bạn..."):
    # Kiểm tra hạn ngạch nếu là Khách
    if st.session_state.user is None:
        if not check_guest_limit():
            st.error("⚠️ Khách đã dùng hết 100 lượt chat trong 1 giờ qua! Vui lòng Đăng ký / Đăng nhập ở sidebar để tiếp tục.")
            st.stop()
        st.session_state.guest_timestamps.append(time.time())

    # Lưu và hiển thị câu hỏi
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Tự động đặt tên chat nếu là câu hỏi đầu tiên (chưa có tiêu đề)
    if len(st.session_state.messages) == 1 and not st.session_state.title_set:
        try:
            with st.spinner("Đang đặt tên cuộc trò chuyện..."):
                title = AutoAIEngine.generate_title(prompt)
                if title:
                    st.session_state.chat_title = title
                    st.session_state.title_set = True
        except Exception:
            pass

    # Gọi AI và hiển thị phản hồi
    with st.chat_message("assistant"):
        with st.spinner("Đang xử lý..."):
            # Lấy system instruction từ Memory
            system_instruction = st.session_state.memory
            response = AutoAIEngine.generate_response(prompt, system_instruction)
            st.markdown(response)
    
    st.session_state.messages.append({"role": "assistant", "content": response})
