import os
import json
import time
import base64
import urllib.request
import urllib.error
from datetime import datetime

import streamlit as st

# ==========================================
# CẤU HÌNH AN TOÀN - BẢO MẬT TOKEN
# ==========================================
# Mã nguồn lấy Token từ Secrets/Environment Variables của hệ thống Cloud
# Tuyệt đối không dán trực tiếp token vào đây để tránh bị GitHub chặn Commit.
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", os.getenv("GITHUB_TOKEN", ""))
GITHUB_REPO = st.secrets.get("GITHUB_REPO", os.getenv("GITHUB_REPO", "username/your-repo-name"))
GITHUB_FILE_PATH = "data/users_encrypted.json"

GEMINI_API_KEY = st.secrets.get("GEMINI_API_KEY", os.getenv("GEMINI_API_KEY", ""))
OPENAI_API_KEY = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", ""))
OLLAMA_HOST = st.secrets.get("OLLAMA_HOST", os.getenv("OLLAMA_HOST", "http://localhost:11434"))

MAX_GUEST_LIMIT = 100

# ==========================================
# MODULE MÃ HÓA & GITHUB DB (CÁCH A)
# ==========================================
def xor_encrypt_decrypt(data_str: str, key: str = "SecretKey123") -> str:
    """Mã hóa / Giải mã chuỗi đơn giản sử dụng thuật toán XOR Hex"""
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
        """Tải và giải mã danh sách user từ GitHub Repo"""
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
        """Mã hóa và đẩy dữ liệu user lên GitHub Repo"""
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
# MODULE TỰ ĐỘNG CHỌN MODEL AI
# ==========================================
class AutoAIEngine:
    @staticmethod
    def generate_response(prompt: str) -> str:
        """Tự động chọn Model theo thứ tự ưu tiên (Không hiển thị selector trên UI)"""
        if GEMINI_API_KEY:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"
                payload = {"contents": [{"parts": [{"text": prompt}]}]}
                req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    res = json.loads(response.read().decode('utf-8'))
                    return res['candidates'][0]['content']['parts'][0]['text']
            except Exception:
                pass

        if OPENAI_API_KEY:
            try:
                url = "https://api.openai.com/v1/chat/completions"
                payload = {
                    "model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}]
                }
                headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {OPENAI_API_KEY}'}
                req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
                with urllib.request.urlopen(req, timeout=10) as response:
                    res = json.loads(response.read().decode('utf-8'))
                    return res['choices'][0]['message']['content']
            except Exception:
                pass

        try:
            url = f"{OLLAMA_HOST}/api/generate"
            payload = {"model": "llama2", "prompt": prompt, "stream": False}
            req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=3) as response:
                res = json.loads(response.read().decode('utf-8'))
                return res.get('response', '')
        except Exception:
            pass

        return f"[Cloud AI Engine] Phản hồi tự động cho câu hỏi: '{prompt}'. (Vui lòng điền GEMINI_API_KEY trong Streamlit Secrets để dùng AI thật)."

# ==========================================
# KHỞI TẠO SESSION STATE
# ==========================================
if "messages" not in st.session_state:
    st.session_state.messages = []

if "user" not in st.session_state:
    st.session_state.user = None

if "guest_timestamps" not in st.session_state:
    st.session_state.guest_timestamps = []

def check_guest_limit() -> bool:
    now = time.time()
    st.session_state.guest_timestamps = [t for t in st.session_state.guest_timestamps if now - t < 3600]
    return len(st.session_state.guest_timestamps) < MAX_GUEST_LIMIT

# ==========================================
# GIAO DIỆN STREAMLIT WEB APP
# ==========================================
st.set_page_config(page_title="Cloud AI Assistant", page_icon="🤖", layout="wide")

# Sidebar Manager
with st.sidebar:
    st.title("🤖 AI Cloud Workspace")
    
    if st.session_state.user:
        st.success(f"👤 **{st.session_state.user}**")
        st.caption("Trạng thái: Đã đăng nhập (Vô thời hạn)")
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

# Khung Chat chính
st.header("💬 Cloud AI Chat Terminal")

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

if prompt := st.chat_input("Nhập câu hỏi của bạn..."):
    if st.session_state.user is None:
        if not check_guest_limit():
            st.error("⚠️ Khách đã dùng hết 100 lượt chat trong 1 giờ qua! Vui lòng Đăng ký / Đăng nhập ở sidebar để tiếp tục.")
            st.stop()
        st.session_state.guest_timestamps.append(time.time())

    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Đang xử lý..."):
            response = AutoAIEngine.generate_response(prompt)
            st.markdown(response)

    st.session_state.messages.append({"role": "assistant", "content": response})
