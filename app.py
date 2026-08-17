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
# CẤU HÌNH TRANG & CUSTOM CSS
# ==========================================
st.set_page_config(
    page_title="Nexus AI Gateway",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    * {
        transition: background-color 0.25s ease, border-color 0.25s ease, box-shadow 0.25s ease;
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .element-container, .stChatMessage, .stButton {
        animation: fadeIn 0.35s ease-out forwards;
    }

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

    .user-card {
        padding: 12px 16px;
        background: linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(168, 85, 247, 0.12) 100%);
        border: 1px solid rgba(168, 85, 247, 0.25);
        border-radius: 12px;
        margin-bottom: 12px;
    }

    .key-item {
        background: rgba(255, 255, 255, 0.05);
        padding: 6px 10px;
        border-radius: 8px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        font-family: monospace;
        margin-bottom: 4px;
    }

    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-thumb {
        background: rgba(156, 163, 175, 0.3);
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# CẤU HÌNH CƠ SỞ & DANH SÁCH MÔ HÌNH FREE TIER
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

AUTO_MODEL_OPTION = "🔄 Tự động chọn Model Free khả dụng"

# Chỉ giữ các mô hình có sẵn trong gói FREE TIER của Google AI Studio
AVAILABLE_GEMINI_FREE_MODELS = [
    AUTO_MODEL_OPTION,
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.7-flash"
]

# Ưu tiên các dòng Flash hoạt động ổn định trên Free Tier
AUTO_FALLBACK_ORDER = [
    "gemini-2.5-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.7-flash",
    "gemini-2.5-pro"
]

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

def normalize_user_data(data: dict) -> dict:
    if "gemini_keys" not in data:
        data["gemini_keys"] = []
        if "gemini_key" in data and data["gemini_key"].strip():
            data["gemini_keys"].append(data["gemini_key"].strip())
    if "selected_model" not in data:
        data["selected_model"] = AUTO_MODEL_OPTION
    if "memory" not in data:
        data["memory"] = ""
    if "chats" not in data:
        data["chats"] = []
    return data

# ==========================================
# QUẢN LÝ DATABASE RAM & ĐỒNG BỘ GITHUB CHÍNH XÁC
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
                
                for username in users:
                    users[username] = normalize_user_data(users[username])

                return users, sha, None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {}, None, None
            return {}, None, f"Lỗi HTTP ({e.code}): {e.reason}"
        except Exception as e:
            return {}, None, str(e)

    @classmethod
    def get_users_db(cls, force_reload=False):
        with cls._lock:
            if cls._users_cache is None or force_reload:
                users, _, err = cls._get_fresh_sha_and_data()
                if not err or "404" in str(err):
                    cls._users_cache = users
            return cls._users_cache.copy() if cls._users_cache else {}

    @classmethod
    def update_user_in_ram(cls, username, user_payload):
        with cls._lock:
            if cls._users_cache is None:
                cls._users_cache = {}
            cls._users_cache[username] = normalize_user_data(user_payload)

    @classmethod
    def sync_ram_to_github(cls, max_retries=3):
        with cls._lock:
            if not cls._users_cache:
                return True, "RAM trống."

            if not GITHUB_TOKEN:
                return False, "Chưa cấu hình GITHUB_TOKEN trong secrets!"

            for attempt in range(max_retries):
                _, fresh_sha, _ = cls._get_fresh_sha_and_data()

                json_str = json.dumps(cls._users_cache, ensure_ascii=False, indent=2)
                content_b64 = encode_data(json_str)

                url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
                payload = {
                    "message": f"Update user data & API Keys (Sync #{attempt + 1})",
                    "content": content_b64
                }
                if fresh_sha:
                    payload["sha"] = fresh_sha

                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(url, data=data, headers=cls._headers(), method="PUT")

                try:
                    with urllib.request.urlopen(req) as response:
                        if response.status in (200, 201):
                            return True, "Đã lưu thành công vào Database GitHub!"
                except urllib.error.HTTPError as e:
                    if e.code == 409:
                        time.sleep(1.0 * (attempt + 1))
                        continue
                    else:
                        return False, f"Lỗi GitHub API ({e.code}): {e.reason}"
                except Exception as e:
                    return False, f"Lỗi hệ thống: {str(e)}"

            return False, "Không thể lưu dữ liệu lên GitHub sau nhiều lần thử."

# ==========================================
# MODULE AI ENGINE (XỬ LÝ GEMINI FREE TIER)
# ==========================================
class AutoAIEngine:
    @staticmethod
    def _is_system_error_msg(content: str) -> bool:
        system_prefixes = [
            "⚠️ **Không thể kết nối Gemini API!**",
            "⚠️ **Chưa cấu hình Gemini API Key!**",
            "⚠️ Bạn đã dùng hết"
        ]
        return any(content.startswith(prefix) for prefix in system_prefixes)

    @staticmethod
    def _filter_valid_messages(messages: list) -> list:
        return [m for m in messages if not AutoAIEngine._is_system_error_msg(m.get("content", ""))]

    @staticmethod
    def _call_gemini_api(payload_contents: list, system_instruction: str, gemini_keys: list, selected_model: str) -> tuple[str, str]:
        models_to_try = AUTO_FALLBACK_ORDER if selected_model == AUTO_MODEL_OPTION else [selected_model]
        last_error = ""

        for key in gemini_keys:
            clean_key = key.strip()
            if not clean_key:
                continue

            for model in models_to_try:
                try:
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={clean_key}"
                    
                    payload = {"contents": payload_contents}
                    if system_instruction and system_instruction.strip():
                        payload["system_instruction"] = {
                            "parts": [{"text": system_instruction.strip()}]
                        }

                    headers = {'Content-Type': 'application/json'}
                    res = requests.post(url, json=payload, headers=headers, timeout=60)
                    
                    if res.status_code == 200:
                        data = res.json()
                        text = data['candidates'][0]['content']['parts'][0]['text']
                        return text, model
                    else:
                        try:
                            err_json = res.json()
                            err_msg = err_json.get("error", {}).get("message", res.text)
                        except Exception:
                            err_msg = res.text
                        last_error = f"Model `{model}` (HTTP {res.status_code}): {err_msg}"

                except Exception as e:
                    last_error = f"Lỗi kết nối ({model}): {str(e)}"

        return f"⚠️ **Không thể kết nối Gemini API!**\n\n`{last_error}`", ""

    @staticmethod
    def generate_response(active_chat: dict, system_instruction: str = "", gemini_keys: list = None, selected_model: str = AUTO_MODEL_OPTION) -> tuple[str, str]:
        if not gemini_keys or not any(k.strip() for k in gemini_keys):
            return "⚠️ **Chưa cấu hình Gemini API Key!** Vui lòng nhập API Key bên thanh Sidebar.", ""

        all_messages = active_chat.get("messages", [])
        valid_messages = AutoAIEngine._filter_valid_messages(all_messages)

        formatted_contents = []
        for msg in valid_messages:
            role = "model" if msg["role"] == "assistant" else "user"
            formatted_contents.append({
                "role": role,
                "parts": [{"text": msg["content"]}]
            })

        return AutoAIEngine._call_gemini_api(formatted_contents, system_instruction, gemini_keys, selected_model)

    @staticmethod
    def generate_title(chat_messages: list, gemini_keys: list = None, selected_model: str = AUTO_MODEL_OPTION) -> str:
        valid_messages = AutoAIEngine._filter_valid_messages(chat_messages)
        conversation_text = "\n".join([f"{m['role']}: {m['content']}" for m in valid_messages if m['role'] != 'system'])
        prompt = f"Đặt 1 tiêu đề ngắn gọn (2-5 từ) cho nội dung sau:\n\n{conversation_text}"
        payload = [{"role": "user", "parts": [{"text": prompt}]}]
        response_text, _ = AutoAIEngine._call_gemini_api(payload, "", gemini_keys, selected_model)
        clean_title = response_text.strip().replace('"', '').replace("'", "").replace("\n", "")[:40]
        return clean_title if clean_title and "Không thể kết nối" not in clean_title else "Cuộc trò chuyện mới"

# ==========================================
# KHỞI TẠO SESSION STATE
# ==========================================
if "user" not in st.session_state:
    st.session_state.user = None
if "user_data" not in st.session_state:
    st.session_state.user_data = normalize_user_data({})
if "current_chat_id" not in st.session_state:
    st.session_state.current_chat_id = None
if "guest_timestamps" not in st.session_state:
    st.session_state.guest_timestamps = []
if "temp_guest_gemini" not in st.session_state:
    st.session_state.temp_guest_gemini = ""
if "guest_model" not in st.session_state:
    st.session_state.guest_model = AUTO_MODEL_OPTION

query_params = st.query_params
if st.session_state.user is None and "session_token" in query_params:
    saved_token = query_params["session_token"]
    try:
        decoded_user = decode_data(saved_token)
        if decoded_user:
            users_db = GlobalRAMDatabase.get_users_db()
            if decoded_user in users_db:
                st.session_state.user = decoded_user
                st.session_state.user_data = normalize_user_data(users_db[decoded_user])
    except Exception:
        pass

def save_and_sync_user_data():
    """Hàm hỗ trợ lưu dữ liệu người dùng vào RAM và đẩy thẳng lên GitHub Database"""
    if st.session_state.user:
        GlobalRAMDatabase.update_user_in_ram(st.session_state.user, st.session_state.user_data)
        success, msg = GlobalRAMDatabase.sync_ram_to_github()
        return success, msg
    return False, "Chưa đăng nhập."

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
        save_and_sync_user_data()
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

    if st.session_state.user:
        st.markdown(f"""
        <div class="user-card">
            <span style="font-size: 0.85em; opacity: 0.8;">Đã đăng nhập</span><br>
            <strong style="font-size: 1.1em;">👤 {st.session_state.user}</strong>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚪 Đăng xuất", use_container_width=True):
            save_and_sync_user_data()
            st.session_state.user = None
            st.session_state.user_data = normalize_user_data({})
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
                    st.session_state.user_data = normalize_user_data(users_db[login_u])

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
                        new_user_payload = normalize_user_data({
                            "password": reg_p,
                            "gemini_keys": [],
                            "selected_model": AUTO_MODEL_OPTION,
                            "memory": "",
                            "chats": []
                        })
                        GlobalRAMDatabase.update_user_in_ram(reg_u, new_user_payload)
                        success, msg = GlobalRAMDatabase.sync_ram_to_github()
                        
                        if success:
                            st.session_state.user = reg_u
                            st.session_state.user_data = new_user_payload
                            st.query_params["session_token"] = encode_data(reg_u)
                            st.toast("Đăng ký thành công!", icon="✅")
                            st.rerun()
                        else:
                            st.error(f"Lỗi đăng ký: {msg}")

    st.markdown("---")

    # --- CẤU HÌNH API KEY VÀ MÔ HÌNH (LƯU TRỰC TIẾP VÀO DATABASE) ---
    with st.expander("🔑 Cấu hình Gemini API & Model Free", expanded=True if st.session_state.user else False):
        if st.session_state.user:
            current_model = st.session_state.user_data.get("selected_model", AUTO_MODEL_OPTION)
            model_index = AVAILABLE_GEMINI_FREE_MODELS.index(current_model) if current_model in AVAILABLE_GEMINI_FREE_MODELS else 0
            
            selected_model = st.selectbox("Chọn mô hình Free Tier:", AVAILABLE_GEMINI_FREE_MODELS, index=model_index)
            if selected_model != current_model:
                st.session_state.user_data["selected_model"] = selected_model
                save_and_sync_user_data()

            st.markdown("---")

            st.markdown("**API Keys đã lưu trong Database:**")
            gemini_keys = st.session_state.user_data.get("gemini_keys", [])

            if not gemini_keys:
                st.caption("⚠️ Chưa có API Key nào trong Database.")

            keys_to_remove = []
            for idx, k in enumerate(gemini_keys):
                col_k, col_del = st.columns([0.8, 0.2])
                masked_key = f"{k[:6]}...{k[-4:]}" if len(k) > 10 else "••••••••"
                col_k.markdown(f"<div class='key-item'>Key {idx+1}: {masked_key}</div>", unsafe_allow_html=True)
                if col_del.button("❌", key=f"del_key_{idx}"):
                    keys_to_remove.append(k)

            # Xóa Key và đồng bộ GitHub
            if keys_to_remove:
                for k in keys_to_remove:
                    gemini_keys.remove(k)
                st.session_state.user_data["gemini_keys"] = gemini_keys
                ok, err = save_and_sync_user_data()
                if ok:
                    st.toast("Đã xóa Key khỏi Database!", icon="🗑️")
                else:
                    st.error(f"Lỗi lưu: {err}")
                st.rerun()

            # Thêm Key mới và ghi ĐẶC BIỆT vào GitHub
            new_key_input = st.text_input("Nhập Gemini API Key mới:", type="password", key="add_new_key_input")
            if st.button("➕ Thêm Key Vào Database", use_container_width=True):
                clean_new_key = new_key_input.strip()
                if clean_new_key:
                    if clean_new_key not in gemini_keys:
                        gemini_keys.append(clean_new_key)
                        st.session_state.user_data["gemini_keys"] = gemini_keys
                        
                        # Ghi thẳng vào Database ngay tức thì
                        with st.spinner("Đang lưu API Key vào GitHub Database..."):
                            ok, err_msg = save_and_sync_user_data()
                        
                        if ok:
                            st.toast("Đã lưu API Key vào Database thành công!", icon="✅")
                            st.rerun()
                        else:
                            st.error(f"Lỗi khi lưu lên GitHub: {err_msg}")
                    else:
                        st.warning("API Key này đã tồn tại trong danh sách.")
                else:
                    st.warning("Vui lòng điền API Key hợp lệ.")
        else:
            guest_selected_model = st.selectbox("Chọn mô hình Free Tier:", AVAILABLE_GEMINI_FREE_MODELS, index=0)
            st.session_state.guest_model = guest_selected_model
            guest_key_input = st.text_input("Gemini Key (Khách)", type="password", value=st.session_state.temp_guest_gemini)
            st.session_state.temp_guest_gemini = guest_key_input.strip()

    # --- BỘ NHỚ AI (MEMORY) ---
    if st.session_state.user:
        with st.expander("🧠 Bộ nhớ AI (Memory)"):
            current_mem = st.session_state.user_data.get("memory", "")
            input_mem = st.text_area("Ghi nhớ cho AI:", value=current_mem, height=90)

            if st.button("💾 Lưu Bộ Nhớ", use_container_width=True):
                st.session_state.user_data["memory"] = input_mem
                ok, err = save_and_sync_user_data()
                if ok:
                    st.toast("Đã lưu bộ nhớ vào Database!", icon="✅")
                else:
                    st.error(f"Lỗi lưu: {err}")

    st.markdown("---")

    # --- DANH SÁCH CUỘC TRÒ CHUYỆN ---
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
                    save_and_sync_user_data()
                if st.session_state.current_chat_id == chat["id"]:
                    st.session_state.current_chat_id = chats_list[0]["id"] if chats_list else None
                st.rerun()

# ==========================================
# KHU VỰC KHUNG CHAT CHÍNH (MAIN AREA)
# ==========================================
active_chat = get_current_chat()

if active_chat:
    st.title(f"💬 {active_chat['title']}")

    for msg in active_chat["messages"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if prompt := st.chat_input("Nhập tin nhắn của bạn..."):
        if st.session_state.user is None:
            if not check_guest_limit():
                st.error("⚠️ Bạn đã dùng hết lượt chat cho Khách! Vui lòng Đăng nhập để tiếp tục.")
                st.stop()
            st.session_state.guest_timestamps.append(time.time())

        active_chat["messages"].append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        if st.session_state.user:
            active_keys = st.session_state.user_data.get("gemini_keys", [])
            active_model = st.session_state.user_data.get("selected_model", AUTO_MODEL_OPTION)
            system_mem = st.session_state.user_data.get("memory", "")
        else:
            active_keys = [st.session_state.temp_guest_gemini] if st.session_state.temp_guest_gemini else []
            active_model = st.session_state.get("guest_model", AUTO_MODEL_OPTION)
            system_mem = ""

        with st.chat_message("assistant"):
            with st.spinner("Đang phản hồi..."):
                response_text, used_model = AutoAIEngine.generate_response(
                    active_chat=active_chat,
                    system_instruction=system_mem,
                    gemini_keys=active_keys,
                    selected_model=active_model
                )
                st.markdown(response_text)
                if used_model and active_model == AUTO_MODEL_OPTION:
                    st.caption(f"⚡ *Model Free được sử dụng: `{used_model}`*")

        active_chat["messages"].append({"role": "assistant", "content": response_text})

        user_msg_count = sum(1 for m in active_chat["messages"] if m["role"] == "user")
        if user_msg_count == 2 and not active_chat.get("title_set", False):
            new_title = AutoAIEngine.generate_title(active_chat["messages"], active_keys, active_model)
            if new_title:
                active_chat["title"] = new_title
                active_chat["title_set"] = True

        if st.session_state.user:
            save_and_sync_user_data()

        st.rerun()
