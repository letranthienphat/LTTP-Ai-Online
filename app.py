import os
import json
import time
import base64
import requests
import streamlit as st

# ==========================================
# 1. CẤU HÌNH TRANG & MODEL GEMINI FREE TIER
# ==========================================
st.set_page_config(
    page_title="Nexus AI Gateway",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

AVAILABLE_FREE_MODELS = [
    "🔄 Tự động chọn Model Free tốt nhất",
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-1.5-flash",
    "gemini-1.5-pro"
]

LOCAL_DB_FILE = "nexus_db.json"
GITHUB_FILE_PATH = "data/users_encrypted.json"
CURRENT_SCHEMA_VERSION = 1

# ==========================================
# 2. KHÓA CHUẨN CẤU TRÚC DỮ LIỆU (SCHEMA)
# ==========================================
def get_default_user_schema() -> dict:
    """Định nghĩa chuẩn cấu trúc JSON cố định cho 1 User"""
    return {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "gemini_keys": [],
        "selected_model": AVAILABLE_FREE_MODELS[0],
        "chats": []
    }

def normalize_user_schema(raw_data: dict) -> dict:
    """
    Ép dữ liệu đầu vào luôn tuân theo đúng 1 chuẩn duy nhất.
    Tự động sửa lỗi sai kiểu dữ liệu hoặc thiếu trường do các phiên bản cũ.
    """
    default_schema = get_default_user_schema()
    if not isinstance(raw_data, dict):
        raw_data = {}

    # 1. Chuẩn hóa gemini_keys (Bắt buộc là List các chuỗi đã strip)
    raw_keys = raw_data.get("gemini_keys", [])
    if isinstance(raw_keys, str):
        clean_keys = [raw_keys.strip()] if raw_keys.strip() else []
    elif isinstance(raw_keys, list):
        clean_keys = [str(k).strip() for k in raw_keys if str(k).strip()]
    else:
        clean_keys = []

    # 2. Chuẩn hóa selected_model
    model = raw_data.get("selected_model", default_schema["selected_model"])
    if model not in AVAILABLE_FREE_MODELS:
        model = default_schema["selected_model"]

    # 3. Chuẩn hóa danh sách chats
    chats = raw_data.get("chats", [])
    if not isinstance(chats, list):
        chats = []
    
    clean_chats = []
    for c in chats:
        if isinstance(c, dict) and "id" in c and "messages" in c:
            clean_chats.append({
                "id": str(c.get("id")),
                "title": str(c.get("title", "Cuộc trò chuyện mới")),
                "messages": c.get("messages", []) if isinstance(c.get("messages"), list) else []
            })

    return {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "gemini_keys": clean_keys,
        "selected_model": model,
        "chats": clean_chats
    }

# ==========================================
# 3. TRÍCH XUẤT SECRETS CHUẨN STREAMLIT
# ==========================================
def fetch_streamlit_secret(key_name: str) -> str:
    """Ưu tiên st.secrets, fallback sang os.getenv"""
    try:
        if key_name in st.secrets:
            return str(st.secrets[key_name]).strip()
    except Exception:
        pass
    val = os.getenv(key_name, "")
    return val.strip()

GITHUB_TOKEN = fetch_streamlit_secret("GITHUB_TOKEN")
GITHUB_REPO = fetch_streamlit_secret("GITHUB_REPO")  # Định dạng: username/repo-name

# ==========================================
# 4. ENGINE XỬ LÝ DATABASE (LOCAL & GITHUB)
# ==========================================
class DatabaseEngine:
    @staticmethod
    def load_local_db() -> dict:
        if os.path.exists(LOCAL_DB_FILE):
            try:
                with open(LOCAL_DB_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    @staticmethod
    def save_local_db(db_data: dict):
        try:
            with open(LOCAL_DB_FILE, "w", encoding="utf-8") as f:
                json.dump(db_data, f, ensure_ascii=False, indent=2)
            return True, None
        except Exception as e:
            return False, f"Lỗi ghi file local: {str(e)}"

    @staticmethod
    def fetch_github_db() -> tuple[dict, str, str]:
        if not GITHUB_TOKEN or not GITHUB_REPO:
            return {}, None, "Chưa cấu hình GITHUB_TOKEN/GITHUB_REPO"

        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        try:
            res = requests.get(url, headers=headers, params={"nocache": time.time()}, timeout=10)
            if res.status_code == 200:
                data = res.json()
                sha = data.get("sha")
                content_b64 = data.get("content", "").replace("\n", "").replace("\r", "")
                decoded = base64.b64decode(content_b64.encode('utf-8')).decode('utf-8')
                return json.loads(decoded), sha, None
            elif res.status_code == 404:
                return {}, None, None
            else:
                return {}, None, f"GitHub HTTP {res.status_code}: {res.text}"
        except Exception as e:
            return {}, None, str(e)

    @staticmethod
    def push_github_db(db_data: dict) -> tuple[bool, str]:
        if not GITHUB_TOKEN or not GITHUB_REPO:
            return False, "Thiếu GITHUB_TOKEN hoặc GITHUB_REPO trong Secrets"

        _, latest_sha, err = DatabaseEngine.fetch_github_db()
        if err and "404" not in err:
            return False, f"Không thể lấy SHA từ GitHub: {err}"

        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }

        json_bytes = json.dumps(db_data, ensure_ascii=False, indent=2).encode('utf-8')
        content_b64 = base64.b64encode(json_bytes).decode('utf-8')

        payload = {
            "message": f"Update DB Schema v{CURRENT_SCHEMA_VERSION} - {time.strftime('%H:%M:%S %d/%m/%Y')}",
            "content": content_b64
        }
        if latest_sha:
            payload["sha"] = latest_sha

        try:
            res = requests.put(url, headers=headers, json=payload, timeout=15)
            if res.status_code in [200, 201]:
                return True, "Thành công!"
            else:
                return False, f"GitHub HTTP {res.status_code}: {res.text}"
        except Exception as e:
            return False, f"Lỗi kết nối GitHub: {str(e)}"

    @classmethod
    def get_user_data(cls, username: str) -> dict:
        """Đọc và ÉP CHUẨN cấu hình ngay khi tải dữ liệu ra"""
        db = {}
        if GITHUB_TOKEN and GITHUB_REPO:
            gh_db, _, err = cls.fetch_github_db()
            if not err:
                db = gh_db
        if not db:
            db = cls.load_local_db()

        raw_user_info = db.get(username, {})
        # Tự động chuẩn hóa dữ liệu theo Schema cố định
        return normalize_user_schema(raw_user_info)

    @classmethod
    def save_user_data(cls, username: str, user_info: dict) -> tuple[bool, str]:
        """Đảm bảo chỉ lưu dữ liệu đã chuẩn hóa 100%"""
        clean_user_info = normalize_user_schema(user_info)

        # 1. Lưu Local
        local_db = cls.load_local_db()
        local_db[username] = clean_user_info
        cls.save_local_db(local_db)

        # 2. Đồng bộ GitHub
        if GITHUB_TOKEN and GITHUB_REPO:
            gh_db, _, err = cls.fetch_github_db()
            if err and "404" not in err:
                return False, f"Lỗi kết nối GitHub trước khi lưu: {err}"
            gh_db[username] = clean_user_info
            ok, msg = cls.push_github_db(gh_db)
            if not ok:
                return False, f"Đã lưu Local nhưng lỗi GitHub: {msg}"

        return True, "Lưu thành công!"

# ==========================================
# 5. KHỞI TẠO SESSION STATE
# ==========================================
if "user" not in st.session_state:
    st.session_state.user = None
if "user_data" not in st.session_state:
    st.session_state.user_data = None
if "current_chat_id" not in st.session_state:
    st.session_state.current_chat_id = None

# ==========================================
# 6. GIAO DIỆN THANH SIDEBAR
# ==========================================
with st.sidebar:
    st.title("🤖 Nexus AI Gateway")

    if GITHUB_TOKEN and GITHUB_REPO:
        st.caption("🟢 **Database:** GitHub Cloud Sync (`st.secrets`)")
    else:
        st.caption("🟡 **Database:** File Cục bộ (`nexus_db.json`)")

    st.markdown("---")

    # 6.1 ĐĂNG NHẬP / NẠP DỮ LIỆU
    if not st.session_state.user:
        st.subheader("👤 Đăng nhập")
        username_input = st.text_input("Tên tài khoản (viết liền, không dấu):")
        if st.button("🔑 Đăng nhập & Đồng bộ", use_container_width=True):
            clean_u = username_input.strip().lower()  # Ép chữ thường tránh lệch Username
            if clean_u:
                with st.spinner("Đang nạp và chuẩn hóa dữ liệu..."):
                    u_data = DatabaseEngine.get_user_data(clean_u)
                    st.session_state.user = clean_u
                    st.session_state.user_data = u_data

                    # Tạo phòng chat mặc định nếu danh sách trống
                    if not st.session_state.user_data["chats"]:
                        new_chat_id = str(int(time.time()))
                        st.session_state.user_data["chats"] = [{
                            "id": new_chat_id,
                            "title": "Cuộc trò chuyện mới",
                            "messages": []
                        }]
                        DatabaseEngine.save_user_data(clean_u, st.session_state.user_data)

                    st.session_state.current_chat_id = st.session_state.user_data["chats"][0]["id"]
                    st.toast(f"Đã nạp chuẩn hóa dữ liệu tài khoản: {clean_u}", icon="✅")
                    st.rerun()
            else:
                st.warning("Vui lòng nhập tên tài khoản.")
    else:
        st.success(f"👤 Tài khoản: **{st.session_state.user}**")
        if st.button("🚪 Đăng xuất", use_container_width=True):
            st.session_state.user = None
            st.session_state.user_data = None
            st.session_state.current_chat_id = None
            st.rerun()

    st.markdown("---")

    # 6.2 CẤU HÌNH API KEY VÀ MODEL
    if st.session_state.user and st.session_state.user_data:
        st.subheader("🔑 Cấu hình Gemini Free")

        # Selectbox Model
        cur_model = st.session_state.user_data.get("selected_model", AVAILABLE_FREE_MODELS[0])
        idx = AVAILABLE_FREE_MODELS.index(cur_model) if cur_model in AVAILABLE_FREE_MODELS else 0
        selected_model = st.selectbox("Chọn mô hình:", AVAILABLE_FREE_MODELS, index=idx)

        if selected_model != cur_model:
            st.session_state.user_data["selected_model"] = selected_model
            DatabaseEngine.save_user_data(st.session_state.user, st.session_state.user_data)

        # Hiển thị danh sách Key
        keys_list = st.session_state.user_data.get("gemini_keys", [])
        st.markdown(f"**API Keys đã lưu trong DB ({len(keys_list)}):**")

        keys_to_delete = None
        for i, k in enumerate(keys_list):
            col_txt, col_del = st.columns([0.8, 0.2])
            col_txt.code(f"{k[:6]}...{k[-4:]}" if len(k) > 10 else k)
            if col_del.button("❌", key=f"del_k_{i}"):
                keys_to_delete = i

        # Xóa Key
        if keys_to_delete is not None:
            updated_keys = [k for idx_k, k in enumerate(keys_list) if idx_k != keys_to_delete]
            st.session_state.user_data["gemini_keys"] = updated_keys
            ok, msg = DatabaseEngine.save_user_data(st.session_state.user, st.session_state.user_data)
            if ok:
                st.toast("Đã xóa Key và cập nhật Database!", icon="🗑️")
                st.rerun()
            else:
                st.error(f"Lỗi lưu: {msg}")

        # Thêm Key Mới
        new_key_val = st.text_input("Nhập Gemini API Key mới:", type="password", key="input_new_key")
        if st.button("💾 LƯU KEY VÀO DATABASE", type="primary", use_container_width=True):
            clean_k = new_key_val.strip()
            if not clean_k:
                st.warning("Vui lòng nhập API Key!")
            elif clean_k in keys_list:
                st.warning("API Key này đã tồn tại!")
            else:
                with st.spinner("Đang lưu chuẩn hóa lên Database..."):
                    st.session_state.user_data["gemini_keys"].append(clean_k)
                    ok, msg = DatabaseEngine.save_user_data(st.session_state.user, st.session_state.user_data)
                    if ok:
                        st.success("🎉 ĐÃ LƯU API KEY THÀNH CÔNG VÀO DATABASE!")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error(f"🔴 Lỗi lưu: {msg}")

        st.markdown("---")

        # 6.3 QUẢN LÝ DANH SÁCH CHAT
        st.subheader("💬 Danh sách Chat")
        if st.button("➕ Tạo hội thoại mới", use_container_width=True):
            new_id = str(int(time.time()))
            new_chat = {"id": new_id, "title": "Cuộc trò chuyện mới", "messages": []}
            st.session_state.user_data["chats"].insert(0, new_chat)
            st.session_state.current_chat_id = new_id

            DatabaseEngine.save_user_data(st.session_state.user, st.session_state.user_data)
            st.rerun()

        chats = st.session_state.user_data.get("chats", [])
        for c in chats:
            btn_style = "primary" if c["id"] == st.session_state.current_chat_id else "secondary"
            col_c1, col_c2 = st.columns([0.8, 0.2])
            if col_c1.button(f"💬 {c['title']}", key=f"chat_{c['id']}", type=btn_style, use_container_width=True):
                st.session_state.current_chat_id = c["id"]
                st.rerun()
            if col_c2.button("🗑️", key=f"del_chat_{c['id']}"):
                st.session_state.user_data["chats"] = [item for item in chats if item["id"] != c["id"]]
                if st.session_state.current_chat_id == c["id"]:
                    st.session_state.current_chat_id = st.session_state.user_data["chats"][0]["id"] if st.session_state.user_data["chats"] else None
                DatabaseEngine.save_user_data(st.session_state.user, st.session_state.user_data)
                st.rerun()

# ==========================================
# 7. KHU VỰC KHUNG CHAT CHÍNH
# ==========================================
st.title("💬 Nexus AI Chatbot")

if not st.session_state.user or not st.session_state.user_data:
    st.info("👈 Vui lòng nhập **Tên tài khoản** ở thanh Sidebar để tải dữ liệu.")
else:
    chats = st.session_state.user_data.get("chats", [])
    active_chat = None
    for c in chats:
        if c["id"] == st.session_state.current_chat_id:
            active_chat = c
            break

    if not active_chat and chats:
        active_chat = chats[0]
        st.session_state.current_chat_id = active_chat["id"]

    if active_chat:
        for msg in active_chat.get("messages", []):
            st.chat_message(msg["role"]).write(msg["content"])

        if prompt := st.chat_input("Nhập tin nhắn của bạn..."):
            user_keys = st.session_state.user_data.get("gemini_keys", [])
            if not user_keys:
                st.error("⚠️ Bạn chưa lưu API Key nào vào Database! Vui lòng thêm Key ở thanh Sidebar.")
            else:
                st.chat_message("user").write(prompt)
                active_chat["messages"].append({"role": "user", "content": prompt})

                if len(active_chat["messages"]) == 1:
                    active_chat["title"] = prompt[:20] + "..." if len(prompt) > 20 else prompt

                sel_model = st.session_state.user_data.get("selected_model", AVAILABLE_FREE_MODELS[0])
                target_model = "gemini-2.5-flash" if sel_model == AVAILABLE_FREE_MODELS[0] else sel_model

                # Lấy key đầu tiên và làm sạch khoảng trắng
                active_key = str(user_keys[0]).strip()

                # Endpoint và Header chuẩn xác thực theo x-goog-api-key
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent"
                headers = {
                    "Content-Type": "application/json",
                    "x-goog-api-key": active_key
                }

                with st.chat_message("assistant"):
                    with st.spinner(f"Đang xử lý với `{target_model}`..."):
                        try:
                            payload_contents = []
                            for m in active_chat["messages"]:
                                role_name = "model" if m["role"] == "assistant" else "user"
                                payload_contents.append({
                                    "role": role_name,
                                    "parts": [{"text": m["content"]}]
                                })

                            res = requests.post(url, headers=headers, json={"contents": payload_contents}, timeout=30)

                            if res.status_code == 200:
                                ans_text = res.json()['candidates'][0]['content']['parts'][0]['text']
                                st.write(ans_text)

                                active_chat["messages"].append({"role": "assistant", "content": ans_text})
                                DatabaseEngine.save_user_data(st.session_state.user, st.session_state.user_data)
                            else:
                                st.error(f"⚠️ Lỗi Gemini API (HTTP {res.status_code}): {res.text}")
                        except Exception as e:
                            st.error(f"Lỗi kết nối: {str(e)}")
