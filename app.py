import os
import json
import time
import base64
import requests
import streamlit as st

# ==========================================
# 1. CẤU HÌNH TRANG & CÁC MODEL FREE TIER
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
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.7-flash"
]

LOCAL_DB_FILE = "nexus_db.json"
GITHUB_FILE_PATH = "data/users_encrypted.json"

# ==========================================
# 2. TRÍCH XUẤT SECRETS CHUẨN STREAMLIT
# ==========================================
def fetch_streamlit_secret(key_name: str) -> str:
    """
    Ưu tiên lấy key trực tiếp từ st.secrets (Streamlit Cloud Secrets / .streamlit/secrets.toml).
    Nếu không thấy thì fallback sang os.getenv (Biến môi trường OS).
    """
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
# 3. ENGINE XỬ LÝ DATABASE (LOCAL & GITHUB)
# ==========================================
class DatabaseEngine:
    @staticmethod
    def load_local_db() -> dict:
        """Đọc file database cục bộ nexus_db.json"""
        if os.path.exists(LOCAL_DB_FILE):
            try:
                with open(LOCAL_DB_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    @staticmethod
    def save_local_db(db_data: dict):
        """Ghi dữ liệu xuống file database cục bộ"""
        try:
            with open(LOCAL_DB_FILE, "w", encoding="utf-8") as f:
                json.dump(db_data, f, ensure_ascii=False, indent=2)
            return True, None
        except Exception as e:
            return False, f"Lỗi ghi file local: {str(e)}"

    @staticmethod
    def fetch_github_db() -> tuple[dict, str, str]:
        """Tải dữ liệu JSON và SHA tươi từ GitHub Repository"""
        if not GITHUB_TOKEN or not GITHUB_REPO:
            return {}, None, "Chưa cấu hình GITHUB_TOKEN hoặc GITHUB_REPO trong Streamlit Secrets"

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
                return {}, None, None  # File chưa tồn tại trên Repo
            else:
                return {}, None, f"GitHub HTTP {res.status_code}: {res.text}"
        except Exception as e:
            return {}, None, str(e)

    @staticmethod
    def push_github_db(db_data: dict) -> tuple[bool, str]:
        """Đẩy dữ liệu đè lên GitHub Repository với SHA tươi lấy trực tiếp"""
        if not GITHUB_TOKEN or not GITHUB_REPO:
            return False, "Thiếu GITHUB_TOKEN hoặc GITHUB_REPO trong Secrets"

        # Lấy SHA mới nhất từ GitHub ngay trước khi ghi
        _, latest_sha, err = DatabaseEngine.fetch_github_db()
        if err and "404" not in err:
            return False, f"Không thể đọc SHA từ GitHub: {err}"

        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }

        json_bytes = json.dumps(db_data, ensure_ascii=False, indent=2).encode('utf-8')
        content_b64 = base64.b64encode(json_bytes).decode('utf-8')

        payload = {
            "message": f"Update DB - {time.strftime('%H:%M:%S %d/%m/%Y')}",
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
        """Đọc dữ liệu của 1 user (Ưu tiên GitHub Sync, fallback sang Local DB)"""
        db = {}
        if GITHUB_TOKEN and GITHUB_REPO:
            gh_db, _, err = cls.fetch_github_db()
            if not err:
                db = gh_db
        if not db:
            db = cls.load_local_db()

        user_info = db.get(username, {})
        if "gemini_keys" not in user_info:
            user_info["gemini_keys"] = []
        if "selected_model" not in user_info:
            user_info["selected_model"] = AVAILABLE_FREE_MODELS[0]
        if "chats" not in user_info:
            user_info["chats"] = []
        return user_info

    @classmethod
    def save_user_data(cls, username: str, user_info: dict) -> tuple[bool, str]:
        """Lưu đồng thời xuống Local DB và GitHub"""
        # 1. Cập nhật Local DB
        local_db = cls.load_local_db()
        local_db[username] = user_info
        cls.save_local_db(local_db)

        # 2. Đồng bộ lên GitHub nếu đã cấu hình Secrets
        if GITHUB_TOKEN and GITHUB_REPO:
            gh_db, _, err = cls.fetch_github_db()
            if err and "404" not in err:
                return False, f"Lỗi đọc GitHub trước khi ghi: {err}"
            gh_db[username] = user_info
            ok, msg = cls.push_github_db(gh_db)
            if not ok:
                return False, f"Đã lưu Local nhưng lỗi GitHub: {msg}"

        return True, "Lưu thành công!"

# ==========================================
# 4. KHỞI TẠO SESSION STATE
# ==========================================
if "user" not in st.session_state:
    st.session_state.user = None
if "user_data" not in st.session_state:
    st.session_state.user_data = None
if "current_chat_id" not in st.session_state:
    st.session_state.current_chat_id = None

# ==========================================
# 5. GIAO DIỆN THANH SIDEBAR
# ==========================================
with st.sidebar:
    st.title("🤖 Nexus AI Gateway")

    # Báo trạng thái kết nối Database
    if GITHUB_TOKEN and GITHUB_REPO:
        st.caption("🟢 **Chế độ DB:** GitHub Cloud Sync (`st.secrets`)")
    else:
        st.caption("🟡 **Chế độ DB:** File Cục bộ (`nexus_db.json`)")

    st.markdown("---")

    # 5.1 ĐĂNG NHẬP / QUẢN LÝ TÀI KHOẢN
    if not st.session_state.user:
        st.subheader("👤 Đăng nhập / Chọn tài khoản")
        username_input = st.text_input("Tên tài khoản (để lưu dữ liệu):")
        if st.button("🔑 Đăng nhập / Tải dữ liệu", use_container_width=True):
            clean_u = username_input.strip()
            if clean_u:
                with st.spinner("Đang tải dữ liệu từ Database..."):
                    u_data = DatabaseEngine.get_user_data(clean_u)
                    st.session_state.user = clean_u
                    st.session_state.user_data = u_data

                    # Tạo hội thoại mặc định nếu chưa có
                    if not st.session_state.user_data["chats"]:
                        new_chat_id = str(int(time.time()))
                        st.session_state.user_data["chats"] = [{
                            "id": new_chat_id,
                            "title": "Cuộc trò chuyện mới",
                            "messages": []
                        }]
                        DatabaseEngine.save_user_data(clean_u, st.session_state.user_data)

                    st.session_state.current_chat_id = st.session_state.user_data["chats"][0]["id"]
                    st.toast(f"Xin chào {clean_u}!", icon="✅")
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

    # 5.2 CẤU HÌNH API KEY VÀ MODEL FREE
    if st.session_state.user:
        st.subheader("🔑 Cấu hình Gemini Free")

        # Chọn Model Free
        cur_model = st.session_state.user_data.get("selected_model", AVAILABLE_FREE_MODELS[0])
        idx = AVAILABLE_FREE_MODELS.index(cur_model) if cur_model in AVAILABLE_FREE_MODELS else 0
        selected_model = st.selectbox("Chọn mô hình Free Tier:", AVAILABLE_FREE_MODELS, index=idx)

        if selected_model != cur_model:
            st.session_state.user_data["selected_model"] = selected_model
            DatabaseEngine.save_user_data(st.session_state.user, st.session_state.user_data)

        # Danh sách API Key
        keys_list = st.session_state.user_data.get("gemini_keys", [])
        st.markdown(f"**API Keys đã lưu ({len(keys_list)}):**")

        keys_to_delete = None
        for i, k in enumerate(keys_list):
            col_txt, col_del = st.columns([0.8, 0.2])
            col_txt.code(f"{k[:6]}...{k[-4:]}" if len(k) > 10 else k)
            if col_del.button("❌", key=f"del_k_{i}"):
                keys_to_delete = i

        # Xóa Key khỏi Database
        if keys_to_delete is not None:
            updated_keys = [k for idx_k, k in enumerate(keys_list) if idx_k != keys_to_delete]
            temp_user_data = dict(st.session_state.user_data)
            temp_user_data["gemini_keys"] = updated_keys

            ok, msg = DatabaseEngine.save_user_data(st.session_state.user, temp_user_data)
            if ok:
                st.session_state.user_data["gemini_keys"] = updated_keys
                st.toast("Đã xóa Key thành công!", icon="🗑️")
                st.rerun()
            else:
                st.error(f"Xóa thất bại: {msg}")

        # Thêm Key Mới (Lưu nguyên tử)
        new_key_val = st.text_input("Nhập Gemini API Key mới:", type="password", key="input_new_key")
        if st.button("💾 THÊM & LƯU VÀO DATABASE", type="primary", use_container_width=True):
            clean_k = new_key_val.strip()
            if not clean_k:
                st.warning("Vui lòng nhập API Key!")
            elif clean_k in keys_list:
                st.warning("API Key này đã tồn tại trong danh sách!")
            else:
                with st.spinner("Đang lưu dữ liệu lên Database..."):
                    updated_keys = keys_list + [clean_k]
                    temp_user_data = dict(st.session_state.user_data)
                    temp_user_data["gemini_keys"] = updated_keys

                    # Chỉ cập nhật State khi Database xác nhận lưu thành công 100%
                    ok, msg = DatabaseEngine.save_user_data(st.session_state.user, temp_user_data)
                    if ok:
                        st.session_state.user_data["gemini_keys"] = updated_keys
                        st.success("🎉 ĐÃ LƯU API KEY THÀNH CÔNG VÀO DATABASE!")
                        time.sleep(0.8)
                        st.rerun()
                    else:
                        st.error(f"🔴 LƯU THẤT BẠI: {msg}")

        st.markdown("---")

        # 5.3 QUẢN LÝ QUẢN LÝ DANH SÁCH CHAT
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
# 6. KHU VỰC KHUNG CHAT CHÍNH
# ==========================================
st.title("💬 Nexus AI Chatbot")

if not st.session_state.user:
    st.info("👈 Vui lòng nhập **Tên tài khoản** ở thanh Sidebar để tải/lưu dữ liệu.")
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
        # Hiển thị tất cả tin nhắn cũ từ Database
        for msg in active_chat.get("messages", []):
            st.chat_message(msg["role"]).write(msg["content"])

        # Ô nhập câu hỏi mới
        if prompt := st.chat_input("Nhập tin nhắn của bạn..."):
            user_keys = st.session_state.user_data.get("gemini_keys", [])
            if not user_keys:
                st.error("⚠️ Bạn chưa lưu API Key nào vào Database! Vui lòng thêm Key bên Sidebar.")
            else:
                # 1. Cập nhật câu hỏi vào UI
                st.chat_message("user").write(prompt)
                active_chat["messages"].append({"role": "user", "content": prompt})

                # Đổi tiêu đề cuộc trò chuyện theo câu đầu tiên
                if len(active_chat["messages"]) == 1:
                    active_chat["title"] = prompt[:20] + "..." if len(prompt) > 20 else prompt

                # 2. Gọi Gemini REST API
                sel_model = st.session_state.user_data.get("selected_model", AVAILABLE_FREE_MODELS[0])
                target_model = "gemini-2.5-flash" if sel_model == AVAILABLE_FREE_MODELS[0] else sel_model
                active_key = user_keys[0]

                url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent?key={active_key}"

                with st.chat_message("assistant"):
                    with st.spinner(f"Đang xử lý với `{target_model}`..."):
                        try:
                            payload_contents = []
                            for m in active_chat["messages"]:
                                role_name = "model" if m["role"] == "assistant" else "user"
                                payload_contents.append({"role": role_name, "parts": [{"text": m["content"]}]})

                            res = requests.post(url, json={"contents": payload_contents}, timeout=30)

                            if res.status_code == 200:
                                ans_text = res.json()['candidates'][0]['content']['parts'][0]['text']
                                st.write(ans_text)

                                active_chat["messages"].append({"role": "assistant", "content": ans_text})

                                # 3. TỰ ĐỘNG LƯU CHAT VÀO DATABASE NGAY LẬP TỨC
                                ok, err_msg = DatabaseEngine.save_user_data(st.session_state.user, st.session_state.user_data)
                                if not ok:
                                    st.warning(f"⚠️ Tin nhắn đã hiển thị nhưng lưu DB thất bại: {err_msg}")
                            else:
                                st.error(f"Lỗi Gemini API ({res.status_code}): {res.text}")
                        except Exception as e:
                            st.error(f"Lỗi kết nối: {str(e)}")
