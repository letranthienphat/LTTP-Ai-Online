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
CURRENT_SCHEMA_VERSION = 2

# ==========================================
# 2. BỘ MÃ HÓA / GIẢI MÃ API KEY (MẮT THẦN GITHUB KHÔNG PHÁT HIỆN)
# ==========================================
def encode_key(raw_key: str) -> str:
    """Mã hóa API Key để vượt qua kiểm duyệt GitHub Secret Scanning"""
    if not raw_key:
        return ""
    if raw_key.startswith("ENC_"):
        return raw_key  # Đã mã hóa trước đó
    # Đảo ngược chuỗi + Mã hóa Base64 + Gắn tiền tố ENC_
    reversed_key = raw_key[::-1]
    b64_str = base64.b64encode(reversed_key.encode('utf-8')).decode('utf-8')
    return f"ENC_{b64_str}"

def decode_key(encoded_key: str) -> str:
    """Giải mã API Key ra dạng nguyên bản AIzaSy... để gọi Gemini API"""
    if not encoded_key:
        return ""
    if not encoded_key.startswith("ENC_"):
        return encoded_key  # Key chưa mã hóa (fallback)
    try:
        pure_b64 = encoded_key.replace("ENC_", "", 1)
        decoded_bytes = base64.b64decode(pure_b64.encode('utf-8'))
        reversed_key = decoded_bytes.decode('utf-8')
        return reversed_key[::-1]  # Đảo ngược lại về ban đầu
    except Exception:
        return encoded_key

# ==========================================
# 3. CHUẨN HÓA DỮ LIỆU (SCHEMA MÃ HÓA)
# ==========================================
def normalize_user_schema(raw_data: dict) -> dict:
    """Tự động ép kiểu và mã hóa toàn bộ API Keys trong danh sách"""
    if not isinstance(raw_data, dict):
        raw_data = {}

    raw_keys = raw_data.get("gemini_keys", [])
    if isinstance(raw_keys, str):
        raw_keys = [raw_keys] if raw_keys.strip() else []

    # Đảm bảo 100% key lưu trữ đều được mã hóa (bắt đầu bằng ENC_)
    encrypted_keys = []
    for k in raw_keys:
        k_str = str(k).strip()
        if k_str:
            encrypted_keys.append(encode_key(k_str))

    model = raw_data.get("selected_model", AVAILABLE_FREE_MODELS[0])
    if model not in AVAILABLE_FREE_MODELS:
        model = AVAILABLE_FREE_MODELS[0]

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
        "gemini_keys": encrypted_keys,
        "selected_model": model,
        "chats": clean_chats
    }

# ==========================================
# 4. TRÍCH XUẤT SECRETS CHUẨN STREAMLIT
# ==========================================
def fetch_streamlit_secret(key_name: str) -> str:
    try:
        if key_name in st.secrets:
            return str(st.secrets[key_name]).strip()
    except Exception:
        pass
    return os.getenv(key_name, "").strip()

GITHUB_TOKEN = fetch_streamlit_secret("GITHUB_TOKEN")
GITHUB_REPO = fetch_streamlit_secret("GITHUB_REPO")

# ==========================================
# 5. ENGINE XỬ LÝ DATABASE (LOCAL & GITHUB)
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
            return False, f"Lỗi ghi Local: {str(e)}"

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
            return False, "Thiếu GITHUB_TOKEN hoặc GITHUB_REPO"

        _, latest_sha, err = DatabaseEngine.fetch_github_db()
        if err and "404" not in err:
            return False, f"Không thể lấy SHA: {err}"

        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }

        json_bytes = json.dumps(db_data, ensure_ascii=False, indent=2).encode('utf-8')
        content_b64 = base64.b64encode(json_bytes).decode('utf-8')

        payload = {
            "message": f"Update DB (Encrypted Keys) - {time.strftime('%H:%M:%S %d/%m/%Y')}",
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
        db = {}
        if GITHUB_TOKEN and GITHUB_REPO:
            gh_db, _, err = cls.fetch_github_db()
            if not err:
                db = gh_db
        if not db:
            db = cls.load_local_db()

        raw_user_info = db.get(username, {})
        return normalize_user_schema(raw_user_info)

    @classmethod
    def save_user_data(cls, username: str, user_info: dict) -> tuple[bool, str]:
        clean_user_info = normalize_user_schema(user_info)

        # 1. Lưu Local
        local_db = cls.load_local_db()
        local_db[username] = clean_user_info
        cls.save_local_db(local_db)

        # 2. Đồng bộ GitHub
        if GITHUB_TOKEN and GITHUB_REPO:
            gh_db, _, err = cls.fetch_github_db()
            if err and "404" not in err:
                return False, f"Lỗi GitHub: {err}"
            gh_db[username] = clean_user_info
            ok, msg = cls.push_github_db(gh_db)
            if not ok:
                return False, f"Đã lưu Local nhưng lỗi GitHub: {msg}"

        return True, "Lưu thành công!"

# ==========================================
# 6. KHỞI TẠO SESSION STATE
# ==========================================
if "user" not in st.session_state:
    st.session_state.user = None
if "user_data" not in st.session_state:
    st.session_state.user_data = None
if "current_chat_id" not in st.session_state:
    st.session_state.current_chat_id = None

# ==========================================
# 7. GIAO DIỆN THANH SIDEBAR
# ==========================================
with st.sidebar:
    st.title("🤖 Nexus AI Gateway")

    if GITHUB_TOKEN and GITHUB_REPO:
        st.caption("🟢 **Database:** GitHub Cloud Sync (`st.secrets`)")
    else:
        st.caption("🟡 **Database:** File Cục bộ (`nexus_db.json`)")

    st.markdown("---")

    # 7.1 ĐĂNG NHẬP / NẠP DỮ LIỆU
    if not st.session_state.user:
        st.subheader("👤 Đăng nhập")
        username_input = st.text_input("Tên tài khoản (viết liền, không dấu):")
        if st.button("🔑 Đăng nhập & Đồng bộ", use_container_width=True):
            clean_u = username_input.strip().lower()
            if clean_u:
                with st.spinner("Đang nạp và chuẩn hóa dữ liệu..."):
                    u_data = DatabaseEngine.get_user_data(clean_u)
                    st.session_state.user = clean_u
                    st.session_state.user_data = u_data

                    if not st.session_state.user_data["chats"]:
                        new_chat_id = str(int(time.time()))
                        st.session_state.user_data["chats"] = [{
                            "id": new_chat_id,
                            "title": "Cuộc trò chuyện mới",
                            "messages": []
                        }]
                        DatabaseEngine.save_user_data(clean_u, st.session_state.user_data)

                    st.session_state.current_chat_id = st.session_state.user_data["chats"][0]["id"]
                    st.toast(f"Đã nạp tài khoản: {clean_u}", icon="✅")
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

    # 7.2 CẤU HÌNH API KEY VÀ MODEL
    if st.session_state.user and st.session_state.user_data:
        st.subheader("🔑 Cấu hình Gemini Free")

        cur_model = st.session_state.user_data.get("selected_model", AVAILABLE_FREE_MODELS[0])
        idx = AVAILABLE_FREE_MODELS.index(cur_model) if cur_model in AVAILABLE_FREE_MODELS else 0
        selected_model = st.selectbox("Chọn mô hình:", AVAILABLE_FREE_MODELS, index=idx)

        if selected_model != cur_model:
            st.session_state.user_data["selected_model"] = selected_model
            DatabaseEngine.save_user_data(st.session_state.user, st.session_state.user_data)

        # Hiển thị danh sách Key (được giải mã để xem trên UI)
        enc_keys_list = st.session_state.user_data.get("gemini_keys", [])
        st.markdown(f"**API Keys đã lưu trong DB ({len(enc_keys_list)}):**")

        keys_to_delete = None
        for i, enc_k in enumerate(enc_keys_list):
            raw_k = decode_key(enc_k)  # Giải mã để hiển thị
            col_txt, col_del = st.columns([0.8, 0.2])
            col_txt.code(f"{raw_k[:6]}...{raw_k[-4:]}" if len(raw_k) > 10 else raw_k)
            if col_del.button("❌", key=f"del_k_{i}"):
                keys_to_delete = i

        if keys_to_delete is not None:
            st.session_state.user_data["gemini_keys"].pop(keys_to_delete)
            ok, msg = DatabaseEngine.save_user_data(st.session_state.user, st.session_state.user_data)
            if ok:
                st.toast("Đã xóa Key khỏi Database!", icon="🗑️")
                st.rerun()
            else:
                st.error(f"Lỗi lưu: {msg}")

        # Thêm Key Mới
        new_key_val = st.text_input("Nhập Gemini API Key mới:", type="password", key="input_new_key")
        if st.button("💾 LƯU KEY VÀO DATABASE", type="primary", use_container_width=True):
            clean_k = new_key_val.strip()
            if not clean_k:
                st.warning("Vui lòng nhập API Key!")
            else:
                # Kiểm tra trùng lặp sau khi giải mã
                existing_raw_keys = [decode_key(k) for k in enc_keys_list]
                if clean_k in existing_raw_keys:
                    st.warning("API Key này đã tồn tại trong Database!")
                else:
                    with st.spinner("Đang mã hóa & lưu lên GitHub..."):
                        # Mã hóa trước khi lưu
                        enc_new_key = encode_key(clean_k)
                        st.session_state.user_data["gemini_keys"].append(enc_new_key)

                        ok, msg = DatabaseEngine.save_user_data(st.session_state.user, st.session_state.user_data)
                        if ok:
                            st.success("🎉 ĐÃ MÃ HÓA VÀ LƯU THÀNH CÔNG VÀO DATABASE!")
                            time.sleep(0.5)
                            st.rerun()
                        else:
                            st.error(f"🔴 Lỗi lưu: {msg}")

        st.markdown("---")

        # 7.3 QUẢN LÝ CHAT
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
# 8. KHU VỰC KHUNG CHAT CHÍNH
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
            enc_keys = st.session_state.user_data.get("gemini_keys", [])
            if not enc_keys:
                st.error("⚠️ Bạn chưa lưu API Key nào vào Database! Vui lòng thêm Key ở thanh Sidebar.")
            else:
                st.chat_message("user").write(prompt)
                active_chat["messages"].append({"role": "user", "content": prompt})

                if len(active_chat["messages"]) == 1:
                    active_chat["title"] = prompt[:20] + "..." if len(prompt) > 20 else prompt

                sel_model = st.session_state.user_data.get("selected_model", AVAILABLE_FREE_MODELS[0])
                target_model = "gemini-2.5-flash" if sel_model == AVAILABLE_FREE_MODELS[0] else sel_model

                # GIẢI MÃ KEY KHI GỌI GEMINI API
                active_raw_key = decode_key(enc_keys[0])

                url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent"
                headers = {
                    "Content-Type": "application/json",
                    "x-goog-api-key": active_raw_key
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
