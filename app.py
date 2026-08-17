import os
import json
import time
import base64
import requests
import streamlit as st

# ==========================================
# 1. CẤU HÌNH TRANG & SECRETS
# ==========================================
st.set_page_config(page_title="Nexus AI Gateway", page_icon="🤖", layout="wide")

def get_secret(key, default=""):
    try:
        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass
    return os.getenv(key, default)

GITHUB_TOKEN = get_secret("GITHUB_TOKEN", "").strip()
GITHUB_REPO = get_secret("GITHUB_REPO", "").strip()  # Dạng: username/repo-name
GITHUB_FILE_PATH = "data/users_encrypted.json"

AVAILABLE_GEMINI_FREE_MODELS = [
    "🔄 Tự động chọn Model Free",
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.7-flash"
]

# ==========================================
# 2. ENGINE KẾT NỐI DATABASE GITHUB (CHUẨN XÁC)
# ==========================================
def github_get_db():
    """Lấy dữ liệu JSON và SHA mới nhất từ GitHub"""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        return {}, None, "Chưa cấu hình GITHUB_TOKEN hoặc GITHUB_REPO trong Secrets!"
    
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
        return {}, None, f"Lỗi kết nối: {str(e)}"

def github_save_db(full_db):
    """Ghi đè dữ liệu lên GitHub (Tự động lấy SHA tươi)"""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        return False, "Thiếu GITHUB_TOKEN hoặc GITHUB_REPO trong Secrets!"
    
    # Lấy SHA tươi ngay trước khi thực hiện ghi
    _, latest_sha, err = github_get_db()
    if err and "404" not in err:
        return False, f"Không thể đọc SHA từ GitHub: {err}"

    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    json_bytes = json.dumps(full_db, ensure_ascii=False, indent=2).encode('utf-8')
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
            return True, "Lưu thành công!"
        else:
            return False, f"Lỗi GitHub ({res.status_code}): {res.text}"
    except Exception as e:
        return False, f"Lỗi gửi dữ liệu: {str(e)}"

# ==========================================
# 3. KHỞI TẠO SESSION STATE
# ==========================================
if "user" not in st.session_state:
    st.session_state.user = None
if "user_data" not in st.session_state:
    st.session_state.user_data = {"gemini_keys": [], "selected_model": AVAILABLE_GEMINI_FREE_MODELS[0], "chats": []}
if "current_chat_id" not in st.session_state:
    st.session_state.current_chat_id = None

# ==========================================
# 4. GIAO DIỆN THANH SIDEBAR
# ==========================================
with st.sidebar:
    st.title("🤖 Nexus AI Gateway")

    # Tool kiểm tra kết nối GitHub
    with st.expander("🔍 Kiểm tra kết nối GitHub DB", expanded=False):
        st.write(f"**Repo:** `{GITHUB_REPO if GITHUB_REPO else 'Chưa điền'}`")
        if st.button("Kiểm tra quyền Ghi File", use_container_width=True):
            with st.spinner("Đang thử kết nối..."):
                db, sha, err = github_get_db()
                if err and "404" not in err:
                    st.error(f"❌ Thất bại: {err}")
                else:
                    st.success(f"✅ Kết nối thành công! (SHA: {sha if sha else 'File mới'})")

    st.markdown("---")

    # ĐĂNG NHẬP / TẢI DỮ LIỆU
    if not st.session_state.user:
        u_input = st.text_input("Tên tài khoản của bạn:")
        if st.button("🔑 Đăng nhập / Tải dữ liệu", use_container_width=True):
            if u_input.strip():
                with st.spinner("Đang lấy dữ liệu từ GitHub..."):
                    db, _, err = github_get_db()
                    if err and "404" not in err:
                        st.error(f"Lỗi tải DB: {err}")
                    else:
                        username = u_input.strip()
                        st.session_state.user = username
                        if username in db:
                            st.session_state.user_data = db[username]
                            st.toast("Đã tải dữ liệu từ Database!", icon="✅")
                        else:
                            # Tài khoản mới
                            st.session_state.user_data = {"gemini_keys": [], "selected_model": AVAILABLE_GEMINI_FREE_MODELS[0], "chats": []}
                            st.toast("Tạo tài khoản mới!", icon="ℹ️")
                        
                        # Tạo chat mặc định nếu trống
                        if not st.session_state.user_data.get("chats"):
                            new_chat_id = str(int(time.time()))
                            st.session_state.user_data["chats"] = [{"id": new_chat_id, "title": "Cuộc trò chuyện mới", "messages": []}]
                        st.session_state.current_chat_id = st.session_state.user_data["chats"][0]["id"]
                        st.rerun()
    else:
        st.success(f"👤 Tài khoản: **{st.session_state.user}**")
        if st.button("🚪 Đăng xuất", use_container_width=True):
            st.session_state.user = None
            st.session_state.user_data = {"gemini_keys": [], "selected_model": AVAILABLE_GEMINI_FREE_MODELS[0], "chats": []}
            st.rerun()

    st.markdown("---")

    # CẤU HÌNH API KEY VÀ MODEL
    st.subheader("🔑 Cấu hình API Key & Model")
    
    # Chọn Model
    current_model = st.session_state.user_data.get("selected_model", AVAILABLE_GEMINI_FREE_MODELS[0])
    idx = AVAILABLE_GEMINI_FREE_MODELS.index(current_model) if current_model in AVAILABLE_GEMINI_FREE_MODELS else 0
    selected_model = st.selectbox("Chọn mô hình Free Tier:", AVAILABLE_GEMINI_FREE_MODELS, index=idx)
    
    if selected_model != current_model and st.session_state.user:
        st.session_state.user_data["selected_model"] = selected_model
        db, _, _ = github_get_db()
        db[st.session_state.user] = st.session_state.user_data
        github_save_db(db)

    # Hiển thị Keys hiện tại
    keys_list = st.session_state.user_data.get("gemini_keys", [])
    st.markdown(f"**API Keys đã lưu ({len(keys_list)}):**")
    
    for i, k in enumerate(keys_list):
        col_txt, col_btn = st.columns([0.8, 0.2])
        col_txt.text(f"Key {i+1}: {k[:6]}...{k[-4:]}")
        if col_btn.button("❌", key=f"del_key_{i}"):
            if st.session_state.user:
                # Tạo bản sao thử nghiệm trước
                temp_keys = list(keys_list)
                temp_keys.pop(i)
                
                db, _, _ = github_get_db()
                temp_user_data = dict(st.session_state.user_data)
                temp_user_data["gemini_keys"] = temp_keys
                db[st.session_state.user] = temp_user_data
                
                ok, msg = github_save_db(db)
                if ok:
                    st.session_state.user_data["gemini_keys"] = temp_keys
                    st.toast("Đã xóa Key khỏi Database!", icon="🗑️")
                    st.rerun()
                else:
                    st.error(f"Không thể xóa trên GitHub: {msg}")

    # Nhập Key Mới
    new_key_input = st.text_input("Nhập Gemini API Key mới:", type="password", key="input_new_key")
    if st.button("💾 LƯU KEY VÀO DATABASE", type="primary", use_container_width=True):
        clean_k = new_key_input.strip()
        if not clean_k:
            st.warning("Vui lòng nhập API Key!")
        elif not st.session_state.user:
            st.error("Bạn chưa đăng nhập tài khoản ở trên!")
        elif clean_k in keys_list:
            st.warning("API Key này đã tồn tại trong danh sách!")
        else:
            with st.spinner("Đang ghi dữ liệu lên GitHub..."):
                # Lấy DB hiện tại từ GitHub
                db, _, err = github_get_db()
                if err and "404" not in err:
                    st.error(f"Lỗi đọc DB: {err}")
                else:
                    # Chuẩn bị dữ liệu cập nhật
                    temp_keys = list(keys_list) + [clean_k]
                    temp_user_data = dict(st.session_state.user_data)
                    temp_user_data["gemini_keys"] = temp_keys
                    db[st.session_state.user] = temp_user_data
                    
                    # Ghi lên GitHub
                    ok, msg = github_save_db(db)
                    if ok:
                        # CHỈ cập nhật RAM khi GitHub báo thành công 100%
                        st.session_state.user_data["gemini_keys"] = temp_keys
                        st.success("🎉 ĐÃ LƯU API KEY THÀNH CÔNG VÀO GITHUB!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(f"🔴 LƯU THẤT BẠI: {msg}")

    st.markdown("---")
    
    # DANH SÁCH CUỘC TRÒ CHUYỆN
    st.subheader("💬 Danh sách Chat")
    if st.button("➕ Tạo hội thoại mới", use_container_width=True):
        if st.session_state.user:
            new_id = str(int(time.time()))
            st.session_state.user_data["chats"].insert(0, {"id": new_id, "title": "Cuộc trò chuyện mới", "messages": []})
            st.session_state.current_chat_id = new_id
            
            db, _, _ = github_get_db()
            db[st.session_state.user] = st.session_state.user_data
            github_save_db(db)
            st.rerun()

    chats = st.session_state.user_data.get("chats", [])
    for c in chats:
        btn_type = "primary" if c["id"] == st.session_state.current_chat_id else "secondary"
        if st.button(f"💬 {c['title']}", key=f"chat_btn_{c['id']}", type=btn_type, use_container_width=True):
            st.session_state.current_chat_id = c["id"]
            st.rerun()

# ==========================================
# 5. KHU VỰC KHUNG CHAT CHÍNH
# ==========================================
st.title("💬 Nexus AI Chatbot")

if not st.session_state.user:
    st.info("👈 Vui lòng nhập **Tên tài khoản** ở thanh Sidebar để Bắt đầu & Lưu dữ liệu.")
else:
    # Tìm chat hiện tại
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
        # Hiển thị tin nhắn lịch sử
        for msg in active_chat.get("messages", []):
            st.chat_message(msg["role"]).write(msg["content"])

        # Nhập tin nhắn mới
        if prompt := st.chat_input("Nhập câu hỏi của bạn..."):
            user_keys = st.session_state.user_data.get("gemini_keys", [])
            if not user_keys:
                st.error("⚠️ Bạn chưa lưu API Key nào vào Database! Vui lòng thêm Key bên Sidebar.")
            else:
                # 1. Hiển thị & Lưu tin nhắn User
                st.chat_message("user").write(prompt)
                active_chat["messages"].append({"role": "user", "content": prompt})

                # Tự đổi tiêu đề chat nếu là câu đầu tiên
                if len(active_chat["messages"]) == 1:
                    active_chat["title"] = prompt[:20] + "..."

                # 2. Gọi Gemini API
                active_key = user_keys[0]
                model_name = "gemini-2.5-flash" if selected_model == "🔄 Tự động chọn Model Free" else selected_model
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={active_key}"

                with st.chat_message("assistant"):
                    with st.spinner(f"Đang suy nghĩ ({model_name})..."):
                        try:
                            # Chuyển lịch sử sang định dạng Gemini
                            contents = []
                            for m in active_chat["messages"]:
                                r = "model" if m["role"] == "assistant" else "user"
                                contents.append({"role": r, "parts": [{"text": m["content"]}]})

                            res = requests.post(url, json={"contents": contents}, timeout=30)
                            if res.status_code == 200:
                                ans_text = res.json()['candidates'][0]['content']['parts'][0]['text']
                                st.write(ans_text)
                                active_chat["messages"].append({"role": "assistant", "content": ans_text})

                                # 3. LƯU TOÀN BỘ CHAT VÀO GITHUB DATABASE NGAY LẬP TỨC
                                db, _, _ = github_get_db()
                                db[st.session_state.user] = st.session_state.user_data
                                ok, msg_err = github_save_db(db)
                                if not ok:
                                    st.warning(f"⚠️ Tin nhắn đã hiện nhưng chưa lưu được lên GitHub: {msg_err}")
                            else:
                                st.error(f"Lỗi Gemini API ({res.status_code}): {res.text}")
                        except Exception as e:
                            st.error(f"Lỗi kết nối: {str(e)}")
