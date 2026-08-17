import os
import json
import time
import base64
import requests
import streamlit as st

# ==========================================
# CẤU HÌNH TRANG
# ==========================================
st.set_page_config(
    page_title="Nexus AI Gateway",
    page_icon="🤖",
    layout="wide"
)

# ==========================================
# LẤY SECRETS & CẤU HÌNH GITHUB
# ==========================================
def get_secret(key, default=""):
    try:
        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass
    return os.getenv(key, default)

GITHUB_TOKEN = get_secret("GITHUB_TOKEN", "")
GITHUB_REPO = get_secret("GITHUB_REPO", "") # Ví dụ: username/repo-name
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
# CÁC HÀM XỬ LÝ GITHUB DATABASE (TRỰC TIẾP)
# ==========================================
def github_get_file():
    """Tải dữ liệu mới nhất và SHA từ GitHub API"""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        return {}, None, "Chưa cấu hình GITHUB_TOKEN hoặc GITHUB_REPO trong Secrets!"
    
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        res = requests.get(url, headers=headers, params={"t": time.time()}, timeout=10)
        if res.status_code == 200:
            data = res.json()
            sha = data.get("sha")
            content_b64 = data.get("content", "")
            decoded_str = base64.b64decode(content_b64.encode('utf-8')).decode('utf-8')
            return json.loads(decoded_str), sha, None
        elif res.status_code == 404:
            return {}, None, None # File chưa tồn tại
        else:
            return {}, None, f"Lỗi GitHub ({res.status_code}): {res.text}"
    except Exception as e:
        return {}, None, f"Lỗi kết nối: {str(e)}"

def github_save_file(data_dict):
    """Ghi đè dữ liệu trực tiếp lên GitHub Repository"""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        return False, "Thiếu GITHUB_TOKEN hoặc GITHUB_REPO trong Secrets!"

    # 1. Lấy SHA mới nhất trước khi ghi
    _, current_sha, err = github_get_file()
    if err and "404" not in err:
        return False, f"Không thể lấy SHA để ghi: {err}"

    # 2. Mã hóa dữ liệu sang Base64
    json_bytes = json.dumps(data_dict, ensure_ascii=False, indent=2).encode('utf-8')
    content_b64 = base64.b64encode(json_bytes).decode('utf-8')

    # 3. Đẩy lên GitHub
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE_PATH}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    payload = {
        "message": "Update user API Keys & Data",
        "content": content_b64
    }
    if current_sha:
        payload["sha"] = current_sha

    try:
        res = requests.put(url, headers=headers, json=payload, timeout=15)
        if res.status_code in [200, 201]:
            return True, "Thành công!"
        else:
            return False, f"GitHub từ chối ({res.status_code}): {res.text}"
    except Exception as e:
        return False, f"Lỗi gửi dữ liệu: {str(e)}"

# ==========================================
# INIT SESSION STATE
# ==========================================
if "user" not in st.session_state:
    st.session_state.user = None
if "user_data" not in st.session_state:
    st.session_state.user_data = {"gemini_keys": [], "selected_model": AVAILABLE_GEMINI_FREE_MODELS[0], "chats": []}

# ==========================================
# SIDEBAR GIAO DIỆN
# ==========================================
with st.sidebar:
    st.title("🤖 Nexus AI Gateway")

    # Báo trạng thái kết nối GitHub
    if not GITHUB_TOKEN or not GITHUB_REPO:
        st.error("⚠️ Bạn chưa điền `GITHUB_TOKEN` hoặc `GITHUB_REPO` vào Streamlit Secrets!")

    # ĐĂNG NHẬP / ĐĂNG KÝ SIMPLE
    if not st.session_state.user:
        u_input = st.text_input("Tên tài khoản (để lưu dữ liệu):")
        if st.button("🔑 Đăng nhập / Tải dữ liệu", use_container_width=True):
            if u_input.strip():
                with st.spinner("Đang kết nối Database GitHub..."):
                    db, _, err = github_get_file()
                    if err:
                        st.error(err)
                    else:
                        st.session_state.user = u_input.strip()
                        if u_input in db:
                            st.session_state.user_data = db[u_input]
                            st.success("Đã tải dữ liệu của bạn từ GitHub!")
                        else:
                            # Tài khoản mới
                            st.session_state.user_data = {"gemini_keys": [], "selected_model": AVAILABLE_GEMINI_FREE_MODELS[0], "chats": []}
                            st.info("Đã tạo tài khoản tạm thời mới.")
                        st.rerun()
    else:
        st.success(f"👤 Tài khoản: **{st.session_state.user}**")
        if st.button("🚪 Đăng xuất", use_container_width=True):
            st.session_state.user = None
            st.rerun()

    st.markdown("---")

    # KHU VỰC CẤU HÌNH API KEY VÀ MODEL
    st.subheader("🔑 API Key & Model Free")
    
    # Chọn Model
    current_model = st.session_state.user_data.get("selected_model", AVAILABLE_GEMINI_FREE_MODELS[0])
    idx = AVAILABLE_GEMINI_FREE_MODELS.index(current_model) if current_model in AVAILABLE_GEMINI_FREE_MODELS else 0
    selected_model = st.selectbox("Chọn mô hình Free Tier:", AVAILABLE_GEMINI_FREE_MODELS, index=idx)
    st.session_state.user_data["selected_model"] = selected_model

    # Danh sách Keys hiện tại
    keys_list = st.session_state.user_data.get("gemini_keys", [])
    st.markdown(f"**Số Key hiện có:** `{len(keys_list)}`")

    for i, k in enumerate(keys_list):
        col_txt, col_btn = st.columns([0.8, 0.2])
        col_txt.text(f"Key {i+1}: {k[:6]}...{k[-4:]}")
        if col_btn.button("❌", key=f"del_{i}"):
            keys_list.pop(i)
            st.session_state.user_data["gemini_keys"] = keys_list
            
            # Lưu ngay khi xóa
            if st.session_state.user:
                db, _, _ = github_get_file()
                db[st.session_state.user] = st.session_state.user_data
                ok, msg = github_save_file(db)
                if ok:
                    st.toast("Đã xóa Key và cập nhật GitHub!", icon="✅")
                else:
                    st.error(f"Lỗi lưu GitHub: {msg}")
            st.rerun()

    # Thêm Key Mới
    new_key = st.text_input("Nhập API Key mới:", type="password")
    if st.button("💾 THÊM & LƯU LÊN DATABASE", type="primary", use_container_width=True):
        clean_k = new_key.strip()
        if not clean_k:
            st.warning("Vui lòng nhập API Key!")
        elif not st.session_state.user:
            st.error("Bạn phải điền tên tài khoản ở trên trước khi lưu!")
        else:
            if clean_k not in keys_list:
                keys_list.append(clean_k)
                st.session_state.user_data["gemini_keys"] = keys_list

                # ĐẨY THẲNG LÊN GITHUB NGAY LẬP TỨC
                with st.spinner("Đang gửi yêu cầu Commit lên GitHub..."):
                    db, _, err_get = github_get_file()
                    db[st.session_state.user] = st.session_state.user_data
                    
                    ok, msg = github_save_file(db)
                    if ok:
                        st.success("🎉 ĐÃ LƯU THÀNH CÔNG LÊN GITHUB DATABASE!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(f"🔴 KHÔNG THỂ LƯU LÊN GITHUB: {msg}")
            else:
                st.warning("Key này đã có trong danh sách.")

# ==========================================
# KHU VỰC HỎI ĐÁP
# ==========================================
st.title("💬 Chatbot AI")
user_keys = st.session_state.user_data.get("gemini_keys", [])

if not user_keys:
    st.info("👈 Hãy đăng nhập và thêm ít nhất 1 Gemini API Key bên thanh Sidebar để bắt đầu.")
else:
    prompt = st.chat_input("Nhập câu hỏi của bạn...")
    if prompt:
        st.chat_message("user").write(prompt)
        
        # Gọi Gemini REST API trực tiếp
        active_key = user_keys[0] # Lấy key đầu tiên
        target_model = "gemini-2.5-flash" if selected_model == "🔄 Tự động chọn Model Free" else selected_model
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent?key={active_key}"
        
        with st.chat_message("assistant"):
            with st.spinner(f"Đang suy nghĩ với model {target_model}..."):
                try:
                    res = requests.post(url, json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=30)
                    if res.status_code == 200:
                        ans = res.json()['candidates'][0]['content']['parts'][0]['text']
                        st.write(ans)
                    else:
                        st.error(f"Lỗi API ({res.status_code}): {res.text}")
                except Exception as e:
                    st.error(f"Lỗi kết nối: {str(e)}")
