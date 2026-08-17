import os
import json
import hashlib
import streamlit as st
import google.generativeai as genai

# ==========================================
# 1. CẤU HÌNH TRANG
# ==========================================
st.set_page_config(
    page_title="Nexus AI Online",
    page_icon="⚡",
    layout="wide"
)

USER_DB_FILE = "users.json"

# ==========================================
# 2. HÀM QUẢN LÝ TÀI KHOẢN (LƯU/ĐỌC FILE)
# ==========================================
def load_users():
    """Tải danh sách người dùng từ file JSON"""
    if not os.path.exists(USER_DB_FILE):
        return {}
    try:
        with open(USER_DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users_data):
    """Lưu danh sách người dùng vào file JSON"""
    with open(USER_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(users_data, f, ensure_ascii=False, indent=4)

def hash_password(password):
    """Mã hóa mật khẩu bằng SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

# ==========================================
# 3. MÀN HÌNH TỰ ĐĂNG KÝ & TỰ ĐĂNG NHẬP
# ==========================================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = ""

def auth_screen():
    st.markdown("<h2 style='text-align: center;'>⚡ Cổng Truy Cập Nexus AI</h2>", unsafe_allow_html=True)
    st.write(" ")
    
    _, col_center, _ = st.columns([1, 2, 1])
    with col_center:
        tab_login, tab_register = st.tabs(["🔑 Đăng nhập", "📝 Đăng ký tài khoản mới"])
        users = load_users()

        # --- TAB ĐĂNG NHẬP ---
        with tab_login:
            with st.form("login_form"):
                login_user = st.text_input("Tên đăng nhập:").strip()
                login_pass = st.text_input("Mật khẩu:", type="password")
                btn_login = st.form_submit_button("Đăng nhập", use_container_width=True)

                if btn_login:
                    if not login_user or not login_pass:
                        st.warning("⚠️ Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.")
                    elif login_user in users and users[login_user] == hash_password(login_pass):
                        st.session_state.authenticated = True
                        st.session_state.username = login_user
                        st.success("✅ Đăng nhập thành công!")
                        st.rerun()
                    else:
                        st.error("❌ Tên đăng nhập hoặc mật khẩu không chính xác.")

        # --- TAB ĐĂNG KÝ TỰ ĐỘNG ---
        with tab_register:
            with st.form("register_form"):
                reg_user = st.text_input("Chọn tên đăng nhập:").strip()
                reg_pass = st.text_input("Tạo mật khẩu:", type="password")
                reg_pass_confirm = st.text_input("Xác nhận mật khẩu:", type="password")
                btn_register = st.form_submit_button("Tạo tài khoản", use_container_width=True)

                if btn_register:
                    if not reg_user or not reg_pass:
                        st.warning("⚠️ Không được để trống tên đăng nhập hoặc mật khẩu.")
                    elif reg_pass != reg_pass_confirm:
                        st.error("❌ Mật khẩu xác nhận không trùng khớp.")
                    elif reg_user in users:
                        st.error("❌ Tên đăng nhập này đã tồn tại. Vui lòng chọn tên khác.")
                    else:
                        users[reg_user] = hash_password(reg_pass)
                        save_users(users)
                        st.success("🎉 Tạo tài khoản thành công! Bạn có thể chuyển sang tab Đăng nhập ngay.")

if not st.session_state.authenticated:
    auth_screen()
    st.stop()

# ==========================================
# 4. GIAO DIỆN CHÍNH (SAU KHI ĐĂNG NHẬP)
# ==========================================
st.title("⚡ Nexus AI Online")
st.caption(f"Trợ lý AI | Tài khoản đang dùng: **{st.session_state.username}**")

# ==========================================
# 5. CẤU HÌNH API KEY & THANH BÊN (SIDEBAR)
# ==========================================
api_key = st.secrets.get("GEMINI_API_KEY") if "GEMINI_API_KEY" in st.secrets else os.environ.get("GEMINI_API_KEY")

with st.sidebar:
    st.header(f"👤 {st.session_state.username}")
    if st.button("🚪 Đăng xuất", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.session_state.messages = []
        st.rerun()
        
    st.divider()
    st.header("⚙️ API Key")
    if not api_key:
        api_key = st.text_input("Nhập Gemini API Key:", type="password", help="Lấy API Key tại aistudio.google.com")
    else:
        st.success("🔑 API Key đã sẵn sàng.")

if not api_key:
    st.info("👋 Vui lòng nhập Gemini API Key ở thanh bên để kích hoạt hệ thống.")
    st.stop()

genai.configure(api_key=api_key)

# ==========================================
# 6. DÒ MÔ HÌNH THỜI GIAN THỰC
# ==========================================
@st.cache_data(ttl=300)
def fetch_realtime_models():
    try:
        valid_models = []
        for model in genai.list_models():
            if 'generateContent' in model.supported_generation_methods:
                clean_name = model.name.replace('models/', '')
                valid_models.append(clean_name)
        return valid_models, None
    except Exception as err:
        return [], str(err)

available_models, error_msg = fetch_realtime_models()

if error_msg:
    st.error(f"❌ Lỗi kết nối Google API: {error_msg}")
    st.stop()

if not available_models:
    st.warning("⚠️ Không tìm thấy mô hình khả dụng cho API Key này.")
    st.stop()

# ==========================================
# 7. THAM SỐ VÀ TÙY CHỈNH CHAT
# ==========================================
with st.sidebar:
    st.subheader("🤖 Chọn Mô hình")
    selected_model = st.selectbox(
        "Mô hình Gemini hiện có:",
        options=available_models,
        index=0
    )
    
    st.divider()
    temperature = st.slider("Độ sáng tạo (Temperature):", min_value=0.0, max_value=1.0, value=0.7, step=0.05)
    max_tokens = st.number_input("Giới hạn độ dài (Max Tokens):", min_value=100, max_value=8192, value=2048, step=100)
    
    st.divider()
    if st.button("🗑️ Xóa lịch sử trò chuyện", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

# ==========================================
# 8. KHUNG CHAT & XỬ LÝ PHẢN HỒI
# ==========================================
if "messages" not in st.session_state:
    st.session_state.messages = []

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if prompt := st.chat_input("Nhập câu hỏi hoặc yêu cầu cho Nexus AI..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    try:
        model = genai.GenerativeModel(
            model_name=selected_model,
            generation_config=genai.types.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens
            )
        )

        with st.chat_message("assistant"):
            with st.spinner(f"Nexus AI đang suy nghĩ ({selected_model})..."):
                history_for_gemini = []
                for msg in st.session_state.messages[:-1]:
                    role = "user" if msg["role"] == "user" else "model"
                    history_for_gemini.append({"role": role, "parts": [msg["content"]]})

                chat = model.start_chat(history=history_for_gemini)
                response = chat.send_message(prompt)
                
                st.markdown(response.text)
                st.session_state.messages.append({"role": "assistant", "content": response.text})

    except Exception as e:
        st.error(f"❌ Lỗi xử lý từ Gemini API: {e}")
