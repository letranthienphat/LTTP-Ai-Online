import os
import streamlit as st
import google.generativeai as genai

# ==========================================
# 1. CẤU HÌNH TRANG VÀ THIẾT LẬP BAN ĐẦU
# ==========================================
st.set_page_config(
    page_title="Nexus AI Online",
    page_icon="⚡",
    layout="wide"
)

st.title("⚡ Nexus AI Online")
st.caption("Hệ thống trợ lý AI tích hợp tự động dò tìm mô hình Google Gemini theo thời gian thực")

# ==========================================
# 2. XỬ LÝ VÀ KIỂM TRA API KEY
# ==========================================
# Tự động lấy API Key từ Streamlit Secrets hoặc môi trường
api_key = st.secrets.get("GEMINI_API_KEY") if "GEMINI_API_KEY" in st.secrets else os.environ.get("GEMINI_API_KEY")

# Cấu hình Sidebar cho người dùng nhập/kiểm tra API Key
with st.sidebar:
    st.header("⚙️ Cấu hình hệ thống")
    if not api_key:
        api_key = st.text_input("Nhập Gemini API Key:", type="password", help="Lấy API key miễn phí tại aistudio.google.com")
        if api_key:
            st.success("🔑 Đã nhận API Key!")
    else:
        st.success("🔑 API Key đã được cấu hình tự động.")

if not api_key:
    st.info("👋 Vui lòng nhập Gemini API Key ở thanh bên (Sidebar) để bắt đầu sử dụng Nexus AI.")
    st.stop()

# Cấu hình thư viện Gemini với API Key
genai.configure(api_key=api_key)

# ==========================================
# 3. HÀM TỰ ĐỘNG DÒ MÔ HÌNH THỜI GIAN THỰC
# ==========================================
@st.cache_data(ttl=300)  # Cập nhật lại danh sách model sau mỗi 5 phút
def fetch_realtime_models():
    """Tự động truy vấn Google API để lấy tất cả các model hỗ trợ generateContent"""
    try:
        valid_models = []
        for model in genai.list_models():
            if 'generateContent' in model.supported_generation_methods:
                clean_name = model.name.replace('models/', '')
                valid_models.append(clean_name)
        return valid_models, None
    except Exception as err:
        return [], str(err)

# Gọi hàm lấy danh sách model
available_models, error_msg = fetch_realtime_models()

# Hiển thị thông báo nếu có lỗi kết nối API Key
if error_msg:
    st.error(f"❌ Lỗi kết nối Google API: {error_msg}")
    st.stop()

if not available_models:
    st.warning("⚠️ Không tìm thấy mô hình nào hỗ trợ tạo nội dung cho API Key này.")
    st.stop()

# ==========================================
# 4. CHỌN MÔ HÌNH VÀ TÙY CHỈNH NÂNG CAO
# ==========================================
with st.sidebar:
    st.subheader("🤖 Tùy chọn Mô hình")
    
    # Cho phép chọn model từ danh sách thực tế tìm được
    selected_model = st.selectbox(
        "Chọn Gemini Model khả dụng:",
        options=available_models,
        index=0,
        help="Danh sách được cập nhật trực tiếp từ Google API cho tài khoản của bạn."
    )
    
    st.divider()
    
    # Các tham số tinh chỉnh phản hồi
    temperature = st.slider("Độ sáng tạo (Temperature):", min_value=0.0, max_value=1.0, value=0.7, step=0.05)
    max_tokens = st.number_input("Giới hạn độ dài (Max Tokens):", min_value=100, max_value=8192, value=2048, step=100)
    
    st.divider()
    if st.button("🗑️ Xóa lịch sử trò chuyện"):
        st.session_state.messages = []
        st.rerun()

# ==========================================
# 5. XỬ LÝ LỊCH SỬ TRÒ CHUYỆN (CHAT SESSION)
# ==========================================
if "messages" not in st.session_state:
    st.session_state.messages = []

# Hiển thị lại các tin nhắn đã trao đổi trước đó
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# ==========================================
# 6. KHỞI TẠO VÀ GỬI YÊU CẦU ĐẾN GEMINI
# ==========================================
if prompt := st.chat_input("Nhập câu hỏi hoặc yêu cầu cho Nexus AI..."):
    # Hiển thị tin nhắn người dùng
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Khởi tạo mô hình được chọn từ danh sách thời gian thực
    try:
        model = genai.GenerativeModel(
            model_name=selected_model,
            generation_config=genai.types.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens
            )
        )

        # Tạo luồng phản hồi từ AI
        with st.chat_message("assistant"):
            with st.spinner(f"Nexus AI đang xử lý ({selected_model})..."):
                # Chuẩn bị lịch sử trò chuyện dạng Gemini SDK
                history_for_gemini = []
                for msg in st.session_state.messages[:-1]:
                    role = "user" if msg["role"] == "user" else "model"
                    history_for_gemini.append({"role": role, "parts": [msg["content"]]})

                chat = model.start_chat(history=history_for_gemini)
                response = chat.send_message(prompt)
                
                # Hiển thị kết quả
                st.markdown(response.text)
                
                # Lưu vào session state
                st.session_state.messages.append({"role": "assistant", "content": response.text})

    except Exception as e:
        st.error(f"❌ Đã xảy ra lỗi khi tạo phản hồi: {e}")
