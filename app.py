import streamlit as st
from PIL import Image
import io

# --- Konfigurasi Halaman ---
st.set_page_config(page_title="Project Kripto", layout="wide")

# =============================================================================
# --- FUNGSI PLACEHOLDER ---
# Ganti isi fungsi-fungsi ini dengan logika dari file .py Anda yang sebenarnya.
# Anda perlu mengimpornya, contoh: from auth.login import cek_login_md5
# =============================================================================

def handle_login(username, password):
    """
    Placeholder untuk auth/login.py (Login dengan MD5).
    Ganti ini dengan fungsi login Anda.
    """
    # from auth.login import fungsi_login_anda
    # return fungsi_login_anda(username, password)
    
    # Logika placeholder sederhana:
    if username == "admin" and password == "123":
        st.success("Login berhasil!")
        return True
    else:
        st.error("Username atau password salah")
        return False

def handle_register(username, password):
    """
    Placeholder untuk registrasi (mungkin juga di auth/login.py atau db_connection.py).
    Ganti ini dengan fungsi registrasi Anda.
    """
    # from auth.register import fungsi_register_anda
    # return fungsi_register_anda(username, password)
    
    # Logika placeholder sederhana:
    print(f"Mencoba mendaftarkan: {username}")
    st.success("Registrasi berhasil! Silakan login.")
    return True

def handle_super_encrypt(plain_text):
    """
    Placeholder untuk crypto/super_encrypt.py (Whitespace + AES128-GCM).
    """
    # from crypto.super_encrypt import fungsi_enkripsi_super
    # return fungsi_enkripsi_super(plain_text)
    
    # Logika placeholder sederhana:
    if not plain_text:
        return ""
    encrypted_text = f"[WHITESPACE_AES_ENCRYPTED: {plain_text[::-1]}]"
    return encrypted_text

def handle_steganography_encode(image_file, secret_text):
    """
    Placeholder untuk crypto/steganography_pvd.py (PVD Steganografi).
    Fungsi ini harus mengembalikan objek gambar (PIL Image) atau bytes.
    """
    # from crypto.steganography_pvd import fungsi_stego_encode
    # pil_image = Image.open(image_file)
    # result_image = fungsi_stego_encode(pil_image, secret_text)
    # return result_image
    
    # Logika placeholder sederhana (hanya mengembalikan gambar asli):
    st.success("Teks berhasil disembunyikan (placeholder).")
    return Image.open(image_file)

def handle_file_encrypt(uploaded_file):
    """
    Placeholder untuk crypto/file_crypto.py (ChaCha20 untuk file).
    Fungsi ini harus mengembalikan bytes dari file yang terenkripsi.
    """
    # from crypto.file_crypto import fungsi_enkripsi_file
    # file_bytes = uploaded_file.getvalue()
    # encrypted_bytes = fungsi_enkripsi_file(file_bytes)
    # return encrypted_bytes
    
    # Logika placeholder sederhana:
    file_bytes = uploaded_file.getvalue()
    encrypted_bytes = b"[CHACHA20_ENCRYPTED] " + file_bytes
    return encrypted_bytes

def handle_file_decrypt(uploaded_file):
    """
    Placeholder untuk crypto/file_crypto.py (ChaCha20 untuk file).
    Fungsi ini harus mengembalikan bytes dari file yang terdekripsi.
    """
    # from crypto.file_crypto import fungsi_dekripsi_file
    # file_bytes = uploaded_file.getvalue()
    # decrypted_bytes = fungsi_dekripsi_file(file_bytes)
    # return decrypted_bytes
    
    # Logika placeholder sederhana:
    file_bytes = uploaded_file.getvalue()
    # Hapus prefix placeholder jika ada
    if file_bytes.startswith(b"[CHACHA20_ENCRYPTED] "):
        decrypted_bytes = file_bytes[len(b"[CHACHA20_ENCRYPTED] "):]
    else:
        decrypted_bytes = b"[DECRYPTION_FAILED_OR_NOT_ENCRYPTED] " + file_bytes
    return decrypted_bytes

# =============================================================================
# --- Inisialisasi Session State ---
# =============================================================================

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'page' not in st.session_state:
    st.session_state.page = 'login'
if 'username' not in st.session_state:
    st.session_state.username = ""

# =============================================================================
# --- Halaman Login & Register ---
# =============================================================================

if not st.session_state.logged_in:
    
    if st.session_state.page == 'login':
        st.title("Selamat Datang! Silakan Login")
        
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            login_button = st.form_submit_button("Login")
            
            if login_button:
                if handle_login(username, password):
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.page = 'main'
                    st.rerun()

        st.markdown("---")
        st.write("Belum punya akun?")
        if st.button("Pergi ke Halaman Register"):
            st.session_state.page = 'register'
            st.rerun()

    elif st.session_state.page == 'register':
        st.title("Buat Akun Baru")
        
        with st.form("register_form"):
            new_username = st.text_input("Username Baru")
            new_password = st.text_input("Password Baru", type="password")
            confirm_password = st.text_input("Konfirmasi Password", type="password")
            register_button = st.form_submit_button("Register")
            
            if register_button:
                if new_password == confirm_password:
                    if handle_register(new_username, new_password):
                        # Otomatis kembali ke login setelah sukses register
                        st.session_state.page = 'login'
                        st.rerun()
                else:
                    st.error("Password tidak cocok!")

        st.markdown("---")
        st.write("Sudah punya akun?")
        if st.button("Pergi ke Halaman Login"):
            st.session_state.page = 'login'
            st.rerun()

# =============================================================================
# --- Halaman Utama (Setelah Login) ---
# =============================================================================

else:
    # --- Sidebar ---
    st.sidebar.title(f"Halo, {st.session_state.username}!")
    st.sidebar.markdown("---")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.page = 'login'
        st.rerun()
    
    st.sidebar.info("Gunakan panel di samping untuk navigasi antar fitur.")

    # --- Konten Halaman Utama ---
    st.title("🔒 Aplikasi Kriptografi & Steganografi")
    st.markdown("Pilih salah satu fitur di bawah ini untuk memulai.")

    tab1, tab2, tab3 = st.tabs([
        "1. Super Enkripsi (Teks)", 
        "2. Steganografi (Gambar)", 
        "3. Kriptografi File (File)"
    ])

    # --- Tab 1: Super Enkripsi (Teks) ---
    with tab1:
        st.header("Super Enkripsi (Whitespace + AES128-GCM)")
        st.write("Masukkan teks di bawah ini untuk dienkripsi.")
        
        plain_text = st.text_area("Teks Anda:", height=150, key="super_encrypt_input")
        
        if st.button("Proses Enkripsi Teks", key="super_encrypt_btn"):
            if plain_text:
                encrypted_result = handle_super_encrypt(plain_text)
                st.subheader("Hasil Enkripsi:")
                st.code(encrypted_result, language=None)
            else:
                st.warning("Harap masukkan teks terlebih dahulu.")

    # --- Tab 2: Steganografi (Gambar) ---
    with tab2:
        st.header("Steganografi PVD (Sembunyikan Teks dalam Gambar)")
        st.write("Upload gambar *cover* dan masukkan teks rahasia yang ingin disembunyikan.")
        
        uploaded_image = st.file_uploader("Upload Gambar Cover (.png, .jpg)", type=["png", "jpg", "jpeg"], key="stego_img_upload")
        secret_text = st.text_area("Teks Rahasia:", height=100, key="stego_text_input")
        
        if st.button("Sembunyikan Teks", key="stego_encode_btn"):
            if uploaded_image is not None and secret_text:
                # Proses steganografi
                result_image = handle_steganography_encode(uploaded_image, secret_text)
                
                st.subheader("Hasil Gambar (Stego-Image):")
                st.image(result_image, caption="Gambar dengan teks tersembunyi")
                
                # Menyiapkan tombol download
                # Mengubah PIL Image menjadi bytes untuk di-download
                buf = io.BytesIO()
                result_image.save(buf, format="PNG")
                img_bytes = buf.getvalue()
                
                st.download_button(
                    label="Download Gambar Hasil",
                    data=img_bytes,
                    file_name="hasil_steganografi.png",
                    mime="image/png"
                )
            else:
                st.warning("Harap upload gambar dan masukkan teks rahasia.")

    # --- Tab 3: Kriptografi File ---
    with tab3:
        st.header("Enkripsi & Dekripsi File (ChaCha20)")
        st.write("Upload file apa saja untuk dienkripsi atau didekripsi.")
        
        uploaded_file = st.file_uploader("Upload File Anda", key="file_crypto_upload")
        
        if uploaded_file is not None:
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("Enkripsi File Ini", key="file_encrypt_btn"):
                    encrypted_data = handle_file_encrypt(uploaded_file)
                    st.success("File berhasil dienkripsi!")
                    st.download_button(
                        label="Download File Terenkripsi",
                        data=encrypted_data,
                        file_name=f"encrypted_{uploaded_file.name}",
                        mime="application/octet-stream"
                    )
            
            with col2:
                if st.button("Dekripsi File Ini", key="file_decrypt_btn"):
                    decrypted_data = handle_file_decrypt(uploaded_file)
                    st.success("File berhasil didekripsi!")
                    st.download_button(
                        label="Download File Terdekripsi",
                        data=decrypted_data,
                        file_name=f"decrypted_{uploaded_file.name}",
                        mime="application/octet-stream"
                    )