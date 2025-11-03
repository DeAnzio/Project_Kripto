import streamlit as st
import base64
import os
from datetime import datetime

# Import modul kita
from auth.login import verify_login, register_user, save_encrypted_message
from crypto.super_encrypt import SuperEncrypt
from crypto.file_crypto import FileCrypto
from crypto.steganography_pvd import PVDSteganography

# Page configuration
st.set_page_config(
    page_title="Aplikasi Kriptografi",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'username' not in st.session_state:
    st.session_state.username = None

def main():
    st.title("🔐 Aplikasi Kriptografi Tugas Akhir")
    st.markdown("---")
    
    # Jika belum login, tampilkan form login/register
    if not st.session_state.logged_in:
        show_login_register()
        return
    
    # Jika sudah login, tampilkan menu utama
    show_main_application()

def show_login_register():
    """Tampilkan form login dan register"""
    tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
    
    with tab1:
        st.subheader("Login ke Aplikasi")
        
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            login_btn = st.form_submit_button("Login")
            
            if login_btn:
                if not username or not password:
                    st.error("Username dan password harus diisi!")
                elif verify_login(username, password):
                    st.session_state.logged_in = True
                    st.success(f"Login berhasil! Selamat datang {username}")
                    st.rerun()
                else:
                    st.error("Username atau password salah!")
    
    with tab2:
        st.subheader("Registrasi User Baru")
        
        with st.form("register_form"):
            new_username = st.text_input("Username", key="reg_username")
            new_email = st.text_input("Email", key="reg_email")
            new_password = st.text_input("Password", type="password", key="reg_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm")
            register_btn = st.form_submit_button("Register")
            
            if register_btn:
                if not new_username or not new_password or not confirm_password:
                    st.error("Semua field harus diisi!")
                elif new_password != confirm_password:
                    st.error("Password tidak cocok!")
                else:
                    success, message = register_user(new_username, new_password, new_email)
                    if success:
                        st.success(message)
                    else:
                        st.error(message)

def show_main_application():
    """Tampilkan aplikasi utama setelah login"""
    st.sidebar.title(f"👋 Welcome, {st.session_state.username}!")
    
    # Navigation menu
    menu = st.sidebar.selectbox(
        "Pilih Menu",
        ["🏠 Dashboard", "📝 Enkripsi Teks", "🔓 Dekripsi Teks", "📁 Enkripsi File", 
         "🖼 Steganografi", "📊 History", "⚙️ Settings"]
    )
    
    st.sidebar.markdown("---")
    if st.sidebar.button("🚪 Logout"):
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.session_state.username = None
        st.rerun()
    
    # Tampilkan konten berdasarkan menu
    if menu == "🏠 Dashboard":
        show_dashboard()
    elif menu == "📝 Enkripsi Teks":
        show_text_encryption()
    elif menu == "🔓 Dekripsi Teks":
        show_text_decryption()
    elif menu == "📁 Enkripsi File":
        show_file_encryption()
    elif menu == "🖼 Steganografi":
        show_steganography()
    elif menu == "📊 History":
        show_history()
    elif menu == "⚙️ Settings":
        show_settings()

def show_dashboard():
    """Dashboard utama"""
    st.header("🏠 Dashboard")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.info("""
        **🔐 Super Enkripsi Teks**
        - Whitespace Manipulation
        - AES128-GCM Encryption
        - Secure Text Storage
        """)
    
    with col2:
        st.info("""
        **📁 File Encryption**
        - ChaCha20-Poly1305
        - All File Types
        - Fast Processing
        """)
    
    with col3:
        st.info("""
        **🖼 Steganografi PVD**
        - Pixel Value Differencing
        - Hide Text in Images
        - Visual Quality Maintained
        """)
    
    st.markdown("---")
    st.subheader("Quick Actions")
    
    quick_col1, quick_col2, quick_col3 = st.columns(3)
    
    with quick_col1:
        if st.button("📝 Enkripsi Teks", use_container_width=True):
            st.switch_page("app.py")  # Akan navigate ke tab enkripsi
    
    with quick_col2:
        if st.button("📁 Enkripsi File", use_container_width=True):
            st.switch_page("app.py")
    
    with quick_col3:
        if st.button("🖼 Steganografi", use_container_width=True):
            st.switch_page("app.py")

def show_text_encryption():
    """Menu enkripsi teks"""
    st.header("📝 Super Enkripsi Teks")
    
    with st.form("text_encryption_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            password = st.text_input("Encryption Password", type="password", 
                                   value="my_secret_key", help="Password untuk enkripsi")
            plaintext = st.text_area("Teks Plaintext", height=150, 
                                   placeholder="Masukkan teks yang akan dienkripsi...")
        
        with col2:
            st.markdown("### Encryption Info")
            st.info("""
            **Algoritma: Super Enkripsi**
            1. Whitespace Manipulation
            2. AES128-GCM Encryption
            """)
            
            if plaintext:
                st.metric("Text Length", f"{len(plaintext)} characters")
        
        encrypt_btn = st.form_submit_button("🔒 Enkripsi Teks")
        
        if encrypt_btn:
            if not plaintext:
                st.error("Masukkan teks yang akan dienkripsi!")
            elif not password:
                st.error("Masukkan password enkripsi!")
            else:
                try:
                    # Initialize crypto
                    crypto = SuperEncrypt(password)
                    
                    # Encrypt text
                    encrypted_text = crypto.super_encrypt(plaintext)
                    
                    # Save to database
                    save_encrypted_message(
                        st.session_state.user_id, 
                        plaintext, 
                        encrypted_text, 
                        "Super_Encrypt_Whitespace_AES128GCM"
                    )
                    
                    # Display results
                    st.success("✅ Teks berhasil dienkripsi!")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.text_area("Encrypted Text", encrypted_text, height=200)
                    
                    with col2:
                        # Download button
                        st.download_button(
                            label="📥 Download Encrypted Text",
                            data=encrypted_text,
                            file_name=f"encrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                            mime="text/plain"
                        )
                        
                        # Stats
                        original_size = len(plaintext.encode('utf-8'))
                        encrypted_size = len(encrypted_text.encode('utf-8'))
                        st.metric("Original Size", f"{original_size} bytes")
                        st.metric("Encrypted Size", f"{encrypted_size} bytes")
                        st.metric("Size Increase", f"{((encrypted_size - original_size) / original_size * 100):.1f}%")
                
                except Exception as e:
                    st.error(f"❌ Enkripsi gagal: {str(e)}")

def show_text_decryption():
    """Menu dekripsi teks"""
    st.header("🔓 Dekripsi Teks")
    
    with st.form("text_decryption_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            password = st.text_input("Decryption Password", type="password", 
                                   value="my_secret_key", help="Password yang digunakan untuk enkripsi")
            encrypted_text = st.text_area("Teks Terenkripsi", height=150, 
                                        placeholder="Masukkan teks terenkripsi...")
        
        with col2:
            st.markdown("### Decryption Info")
            st.info("""
            **Proses Dekripsi:**
            1. AES128-GCM Decryption
            2. Whitespace Removal
            """)
        
        decrypt_btn = st.form_submit_button("🔓 Dekripsi Teks")
        
        if decrypt_btn:
            if not encrypted_text:
                st.error("Masukkan teks terenkripsi!")
            elif not password:
                st.error("Masukkan password dekripsi!")
            else:
                try:
                    # Initialize crypto
                    crypto = SuperEncrypt(password)
                    
                    # Decrypt text
                    decrypted_text = crypto.super_decrypt(encrypted_text)
                    
                    # Display results
                    st.success("✅ Teks berhasil didekripsi!")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.text_area("Decrypted Text", decrypted_text, height=200)
                    
                    with col2:
                        # Download button
                        st.download_button(
                            label="📥 Download Decrypted Text",
                            data=decrypted_text,
                            file_name=f"decrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                            mime="text/plain"
                        )
                
                except Exception as e:
                    st.error(f"❌ Dekripsi gagal: {str(e)}")

def show_file_encryption():
    """Menu enkripsi file"""
    st.header("📁 Enkripsi File dengan ChaCha20")
    
    tab1, tab2 = st.tabs(["🔒 Enkripsi File", "🔓 Dekripsi File"])
    
    with tab1:
        st.subheader("Enkripsi File")
        
        with st.form("file_encryption_form"):
            file_password = st.text_input("File Encryption Password", type="password",
                                        value="file_secret_123")
            uploaded_file = st.file_uploader("Pilih file untuk dienkripsi", 
                                           type=None,  # All file types
                                           key="encrypt_upload")
            
            encrypt_file_btn = st.form_submit_button("🔒 Enkripsi File")
            
            if encrypt_file_btn:
                if not uploaded_file:
                    st.error("Pilih file terlebih dahulu!")
                elif not file_password:
                    st.error("Masukkan password enkripsi!")
                else:
                    try:
                        # Read file data
                        file_data = uploaded_file.getvalue()
                        
                        # Initialize file crypto
                        file_crypto = FileCrypto(file_password)
                        
                        # Encrypt file
                        encrypted_data = file_crypto.encrypt_file(file_data)
                        
                        st.success("✅ File berhasil dienkripsi!")
                        
                        # Download encrypted file
                        st.download_button(
                            label="📥 Download Encrypted File",
                            data=encrypted_data,
                            file_name=f"encrypted_{uploaded_file.name}",
                            mime="text/plain"
                        )
                        
                        # Show stats
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Original Size", f"{len(file_data)} bytes")
                        with col2:
                            st.metric("Encrypted Size", f"{len(encrypted_data)} bytes")
                        with col3:
                            size_increase = ((len(encrypted_data) - len(file_data)) / len(file_data) * 100)
                            st.metric("Size Change", f"{size_increase:.1f}%")
                    
                    except Exception as e:
                        st.error(f"❌ Enkripsi file gagal: {str(e)}")
    
    with tab2:
        st.subheader("Dekripsi File")
        
        with st.form("file_decryption_form"):
            decrypt_file_password = st.text_input("File Decryption Password", type="password",
                                                value="file_secret_123")
            encrypted_file = st.file_uploader("Pilih file terenkripsi", 
                                            type=['txt'],
                                            key="decrypt_upload")
            
            decrypt_file_btn = st.form_submit_button("🔓 Dekripsi File")
            
            if decrypt_file_btn:
                if not encrypted_file:
                    st.error("Pilih file terenkripsi terlebih dahulu!")
                elif not decrypt_file_password:
                    st.error("Masukkan password dekripsi!")
                else:
                    try:
                        # Read encrypted data
                        encrypted_data = encrypted_file.getvalue().decode('utf-8')
                        
                        # Initialize file crypto
                        file_crypto = FileCrypto(decrypt_file_password)
                        
                        # Decrypt file
                        decrypted_data = file_crypto.decrypt_file(encrypted_data)
                        
                        st.success("✅ File berhasil didekripsi!")
                        
                        # Determine file extension
                        original_filename = encrypted_file.name
                        if original_filename.startswith('encrypted_'):
                            decrypted_filename = original_filename.replace('encrypted_', 'decrypted_')
                        else:
                            decrypted_filename = f"decrypted_{original_filename}"
                        
                        # Download decrypted file
                        st.download_button(
                            label="📥 Download Decrypted File",
                            data=decrypted_data,
                            file_name=decrypted_filename,
                            mime="application/octet-stream"
                        )
                    
                    except Exception as e:
                        st.error(f"❌ Dekripsi file gagal: {str(e)}")

def show_steganography():
    """Menu steganografi PVD"""
    st.header("🖼 Steganografi PVD")
    
    tab1, tab2 = st.tabs(["📤 Embed Text", "📥 Extract Text"])
    
    with tab1:
        st.subheader("Sembunyikan Teks dalam Gambar")
        
        with st.form("stego_embed_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                image_file = st.file_uploader("Pilih gambar", 
                                            type=['png', 'jpg', 'jpeg'],
                                            key="embed_image")
                secret_text = st.text_area("Teks Rahasia", height=100,
                                         placeholder="Masukkan teks yang akan disembunyikan...")
            
            with col2:
                if image_file:
                    st.image(image_file, caption="Gambar yang dipilih", use_column_width=True)
                
                if secret_text:
                    st.metric("Text Length", f"{len(secret_text)} characters")
                    st.metric("Binary Length", f"{len(secret_text) * 8} bits")
            
            embed_btn = st.form_submit_button("🖼 Sembunyikan Teks")
            
            if embed_btn:
                if not image_file:
                    st.error("Pilih gambar terlebih dahulu!")
                elif not secret_text:
                    st.error("Masukkan teks rahasia!")
                else:
                    try:
                        # Save uploaded image temporarily
                        with open("temp_input.png", "wb") as f:
                            f.write(image_file.getvalue())
                        
                        # Initialize steganography
                        stego = PVDSteganography()
                        
                        # Embed text
                        output_path = f"stego_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                        success, message = stego.embed_text("temp_input.png", secret_text, output_path)
                        
                        if success:
                            st.success("✅ Teks berhasil disembunyikan dalam gambar!")
                            
                            # Show result
                            col1, col2 = st.columns(2)
                            with col1:
                                st.image("temp_input.png", caption="Gambar Asli", use_column_width=True)
                            with col2:
                                st.image(output_path, caption="Gambar dengan Stegano", use_column_width=True)
                            
                            # Download button
                            with open(output_path, "rb") as f:
                                st.download_button(
                                    label="📥 Download Stego Image",
                                    data=f,
                                    file_name=output_path,
                                    mime="image/png"
                                )
                            
                            st.info(f"**Info:** {message}")
                            
                            # Cleanup
                            if os.path.exists("temp_input.png"):
                                os.remove("temp_input.png")
                        else:
                            st.error(f"❌ Gagal: {message}")
                    
                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")
    
    with tab2:
        st.subheader("Ekstrak Teks dari Gambar")
        
        with st.form("stego_extract_form"):
            stego_image = st.file_uploader("Pilih gambar dengan steganografi",
                                         type=['png', 'jpg', 'jpeg'],
                                         key="extract_image")
            
            extract_btn = st.form_submit_button("🔍 Ekstrak Teks")
            
            if extract_btn:
                if not stego_image:
                    st.error("Pilih gambar terlebih dahulu!")
                else:
                    try:
                        # Save uploaded image temporarily
                        with open("temp_stego.png", "wb") as f:
                            f.write(stego_image.getvalue())
                        
                        # Initialize steganography
                        stego = PVDSteganography()
                        
                        # Extract text
                        success, extracted_text = stego.extract_text("temp_stego.png")
                        
                        if success:
                            st.success("✅ Teks berhasil diekstrak!")
                            
                            st.image("temp_stego.png", caption="Gambar Stegano", use_column_width=True)
                            
                            st.text_area("Teks yang Diekstrak", extracted_text, height=150)
                            
                            # Download extracted text
                            st.download_button(
                                label="📥 Download Extracted Text",
                                data=extracted_text,
                                file_name=f"extracted_text_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                mime="text/plain"
                            )
                        else:
                            st.error(f"❌ Gagal mengekstrak teks: {extracted_text}")
                        
                        # Cleanup
                        if os.path.exists("temp_stego.png"):
                            os.remove("temp_stego.png")
                    
                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")

def show_history():
    """Menu history"""
    st.header("📊 History Enkripsi")
    st.info("Fitur history akan diimplementasikan dengan query database")
    
    # Placeholder untuk history
    st.write("""
    Fitur ini akan menampilkan:
    - Riwayat enkripsi/dekripsi teks
    - File yang telah diproses
    - Gambar steganografi yang dibuat
    - Statistik penggunaan
    """)

def show_settings():
    """Menu settings"""
    st.header("⚙️ Settings")
    
    st.subheader("Encryption Settings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.selectbox("Default Encryption Method", 
                    ["Super Encrypt (Whitespace + AES128-GCM)", "AES-256", "ChaCha20"])
        
        st.number_input("Whitespace Probability", min_value=0.1, max_value=0.9, value=0.4, step=0.1)
    
    with col2:
        st.selectbox("Default File Encryption", 
                    ["ChaCha20-Poly1305", "AES-GCM", "XChaCha20"])
        
        st.selectbox("Steganography Method", 
                    ["PVD (Pixel Value Differencing)", "LSB", "DCT"])
    
    st.subheader("Application Settings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.checkbox("Auto-save to database", value=True)
        st.checkbox("Show encryption statistics", value=True)
    
    with col2:
        st.checkbox("Auto-delete temporary files", value=True)
        st.checkbox("Enable file preview", value=True)
    
    if st.button("💾 Save Settings"):
        st.success("Settings saved successfully!")

if __name__ == "__main__":
    main()