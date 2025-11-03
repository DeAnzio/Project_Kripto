import hashlib
from database.db_connection import fetch_one, execute_query
import streamlit as st

def hash_md5(password):
    """Hash password menggunakan MD5"""
    return hashlib.md5(password.encode()).hexdigest()

def verify_login(username, password):
    """Verifikasi login user"""
    try:
        query = "SELECT id, username, password FROM users WHERE username = %s"
        result = fetch_one(query, (username,))
        
        if result:
            user_id, db_username, db_password = result
            if db_password == hash_md5(password):
                st.session_state.user_id = user_id
                st.session_state.username = db_username
                return True
        return False
    except Exception as e:
        st.error(f"Login error: {e}")
        return False

def register_user(username, password, email):
    """Registrasi user baru"""
    try:
        # Check if username exists
        check_query = "SELECT id FROM users WHERE username = %s"
        if fetch_one(check_query, (username,)):
            return False, "Username already exists"
        
        # Insert new user
        insert_query = """
        INSERT INTO users (username, password, email) 
        VALUES (%s, %s, %s)
        """
        execute_query(insert_query, (username, hash_md5(password), email))
        return True, "Registration successful"
    except Exception as e:
        return False, f"Registration error: {e}"

def save_encrypted_message(user_id, original_text, encrypted_text, enc_type):
    """Simpan pesan terenkripsi ke database"""
    try:
        query = """
        INSERT INTO encrypted_messages (user_id, original_text, encrypted_text, encryption_type)
        VALUES (%s, %s, %s, %s)
        """
        execute_query(query, (user_id, original_text, encrypted_text, enc_type))
        return True
    except Exception as e:
        st.error(f"Save message error: {e}")
        return False