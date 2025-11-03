import mysql.connector
import streamlit as st

@st.cache_resource
def init_connection():
    try:
        conn = mysql.connector.connect(
            host=st.secrets["mysql"]["host"],
            user=st.secrets["mysql"]["user"],
            password=st.secrets["mysql"]["password"],
            database=st.secrets["mysql"]["database"],
            port=st.secrets["mysql"].get("port", 3306)
        )
        return conn
    except mysql.connector.Error as e:
        st.error(f"Database connection error: {e}")
        return None

def get_cursor():
    conn = init_connection()
    if conn:
        return conn.cursor()
    return None

def execute_query(query, params=None):
    conn = init_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(query, params or ())
            conn.commit()
            return cursor
        except mysql.connector.Error as e:
            st.error(f"Query error: {e}")
            return None
    return None

def fetch_one(query, params=None):
    cursor = execute_query(query, params)
    if cursor:
        return cursor.fetchone()
    return None

def fetch_all(query, params=None):
    cursor = execute_query(query, params)
    if cursor:
        return cursor.fetchall()
    return []