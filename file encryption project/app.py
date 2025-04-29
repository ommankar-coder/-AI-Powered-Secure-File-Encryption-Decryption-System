import streamlit as st
import sqlite3
import hashlib
import os
import base64
import json
from cryptography.fernet import Fernet

# Database Setup
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

# Password Hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# User Authentication
def register_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def login_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hash_password(password)))
    user = c.fetchone()
    conn.close()
    return user

# Generate Encryption Key from Passkey
def generate_fernet_key(passkey):
    key = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])

# File Encryption
def encrypt_file(file, key, filename):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file.read())
    metadata = json.dumps({"filename": filename}).encode()
    encrypted_metadata = fernet.encrypt(metadata)
    return encrypted_metadata + b"\n" + encrypted_data

# File Decryption
def decrypt_file(encrypted_data, key):
    fernet = Fernet(key)
    try:
        encrypted_metadata, encrypted_content = encrypted_data.split(b"\n", 1)
        metadata = json.loads(fernet.decrypt(encrypted_metadata).decode())
        original_filename = metadata["filename"]
        decrypted_data = fernet.decrypt(encrypted_content)
        return decrypted_data, original_filename
    except Exception:
        raise ValueError("Invalid decryption key or corrupted file.")

# Streamlit App
st.title("AI-Powered Secure File Encryption & Decryption")
init_db()

# Session Management
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

# Login/Signup
if not st.session_state["authenticated"]:
    option = st.sidebar.selectbox("Login or Register", ["Login", "Register"])
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button(option):
        if option == "Login":
            if login_user(username, password):
                st.session_state["authenticated"] = True
                st.session_state["username"] = username
                st.success("Logged in successfully!")
            else:
                st.error("Invalid credentials")
        else:
            if register_user(username, password):
                st.success("Registered successfully! Please login.")
            else:
                st.error("Username already exists")
else:
    st.sidebar.write(f"Welcome, {st.session_state['username']}")
    if st.sidebar.button("Logout"):
        st.session_state["authenticated"] = False
        st.rerun()
    
    st.subheader("Encryption")
    uploaded_file = st.file_uploader("Upload a file to encrypt")
    passkey = st.text_input("Enter a passkey for encryption", type="password")
    
    if uploaded_file and passkey:
        key = generate_fernet_key(passkey)
        encrypted_data = encrypt_file(uploaded_file, key, uploaded_file.name)
        encrypted_filename = uploaded_file.name + ".enc"
        st.download_button("Download Encrypted File", encrypted_data, file_name=encrypted_filename)
    
    st.subheader("Decryption")
    encrypted_file = st.file_uploader("Upload encrypted file", type=["enc"])
    decrypt_passkey = st.text_input("Enter decryption passkey", type="password")
    
    if encrypted_file and decrypt_passkey:
        key = generate_fernet_key(decrypt_passkey)
        try:
            encrypted_data = encrypted_file.read()
            decrypted_data, original_filename = decrypt_file(encrypted_data, key)
            st.download_button("Download Decrypted File", decrypted_data, file_name=original_filename)
        except ValueError:
            st.error("Invalid decryption key or corrupted file.")