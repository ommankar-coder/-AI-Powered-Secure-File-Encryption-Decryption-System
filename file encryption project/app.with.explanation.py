import streamlit as st  # Import Streamlit for the web UI
import sqlite3  # SQLite for user authentication
import hashlib  # Hashing for secure password storage
import os  # OS operations
import base64  # Base64 encoding for key conversion
import json  # JSON for metadata storage
from cryptography.fernet import Fernet  # Fernet encryption for file security

# Database Initialization
# Creates a SQLite database if it does not exist and initializes a users table.
def init_db():
    conn = sqlite3.connect("users.db")  # Connect to SQLite database
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)  # Create table if it doesn't exist
    conn.commit()
    conn.close()

# Securely hash passwords using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Register a new user into the database
def register_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        return True  # Registration successful
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        conn.close()

# Authenticate user login credentials
def login_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hash_password(password)))
    user = c.fetchone()
    conn.close()
    return user  # Returns user data if valid, else None

# Generate an encryption key using a passkey
def generate_fernet_key(passkey):
    key = hashlib.sha256(passkey.encode()).digest()  # Hash the passkey
    return base64.urlsafe_b64encode(key[:32])  # Encode it to create a valid Fernet key

# Encrypt the uploaded file
def encrypt_file(file, key, filename):
    fernet = Fernet(key)  # Initialize Fernet encryption
    encrypted_data = fernet.encrypt(file.read())  # Encrypt file content
    metadata = json.dumps({"filename": filename}).encode()  # Store original filename
    encrypted_metadata = fernet.encrypt(metadata)  # Encrypt metadata
    return encrypted_metadata + b"\n" + encrypted_data  # Combine metadata and encrypted content

# Decrypt the uploaded file
def decrypt_file(encrypted_data, key):
    fernet = Fernet(key)
    try:
        encrypted_metadata, encrypted_content = encrypted_data.split(b"\n", 1)  # Split metadata and file content
        metadata = json.loads(fernet.decrypt(encrypted_metadata).decode())  # Decrypt metadata
        original_filename = metadata["filename"]  # Extract original filename
        decrypted_data = fernet.decrypt(encrypted_content)  # Decrypt file content
        return decrypted_data, original_filename
    except Exception:
        raise ValueError("Invalid decryption key or corrupted file.")

# Streamlit UI
st.title("AI-Powered Secure File Encryption & Decryption")
init_db()  # Ensure the database is initialized

# Session Management (User authentication state)
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

# Authentication UI (Login/Register)
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
        else:  # Register User
            if register_user(username, password):
                st.success("Registered successfully! Please login.")
            else:
                st.error("Username already exists")
else:
    st.sidebar.write(f"Welcome, {st.session_state['username']}")
    if st.sidebar.button("Logout"):
        st.session_state["authenticated"] = False
        st.rerun()
    
    # Encryption Section
    st.subheader("Encryption")
    uploaded_file = st.file_uploader("Upload a file to encrypt")
    passkey = st.text_input("Enter a passkey for encryption", type="password")
    
    if uploaded_file and passkey:
        key = generate_fernet_key(passkey)
        encrypted_data = encrypt_file(uploaded_file, key, uploaded_file.name)
        encrypted_filename = uploaded_file.name + ".enc"
        st.download_button("Download Encrypted File", encrypted_data, file_name=encrypted_filename)
    
    # Decryption Section
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