import os
import sqlite3
import secrets
import hashlib
import base64
from datetime import datetime

import streamlit as st
from cryptography.fernet import Fernet

DB_NAME = "p2p_learning.db"
KEY_FILE = "secret.key"

# -----------------------------
# Security helpers
# -----------------------------
def load_or_create_master_key():
    """Creates one AES-compatible Fernet key for demo encryption."""
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        return f.read()


def get_cipher():
    return Fernet(load_or_create_master_key())


def hash_password(password: str, salt: str | None = None):
    """Hashes passwords using SHA-256 + per-user salt for prototype use."""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, digest


def verify_password(password: str, salt: str, stored_hash: str):
    _, digest = hash_password(password, salt)
    return secrets.compare_digest(digest, stored_hash)


def generate_random_key():
    return secrets.token_urlsafe(8).upper()


def encrypt_text(plain_text: str):
    return get_cipher().encrypt(plain_text.encode()).decode()


def decrypt_text(cipher_text: str):
    return get_cipher().decrypt(cipher_text.encode()).decode()

# -----------------------------
# Database layer
# -----------------------------
def connect_db():
    return sqlite3.connect(DB_NAME, check_same_thread=False)


def init_db():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            random_key TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS learning_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def create_user(username, full_name, role, password):
    salt, password_hash = hash_password(password)
    random_key = generate_random_key()
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO users(username, full_name, role, salt, password_hash, random_key, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (username, full_name, role, salt, password_hash, random_key, datetime.now().isoformat(timespec="seconds")),
    )
    conn.commit()
    conn.close()
    return random_key


def get_user(username):
    conn = connect_db()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    return user


def save_learning_file(title, uploaded_by, plain_content):
    encrypted_content = encrypt_text(plain_content)
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO learning_files(title, uploaded_by, encrypted_content, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (title, uploaded_by, encrypted_content, datetime.now().isoformat(timespec="seconds")),
    )
    conn.commit()
    conn.close()


def list_learning_files():
    conn = connect_db()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM learning_files ORDER BY id DESC")
    files = cur.fetchall()
    conn.close()
    return files

# -----------------------------
# Streamlit UI
# -----------------------------
st.set_page_config(page_title="P2P Triple-Staged Crypto Authentication", page_icon="🔐", layout="wide")
init_db()

st.title("🔐 P2P Online Learning: Triple-Staged Crypto Authentication")
st.caption("Prototype based on: password authentication + random key verification + AES/Fernet encryption.")

if "auth_user" not in st.session_state:
    st.session_state.auth_user = None
if "stage1_user" not in st.session_state:
    st.session_state.stage1_user = None

menu = st.sidebar.radio("Menu", ["Register", "Login", "Dashboard", "Attack Simulation", "Logout"])

if menu == "Register":
    st.header("1. New User Registration")
    with st.form("register_form"):
        full_name = st.text_input("Full name")
        username = st.text_input("Username")
        role = st.selectbox("Role", ["Student", "Staff", "Admin"])
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Create account")

    if submitted:
        if not full_name or not username or not password:
            st.error("Please complete all fields.")
        elif len(password) < 6:
            st.error("Password must be at least 6 characters for this prototype.")
        else:
            try:
                random_key = create_user(username, full_name, role, password)
                st.success("Account created successfully.")
                st.warning("Save this random key. It is required for Stage 2 authentication.")
                st.code(random_key)
            except sqlite3.IntegrityError:
                st.error("Username already exists. Choose another username.")

elif menu == "Login":
    st.header("2. Stage 1: Text Password Authentication")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Verify password")

    if submitted:
        user = get_user(username)
        if user and verify_password(password, user["salt"], user["password_hash"]):
            st.session_state.stage1_user = username
            st.success("Stage 1 passed. Continue to random key verification.")
        else:
            st.error("Invalid username or password.")

    st.divider()
    st.header("3. Stage 2: Random Key Verification")
    if st.session_state.stage1_user:
        with st.form("key_form"):
            random_key = st.text_input("Enter your random key")
            submitted_key = st.form_submit_button("Complete login")
        if submitted_key:
            user = get_user(st.session_state.stage1_user)
            if user and secrets.compare_digest(random_key.strip(), user["random_key"]):
                st.session_state.auth_user = dict(user)
                st.session_state.stage1_user = None
                st.success(f"Welcome, {user['full_name']}! Authentication complete.")
            else:
                st.error("Wrong random key. Access denied.")
    else:
        st.info("Pass Stage 1 first.")

elif menu == "Dashboard":
    st.header("Secure Learning Dashboard")
    user = st.session_state.auth_user
    if not user:
        st.error("Please login first.")
    else:
        st.success(f"Logged in as {user['full_name']} ({user['role']})")

        if user["role"] in ["Staff", "Admin"]:
            st.subheader("Staff: Encrypt and Upload Learning Material")
            with st.form("upload_form"):
                title = st.text_input("File title")
                content = st.text_area("Confidential learning content")
                upload = st.form_submit_button("Encrypt and save")
            if upload:
                if title and content:
                    save_learning_file(title, user["username"], content)
                    st.success("File encrypted and stored successfully.")
                else:
                    st.error("Please enter title and content.")

        st.subheader("Encrypted Learning Files")
        files = list_learning_files()
        if not files:
            st.info("No files uploaded yet.")
        for f in files:
            with st.expander(f"{f['title']} — uploaded by {f['uploaded_by']}"):
                st.write("Encrypted ciphertext:")
                st.code(f["encrypted_content"][:500] + ("..." if len(f["encrypted_content"]) > 500 else ""))
                key_input = st.text_input("Re-enter your random key to decrypt", key=f"key_{f['id']}")
                if st.button("Decrypt", key=f"decrypt_{f['id']}"):
                    if secrets.compare_digest(key_input.strip(), user["random_key"]):
                        try:
                            st.success("Decryption successful.")
                            st.text_area("Plain content", decrypt_text(f["encrypted_content"]), height=150)
                        except Exception:
                            st.error("Could not decrypt this file.")
                    else:
                        st.error("Wrong random key. Decryption denied.")

elif menu == "Attack Simulation":
    st.header("Attack Simulation")
    st.write("Use this section to demonstrate the evaluation scenarios from the report.")

    attack = st.selectbox("Select attack scenario", ["Brute force / dictionary password guessed", "MITM intercepted encrypted file"])

    if attack == "Brute force / dictionary password guessed":
        st.info("Even if an attacker guesses the password, they still need the random key to pass Stage 2.")
        username = st.text_input("Target username")
        guessed_key = st.text_input("Attacker random-key guess")
        if st.button("Test unauthorized access"):
            user = get_user(username)
            if user and secrets.compare_digest(guessed_key.strip(), user["random_key"]):
                st.error("Access granted. This means the attacker had both password and key.")
            else:
                st.success("Access denied because the second authentication factor is wrong.")

    else:
        st.info("AES/Fernet encryption keeps intercepted file content unreadable without authorized decryption.")
        files = list_learning_files()
        if files:
            f = files[0]
            st.write("Intercepted ciphertext example:")
            st.code(f["encrypted_content"])
        else:
            st.warning("Upload at least one file from the Dashboard first.")

elif menu == "Logout":
    st.session_state.auth_user = None
    st.session_state.stage1_user = None
    st.success("Logged out.")
