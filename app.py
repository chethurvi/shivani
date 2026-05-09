import streamlit as st
import sqlite3
import secrets
import hashlib
import base64
from cryptography.fernet import Fernet

DB_NAME = "p2p_learning.db"


def get_connection():
    return sqlite3.connect(DB_NAME, check_same_thread=False)


def create_tables():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            random_key TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            uploaded_by TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def generate_random_key():
    return secrets.token_hex(4).upper()


def generate_fernet_key():
    key_text = "P2P_ONLINE_LEARNING_AES_SECRET_KEY_123"
    return base64.urlsafe_b64encode(hashlib.sha256(key_text.encode()).digest())


def encrypt_text(text):
    fernet = Fernet(generate_fernet_key())
    return fernet.encrypt(text.encode()).decode()


def decrypt_text(encrypted_text):
    fernet = Fernet(generate_fernet_key())
    return fernet.decrypt(encrypted_text.encode()).decode()


def register_user(username, password, role):
    random_key = generate_random_key()

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, random_key, role) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), random_key, role)
        )
        conn.commit()
        return random_key
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def verify_login(username, password):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT username, random_key, role FROM users WHERE username=? AND password_hash=?",
        (username, hash_password(password))
    )

    user = cur.fetchone()
    conn.close()
    return user


def verify_random_key(username, random_key):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT role FROM users WHERE username=? AND random_key=?",
        (username, random_key)
    )

    result = cur.fetchone()
    conn.close()
    return result is not None


def save_encrypted_file(title, content, uploaded_by):
    encrypted_content = encrypt_text(content)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO files (title, encrypted_content, uploaded_by) VALUES (?, ?, ?)",
        (title, encrypted_content, uploaded_by)
    )

    conn.commit()
    conn.close()


def get_files():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, title, encrypted_content, uploaded_by FROM files")
    files = cur.fetchall()

    conn.close()
    return files


create_tables()

st.set_page_config(
    page_title="P2P Online Learning Security System",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 Triple-Staged Crypto Authentication")
st.subheader("Secure P2P Online Learning Application")

menu = st.sidebar.selectbox(
    "Choose Option",
    ["Home", "Register", "Login", "Upload Secure File", "View / Decrypt Files"]
)

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if "username" not in st.session_state:
    st.session_state.username = ""

if "role" not in st.session_state:
    st.session_state.role = ""


if menu == "Home":
    st.write("""
    This prototype demonstrates a secure Peer-to-Peer online learning system using:

    1. Text-based authentication  
    2. Random key verification  
    3. AES-style encryption for confidential learning files  
    """)

    st.info("Use Register first, then Login, then verify your random key.")


elif menu == "Register":
    st.header("New User Registration")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["Student", "Staff"])

    if st.button("Register"):
        if username and password:
            random_key = register_user(username, password, role)

            if random_key:
                st.success("Registration successful!")
                st.warning(f"Your random verification key is: {random_key}")
                st.write("Please save this key. You will need it during login.")
            else:
                st.error("Username already exists.")
        else:
            st.error("Please fill all fields.")


elif menu == "Login":
    st.header("Stage 1: Text-Based Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Verify Password"):
        user = verify_login(username, password)

        if user:
            st.session_state.temp_username = user[0]
            st.session_state.temp_random_key = user[1]
            st.session_state.temp_role = user[2]
            st.success("Password verified. Continue to Stage 2.")
        else:
            st.error("Invalid username or password.")

    if "temp_username" in st.session_state:
        st.header("Stage 2: Random Key Verification")

        entered_key = st.text_input("Enter Random Key")

        if st.button("Verify Random Key"):
            valid_key = verify_random_key(
                st.session_state.temp_username,
                entered_key
            )

            if valid_key:
                st.session_state.authenticated = True
                st.session_state.username = st.session_state.temp_username
                st.session_state.role = st.session_state.temp_role

                st.success("Authentication successful!")
                st.write(f"Welcome, {st.session_state.username}")
                st.write(f"Role: {st.session_state.role}")
            else:
                st.error("Invalid random key. Access denied.")


elif menu == "Upload Secure File":
    st.header("Stage 3: AES Encryption for Learning Files")

    if not st.session_state.authenticated:
        st.error("Please login and verify your random key first.")
    elif st.session_state.role != "Staff":
        st.error("Only staff users can upload encrypted learning files.")
    else:
        title = st.text_input("File Title")
        content = st.text_area("Confidential Learning Content")

        if st.button("Encrypt and Save"):
            if title and content:
                save_encrypted_file(title, content, st.session_state.username)
                st.success("File encrypted and stored successfully.")
            else:
                st.error("Please enter title and content.")


elif menu == "View / Decrypt Files":
    st.header("View Encrypted Learning Files")

    if not st.session_state.authenticated:
        st.error("Please login and verify your random key first.")
    else:
        files = get_files()

        if not files:
            st.info("No encrypted files available.")
        else:
            for file_id, title, encrypted_content, uploaded_by in files:
                with st.expander(f"{title} - uploaded by {uploaded_by}"):
                    st.write("Encrypted Content:")
                    st.code(encrypted_content)

                    if st.button(f"Decrypt File {file_id}"):
                        try:
                            decrypted = decrypt_text(encrypted_content)
                            st.success("Decryption successful.")
                            st.write("Decrypted Content:")
                            st.write(decrypted)
                        except Exception:
                            st.error("Decryption failed.")
