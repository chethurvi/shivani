 import streamlit as st
import sqlite3
import secrets
import hashlib
import base64
from cryptography.fernet import Fernet


DB_NAME = "p2p_learning.db"


# ---------------- DATABASE ----------------

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
            filename TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            uploaded_by TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ---------------- SECURITY ----------------

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def generate_random_key():
    return secrets.token_hex(4).upper()


def generate_encryption_key():
    secret = "TRIPLE_STAGE_CRYPTO_AUTH_SECRET_KEY"
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())


def encrypt_file(file_bytes):
    fernet = Fernet(generate_encryption_key())
    return fernet.encrypt(file_bytes)


def decrypt_file(encrypted_bytes):
    fernet = Fernet(generate_encryption_key())
    return fernet.decrypt(encrypted_bytes)


# ---------------- USER FUNCTIONS ----------------

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


def verify_password(username, password):
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


def verify_file_access_key(access_key):
    return access_key == "AES123"


# ---------------- FILE FUNCTIONS ----------------

def save_file(filename, file_bytes, uploaded_by):
    encrypted_data = encrypt_file(file_bytes)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO files (filename, encrypted_data, uploaded_by) VALUES (?, ?, ?)",
        (filename, encrypted_data, uploaded_by)
    )

    conn.commit()
    conn.close()


def get_all_files():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, filename, encrypted_data, uploaded_by FROM files")
    files = cur.fetchall()

    conn.close()
    return files


# ---------------- STREAMLIT SETUP ----------------

create_tables()

st.set_page_config(
    page_title="Triple-Staged Crypto Authentication",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 Triple-Staged Crypto Authentication")
st.subheader("Secure P2P Online Learning Application")

menu = st.sidebar.selectbox(
    "Menu",
    [
        "Home",
        "Register",
        "Login",
        "Staff Upload File",
        "Student View / Download File",
        "Attack Scenarios",
        "Logout"
    ]
)

if "stage1" not in st.session_state:
    st.session_state.stage1 = False

if "stage2" not in st.session_state:
    st.session_state.stage2 = False

if "stage3" not in st.session_state:
    st.session_state.stage3 = False

if "username" not in st.session_state:
    st.session_state.username = ""

if "role" not in st.session_state:
    st.session_state.role = ""


# ---------------- HOME ----------------

if menu == "Home":
    st.info("This system uses three security phases.")

    st.write("""
    ### Three Authentication Phases

    **Phase 1:** Username and password authentication  
    **Phase 2:** Random key verification  
    **Phase 3:** AES file access/decryption key verification  

    Staff can upload encrypted files.  
    Students can view and download files only after passing all three stages.
    """)


# ---------------- REGISTER ----------------

elif menu == "Register":
    st.header("User Registration")

    username = st.text_input("Create Username")
    password = st.text_input("Create Password", type="password")
    role = st.selectbox("Select Role", ["Student", "Staff"])

    if st.button("Register"):
        if username and password:
            random_key = register_user(username, password, role)

            if random_key:
                st.success("Registration successful!")
                st.warning(f"Your random key is: {random_key}")
                st.info("Save this key. You need it for Phase 2 authentication.")
            else:
                st.error("Username already exists.")
        else:
            st.error("Please fill all fields.")


# ---------------- LOGIN ----------------

elif menu == "Login":
    st.header("Phase 1: Username and Password Authentication")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Verify Phase 1"):
        user = verify_password(username, password)

        if user:
            st.session_state.temp_username = user[0]
            st.session_state.temp_random_key = user[1]
            st.session_state.temp_role = user[2]
            st.session_state.stage1 = True
            st.success("Phase 1 passed.")
        else:
            st.error("Invalid username or password.")

    if st.session_state.stage1:
        st.header("Phase 2: Random Key Verification")

        random_key = st.text_input("Enter Random Key")

        if st.button("Verify Phase 2"):
            if verify_random_key(st.session_state.temp_username, random_key):
                st.session_state.stage2 = True
                st.session_state.username = st.session_state.temp_username
                st.session_state.role = st.session_state.temp_role
                st.success("Phase 2 passed.")
                st.info(f"Logged in as {st.session_state.username} ({st.session_state.role})")
            else:
                st.error("Invalid random key. Access denied.")


# ---------------- STAFF UPLOAD ----------------

elif menu == "Staff Upload File":
    st.header("Staff Upload Encrypted File")

    if not st.session_state.stage2:
        st.error("Please complete Phase 1 and Phase 2 login first.")
    elif st.session_state.role != "Staff":
        st.error("Only staff can upload files.")
    else:
        uploaded_file = st.file_uploader("Upload Learning File")

        if uploaded_file is not None:
            file_bytes = uploaded_file.read()

            if st.button("Encrypt and Upload File"):
                save_file(uploaded_file.name, file_bytes, st.session_state.username)
                st.success("File encrypted and uploaded successfully.")


# ---------------- STUDENT VIEW / DOWNLOAD ----------------

elif menu == "Student View / Download File":
    st.header("Student View and Download Files")

    if not st.session_state.stage2:
        st.error("Please complete Phase 1 and Phase 2 login first.")
    elif st.session_state.role != "Student":
        st.error("Only students can view and download learning files.")
    else:
        st.subheader("Phase 3: AES File Access Key Verification")

        access_key = st.text_input("Enter AES File Access Key", type="password")

        if st.button("Verify Phase 3"):
            if verify_file_access_key(access_key):
                st.session_state.stage3 = True
                st.success("Phase 3 passed. You can now view and download files.")
            else:
                st.error("Invalid AES file access key.")

        if st.session_state.stage3:
            files = get_all_files()

            if not files:
                st.info("No files uploaded yet.")
            else:
                for file_id, filename, encrypted_data, uploaded_by in files:
                    with st.expander(f"{filename} | Uploaded by {uploaded_by}"):
                        st.write("Encrypted file data:")
                        st.code(str(encrypted_data[:150]) + "...")

                        try:
                            decrypted_file = decrypt_file(encrypted_data)

                            st.success("File decrypted successfully.")

                            st.download_button(
                                label=f"Download {filename}",
                                data=decrypted_file,
                                file_name=filename,
                                mime="application/octet-stream"
                            )

                        except Exception:
                            st.error("Unable to decrypt file.")


# ---------------- ATTACK SCENARIOS ----------------

elif menu == "Attack Scenarios":
    st.header("Attack Scenario Simulation")

    attack = st.selectbox(
        "Choose Attack Scenario",
        [
            "Brute Force Attack",
            "Dictionary Attack",
            "Man-In-The-Middle Attack"
        ]
    )

    if attack == "Brute Force Attack":
        st.subheader("Brute Force Attack Simulation")

        st.write("""
        In a brute force attack, an attacker repeatedly guesses the password.
        In this system, even if the password is guessed, the attacker still needs
        the random key and AES file access key.
        """)

        guessed_password = st.text_input("Attacker guessed password")
        guessed_random_key = st.text_input("Attacker guessed random key")

        if st.button("Launch Brute Force Simulation"):
            if guessed_password and not guessed_random_key:
                st.warning("Password guessed, but random key missing.")
                st.error("Attack failed at Phase 2.")
            elif guessed_password and guessed_random_key != "correct":
                st.error("Attack failed because random key is incorrect.")
            else:
                st.error("Attack failed. Three-phase authentication blocks access.")

    elif attack == "Dictionary Attack":
        st.subheader("Dictionary Attack Simulation")

        st.write("""
        In a dictionary attack, the attacker uses common passwords such as
        password123, admin, qwerty, or student123.
        """)

        common_password = st.selectbox(
            "Choose dictionary password",
            ["password123", "admin", "qwerty", "student123", "letmein"]
        )

        if st.button("Launch Dictionary Attack"):
            st.warning(f"Attacker tried password: {common_password}")
            st.error("Attack failed because random key and AES file access key are still required.")

    elif attack == "Man-In-The-Middle Attack":
        st.subheader("MITM Attack Simulation")

        st.write("""
        In a MITM attack, the attacker tries to intercept files during communication.
        Since the uploaded files are encrypted, intercepted data is unreadable.
        """)

        sample_text = b"This is confidential learning material."
        encrypted_sample = encrypt_file(sample_text)

        st.write("Intercepted encrypted data:")
        st.code(encrypted_sample)

        if st.button("Try to Read Intercepted Data"):
            st.error("MITM attack failed. The attacker can only see encrypted ciphertext.")


# ---------------- LOGOUT ----------------

elif menu == "Logout":
    st.session_state.stage1 = False
    st.session_state.stage2 = False
    st.session_state.stage3 = False
    st.session_state.username = ""
    st.session_state.role = ""

    st.success("Logged out successfully.")
