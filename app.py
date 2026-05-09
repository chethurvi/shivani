import streamlit as st
import sqlite3
import secrets
import hashlib
import base64
from cryptography.fernet import Fernet

DB_NAME = "p2p_learning.db"
FILE_ACCESS_KEY = "AES123"

# ---------------- DATABASE ----------------

def get_connection():
    return sqlite3.connect(DB_NAME, check_same_thread=False)


def create_tables():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            random_key TEXT,
            role TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            encrypted_data BLOB,
            uploaded_by TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT,
            details TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def reset_old_database_if_needed():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("PRAGMA table_info(files)")
    columns = [col[1] for col in cur.fetchall()]
    expected = {"id", "filename", "encrypted_data", "uploaded_by"}

    if columns and not expected.issubset(set(columns)):
        cur.execute("DROP TABLE IF EXISTS files")
        cur.execute("""
            CREATE TABLE files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                encrypted_data BLOB,
                uploaded_by TEXT
            )
        """)
        conn.commit()

    conn.close()


def reset_old_logs_if_needed():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("PRAGMA table_info(logs)")
    columns = [col[1] for col in cur.fetchall()]
    expected = {"id", "event", "details", "status", "created_at"}

    if columns and not expected.issubset(set(columns)):
        cur.execute("DROP TABLE IF EXISTS logs")
        cur.execute("""
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT,
                details TEXT,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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


def verify_file_access_key(access_key):
    return access_key == FILE_ACCESS_KEY


# ---------------- LOGS ----------------

def add_log(event, details, status):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO logs (event, details, status) VALUES (?, ?, ?)",
        (event, details, status)
    )

    conn.commit()
    conn.close()


def get_logs():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT created_at, event, details, status FROM logs ORDER BY id DESC")
    logs = cur.fetchall()

    conn.close()
    return logs


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
        conn.close()

        add_log("User Registration", f"{username} registered as {role}", "Success")
        return random_key

    except sqlite3.IntegrityError:
        conn.close()
        add_log("User Registration", f"Duplicate username attempted: {username}", "Failed")
        return None


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


def count_users():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM users")
    total = cur.fetchone()[0]

    conn.close()
    return total


def count_logs():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM logs")
    total = cur.fetchone()[0]

    conn.close()
    return total


# ---------------- FILE FUNCTIONS ----------------

def save_file(filename, file_bytes, uploaded_by):
    encrypted_data = encrypt_file(file_bytes)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO files (filename, encrypted_data, uploaded_by)
        VALUES (?, ?, ?)
    """, (filename, encrypted_data, uploaded_by))

    conn.commit()
    conn.close()

    add_log("File Upload", f"{filename} uploaded by {uploaded_by}", "Encrypted")


def get_all_files():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, filename, encrypted_data, uploaded_by FROM files")
    files = cur.fetchall()

    conn.close()
    return files


# ---------------- APP SETUP ----------------

create_tables()
reset_old_database_if_needed()
reset_old_logs_if_needed()

st.set_page_config(
    page_title="Secure P2P Authentication",
    page_icon="🔐",
    layout="wide"
)


# ---------------- SESSION STATE ----------------

default_session_values = {
    "stage1": False,
    "stage2": False,
    "stage3": False,
    "username": "",
    "role": "",
    "temp_username": "",
    "temp_random_key": "",
    "temp_role": ""
}

for key, value in default_session_values.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ---------------- SIDEBAR MENU ----------------

st.sidebar.title("🔐 P2P Security")
st.sidebar.write("Menu")

menu = st.sidebar.radio(
    "",
    [
        "Dashboard",
        "Register Peer",
        "Phase 1: Identity Verification",
        "Phase 2: Session Key",
        "Phase 3: Secure Transfer",
        "Secure Login",
        "Application Dashboard",
        "Attack Simulation",
        "Authentication Logs",
        "Logout"
    ]
)

st.sidebar.divider()

if st.session_state.stage2:
    st.sidebar.success(f"Logged in: {st.session_state.username}")
    st.sidebar.info(f"Role: {st.session_state.role}")
else:
    st.sidebar.warning("Not logged in")


# ---------------- HEADER ----------------

st.title("🔐 Secure Three-Phase P2P Authentication System")
st.caption("Python + Streamlit + SQLite + Hashing + Random Key + AES Encryption + Secure File Transfer")
st.divider()


# ---------------- DASHBOARD ----------------

if menu == "Dashboard":
    st.header("System Dashboard")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Registered Peers", count_users())
    col2.metric("Total Events", count_logs())
    col3.metric("Logged In", "Yes" if st.session_state.stage2 else "No")
    col4.metric("Current Peer", st.session_state.username if st.session_state.username else "None")

    st.subheader("Authentication Flow")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.info("""
        ### Phase 1  
        **Identity Verification**  
        Username and password authentication
        """)

    with c2:
        st.warning("""
        ### Phase 2  
        **Session Key**  
        Random key verification
        """)

    with c3:
        st.success("""
        ### Phase 3  
        **Secure Transfer**  
        AES encrypted file upload, view and download
        """)

    st.subheader("System Status")
    st.success("Database: Connected")
    st.success("Encryption: Active")
    st.success("Session Management: Active")
    st.success("Security Layer: Three-Phase Enabled")


# ---------------- REGISTER ----------------

elif menu == "Register Peer":
    st.header("Register New Peer")

    username = st.text_input("Create Username")
    password = st.text_input("Create Password", type="password")
    role = st.selectbox("Select Role", ["Student", "Staff"])

    if st.button("Register Peer"):
        if username and password:
            random_key = register_user(username, password, role)

            if random_key:
                st.success("Registration successful!")
                st.warning(f"Your random session key is: {random_key}")
                st.info("Save this key. You need it for Phase 2 authentication.")
            else:
                st.error("Username already exists.")
        else:
            st.error("Please fill all fields.")


# ---------------- PHASE 1 ----------------

elif menu == "Phase 1: Identity Verification":
    st.header("Phase 1: Identity Verification")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Verify Identity"):
        user = verify_password(username, password)

        if user:
            st.session_state.temp_username = user[0]
            st.session_state.temp_random_key = user[1]
            st.session_state.temp_role = user[2]
            st.session_state.stage1 = True

            add_log("Phase 1 Authentication", f"{username} password verified", "Success")
            st.success("Phase 1 passed. Now go to Phase 2: Session Key.")
        else:
            add_log("Phase 1 Authentication", f"Failed login attempt for {username}", "Failed")
            st.error("Invalid username or password.")


# ---------------- PHASE 2 ----------------

elif menu == "Phase 2: Session Key":
    st.header("Phase 2: Random Session Key Verification")

    if not st.session_state.stage1:
        st.error("Please complete Phase 1 first.")
    else:
        random_key = st.text_input("Enter Random Session Key")

        if st.button("Verify Session Key"):
            if verify_random_key(st.session_state.temp_username, random_key):
                st.session_state.stage2 = True
                st.session_state.username = st.session_state.temp_username
                st.session_state.role = st.session_state.temp_role

                add_log("Phase 2 Authentication", f"{st.session_state.username} random key verified", "Success")
                st.success("Phase 2 passed.")
                st.info(f"Logged in as {st.session_state.username} ({st.session_state.role})")
            else:
                add_log("Phase 2 Authentication", "Incorrect random key entered", "Failed")
                st.error("Invalid random key. Access denied.")


# ---------------- PHASE 3 ----------------

elif menu == "Phase 3: Secure Transfer":
    st.header("Phase 3: Secure File Transfer")

    if not st.session_state.stage2:
        st.error("Please complete Phase 1 and Phase 2 first.")
    else:
        access_key = st.text_input("Enter AES File Access Key", type="password")

        if st.button("Verify Phase 3"):
            if verify_file_access_key(access_key):
                st.session_state.stage3 = True
                add_log("Phase 3 Authentication", f"{st.session_state.username} verified AES access key", "Success")
                st.success("Phase 3 passed. Secure file transfer unlocked.")
            else:
                add_log("Phase 3 Authentication", "Wrong AES file access key", "Failed")
                st.error("Invalid AES file access key.")

        st.info("Default Phase 3 key for demo: AES123")


# ---------------- SECURE LOGIN ----------------

elif menu == "Secure Login":
    st.header("Complete Secure Login")

    st.write("This page checks your full login status.")

    if st.session_state.stage1:
        st.success("Phase 1: Passed")
    else:
        st.error("Phase 1: Not completed")

    if st.session_state.stage2:
        st.success("Phase 2: Passed")
    else:
        st.error("Phase 2: Not completed")

    if st.session_state.stage3:
        st.success("Phase 3: Passed")
    else:
        st.error("Phase 3: Not completed")


# ---------------- APPLICATION DASHBOARD ----------------

elif menu == "Application Dashboard":
    st.header("Application Dashboard")

    if not st.session_state.stage2:
        st.error("Please login first.")
    else:
        st.success(f"Welcome {st.session_state.username}")

        if st.session_state.role == "Staff":
            st.subheader("Staff File Upload")

            uploaded_file = st.file_uploader("Upload Learning File")

            if uploaded_file is not None:
                file_bytes = uploaded_file.read()

                if st.button("Encrypt and Upload File"):
                    save_file(uploaded_file.name, file_bytes, st.session_state.username)
                    st.success("File encrypted and uploaded successfully.")

        elif st.session_state.role == "Student":
            st.subheader("Student View and Download Files")

            if not st.session_state.stage3:
                st.error("Please complete Phase 3 before viewing or downloading files.")
            else:
                files = get_all_files()

                if not files:
                    st.info("No files uploaded yet.")
                else:
                    for file_id, filename, encrypted_data, uploaded_by in files:
                        with st.expander(f"{filename} | Uploaded by {uploaded_by}"):
                            st.write("Encrypted file preview:")
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


# ---------------- ATTACK SIMULATION ----------------

elif menu == "Attack Simulation":
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
        st.subheader("Brute Force Attack")

        st.write("""
        A brute force attacker repeatedly guesses passwords.
        This system blocks the attacker because password alone is not enough.
        Random key and AES access key are also required.
        """)

        guessed_password = st.text_input("Attacker guessed password")
        guessed_key = st.text_input("Attacker guessed random key")

        if st.button("Launch Brute Force Attack"):
            if guessed_password and not guessed_key:
                st.warning("Password guessed, but random key missing.")
                st.error("Attack failed at Phase 2.")
            else:
                st.error("Attack failed. Three-phase authentication blocks access.")

            add_log("Attack Simulation", "Brute force attack simulated", "Blocked")

    elif attack == "Dictionary Attack":
        st.subheader("Dictionary Attack")

        st.write("""
        A dictionary attacker tries common passwords such as admin, password123,
        student123, qwerty, or letmein.
        """)

        password = st.selectbox(
            "Dictionary password attempted",
            ["admin", "password123", "student123", "qwerty", "letmein"]
        )

        if st.button("Launch Dictionary Attack"):
            st.warning(f"Attacker tried: {password}")
            st.error("Attack failed. Random key and AES access key are still required.")
            add_log("Attack Simulation", "Dictionary attack simulated", "Blocked")

    elif attack == "Man-In-The-Middle Attack":
        st.subheader("Man-In-The-Middle Attack")

        st.write("""
        A MITM attacker tries to intercept a file during transfer.
        Since files are encrypted, intercepted data is unreadable.
        """)

        sample_data = b"This is confidential learning material."
        encrypted_sample = encrypt_file(sample_data)

        st.write("Intercepted encrypted data:")
        st.code(encrypted_sample)

        if st.button("Try to Read Intercepted Data"):
            st.error("MITM attack failed. Attacker only sees encrypted ciphertext.")
            add_log("Attack Simulation", "MITM attack simulated", "Blocked")


# ---------------- LOGS ----------------

elif menu == "Authentication Logs":
    st.header("Authentication Logs")

    logs = get_logs()

    if not logs:
        st.info("No logs available.")
    else:
        st.table(logs)


# ---------------- LOGOUT ----------------

elif menu == "Logout":
    st.session_state.stage1 = False
    st.session_state.stage2 = False
    st.session_state.stage3 = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.session_state.temp_username = ""
    st.session_state.temp_random_key = ""
    st.session_state.temp_role = ""

    st.success("Logged out successfully.")
