# P2P Triple-Staged Crypto Authentication App

This Streamlit prototype implements a secure P2P online learning authentication idea:

1. Text/password authentication
2. Random key verification
3. AES-compatible encryption/decryption using `cryptography.Fernet`

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

## GitHub upload

Create a new repository, then upload:

- `app.py`
- `requirements.txt`
- `README.md`
- `colab_run.ipynb`

## Streamlit Cloud deployment

1. Push files to GitHub.
2. Go to Streamlit Community Cloud.
3. Select your repo.
4. Set main file path as `app.py`.
5. Deploy.

## Notes

This is a prototype using SQLite and local key storage. For production, use stronger password hashing such as bcrypt/Argon2, HTTPS, secure secrets management, audit logging, and proper key rotation.
