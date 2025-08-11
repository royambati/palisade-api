import secrets, hashlib

def generate_key(prefix: str, nbytes: int):
    """Return (plaintext_key, salt, hash). Hash = sha256(salt + key)."""
    raw = secrets.token_urlsafe(nbytes)
    plaintext = f"{prefix}{raw}"
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + plaintext).encode()).hexdigest()
    return plaintext, salt, h

def hash_key(salt: str, plaintext: str) -> str:
    return hashlib.sha256((salt + plaintext).encode()).hexdigest()