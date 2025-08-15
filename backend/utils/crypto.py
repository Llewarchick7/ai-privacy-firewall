import secrets

def random_secret(length: int = 32) -> str:
    """Return a URL-safe random secret (base64url without padding)."""
    return secrets.token_urlsafe(length)

def random_code(length: int = 10) -> str:
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(length))
