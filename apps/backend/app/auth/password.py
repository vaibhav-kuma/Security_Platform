"""Password hashing utilities using bcrypt via passlib."""

from passlib.context import CryptContext

# bcrypt with rounds=12 (adjustable via env in production)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    """Return a bcrypt hash of the plaintext password."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)
