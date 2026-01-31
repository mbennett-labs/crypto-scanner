"""Sample Python file with various cryptographic patterns for testing."""

# CRITICAL - Quantum-vulnerable algorithms
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from Crypto.PublicKey import RSA, DSA

# RSA key generation
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# ECDSA usage
ec_key = ec.generate_private_key(ec.SECP256R1())

# HIGH - Deprecated/weak algorithms
import hashlib

# MD5 - broken
md5_hash = hashlib.md5(b"password").hexdigest()

# SHA-1 - deprecated
sha1_hash = hashlib.sha1(b"data").hexdigest()

# MEDIUM - Acceptable but plan migration
sha256_hash = hashlib.sha256(b"secure_data").hexdigest()
sha512_hash = hashlib.sha512(b"more_secure").hexdigest()

# LOW - Quantum-resistant or adequate
# AES-256 configuration
AES_KEY_SIZE = 256
ENCRYPTION_ALGORITHM = "AES-256-GCM"

# ChaCha20 usage
cipher_suite = "ChaCha20-Poly1305"
