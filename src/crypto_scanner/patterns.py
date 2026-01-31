"""Regex patterns for detecting cryptographic usage in source code and configs."""

import re
from dataclasses import dataclass

from crypto_scanner.models import RiskLevel


@dataclass
class CryptoPattern:
    """A pattern for detecting cryptographic usage."""

    name: str
    pattern: re.Pattern
    algorithm: str
    risk_level: RiskLevel
    description: str
    recommendation: str
    key_size: int | None = None


# ============================================================================
# Quantum-Vulnerable Algorithms (CRITICAL)
# ============================================================================

RSA_PATTERNS = [
    CryptoPattern(
        name="RSA Import (Python)",
        pattern=re.compile(r"from\s+(?:Crypto(?:dome)?\.PublicKey|cryptography\.hazmat\.primitives\.asymmetric)\s+import\s+.*\brsa\b", re.IGNORECASE),
        algorithm="RSA",
        risk_level=RiskLevel.CRITICAL,
        description="RSA cryptographic library import detected",
        recommendation="Plan migration to post-quantum algorithms (ML-KEM, ML-DSA). RSA is vulnerable to Shor's algorithm on quantum computers.",
    ),
    CryptoPattern(
        name="RSA Key Generation",
        pattern=re.compile(r"(?:rsa\.generate|RSA\.generate|generate_private_key.*rsa|RSAKeyPairGenerator)", re.IGNORECASE),
        algorithm="RSA",
        risk_level=RiskLevel.CRITICAL,
        description="RSA key generation detected",
        recommendation="Plan migration to post-quantum key encapsulation (ML-KEM). Document key locations for future rotation.",
    ),
    CryptoPattern(
        name="RSA Usage (Java)",
        pattern=re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']', re.IGNORECASE),
        algorithm="RSA",
        risk_level=RiskLevel.CRITICAL,
        description="RSA key pair generation in Java",
        recommendation="Plan migration to post-quantum algorithms. Consider hybrid approaches during transition.",
    ),
    CryptoPattern(
        name="RSA Cipher (Java)",
        pattern=re.compile(r'Cipher\.getInstance\s*\(\s*["\']RSA', re.IGNORECASE),
        algorithm="RSA",
        risk_level=RiskLevel.CRITICAL,
        description="RSA cipher usage in Java",
        recommendation="Migrate to post-quantum encryption schemes.",
    ),
]

ECDSA_PATTERNS = [
    CryptoPattern(
        name="ECDSA Import (Python)",
        pattern=re.compile(r"from\s+(?:Crypto(?:dome)?\.PublicKey|cryptography\.hazmat\.primitives\.asymmetric)\s+import\s+.*\bec\b", re.IGNORECASE),
        algorithm="ECDSA/ECC",
        risk_level=RiskLevel.CRITICAL,
        description="Elliptic curve cryptography import detected",
        recommendation="Plan migration to post-quantum signatures (ML-DSA, SLH-DSA). ECC is vulnerable to Shor's algorithm.",
    ),
    CryptoPattern(
        name="ECDSA Usage",
        pattern=re.compile(r"(?:ECDSA|ec\.generate|EllipticCurve|SECP\d+|P-\d{3}|prime256v1|secp384r1)", re.IGNORECASE),
        algorithm="ECDSA/ECC",
        risk_level=RiskLevel.CRITICAL,
        description="Elliptic curve cryptography usage detected",
        recommendation="Plan migration to post-quantum digital signatures (ML-DSA).",
    ),
    CryptoPattern(
        name="EC Key Generation (Java)",
        pattern=re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*["\']EC["\']', re.IGNORECASE),
        algorithm="ECDSA/ECC",
        risk_level=RiskLevel.CRITICAL,
        description="EC key pair generation in Java",
        recommendation="Plan migration to post-quantum algorithms.",
    ),
]

DH_PATTERNS = [
    CryptoPattern(
        name="Diffie-Hellman Import",
        pattern=re.compile(r"(?:from\s+.*import\s+.*\bdh\b|DiffieHellman|DHParameterSpec)", re.IGNORECASE),
        algorithm="DH/ECDH",
        risk_level=RiskLevel.CRITICAL,
        description="Diffie-Hellman key exchange detected",
        recommendation="Plan migration to post-quantum key encapsulation (ML-KEM). DH is vulnerable to quantum attacks.",
    ),
    CryptoPattern(
        name="ECDH Usage",
        pattern=re.compile(r"(?:ECDH|X25519|X448|derive.*shared)", re.IGNORECASE),
        algorithm="ECDH",
        risk_level=RiskLevel.CRITICAL,
        description="Elliptic curve Diffie-Hellman key exchange detected",
        recommendation="Plan migration to ML-KEM for key encapsulation.",
    ),
]

DSA_PATTERNS = [
    CryptoPattern(
        name="DSA Usage",
        pattern=re.compile(r"(?:from\s+.*import\s+.*\bdsa\b|DSA\.generate|KeyPairGenerator.*DSA)", re.IGNORECASE),
        algorithm="DSA",
        risk_level=RiskLevel.CRITICAL,
        description="DSA digital signature algorithm detected",
        recommendation="Migrate to post-quantum signatures (ML-DSA). DSA is both deprecated and quantum-vulnerable.",
    ),
]

# ============================================================================
# Weak/Deprecated Algorithms (HIGH)
# ============================================================================

MD5_PATTERNS = [
    CryptoPattern(
        name="MD5 Usage (Python)",
        pattern=re.compile(r"(?:hashlib\.md5|MD5\.new|MessageDigest.*MD5)", re.IGNORECASE),
        algorithm="MD5",
        risk_level=RiskLevel.HIGH,
        description="MD5 hash function detected",
        recommendation="Replace with SHA-256 or SHA-3. MD5 is cryptographically broken.",
    ),
    CryptoPattern(
        name="MD5 String Reference",
        pattern=re.compile(r'["\']MD5["\']', re.IGNORECASE),
        algorithm="MD5",
        risk_level=RiskLevel.HIGH,
        description="MD5 algorithm reference detected",
        recommendation="Replace with SHA-256 or SHA-3.",
    ),
]

SHA1_PATTERNS = [
    CryptoPattern(
        name="SHA-1 Usage (Python)",
        pattern=re.compile(r"(?:hashlib\.sha1|SHA\.new|SHA1\.new)", re.IGNORECASE),
        algorithm="SHA-1",
        risk_level=RiskLevel.HIGH,
        description="SHA-1 hash function detected",
        recommendation="Migrate to SHA-256 or SHA-3. SHA-1 is deprecated due to collision attacks.",
    ),
    CryptoPattern(
        name="SHA-1 Reference (Java)",
        pattern=re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', re.IGNORECASE),
        algorithm="SHA-1",
        risk_level=RiskLevel.HIGH,
        description="SHA-1 hash function in Java",
        recommendation="Migrate to SHA-256 or SHA-3.",
    ),
]

DES_PATTERNS = [
    CryptoPattern(
        name="DES Usage",
        pattern=re.compile(r'(?:Cipher\.getInstance\s*\(\s*["\']DES["\']|DES\.new|from\s+.*DES\s+import)', re.IGNORECASE),
        algorithm="DES",
        risk_level=RiskLevel.HIGH,
        description="DES encryption detected",
        recommendation="Migrate to AES-256. DES has inadequate key length (56 bits).",
    ),
    CryptoPattern(
        name="3DES/Triple DES Usage",
        pattern=re.compile(r"(?:3DES|Triple.?DES|DESede|TDES)", re.IGNORECASE),
        algorithm="3DES",
        risk_level=RiskLevel.HIGH,
        description="Triple DES encryption detected",
        recommendation="Migrate to AES-256. 3DES is deprecated and slow.",
    ),
]

AES_128_PATTERNS = [
    CryptoPattern(
        name="AES-128 Key Size",
        pattern=re.compile(r"(?:AES.?128|key.?(?:size|length|bits)\s*[=:]\s*128|128.?bit.*AES)", re.IGNORECASE),
        algorithm="AES-128",
        key_size=128,
        risk_level=RiskLevel.HIGH,
        description="AES with 128-bit key detected",
        recommendation="Upgrade to AES-256 for long-term quantum resistance (Grover's algorithm consideration).",
    ),
]

# ============================================================================
# Acceptable but Plan Migration (MEDIUM)
# ============================================================================

SHA256_PATTERNS = [
    CryptoPattern(
        name="SHA-256 Usage",
        pattern=re.compile(r"(?:hashlib\.sha256|SHA256\.new|sha-?256)", re.IGNORECASE),
        algorithm="SHA-256",
        risk_level=RiskLevel.MEDIUM,
        description="SHA-256 hash function detected",
        recommendation="SHA-256 is currently secure. Consider SHA-3 for new implementations as a hedge against future cryptanalysis.",
    ),
    CryptoPattern(
        name="SHA-384 Usage",
        pattern=re.compile(r"(?:hashlib\.sha384|SHA384|sha-?384)", re.IGNORECASE),
        algorithm="SHA-384",
        risk_level=RiskLevel.MEDIUM,
        description="SHA-384 hash function detected",
        recommendation="SHA-384 is secure. No immediate action required.",
    ),
    CryptoPattern(
        name="SHA-512 Usage",
        pattern=re.compile(r"(?:hashlib\.sha512|SHA512|sha-?512)", re.IGNORECASE),
        algorithm="SHA-512",
        risk_level=RiskLevel.MEDIUM,
        description="SHA-512 hash function detected",
        recommendation="SHA-512 is secure with good quantum resistance. No immediate action required.",
    ),
]

# ============================================================================
# Quantum-Resistant / Adequate (LOW)
# ============================================================================

AES_256_PATTERNS = [
    CryptoPattern(
        name="AES-256 Key Size",
        pattern=re.compile(r"(?:AES.?256|key.?(?:size|length|bits)\s*[=:]\s*256|256.?bit.*AES)", re.IGNORECASE),
        algorithm="AES-256",
        key_size=256,
        risk_level=RiskLevel.LOW,
        description="AES with 256-bit key detected",
        recommendation="AES-256 provides adequate quantum resistance. No immediate action required.",
    ),
]

CHACHA_PATTERNS = [
    CryptoPattern(
        name="ChaCha20 Usage",
        pattern=re.compile(r"(?:ChaCha20|chacha20-?poly1305|CHACHA)", re.IGNORECASE),
        algorithm="ChaCha20",
        risk_level=RiskLevel.LOW,
        description="ChaCha20 stream cipher detected",
        recommendation="ChaCha20 is secure and performant. No action required.",
    ),
]

SHA3_PATTERNS = [
    CryptoPattern(
        name="SHA-3 Usage",
        pattern=re.compile(r"(?:sha-?3|SHA3|Keccak)", re.IGNORECASE),
        algorithm="SHA-3",
        risk_level=RiskLevel.LOW,
        description="SHA-3 hash function detected",
        recommendation="SHA-3 is the latest standard with excellent security properties. No action required.",
    ),
]

PQC_PATTERNS = [
    CryptoPattern(
        name="Post-Quantum Algorithm",
        pattern=re.compile(r"(?:ML-KEM|ML-DSA|SLH-DSA|Kyber|Dilithium|SPHINCS|FALCON|BIKE|HQC|Classic.?McEliece)", re.IGNORECASE),
        algorithm="Post-Quantum",
        risk_level=RiskLevel.LOW,
        description="Post-quantum cryptographic algorithm detected",
        recommendation="Excellent! Post-quantum algorithms are the recommended path forward.",
    ),
]

# ============================================================================
# Config/Environment Patterns
# ============================================================================

CONFIG_PATTERNS = [
    CryptoPattern(
        name="SSL/TLS Version",
        pattern=re.compile(r"(?:ssl_protocols?\s*[=:]\s*|TLSv1\.[0-2]|SSLv[23])", re.IGNORECASE),
        algorithm="TLS",
        risk_level=RiskLevel.MEDIUM,
        description="TLS/SSL configuration detected",
        recommendation="Ensure TLS 1.3 is enabled. Disable TLS 1.0/1.1 and all SSL versions.",
    ),
    CryptoPattern(
        name="Cipher Suite Config",
        pattern=re.compile(r"(?:cipher_?suites?\s*[=:]|ssl_ciphers?\s*[=:])", re.IGNORECASE),
        algorithm="Cipher Suite",
        risk_level=RiskLevel.MEDIUM,
        description="Cipher suite configuration detected",
        recommendation="Review cipher suite configuration. Prioritize AES-256-GCM and ChaCha20-Poly1305.",
    ),
    CryptoPattern(
        name="Private Key Reference",
        pattern=re.compile(r"(?:private_?key|PRIVATE.?KEY|\.pem|\.key)\s*[=:]", re.IGNORECASE),
        algorithm="Private Key",
        risk_level=RiskLevel.MEDIUM,
        description="Private key reference in configuration",
        recommendation="Ensure private keys are stored securely. Document key locations for quantum migration planning.",
    ),
]

# ============================================================================
# Aggregated Pattern Groups
# ============================================================================

ALL_PATTERNS = (
    RSA_PATTERNS +
    ECDSA_PATTERNS +
    DH_PATTERNS +
    DSA_PATTERNS +
    MD5_PATTERNS +
    SHA1_PATTERNS +
    DES_PATTERNS +
    AES_128_PATTERNS +
    SHA256_PATTERNS +
    AES_256_PATTERNS +
    CHACHA_PATTERNS +
    SHA3_PATTERNS +
    PQC_PATTERNS +
    CONFIG_PATTERNS
)

CRITICAL_PATTERNS = RSA_PATTERNS + ECDSA_PATTERNS + DH_PATTERNS + DSA_PATTERNS
HIGH_PATTERNS = MD5_PATTERNS + SHA1_PATTERNS + DES_PATTERNS + AES_128_PATTERNS
MEDIUM_PATTERNS = SHA256_PATTERNS + CONFIG_PATTERNS
LOW_PATTERNS = AES_256_PATTERNS + CHACHA_PATTERNS + SHA3_PATTERNS + PQC_PATTERNS


def get_patterns_for_extension(extension: str) -> list[CryptoPattern]:
    """Get relevant patterns based on file extension."""
    source_extensions = {".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".cs", ".rb", ".php"}
    config_extensions = {".conf", ".yaml", ".yml", ".json", ".env", ".ini", ".toml", ".cfg"}

    if extension.lower() in source_extensions:
        return ALL_PATTERNS
    elif extension.lower() in config_extensions:
        return CONFIG_PATTERNS + HIGH_PATTERNS + CRITICAL_PATTERNS
    else:
        return ALL_PATTERNS
