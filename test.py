
"""
AST-SCANNER CRYPTOGRAPHIC TEST FIXTURE
-------------------------------------
For defensive scanner testing only. Do not use these examples in production.
Dummy data only. This file is designed to be scanned, not executed.
"""

import hashlib
import hmac
import ssl

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# 1. WEAK HASH ALGORITHMS
# Expected checks: algorithm name, API, risk classification
# ============================================================

def weak_hashes(data: bytes):
    md5_digest = hashlib.md5(data).hexdigest()
    sha1_digest = hashlib.sha1(data).hexdigest()

    # Modern comparison cases
    sha256_digest = hashlib.sha256(data).hexdigest()
    sha512_digest = hashlib.sha512(data).hexdigest()

    return md5_digest, sha1_digest, sha256_digest, sha512_digest


# ============================================================
# 2. HMAC ALGORITHM SELECTION
# Expected checks: digest algorithm and key handling
# ============================================================

def weak_hmac(dummy_key: bytes, data: bytes):
    weak_mac = hmac.new(dummy_key, data, hashlib.md5).hexdigest()
    stronger_mac = hmac.new(dummy_key, data, hashlib.sha256).hexdigest()
    return weak_mac, stronger_mac


# ============================================================
# 3. RSA KEY SIZES
# Expected checks: algorithm, key_size, public_exponent
# ============================================================

def rsa_key_size_examples():
    # Intentionally weak: 1024-bit RSA
    weak_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )

    # RSA-2048: not broken by today's classical standards,
    # but requires post-quantum migration planning.
    migration_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Larger classical RSA key; still not post-quantum safe.
    larger_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    return weak_rsa, migration_rsa, larger_rsa


# ============================================================
# 4. ELLIPTIC-CURVE CRYPTOGRAPHY
# Expected checks: curve name and quantum-vulnerability status
# ============================================================

def elliptic_curve_examples():
    # Small legacy curve
    weak_ec = ec.generate_private_key(ec.SECP192R1())

    # Common classical curve; still vulnerable to a sufficiently
    # capable cryptographically relevant quantum computer.
    migration_ec = ec.generate_private_key(ec.SECP256R1())

    return weak_ec, migration_ec


# ============================================================
# 5. WEAK SYMMETRIC CIPHER / MODE / IV
# Expected checks: algorithm, key length, mode, IV length
# ============================================================

def weak_aes_cbc(dummy_key: bytes, data: bytes):
    # Test-only fixed IV. AES-CBC requires a 16-byte IV.
    fixed_iv = b"0123456789abcdef"

    cipher = Cipher(
        algorithms.AES(dummy_key),  # Inspect actual key length
        modes.CBC(fixed_iv),
    )

    encryptor = cipher.encryptor()
    padded_test_data = data.ljust(
        ((len(data) + 15) // 16) * 16,
        b" ",
    )
    return encryptor.update(padded_test_data) + encryptor.finalize()


def aes_ecb_example(dummy_key: bytes, data: bytes):
    # ECB is an insecure mode for general-purpose data encryption.
    cipher = Cipher(
        algorithms.AES(dummy_key),
        modes.ECB(),
    )
    encryptor = cipher.encryptor()

    padded_test_data = data.ljust(
        ((len(data) + 15) // 16) * 16,
        b" ",
    )
    return encryptor.update(padded_test_data) + encryptor.finalize()


# ============================================================
# 6. DES / TRIPLE DES
# Expected checks: weak algorithm detection
# ============================================================

def legacy_cipher_examples(dummy_key: bytes, data: bytes):
    # Some cryptography versions expose TripleDES in a decrepit
    # namespace. This import is kept inside the function so the
    # scanner can inspect it without requiring execution.
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

    legacy_cipher = Cipher(
        TripleDES(dummy_key[:8]),
        modes.CBC(b"01234567"),
    )

    # DES is intentionally represented by an API name below.
    # Whether this is detected depends on the scanner's rules.
    legacy_des_api = "Crypto.Cipher.DES"

    return legacy_cipher, legacy_des_api


# ============================================================
# 7. AES-GCM NONCE HANDLING
# Expected checks: key size, authenticated mode, nonce reuse
# ============================================================

def aes_gcm_example(dummy_key: bytes, data: bytes):
    # Test-only fixed nonce. Reusing a nonce with the same GCM key
    # is unsafe. Real applications must generate unique nonces.
    fixed_nonce = b"0123456789ab"

    cipher = AESGCM(dummy_key)
    return cipher.encrypt(fixed_nonce, data, None)


# ============================================================
# 8. DUMMY HARD-CODED KEY MATERIAL
# Expected checks: possible secrets / key exposure
# ============================================================

DUMMY_API_SECRET = "TEST_ONLY_NOT_A_REAL_SECRET"
DUMMY_PRIVATE_KEY_TEXT = (
    "-----BEGIN PRIVATE KEY-----\n"
    "TEST_FIXTURE_NOT_A_REAL_PRIVATE_KEY\n"
    "-----END PRIVATE KEY-----"
)


# ============================================================
# 9. PRIVATE KEY SERIALIZATION
# Expected checks: encryption of exported private keys
# ============================================================

def unsafe_private_key_export(private_key):
    # Intentionally unsafe test case: exports a private key without
    # password-based encryption. Never use for real private keys.
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ============================================================
# 10. INSECURE TLS CONFIGURATION
# Expected checks: protocol version and certificate validation
# ============================================================

def insecure_tls_examples():
    # Legacy protocol constants are intentionally included as
    # scanner test inputs; availability depends on Python version.
    legacy_tls_10 = getattr(ssl, "PROTOCOL_TLSv1", None)
    legacy_tls_11 = getattr(ssl, "PROTOCOL_TLSv1_1", None)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    return legacy_tls_10, legacy_tls_11, context


# ============================================================
# 11. MODERN BASELINE
# Expected checks: don't flag these as weak by algorithm alone
# ============================================================

def modern_baseline(data: bytes):
    digest = hashlib.sha256(data).hexdigest()

    # 32-byte dummy key = 256 bits; unique nonce needed per key.
    key = b"T" * 32
    nonce = b"unique-test1"  # Demonstration only; manage uniqueness.
    encrypted = AESGCM(key).encrypt(nonce, data, None)

    return digest, encrypted


# ============================================================
# SCANNER TEST MATRIX
# Use this as a checklist when reviewing scanner output.
# ============================================================

EXPECTED_TEST_CATEGORIES = [
    "MD5 weak hash",
    "SHA-1 weak hash",
    "HMAC-MD5 weak digest",
    "RSA-1024 weak key size",
    "RSA-2048 quantum migration planning",
    "RSA-4096 classical key; still not post-quantum",
    "SECP192R1 small legacy curve",
    "SECP256R1 quantum migration planning",
    "AES-CBC mode and IV inspection",
    "AES-ECB insecure mode",
    "Triple DES legacy algorithm",
    "AES-GCM nonce uniqueness review",
    "Possible hardcoded secret",
    "Unencrypted private-key export",
    "TLS 1.0 / TLS 1.1 legacy protocols",
    "TLS certificate verification disabled",
    "SHA-256 modern baseline",
    "AES-256-GCM modern baseline",
]
