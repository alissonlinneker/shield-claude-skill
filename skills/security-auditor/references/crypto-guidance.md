# Cryptography Security Reference

## Password Storage

### NEVER use
- MD5, SHA1, SHA256, SHA512 (alone, without key derivation) — all are fast hashes, brute-forceable
- Reversible encoding (base64, ROT13, AES with a hardcoded key)
- Salted MD5/SHA1 — still fast, still crackable with GPU

### USE
| Algorithm | When | Notes |
|-----------|------|-------|
| `bcrypt` | General purpose | Work factor 12+. Standard choice. |
| `argon2id` | New systems | Memory-hard. Best defense against GPU cracking. |
| `scrypt` | Memory-constrained | Good but harder to tune than argon2 |
| `PBKDF2-HMAC-SHA256` | FIPS compliance required | 600,000+ iterations per NIST SP 800-132 (2023) |

```python
# Python — use passlib or argon2-cffi
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
hash = ph.hash(password)
ph.verify(hash, password)  # raises VerifyMismatchError on failure

# Node.js
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
const match = await bcrypt.compare(password, hash);
```

## Symmetric Encryption

### NEVER use
- DES, 3DES (deprecated, broken)
- RC4 (broken)
- AES-ECB (same plaintext block → same ciphertext block — "penguin problem")
- AES-CBC without authenticated encryption (vulnerable to padding oracle attacks)
- Reusing IV/nonce with the same key (catastrophic for GCM)

### USE
| Algorithm | When |
|-----------|------|
| AES-256-GCM | Standard choice — provides authentication + encryption |
| AES-256-CBC + HMAC-SHA256 | When GCM unavailable — encrypt-then-MAC |
| ChaCha20-Poly1305 | Mobile / IoT where AES hardware acceleration unavailable |
| XChaCha20-Poly1305 | When large nonce space needed (random nonces at scale) |

```python
# Python — use cryptography library, NOT PyCrypto/PyCryptodome
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = os.urandom(32)        # 256-bit key — generate once, store securely
nonce = os.urandom(12)      # 96-bit nonce — MUST be unique per message
ct = AESGCM(key).encrypt(nonce, plaintext, aad)   # aad = associated data (optional)
pt = AESGCM(key).decrypt(nonce, ct, aad)          # raises InvalidTag if tampered
```

## Random Number Generation

### NEVER use for security
- `Math.random()` — JavaScript, not cryptographically random
- `random.random()`, `random.randint()` — Python standard library
- `rand()` — C, predictable
- Timestamp-seeded values
- Sequential IDs for tokens

### USE
| Language | Secure Random |
|----------|--------------|
| Python | `secrets.token_hex(32)`, `secrets.token_urlsafe(32)`, `os.urandom(32)` |
| Node.js | `crypto.randomBytes(32)`, `crypto.randomUUID()` |
| Go | `crypto/rand.Read()` |
| Java | `SecureRandom` |
| PHP | `random_bytes(32)`, `bin2hex(random_bytes(16))` |
| Ruby | `SecureRandom.hex(32)` |

```python
# Token generation
import secrets
token = secrets.token_urlsafe(32)    # 256 bits of entropy, URL-safe

# UUID
import uuid
uid = str(uuid.uuid4())  # UUID4 uses os.urandom — acceptable for IDs, not secrets

# Comparison (timing-safe)
import hmac
if hmac.compare_digest(expected_token, provided_token):  # NOT: if token == provided
    ...
```

## Hashing (Non-Password)

| Use Case | Algorithm |
|----------|-----------|
| Data integrity | SHA-256 or SHA-3 |
| HMAC (message auth) | HMAC-SHA256 |
| Content addressing / checksums | SHA-256 |
| JWT signature | RS256 (RSA) or ES256 (ECDSA) — NOT HS256 with weak secret |
| Password | See Password Storage above — use KDF, not plain hash |

**Never use MD5 or SHA1 for any new implementation** — even for non-security purposes
(collision attacks make them unreliable for integrity checks too).

## JWT

### Common JWT vulnerabilities

**1. Algorithm confusion (`alg: none`)**
```javascript
// Attacker forges token by setting alg to "none"
// Fix: always explicitly specify allowed algorithms
jwt.verify(token, secret, { algorithms: ['HS256'] })  // NOT: jwt.verify(token, secret)
```

**2. Weak secret**
- `HS256` with a short or guessable secret is crackable offline
- Use minimum 256 bits of entropy: `openssl rand -hex 32`
- Prefer `RS256` (asymmetric) so verification key can be public without compromising signing

**3. Missing or ignoring `exp` claim**
```javascript
// NEVER
jwt.verify(token, secret, { ignoreExpiration: true })

// Short expiry for access tokens (15 min), longer for refresh (7 days)
```

**4. `kid` header injection**
```javascript
// If your code does: key = keys[header.kid]
// Attacker sets: kid = "../../etc/passwd" or uses SQL injection
// Fix: validate kid against an allowlist of known key IDs
```

**5. JWT secret in source code**
```javascript
const secret = "mysecret"  // Hardcoded — rotate immediately
const secret = process.env.JWT_SECRET  // Correct
```

## TLS Configuration

### Minimum acceptable
- TLS 1.2+ (disable 1.0, 1.1)
- Cipher suites: ECDHE + AES-128-GCM or AES-256-GCM (forward secrecy)
- Certificate signed by trusted CA (not self-signed in production)
- HSTS enabled with `max-age >= 31536000`

### Modern recommended
- TLS 1.3 only (for new deployments)
- OCSP stapling enabled
- Certificate Transparency monitoring
- HPKP deprecated — use Certificate Authority Authorization (CAA) DNS records instead

### Testing
- SSL Labs (ssllabs.com/ssltest) — A+ rating target
- Mozilla SSL Configuration Generator for server-specific config

## Key Management

### Principles
1. **Generate keys properly** — use the right algorithm and key length (RSA 4096 or EC P-256/P-384)
2. **Never store keys in source code** — use secrets manager (AWS Secrets Manager, Vault, GCP Secret Manager)
3. **Rotate regularly** — API keys: 90 days, signing keys: 1 year, TLS certs: 1 year (auto-renewal via ACME)
4. **Principle of least privilege** — each service gets its own key with minimal permissions
5. **Audit key usage** — log every access, alert on anomalies
6. **Secure deletion** — overwrite before freeing memory for sensitive key material

### Secrets in environment
```bash
# BAD — visible in process list, child processes, logs
cmd arg1 --api-key=secret123

# GOOD — via environment variable
export API_KEY=$(aws secretsmanager get-secret-value --secret-id my-key --query SecretString --output text)
cmd arg1
```
