# OWASP Top 10 2021 — Quick Reference for Security Auditor

## A01 — Broken Access Control
**CWEs:** CWE-22 (Path Traversal), CWE-284, CWE-285, CWE-639 (IDOR)
**What to look for:**
- Direct object references without authorization check (`/api/orders/1234` — is 1234 validated against session user?)
- Missing function-level access control (admin endpoints accessible without role check)
- CORS misconfiguration (`Access-Control-Allow-Origin: *` on credentialed endpoints)
- JWT: not verifying `sub` claim matches the resource owner
- Forced browsing to unauthenticated pages that should require login
**Key patterns in code:**
```python
# IDOR — no ownership check
order = Order.find(params[:id])   # Missing: and order.user_id == current_user.id

# Missing authz
@app.route("/admin/users")        # Missing: @require_role("admin")
def list_users(): ...
```

## A02 — Cryptographic Failures
**CWEs:** CWE-259 (Hardcoded Password), CWE-327 (Broken Crypto), CWE-328 (Weak Hash)
**What to look for:**
- MD5 or SHA1 for password storage (use bcrypt/argon2/scrypt)
- ECB mode for symmetric encryption
- Hardcoded cryptographic keys
- `random()` / `Math.random()` for security tokens (use `secrets` / `crypto.randomBytes`)
- HTTP instead of HTTPS for sensitive data
- Unencrypted sensitive fields in database
- JWT with `alg: "none"` or weak `HS256` with guessable secret
**Key patterns in code:**
```python
# Weak hash for password
hashlib.md5(password.encode()).hexdigest()   # Use: bcrypt.hashpw()

# Predictable token
token = str(random.randint(100000, 999999))  # Use: secrets.token_hex(32)
```

## A03 — Injection
**CWEs:** CWE-89 (SQLi), CWE-79 (XSS), CWE-74, CWE-77 (Command Injection)
**What to look for:**
- String concatenation in SQL queries
- `eval()`, `exec()`, `os.system()` with user input
- Template injection (`render_template_string(user_input)`)
- LDAP injection, XPath injection, NoSQL injection (`{"$gt": ""}`)
- `innerHTML` / `dangerouslySetInnerHTML` with user content
- Shell metacharacters passed to subprocess without sanitization
**Key patterns in code:**
```javascript
// SQLi
db.query(`SELECT * FROM users WHERE name = '${req.body.name}'`)
// Fix: db.query("SELECT * FROM users WHERE name = ?", [req.body.name])

// Command injection
exec(`ping ${req.query.host}`)
// Fix: execFile('ping', [sanitizedHost]) — never shell interpolation

// Stored XSS
div.innerHTML = userComment
// Fix: div.textContent = userComment
```

## A04 — Insecure Design
**CWEs:** CWE-209, CWE-256, CWE-501
**What to look for:**
- No rate limiting on authentication, password reset, or OTP endpoints
- Security questions as recovery mechanism
- Password reset links that don't expire
- "Security through obscurity" as the only control
- Missing fraud detection on financial operations
- Unlimited failed login attempts
**Assessment:** This category requires reasoning about the business flow, not just code patterns.

## A05 — Security Misconfiguration
**CWEs:** CWE-16, CWE-611 (XXE)
**What to look for:**
- Debug mode enabled in production (`DEBUG=True`, `app.debug = True`)
- Default credentials not changed
- Stack traces exposed to users
- Unnecessary features enabled (admin panels, test endpoints, sample apps)
- Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- XXE: XML parsing without disabling external entities
- Directory listing enabled
```python
# Django
DEBUG = True  # Never in production

# Flask
app.run(debug=True)  # Never in production
```

## A06 — Vulnerable and Outdated Components
**CWEs:** CWE-1035
**What to look for in manifest files:**
- Known vulnerable packages (log4j < 2.17, node-serialize, etc.)
- Unpinned dependencies (`"express": "*"` or `">=1.0.0"`)
- No lockfile committed
- Packages not updated in years
- Direct dependency on abandoned packages
**Note:** For live CVE data, defer to Shield's SCA scanner or `npm audit` / `pip-audit`.
This skill provides pattern-based assessment without network access.

## A07 — Identification and Authentication Failures
**CWEs:** CWE-287 (Improper Auth), CWE-384 (Session Fixation)
**What to look for:**
- Session ID not regenerated after login (session fixation)
- Weak session token (short, sequential, predictable)
- Password stored in plaintext or reversible encoding
- No account lockout after failed attempts
- JWT: missing expiry (`exp` claim), accepting expired tokens
- "Remember me" implemented as permanent session (no expiry)
- Multi-factor authentication bypassable
```javascript
// Session fixation
app.post('/login', (req, res) => {
  // Missing: req.session.regenerate() before setting user
  req.session.userId = user.id;
});

// JWT: missing exp check
jwt.verify(token, secret, { ignoreExpiration: true })  // NEVER
```

## A08 — Software and Data Integrity Failures
**CWEs:** CWE-345, CWE-502 (Insecure Deserialization)
**What to look for:**
- `pickle.loads()`, `yaml.load()` (not `yaml.safe_load()`), `unserialize()` on untrusted data
- npm/pip packages without integrity checks (no lockfile, no subresource integrity)
- CI/CD pipeline that can be modified by untrusted contributors
- Auto-update mechanisms without signature verification
- Deserialization of cookies or JWT without proper validation
```python
# Insecure deserialization
data = pickle.loads(request.cookies.get('session'))  # RCE possible
# Fix: use signed, structured formats (JWT, JSON + HMAC) — never pickle user input

# YAML unsafe load
config = yaml.load(user_input)          # Can execute arbitrary Python
config = yaml.safe_load(user_input)     # Safe
```

## A09 — Security Logging and Monitoring Failures
**CWEs:** CWE-117, CWE-223, CWE-778
**What to look for:**
- No logging of authentication attempts (success and failure)
- No logging of access control failures
- Logging sensitive data (passwords, tokens, PII in logs)
- Log injection (user input written directly to log without sanitization)
- No alerting on suspicious activity patterns
- Logs accessible to application users
```python
# Logging sensitive data (BAD)
logger.info(f"Login attempt: user={username}, password={password}")

# Log injection (BAD)
logger.info(f"User action: {user_input}")  # If input contains \n, can inject fake log lines
# Fix: logger.info("User action: %s", user_input)  # Structured logging escapes special chars
```

## A10 — Server-Side Request Forgery (SSRF)
**CWEs:** CWE-918
**What to look for:**
- HTTP requests to user-supplied URLs without validation
- Image/file loading from user-provided URLs
- Webhook URL validation insufficient
- PDF generators, screenshot services, or importers that fetch external content
- Internal metadata endpoints accessible (AWS: 169.254.169.254, GCP: metadata.google.internal)
```python
# SSRF
url = request.json['webhook_url']
requests.get(url)  # Attacker supplies: http://169.254.169.254/latest/meta-data/

# Partial fix — blocklist is insufficient (can be bypassed with redirects, DNS rebinding)
# Proper fix: allowlist of domains + block private IP ranges at network level
import ipaddress
parsed = urllib.parse.urlparse(url)
ip = socket.gethostbyname(parsed.hostname)
if ipaddress.ip_address(ip).is_private:
    raise ValueError("Private IP addresses not allowed")
```
