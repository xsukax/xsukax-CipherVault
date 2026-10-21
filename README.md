# xsukax CipherVault

Self-hosted encrypted file storage and sharing for **Debian 13**, with a Python/FastAPI backend, a responsive web UI, browser-only file passwords, and a second independent encryption layer on the server.

> **Security description, not an absolute promise:** CipherVault is designed so the normal backend never receives original file content or browser file passwords. This is **not** protection against a malicious/compromised server that changes the JavaScript delivered to a visitor, a compromised browser, or an attacker who guesses a weak password after acquiring encrypted data. Audit the code and secure the host, domain, and clients.

## Security architecture

```text
Uploader's browser                  Debian server                  Recipient's browser
==================                  =============                  ===================
Plain file                          Cannot access plaintext        Download protected ciphertext
     |                                    |                                 |
PBKDF2-SHA256 (600k) + password          |                          Independent server layer removed
     |                                    |                                 |
AES-256-GCM encrypts chunks              |                          AES-256-GCM ciphertext
AES-256-GCM encrypts filename            |                                 |
     |                                    |                          Browser file password (local)
     | ---- AES-GCM ciphertext ---------> |                                 |
     |                              HKDF-derived file key                |
     |                              ChaCha20-Poly1305                     |
     |                              Double-encrypted chunks              |
     |                                    |  -- AES-GCM ciphertext ------> |
     |                                    |                          Plain file saved locally
```

- **Inner layer:** Web Crypto API AES-256-GCM; independent randomly generated 16-byte salt per file, 600,000-iteration PBKDF2-HMAC-SHA256, and a 96-bit nonce formed from a random 4-byte per-file prefix plus a unique 64-bit chunk index. Each 1-MiB chunk has its own authentication tag. Filename and MIME metadata are encrypted with a **separately random 96-bit IV** under the browser key.
- **Outer layer:** Python `cryptography` ChaCha20-Poly1305; an independent 256-bit master key is generated and stored in `appdata/outer-master.key` with mode 0600. Each file derives a unique outer encryption key using HKDF-SHA256, its own randomly generated 32-byte salt, and a file-specific domain label. Outer chunk nonces contain an independent per-file random prefix plus the chunk index. Additional authenticated data binds file ID, index, and declared file size.
- **Administrator authentication:** Argon2id hash, random signed-in session secrets stored as SHA-256 hashes, HttpOnly Secure SameSite=Strict cookies, a per-session CSRF token, 12-hour session expiry, and login attempt throttling. Admin login password is **not** used to derive file-encryption keys.
- **One-time initialization:** A strong random setup code is created by the installer, shown in the privileged terminal, and required alongside the first administrator password. The code is deleted after successful setup.
- **Temporary sharing:** A random 256-bit bearer token is embedded in the sharing URL's **fragment** (`/share#TOKEN`), so it is omitted from the GET request line. The browser sends the token via HTTPS request JSON for authorization. The server stores only its hash. Links have an expiration and a maximum number of download sessions; they can be revoked.
- **Downloads:** The server removes **only ChaCha20-Poly1305**, one chunk per request, and sends the remaining AES-GCM ciphertext to the browser. The browser locally verifies/decrypts each chunk. Passwords are not included in any download API schema.
- **Metadata:** Filenames and MIME types are encrypted. The server can still see approximate original sizes, upload times, record IDs, and download/share activity. The end-to-end encryption **does not hide** this metadata.

## Debian 13 installation

Place the project folder on your VPS. Run as a sudo-capable user:

```bash
cd xsukax-vault
sudo ./install.sh
```

The installer checks Debian 13, installs official Docker Engine / Docker Compose if missing, creates private persistent storage, creates the one-time bootstrap code, builds the image, and starts the service. On subsequent runs the existing database and encryption key are retained.

**First-time setup:** Copy the one-time setup code displayed by `install.sh`. Point Cloudflare Tunnel at the loopback HTTP service and open **your HTTPS hostname**. The first-run screen asks for that code and an administrator password of at least 14 characters. Copy the bootstrap code safely; it is removed from the server after initialization.

### Cloudflared tunnel

Configure the ingress rule on your existing Cloudflare Tunnel (or via the Cloudflare dashboard):

```yaml
tunnel: YOUR_TUNNEL_ID
credentials-file: /path/to/your/tunnel-credentials.json
ingress:
  - hostname: vault.example.com
    service: http://127.0.0.1:8743
  - service: http_status:404
```

Create a public hostname route to the tunnel. **Do not publish the Docker HTTP port on the Internet**: Compose binds `127.0.0.1:8743` on the Debian host by default. Cloudflare handles public HTTPS; `cloudflared` connects to local HTTP. The tunnel service should be run on the host OS (not in a different Docker network namespace) for `127.0.0.1` to resolve to the correct service.

**Important Cloudflare security settings:** Do not cache `/`, `/share`, `/api/*`, or `/static/*` through a Cache Everything rule. The application sends `Cache-Control: no-store`. Do not inject third-party scripts into the page or enable features that rewrite its JavaScript. Use HTTPS and DNS controls; consider Cloudflare Access only for the admin route if your sharing-access design permits it. If Access protects the whole hostname, recipients will also need Access authentication.

### Environment options

The installer creates `.env` (permissions 0600), which may be edited before restarting:

```dotenv
VAULT_DATA_DIR=/data
VAULT_PORT=8743
COOKIE_SECURE=1
TRUST_CF_HEADERS=1
MAX_FILE_BYTES=5368709120
```

- `VAULT_PORT` — local host port exposed **only on 127.0.0.1**. For first installation you can run `sudo VAULT_PORT=9080 ./install.sh`; the saved `.env` is retained on subsequent runs.
- `COOKIE_SECURE=1` — strongly recommended for Cloudflare HTTPS. Cookies will **not** work for an ordinary `http://localhost` session; for strictly local development only, set `COOKIE_SECURE=0` and restart. Never do so on a publicly used deployment.
- `TRUST_CF_HEADERS=1` — use Cloudflare `CF-Connecting-IP` to throttle login attempts. Only appropriate if the origin is loopback-only and all remote HTTP traffic arrives through Cloudflare. If you change the network topology, adjust this trust boundary.
- `MAX_FILE_BYTES` — maximum accepted source file size. Client code encrypts in 1-MiB pieces so each tunnel HTTP request is small.

Restart after edits:

```bash
sudo docker compose up -d --build
sudo docker compose logs --tail 100 vault
```

### Using the vault

1. Sign in with the **administrator password**.
2. Select a file, choose a **different, strong and unique file passphrase**, confirm it and click **Encrypt & upload**. The UI tracks browser encryption, encrypted upload, and completed outer encryption.
3. In file management, select **Download**, enter the matching file password to decrypt the filename locally, and click **Save decrypted file**. The interface tracks both decryption layers separately.
4. To share, click **Share**, choose expiration and max download count, create the link, and copy it. Send the password through a **separate secure channel**. The recipient can view the progress and download without signing in as administrator.
5. Revoke individual sharing URLs, or delete a file and its URLs from the dashboard. Deletion is a logical deletion and filesystem removal; it cannot guarantee forensic erasure on SSDs, backups, or snapshots.

### Browser support and large files

Chrome/Edge desktop browser versions supporting **File System Access API** can write decrypted chunks incrementally to disk, allowing large files without buffering the whole plaintext in browser memory. The file-picker dialog is initiated directly by the Save button, preserving the browser user-gesture requirement. Other browsers (including typical Safari/Firefox/mobile configurations) use a Blob fallback limited to **160 MiB** to prevent excessive memory use. All browsers need `crypto.subtle` in an HTTPS secure context.

## Operations and backups

```bash
sudo docker compose ps
sudo docker compose logs -f vault
sudo docker compose restart
sudo docker compose down               # does not delete appdata
sudo du -sh appdata
```

**Critical:** Back up **both** `appdata/vault.sqlite3` (including a consistent SQLite backup) and `appdata/blobs/`, **and** `appdata/outer-master.key`. Never publish this key, include `appdata` in Git, or expose it through a web server. The outer master key alone cannot unlock files without file passwords, but losing it makes all stored files unrecoverable. Back up the whole `appdata` volume while the service is stopped, or use SQLite's backup mechanism with a consistent storage snapshot. Keep sensitive backups offline/encrypted. The administrator password does **not** recover forgotten file passwords; there is no server-side password reset recovery flow. Preserve your administrator password too.

Access logs are disabled in Uvicorn. Avoid proxies or monitoring tools configured to log request bodies, session cookies, or sharing tokens. The public share token appears in a URL fragment, so it stays out of an ordinary HTTP GET request, but can still be copied, viewed in browser history, or exposed to malicious browser extensions. The password is never sent in an application API request; browser password managers/extensions, screen capture, compromised scripts, and endpoint malware remain outside this guarantee.

## Developer tests

```bash
python3 -m pip install -r requirements.txt pytest httpx
pytest -q
node --check app/static/app.js
```

**Limitations and threat model:** This implementation does not provide multi-admin access, organization-level ACLs, resumable interrupted uploads across page reloads, distributed key management, cryptographic key rotation, a hardware security module, client code signature pinning, malware inspection, anti-traffic-analysis protection, or independently audited zero-knowledge security. Do not claim it is formally audited. The container must access the independent outer key to remove the server layer; compromise of the VPS (or its key backups) defeats that outer layer. A compromised backend can also alter the JavaScript it serves and steal browser passwords entered afterward, so the term "100% blind" cannot be guaranteed against an *actively malicious* server. Deploy in a trusted environment, use strong passwords and a secure client, restrict infrastructure access, and commission an independent audit before storing highly sensitive documents.

## Project layout

```text
xsukax-vault/
├── app/
│   ├── main.py               Python HTTP API, storage, auth, ChaCha20-Poly1305
│   └── static/
│       ├── index.html        Web GUI
│       ├── app.js            Browser PBKDF2 + AES-GCM, upload/download UI
│       └── style.css         Responsive interface
├── tests/test_end_to_end.py  Full API + encryption round-trip regression tests
├── Dockerfile
├── compose.yaml
├── requirements.txt
├── install.sh
├── .dockerignore
└── .gitignore
```

License: GPL-3.0
