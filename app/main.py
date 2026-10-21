"""xsukax CipherVault - encrypted-at-rest, browser-password-protected file vault.

Browser plaintext and browser passwords never appear in this server's request schema.
The outer key is kept in /data, independently from PBKDF2/AES browser keys.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import math
import os
import re
import secrets
import shutil
import sqlite3
import struct
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get('VAULT_DATA_DIR', '/data')).resolve()
BLOBS = DATA / 'blobs'
DB_PATH = DATA / 'vault.sqlite3'
KEY_PATH = DATA / 'outer-master.key'
BOOTSTRAP_PATH = DATA / 'bootstrap.token'
CHUNK_SIZE = 1024 * 1024
MAX_FILE_BYTES = int(os.environ.get('MAX_FILE_BYTES', str(5 * 1024 ** 3)))
SESSION_SECURE = os.environ.get('COOKIE_SECURE', '1') == '1'
COOKIE_NAME = 'cv_session'
SESSION_SECONDS = 12 * 3600
TICKET_SECONDS = 30 * 60
IDENTIFIER = re.compile(r'^[0-9a-f]{32}$')
PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
AUTH_SEMAPHORE = threading.BoundedSemaphore(2)  # bound Argon2id memory pressure per worker

@asynccontextmanager
async def lifespan(_app: FastAPI):
    routine_cleanup()
    yield


app = FastAPI(title='xsukax CipherVault', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount('/static', StaticFiles(directory=BASE / 'static'), name='static')


@contextmanager
def dbconn():
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=15000')
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_store() -> bytes:
    DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    BLOBS.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(DATA, 0o700)
    os.chmod(BLOBS, 0o700)
    with dbconn() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL, created INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_failures (
              remote_hash TEXT NOT NULL, created INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_login_failures ON login_failures(remote_hash, created);
            CREATE TABLE IF NOT EXISTS files (
              id TEXT PRIMARY KEY, created INTEGER NOT NULL,
              plain_size INTEGER NOT NULL, chunk_count INTEGER NOT NULL, received INTEGER NOT NULL DEFAULT 0,
              status TEXT NOT NULL CHECK(status IN ('uploading','ready')),
              salt TEXT NOT NULL, nonce_prefix TEXT NOT NULL, meta_iv TEXT NOT NULL,
              meta_cipher TEXT NOT NULL, outer_salt BLOB NOT NULL, outer_nonce_prefix BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS shares (
              id TEXT PRIMARY KEY, file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
              token_hash TEXT NOT NULL UNIQUE, expires INTEGER NOT NULL,
              max_downloads INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_shares_file ON shares(file_id);
            CREATE TABLE IF NOT EXISTS download_sessions (
              token_hash TEXT PRIMARY KEY, file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
              share_id TEXT REFERENCES shares(id) ON DELETE CASCADE, expires INTEGER NOT NULL
            );
        ''')
        count = db.execute('SELECT count(*) FROM files').fetchone()[0]
    if not KEY_PATH.exists():
        if count:
            raise RuntimeError('Missing outer master key with existing files: refusing to generate a new key')
        try:
            fd = os.open(KEY_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(secrets.token_bytes(32))
                f.flush()
                os.fsync(f.fileno())
        except FileExistsError:
            pass
    if KEY_PATH.is_symlink() or KEY_PATH.stat().st_mode & 0o077:
        raise RuntimeError('Outer master key permissions must be 0600 and must not be a symlink')
    master = KEY_PATH.read_bytes()
    if len(master) != 32:
        raise RuntimeError('Invalid outer master key length')
    return master


MASTER = init_store()


def now() -> int:
    return int(time.time())


def bad(message: str, code: int = 400):
    raise HTTPException(status_code=code, detail=message)


def h(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def b64decode(value: str, size: int, name: str) -> bytes:
    try:
        value_bytes = base64.b64decode(value, validate=True)
    except Exception:
        bad('Invalid ' + name)
    if len(value_bytes) != size:
        bad('Invalid ' + name + ' length')
    return value_bytes


def validate_id(value: str) -> str:
    if not IDENTIFIER.fullmatch(value):
        bad('Invalid identifier')
    return value


def client_identifier(request: Request) -> str:
    # With Cloudflared terminating public TLS and forwarding ONLY to 127.0.0.1,
    # Cloudflare sets this header. An external route to this port must never exist.
    claimed = request.headers.get('cf-connecting-ip', '') if os.getenv('TRUST_CF_HEADERS', '1') == '1' else ''
    try:
        ip = str(ipaddress.ip_address(claimed)) if claimed else (request.client.host if request.client else 'unknown')
    except ValueError:
        ip = request.client.host if request.client else 'unknown'
    return h(ip)


def throttle(request: Request, failure: bool = False) -> None:
    client = client_identifier(request)
    with dbconn() as db:
        db.execute('DELETE FROM login_failures WHERE created < ?', (now() - 900,))
        if failure:
            db.execute('INSERT INTO login_failures(remote_hash,created) VALUES (?,?)', (client, now()))
        attempts = db.execute('SELECT count(*) FROM login_failures WHERE remote_hash=?', (client,)).fetchone()[0]
    if attempts >= 10:
        bad('Too many attempts; try again after 15 minutes', 429)


def clear_failures(request: Request) -> None:
    with dbconn() as db:
        db.execute('DELETE FROM login_failures WHERE remote_hash=?', (client_identifier(request),))


def is_setup() -> bool:
    with dbconn() as db:
        return db.execute('SELECT 1 FROM users WHERE id=1').fetchone() is not None


def require_auth(request: Request, csrf: bool = False) -> sqlite3.Row:
    cookie = request.cookies.get(COOKIE_NAME, '')
    if not cookie or len(cookie) > 128:
        bad('Authentication required', 401)
    with dbconn() as db:
        row = db.execute('SELECT csrf, expires FROM sessions WHERE token_hash=?', (h(cookie),)).fetchone()
    if row is None or row['expires'] <= now():
        bad('Session expired; sign in again', 401)
    if csrf and not secrets.compare_digest(request.headers.get('x-csrf-token', ''), row['csrf']):
        bad('Invalid anti-CSRF token', 403)
    return row


def attach_session(response: Response) -> str:
    token = secrets.token_urlsafe(36)
    csrf = secrets.token_urlsafe(32)
    expiry = now() + SESSION_SECONDS
    with dbconn() as db:
        db.execute('INSERT INTO sessions VALUES (?,?,?)', (h(token), csrf, expiry))
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_SECONDS, secure=SESSION_SECURE,
                        httponly=True, samesite='strict', path='/')
    return csrf


def manifest(row: sqlite3.Row) -> dict[str, Any]:
    return {
        'id': row['id'], 'size': row['plain_size'], 'chunks': row['chunk_count'],
        'chunkSize': CHUNK_SIZE, 'salt': row['salt'],
        'noncePrefix': row['nonce_prefix'], 'metaIv': row['meta_iv'], 'metaCipher': row['meta_cipher'],
    }


def get_file(db: sqlite3.Connection, file_id: str, ready: bool = True):
    validate_id(file_id)
    row = db.execute('SELECT * FROM files WHERE id=?', (file_id,)).fetchone()
    if row is None or (ready and row['status'] != 'ready'):
        bad('File not found', 404)
    return row


def derive_outer(row: sqlite3.Row) -> ChaCha20Poly1305:
    k = HKDF(algorithm=hashes.SHA256(), length=32, salt=row['outer_salt'],
             info=b'xsukax-ciphervault:outer:v1:' + row['id'].encode()).derive(MASTER)
    return ChaCha20Poly1305(k)


def outer_nonce(row: sqlite3.Row, idx: int) -> bytes:
    return row['outer_nonce_prefix'] + struct.pack('>Q', idx)


def aad(row: sqlite3.Row, idx: int) -> bytes:
    return b'CV1:' + bytes.fromhex(row['id']) + struct.pack('>QQ', idx, row['plain_size'])


def share_by_token(db: sqlite3.Connection, token: str):
    if not isinstance(token, str) or len(token) > 128 or len(token) < 30:
        bad('Invalid or expired sharing link', 404)
    row = db.execute('SELECT shares.*, files.status FROM shares JOIN files ON files.id=shares.file_id '
                     'WHERE shares.token_hash=?', (h(token),)).fetchone()
    if row is None or row['expires'] <= now() or row['status'] != 'ready' or row['used'] >= row['max_downloads']:
        bad('Invalid, expired, or exhausted sharing link', 404)
    return row


@app.middleware('http')
async def protect(request: Request, call_next):
    if request.url.path.startswith('/api/') and request.method not in ('GET', 'HEAD', 'OPTIONS'):
        length = request.headers.get('content-length')
        if length:
            try:
                if int(length) > CHUNK_SIZE + 65536:
                    return JSONResponse({'detail': 'Request too large'}, status_code=413)
            except ValueError:
                return JSONResponse({'detail': 'Invalid Content-Length'}, status_code=400)
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    if SESSION_SECURE:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.get('/')
@app.get('/share')
def home():
    return FileResponse(BASE / 'static' / 'index.html')


@app.get('/healthz')
def healthz():
    return {'ok': True}


@app.get('/api/bootstrap')
def bootstrap():
    return {'initialized': is_setup(), 'chunkSize': CHUNK_SIZE, 'maxBytes': MAX_FILE_BYTES}


class Setup(BaseModel):
    bootstrap_token: str = Field(min_length=40, max_length=200)
    password: str = Field(min_length=14, max_length=1024)


@app.post('/api/setup')
def setup(payload: Setup, request: Request, response: Response):
    throttle(request)
    if not BOOTSTRAP_PATH.exists():
        bad('Setup is unavailable', 403)
    stored = BOOTSTRAP_PATH.read_text(encoding='ascii').strip()
    if not secrets.compare_digest(stored, payload.bootstrap_token):
        throttle(request, failure=True)
        bad('Invalid setup code', 403)
    with dbconn() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT 1 FROM users WHERE id=1').fetchone():
            bad('Administrator already initialized', 409)
        with AUTH_SEMAPHORE:
            admin_hash = PH.hash(payload.password)
        db.execute('INSERT INTO users(id,password_hash,created) VALUES (1,?,?)', (admin_hash, now()))
    BOOTSTRAP_PATH.unlink(missing_ok=True)
    clear_failures(request)
    return {'ok': True, 'csrf': attach_session(response)}


class Credentials(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


@app.post('/api/login')
def login(payload: Credentials, request: Request, response: Response):
    throttle(request)
    with dbconn() as db:
        row = db.execute('SELECT password_hash FROM users WHERE id=1').fetchone()
    try:
        with AUTH_SEMAPHORE:
            valid = row is not None and PH.verify(row['password_hash'], payload.password)
    except (VerificationError, InvalidHashError):
        valid = False
    if not valid:
        throttle(request, failure=True)
        bad('Invalid credentials', 401)
    clear_failures(request)
    return {'ok': True, 'csrf': attach_session(response)}


@app.get('/api/me')
def me(request: Request):
    row = require_auth(request)
    return {'admin': True, 'csrf': row['csrf']}


@app.post('/api/logout')
def logout(request: Request, response: Response):
    require_auth(request, csrf=True)
    cookie = request.cookies.get(COOKIE_NAME, '')
    with dbconn() as db:
        db.execute('DELETE FROM sessions WHERE token_hash=?', (h(cookie),))
    response.delete_cookie(COOKIE_NAME, path='/', secure=SESSION_SECURE, httponly=True, samesite='strict')
    return {'ok': True}


class UploadInit(BaseModel):
    size: int = Field(ge=0)
    chunks: int = Field(ge=1)
    salt: str = Field(min_length=20, max_length=128)
    noncePrefix: str = Field(min_length=4, max_length=40)
    metaIv: str = Field(min_length=12, max_length=64)
    metaCipher: str = Field(min_length=20, max_length=6000)


@app.post('/api/uploads')
def start_upload(payload: UploadInit, request: Request):
    require_auth(request, csrf=True)
    if payload.size > MAX_FILE_BYTES:
        bad('File exceeds configured limit', 413)
    needed = max(1, math.ceil(payload.size / CHUNK_SIZE))
    if payload.chunks != needed:
        bad('Invalid chunk count')
    b64decode(payload.salt, 16, 'browser salt')
    b64decode(payload.noncePrefix, 4, 'browser nonce prefix')
    b64decode(payload.metaIv, 12, 'metadata IV')
    try:
        meta_cipher = base64.b64decode(payload.metaCipher, validate=True)
    except Exception:
        bad('Invalid encrypted filename')
    if not 17 <= len(meta_cipher) <= 4096:
        bad('Invalid encrypted metadata size')
    file_id = secrets.token_hex(16)
    file_dir = BLOBS / file_id
    file_dir.mkdir(mode=0o700)
    try:
        with dbconn() as db:
            db.execute('''INSERT INTO files(id,created,plain_size,chunk_count,received,status,
                 salt,nonce_prefix,meta_iv,meta_cipher,outer_salt,outer_nonce_prefix)
                 VALUES (?,?,?,?,0,'uploading',?,?,?,?,?,?)''',
                       (file_id, now(), payload.size, payload.chunks, payload.salt,
                        payload.noncePrefix, payload.metaIv, payload.metaCipher,
                        secrets.token_bytes(32), secrets.token_bytes(4)))
    except Exception:
        shutil.rmtree(file_dir, ignore_errors=True)
        raise
    return {'id': file_id, 'received': 0, 'chunks': payload.chunks}


@app.put('/api/uploads/{file_id}/chunks/{idx}')
async def upload_chunk(file_id: str, idx: int, request: Request):
    require_auth(request, csrf=True)
    validate_id(file_id)
    if idx < 0:
        bad('Invalid chunk index')
    if request.headers.get('content-type', '').split(';')[0].lower() != 'application/octet-stream':
        bad('Expected binary browser-encrypted chunk', 415)
    ciphertext = bytearray()
    async for part in request.stream():
        ciphertext.extend(part)
        if len(ciphertext) > CHUNK_SIZE + 16:
            bad('Chunk too large', 413)
    with dbconn() as db:
        db.execute('BEGIN IMMEDIATE')
        row = get_file(db, file_id, ready=False)
        if row['status'] != 'uploading':
            bad('Upload already finalized', 409)
        if idx < row['received']:
            return {'received': row['received'], 'chunks': row['chunk_count']}
        if idx != row['received'] or idx >= row['chunk_count']:
            bad('Upload chunks must be sequential', 409)
        expected_plain_len = min(CHUNK_SIZE, max(0, row['plain_size'] - idx * CHUNK_SIZE))
        if len(ciphertext) != expected_plain_len + 16:
            bad('Browser ciphertext chunk length mismatch')
        output = derive_outer(row).encrypt(outer_nonce(row, idx), bytes(ciphertext), aad(row, idx))
        name = f'{idx:08d}.bin'
        tmp = BLOBS / file_id / (name + '.tmp')
        dest = BLOBS / file_id / name
        with tmp.open('wb') as f:
            f.write(output)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(dest)
        db.execute('UPDATE files SET received=received+1 WHERE id=?', (file_id,))
    return {'received': idx + 1, 'chunks': row['chunk_count']}


@app.post('/api/uploads/{file_id}/complete')
def finish_upload(file_id: str, request: Request):
    require_auth(request, csrf=True)
    with dbconn() as db:
        db.execute('BEGIN IMMEDIATE')
        row = get_file(db, file_id, ready=False)
        if row['status'] == 'ready':
            return {'ok': True}
        if row['received'] != row['chunk_count']:
            bad('Upload is incomplete', 409)
        db.execute("UPDATE files SET status='ready' WHERE id=?", (file_id,))
    return {'ok': True}


@app.get('/api/files')
def list_files(request: Request):
    require_auth(request)
    with dbconn() as db:
        items = [dict(r) for r in db.execute('''SELECT id,created,plain_size AS size,
                 chunk_count AS chunks,received,status FROM files ORDER BY created DESC, id DESC''')]
    return {'files': items}


@app.delete('/api/files/{file_id}')
def delete_file(file_id: str, request: Request):
    require_auth(request, csrf=True)
    with dbconn() as db:
        db.execute('BEGIN IMMEDIATE')
        get_file(db, file_id, ready=False)
        db.execute('DELETE FROM files WHERE id=?', (file_id,))
    shutil.rmtree(BLOBS / file_id, ignore_errors=True)
    return {'ok': True}


@app.get('/api/files/{file_id}/manifest')
def admin_manifest(file_id: str, request: Request):
    require_auth(request)
    with dbconn() as db:
        return manifest(get_file(db, file_id))


class ShareCreate(BaseModel):
    minutes: int = Field(ge=1, le=10080)
    maxDownloads: int = Field(ge=1, le=100)


@app.post('/api/files/{file_id}/shares')
def create_share(file_id: str, payload: ShareCreate, request: Request):
    require_auth(request, csrf=True)
    token = secrets.token_urlsafe(32)
    share_id = secrets.token_hex(16)
    expires = now() + payload.minutes * 60
    with dbconn() as db:
        get_file(db, file_id)
        db.execute('INSERT INTO shares VALUES(?,?,?,?,?,?,?)',
                   (share_id, file_id, h(token), expires, payload.maxDownloads, 0, now()))
    return {'id': share_id, 'token': token, 'expires': expires,
            'maxDownloads': payload.maxDownloads}


@app.get('/api/files/{file_id}/shares')
def list_shares(file_id: str, request: Request):
    require_auth(request)
    with dbconn() as db:
        get_file(db, file_id)
        entries = [dict(row) for row in db.execute(
            'SELECT id, created, expires, max_downloads AS maxDownloads, used FROM shares WHERE file_id=? ORDER BY created DESC',
            (file_id,))]
    return {'shares': entries}


@app.delete('/api/shares/{share_id}')
def revoke_share(share_id: str, request: Request):
    require_auth(request, csrf=True)
    validate_id(share_id)
    with dbconn() as db:
        db.execute('DELETE FROM shares WHERE id=?', (share_id,))
    return {'ok': True}


class TokenPayload(BaseModel):
    token: str = Field(min_length=30, max_length=128)


@app.post('/api/share/manifest')
def shared_manifest(payload: TokenPayload):
    with dbconn() as db:
        share = share_by_token(db, payload.token)
        row = get_file(db, share['file_id'])
    return manifest(row) | {'expires': share['expires'], 'remaining': share['max_downloads'] - share['used']}


def make_ticket(db: sqlite3.Connection, file_id: str, share_id: str | None, expiry: int):
    ticket = secrets.token_urlsafe(36)
    db.execute('INSERT INTO download_sessions(token_hash,file_id,share_id,expires) VALUES(?,?,?,?)',
               (h(ticket), file_id, share_id, expiry))
    return {'ticket': ticket, 'expires': expiry}


@app.post('/api/files/{file_id}/ticket')
def admin_ticket(file_id: str, request: Request):
    require_auth(request, csrf=True)
    with dbconn() as db:
        get_file(db, file_id)
        return make_ticket(db, file_id, None, now() + TICKET_SECONDS)


@app.post('/api/share/ticket')
def share_ticket(payload: TokenPayload):
    with dbconn() as db:
        db.execute('BEGIN IMMEDIATE')
        share = share_by_token(db, payload.token)
        db.execute('UPDATE shares SET used=used+1 WHERE id=?', (share['id'],))
        return make_ticket(db, share['file_id'], share['id'], min(now() + TICKET_SECONDS, share['expires']))


class DownloadChunk(BaseModel):
    ticket: str = Field(min_length=30, max_length=128)
    index: int = Field(ge=0)


@app.post('/api/download/chunk')
def download_chunk(payload: DownloadChunk):
    with dbconn() as db:
        session = db.execute('''SELECT download_sessions.*, shares.expires AS share_expires
           FROM download_sessions LEFT JOIN shares ON shares.id=download_sessions.share_id
           WHERE download_sessions.token_hash=?''', (h(payload.ticket),)).fetchone()
        if session is None or session['expires'] <= now():
            bad('Download session expired', 401)
        if session['share_id'] and (session['share_expires'] is None or session['share_expires'] <= now()):
            bad('Sharing link has expired or been revoked', 403)
        row = get_file(db, session['file_id'])
    if payload.index >= row['chunk_count']:
        bad('Invalid chunk index')
    path = BLOBS / row['id'] / f'{payload.index:08d}.bin'
    if not path.is_file():
        bad('Encrypted chunk missing', 500)
    try:
        # This value is STILL the browser-side AES-GCM ciphertext, never the original content.
        browser_ciphertext = derive_outer(row).decrypt(
            outer_nonce(row, payload.index), path.read_bytes(), aad(row, payload.index))
    except Exception:
        bad('Stored encrypted chunk failed authentication', 500)
    expected = min(CHUNK_SIZE, max(0, row['plain_size'] - payload.index * CHUNK_SIZE)) + 16
    if len(browser_ciphertext) != expected:
        bad('Stored encrypted chunk size mismatch', 500)
    return Response(content=browser_ciphertext, media_type='application/octet-stream')


def routine_cleanup():
    # Keep interrupted uploads temporarily so the administrator can remove them.
    limit = now() - 24 * 3600
    with dbconn() as db:
        ids = [r[0] for r in db.execute("SELECT id FROM files WHERE status='uploading' AND created<?", (limit,))]
        db.execute("DELETE FROM files WHERE status='uploading' AND created<?", (limit,))
        db.execute('DELETE FROM sessions WHERE expires<?', (now(),))
        db.execute('DELETE FROM download_sessions WHERE expires<?', (now(),))
        db.execute('DELETE FROM shares WHERE expires<?', (now() - 24 * 3600,))
        db.execute('DELETE FROM login_failures WHERE created<?', (now() - 900,))
    for file_id in ids:
        shutil.rmtree(BLOBS / file_id, ignore_errors=True)
