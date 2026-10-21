"""Real HTTP API test with genuine PBKDF2/AES-GCM + HKDF/ChaCha20-Poly1305."""
from __future__ import annotations

import base64
import importlib
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi.testclient import TestClient


def encode(v):
    return base64.b64encode(v).decode('ascii')


def load_app(tmp):
    os.environ['VAULT_DATA_DIR'] = str(tmp)
    os.environ['COOKIE_SECURE'] = '1'
    os.environ['TRUST_CF_HEADERS'] = '0'
    if 'app.main' in sys.modules:
        del sys.modules['app.main']
    mod = importlib.import_module('app.main')
    (tmp / 'bootstrap.token').write_text('a-long-random-bootstrap-token-for-the-unit-test-only-12345')
    return mod


def test_end_to_end_encrypted_chunks_share_and_revocation():
    with tempfile.TemporaryDirectory() as working:
        tmp = Path(working)
        mod = load_app(tmp)
        with TestClient(mod.app, base_url='https://vault.example') as client:
            assert client.get('/healthz').json()['ok']
            assert client.get('/api/bootstrap').json()['initialized'] is False
            assert client.get('/api/files').status_code == 401
            assert client.post('/api/setup', json={
                'bootstrap_token':'WRONG-BUT-LONG-SETUP-TOKEN-THAT-IS-NOT-VALID',
                'password':'an-extremely-long-admin-password-2026'}).status_code == 403
            setup = client.post('/api/setup', json={
                'bootstrap_token': 'a-long-random-bootstrap-token-for-the-unit-test-only-12345',
                'password': 'an-extremely-long-admin-password-2026'
            })
            assert setup.status_code == 200, setup.text
            csrf = setup.json()['csrf']
            assert not (tmp / 'bootstrap.token').exists()
            assert mod.KEY_PATH.stat().st_mode & 0o077 == 0
            assert client.get('/api/bootstrap').json()['initialized'] is True
            assert client.post('/api/uploads',json={'size':0,'chunks':1,'salt':encode(b'0'*16),'noncePrefix':encode(b'0'*4),'metaIv':encode(b'0'*12),'metaCipher':encode(b'fake cipher metadata...')}).status_code == 403
            assert client.get('/api/files').json() == {'files': []}
            # An actual two-chunk browser-side encryption, built by independent test code.
            plaintext = (b'zero-knowledge-by-default' * 50000) + b'__end__'
            password = 'A-unique-random-passphrase-used-only-in-the-browser!'
            salt = os.urandom(16)
            prefix = os.urandom(4)
            metadata_iv = os.urandom(12)
            key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                             salt=salt, iterations=600000).derive(password.encode())
            aes = AESGCM(key)
            original_name = 'super confidential original name.pdf'
            import json
            metadata_ct = aes.encrypt(metadata_iv, json.dumps({'name': original_name,
                                      'mime': 'application/pdf'}).encode(), None)
            chunks = [plaintext[i:i+mod.CHUNK_SIZE] for i in range(0, len(plaintext), mod.CHUNK_SIZE)]
            browser_ciphertexts = [aes.encrypt(prefix + i.to_bytes(8, 'big'), c, None)
                                   for i, c in enumerate(chunks)]
            headers = {'X-CSRF-Token':csrf}
            init = client.post('/api/uploads', headers=headers, json={
                'size': len(plaintext), 'chunks':len(chunks),'salt':encode(salt),
                'noncePrefix':encode(prefix),'metaIv':encode(metadata_iv),
                'metaCipher':encode(metadata_ct)
            })
            assert init.status_code == 200, init.text
            fid = init.json()['id']
            assert client.post(f'/api/uploads/{fid}/complete', headers=headers).status_code == 409
            for i, ciphertext in enumerate(browser_ciphertexts):
                received = client.put(f'/api/uploads/{fid}/chunks/{i}', content=ciphertext,
                                      headers=headers | {'Content-Type':'application/octet-stream'})
                assert received.status_code == 200, received.text
                assert received.json()['received'] == i + 1
                # Outer ciphertext must not be plain content OR browser ciphertext.
                stored_chunk = (tmp/'blobs'/fid/f'{i:08d}.bin').read_bytes()
                assert stored_chunk != ciphertext
                assert plaintext[:40] not in stored_chunk
            assert client.post(f'/api/uploads/{fid}/complete', headers=headers).status_code == 200
            assert original_name.encode() not in (tmp/'vault.sqlite3').read_bytes()
            manifest = client.get(f'/api/files/{fid}/manifest').json()
            assert manifest['metaCipher'] == encode(metadata_ct)
            assert 'name' not in manifest
            # Admin download ticket and complete content recovery.
            ticket = client.post(f'/api/files/{fid}/ticket', headers=headers).json()['ticket']
            restored = bytearray()
            for i in range(len(chunks)):
                raw = client.post('/api/download/chunk',json={'ticket':ticket, 'index':i})
                assert raw.status_code == 200, raw.text
                assert raw.content == browser_ciphertexts[i]
                restored.extend(aes.decrypt(prefix + i.to_bytes(8,'big'), raw.content, None))
            assert bytes(restored) == plaintext
            # Limited links: exact download/session allowance and revocation.
            link = client.post(f'/api/files/{fid}/shares', headers=headers,
                               json={'minutes':60,'maxDownloads':1}).json()
            token = link['token']
            assert token not in (tmp/'vault.sqlite3').read_text(errors='replace')
            anonymous = TestClient(mod.app, base_url='https://vault.example')
            assert anonymous.post('/api/share/manifest',json={'token':token}).status_code == 200
            shared_ticket = anonymous.post('/api/share/ticket',json={'token':token}).json()['ticket']
            assert anonymous.post('/api/share/ticket',json={'token':token}).status_code == 404
            assert anonymous.post('/api/download/chunk',json={
                'ticket':shared_ticket,'index':0}).content == browser_ciphertexts[0]
            assert client.delete(f'/api/shares/{link["id"]}',headers=headers).status_code == 200
            assert anonymous.post('/api/download/chunk',json={
                'ticket':shared_ticket,'index':0}).status_code == 401
            # CSRF and file deletion revoke access to content.
            assert client.delete(f'/api/files/{fid}').status_code == 403
            assert client.delete(f'/api/files/{fid}',headers=headers).status_code == 200
            assert client.post('/api/download/chunk',json={'ticket':ticket, 'index':0}).status_code == 401
            assert not (tmp/'blobs'/fid).exists()
            assert client.post('/api/logout',headers=headers).status_code == 200
            assert client.get('/api/files').status_code == 401
            bad_login = client.post('/api/login',json={'password':'wrong'})
            assert bad_login.status_code == 401
            logged_in = client.post('/api/login',json={'password':'an-extremely-long-admin-password-2026'})
            assert logged_in.status_code == 200


def test_zero_length_file_and_authenticated_outer_corruption():
    with tempfile.TemporaryDirectory() as working:
        tmp = Path(working)
        mod = load_app(tmp)
        with TestClient(mod.app,base_url='https://vault.example') as c:
            csrf = c.post('/api/setup',json={'bootstrap_token':
                'a-long-random-bootstrap-token-for-the-unit-test-only-12345',
                'password':'a-long-enough-admin-password'}).json()['csrf']
            s,p,m = os.urandom(16),os.urandom(4),os.urandom(12)
            aes = AESGCM(PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=s,
                                  iterations=600000).derive(b'dummy-strong-passphrase'))
            metadata_ct = aes.encrypt(m,b'{"name":"empty.txt","mime":"text/plain"}',None)
            blob = aes.encrypt(p + (0).to_bytes(8,'big'), b'',None)
            headers={'X-CSRF-Token':csrf}
            fid=c.post('/api/uploads',headers=headers,json={
                'size':0,'chunks':1,'salt':encode(s),'noncePrefix':encode(p),
                'metaIv':encode(m),'metaCipher':encode(metadata_ct)}).json()['id']
            r=c.put(f'/api/uploads/{fid}/chunks/0',content=blob,
                    headers=headers|{'Content-Type':'application/octet-stream'})
            assert r.status_code == 200,r.text
            assert c.post(f'/api/uploads/{fid}/complete',headers=headers).status_code == 200
            ticket=c.post(f'/api/files/{fid}/ticket',headers=headers).json()['ticket']
            assert c.post('/api/download/chunk',json={'ticket':ticket,'index':0}).content == blob
            stored=tmp/'blobs'/fid/'00000000.bin'
            ciphertext=bytearray(stored.read_bytes());ciphertext[-1] ^= 0xff; stored.write_bytes(ciphertext)
            assert c.post('/api/download/chunk',json={'ticket':ticket,'index':0}).status_code == 500
