/* xsukax CipherVault - browser-only password handling and AES-256-GCM.
 * There are deliberately no analytics, third-party scripts, or password-bearing API requests.
 */
'use strict';
const app = document.getElementById('app');
const toast = document.getElementById('toast');
const logoutBtn = document.getElementById('logoutBtn');
const downloadDialog = document.getElementById('downloadDialog');
const shareDialog = document.getElementById('shareDialog');
const CHUNK = 1024 * 1024;
const PBKDF2_ITERATIONS = 600000;
const FALLBACK_LIMIT = 160 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {fatal: true});
let csrf = '';
let boot = null;
let busy = false;
let activeFile = null;
let currentShare = null;
let downloaded = null;
const shareToken = location.pathname === '/share' ? location.hash.slice(1) : null;
let toastTimer = null;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function bytes(n) {
  if (n === 0) return '0 B';
  const i = Math.min(4, Math.floor(Math.log(n) / Math.log(1024)));
  return (n / (1024 ** i)).toFixed(i ? 1 : 0) + ' ' + ['B','KiB','MiB','GiB','TiB'][i];
}
function formattedDate(seconds) { return new Date(seconds * 1000).toLocaleString(); }
function formatError(err) { return (err instanceof Error && err.message) ? err.message : String(err); }
function message(s, error = false) {
  toast.textContent = s;
  toast.classList.toggle('error', error);
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 7500);
}
function pct(progressId, textId, amount) {
  const n = Math.max(0, Math.min(100, Math.round(amount * 100)));
  document.getElementById(progressId).value = n;
  document.getElementById(textId).textContent = `${n}%`;
}
function b64(bytesLike) {
  const array = new Uint8Array(bytesLike);
  let out = '';
  for (let i = 0; i < array.length; i += 8192) {
    out += String.fromCharCode(...array.subarray(i, i + 8192));
  }
  return btoa(out);
}
function fromB64(source) {
  const str = atob(source);
  return Uint8Array.from(str, c => c.charCodeAt(0));
}
function random(length) { return crypto.getRandomValues(new Uint8Array(length)); }
function nonce(prefix, idx) {
  const iv = new Uint8Array(12);
  iv.set(prefix, 0);
  new DataView(iv.buffer).setBigUint64(4, BigInt(idx), false);
  return iv;
}
async function browserKey(password, salt) {
  const imported = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:PBKDF2_ITERATIONS, hash:'SHA-256'},
    imported, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function aesEncrypt(key, iv, array) {
  return new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv, tagLength:128}, key, array));
}
async function aesDecrypt(key, iv, array) {
  return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM', iv, tagLength:128}, key, array));
}
async function api(path, opts = {}) {
  const headers = {...(opts.headers || {})};
  if (opts.body !== undefined && !(opts.body instanceof Uint8Array)) headers['Content-Type'] = 'application/json';
  if (csrf && opts.method && !['GET','HEAD'].includes(opts.method)) headers['X-CSRF-Token'] = csrf;
  const response = await fetch(path, {credentials:'same-origin', cache:'no-store', ...opts, headers});
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try { detail = (await response.json()).detail || detail; } catch (_) { /* invalid error response */ }
    throw new Error(detail);
  }
  if (opts.binary) return new Uint8Array(await response.arrayBuffer());
  return response.json();
}
function showAuth(initializing) {
  logoutBtn.hidden = true;
  app.innerHTML = `<section class="hero"><div class="hero-icon">◇</div><span class="eyebrow">${initializing ? 'INITIALIZE YOUR PRIVATE VAULT' : 'PRIVATE FILE ACCESS'}</span><h1>${initializing ? 'Secure your vault.' : 'Welcome back.'}</h1><p class="muted">Your file passwords never leave your browser. An independent server key adds a separate encrypted storage layer.</p></section>
  <section class="panel auth-panel"><h2>${initializing ? 'Create administrator credentials' : 'Administrator sign in'}</h2>
  <p class="muted">${initializing ? 'Enter the setup code shown by install.sh on the server, and choose a strong administrator password.' : 'Sign in to manage encrypted files and temporary links.'}</p>
  <form id="authForm">${initializing ? '<label for="setupCode">One-time installer setup code</label><input id="setupCode" type="password" required autocomplete="off" placeholder="Paste setup code">' : ''}
  <label for="adminPassword">Administrator password</label><input id="adminPassword" type="password" required autocomplete="current-password" ${initializing ? 'minlength="14"' : ''} placeholder="${initializing ? '14+ characters' : 'Password'}">
  ${initializing ? '<label for="confirmAdmin">Confirm administrator password</label><input id="confirmAdmin" type="password" required autocomplete="new-password" minlength="14" placeholder="Repeat password">' : ''}
  <button class="button primary full" type="submit">${initializing ? 'Initialize encrypted vault' : 'Sign in securely'}</button></form>
  <div class="server-blind-note">File encryption passwords are different from this login password. Losing a file password means its content cannot be recovered by the server.</div></section>`;
}
function renderDashboard(files) {
  logoutBtn.hidden = false;
  const ready = files.filter(x => x.status === 'ready');
  const items = files.map(f => `<tr><td><span class="file-identifier">Vault item ${escapeHtml(f.id.slice(0, 10))}</span><span class="file-sub">${escapeHtml(formattedDate(f.created))}</span></td><td>${escapeHtml(bytes(f.size))}</td><td><span class="state ${f.status === 'ready' ? '' : 'pending'}">${f.status === 'ready' ? 'Protected' : `Uploading ${f.received}/${f.chunks}`}</span></td><td><div class="file-actions">${f.status === 'ready' ? `<button class="button ghost" data-action="download" data-id="${f.id}">Download</button><button class="button ghost" data-action="share" data-id="${f.id}">Share</button>` : ''}<button class="button danger" data-action="delete" data-id="${f.id}">Delete</button></div></td></tr>`).join('');
  app.innerHTML = `<div class="header-zone"><div><span class="eyebrow">ADMINISTRATOR WORKSPACE</span><h1>Your private vault</h1><p class="muted">Encrypt, store, retrieve and share without revealing original files to the server.</p></div><button class="button ghost" data-action="refresh">↻ Refresh files</button></div>
    <section class="summary"><div class="summary-card"><div class="lab">Encrypted files</div><div class="num">${ready.length}</div></div><div class="summary-card"><div class="lab">Approx. original size</div><div class="num">${bytes(ready.reduce((a,b) => a+b.size, 0))}</div></div><div class="summary-card"><div class="lab">Independent layers</div><div class="num">02</div></div></section>
    <section class="dashboard"><div class="column"><div class="panel upload-panel"><div class="panel-head"><div><span class="eyebrow">YOUR DEVICE → VAULT</span><h2>Secure upload</h2></div></div>
    <form id="uploadForm"><label for="sourceFile">Select a file</label><input id="sourceFile" type="file" required><label for="encryptPassword">File encryption password</label><input id="encryptPassword" type="password" minlength="12" autocomplete="off" required placeholder="Strong unique passphrase"><label for="encryptConfirm">Confirm file password</label><input id="encryptConfirm" type="password" minlength="12" autocomplete="off" required placeholder="Repeat passphrase"><button class="button primary full" id="uploadBtn" type="submit">Encrypt & upload</button></form>
    <p class="micro">File contents and the original filename are AES-256-GCM encrypted before any upload request. Each server-stored chunk then receives independent ChaCha20-Poly1305 encryption.</p>
    <div class="progress-box" id="uploadProgress" hidden><div class="metric"><span>1. Browser encryption</span><output id="encryptText">0%</output></div><progress id="encryptProgress" max="100" value="0"></progress><div class="metric"><span>2. Encrypted upload</span><output id="uploadText">0%</output></div><progress id="uploadBar" max="100" value="0"></progress><div class="metric"><span>3. Server encryption</span><output id="serverText">0%</output></div><progress id="serverProgress" max="100" value="0"></progress><p class="micro" role="status" id="uploadNote"></p></div></div>
    <div class="panel"><h3>How privacy is protected</h3><ul class="info-list"><li>The server never receives your file passwords or original filenames</li><li>Encryption keys for both layers are completely independent</li><li>Shared links grant limited access, not an admin session</li><li>Only you can unlock the browser-encrypted contents</li></ul></div></div>
    <div class="panel"><div class="panel-head"><div><span class="eyebrow">ENCRYPTED CONTENT</span><h2>File management</h2></div><span class="caption-text">${files.length} item(s)</span></div>
    <div class="table-scroll">${files.length ? `<table class="files-table"><thead><tr><th>Encrypted record</th><th>Size</th><th>Status</th><th style="text-align:right">Actions</th></tr></thead><tbody>${items}</tbody></table>` : '<div class="empty"><div class="empty-symbol">◇</div><h3>No encrypted files yet</h3><p>Choose a file on the left to begin.</p></div>'}</div><p class="caption-text">Filenames remain encrypted in the vault. Enter the corresponding file password when recovering a file to reveal its name locally.</p></div></section>`;
}
async function loadDashboard() {
  const data = await api('/api/files');
  renderDashboard(data.files);
}
async function submitAuth(event) {
  event.preventDefault();
  if (busy) return;
  const passEl = document.getElementById('adminPassword');
  let password = passEl.value;
  const initializing = !boot.initialized;
  if (initializing && password !== document.getElementById('confirmAdmin').value) throw new Error('Administrator passwords do not match');
  const payload = initializing ? {password, bootstrap_token:document.getElementById('setupCode').value} : {password};
  passEl.value = '';
  if (initializing) document.getElementById('confirmAdmin').value = '';
  busy = true;
  try {
    const result = await api(initializing ? '/api/setup' : '/api/login', {method:'POST', body:JSON.stringify(payload)});
    csrf = result.csrf;
    password = '';
    boot.initialized = true;
    message(initializing ? 'Vault initialized securely' : 'Welcome back');
    await loadDashboard();
  } finally { busy = false; }
}
async function uploadFile(event) {
  event.preventDefault();
  if (busy) return;
  const file = document.getElementById('sourceFile').files[0];
  if (!file) throw new Error('Choose a file first');
  if (file.size > boot.maxBytes) throw new Error('File exceeds the server size limit of ' + bytes(boot.maxBytes));
  const passInput = document.getElementById('encryptPassword');
  const confirmInput = document.getElementById('encryptConfirm');
  let password = passInput.value;
  if (password.length < 12) throw new Error('Use a file password of at least 12 characters (long random passphrases are safer)');
  if (password !== confirmInput.value) throw new Error('File passwords do not match');
  busy = true;
  const button = document.getElementById('uploadBtn');
  button.disabled = true;
  const progress = document.getElementById('uploadProgress');
  progress.hidden = false;
  ['encryptProgress','uploadBar','serverProgress'].forEach(id => document.getElementById(id).value = 0);
  document.getElementById('uploadNote').textContent = 'Deriving the browser encryption key locally…';
  try {
    const salt = random(16);
    const prefix = random(4);
    const metaIv = random(12);
    const key = await browserKey(password, salt);
    password = '';
    passInput.value = '';
    confirmInput.value = '';
    const meta = {name:file.name, mime:file.type || 'application/octet-stream'};
    const metaCipher = await aesEncrypt(key, metaIv, encoder.encode(JSON.stringify(meta)));
    const total = Math.max(1, Math.ceil(file.size / CHUNK));
    const upload = await api('/api/uploads', {method:'POST', body:JSON.stringify({
      size:file.size, chunks:total, salt:b64(salt), noncePrefix:b64(prefix), metaIv:b64(metaIv), metaCipher:b64(metaCipher)
    })});
    for (let i = 0; i < total; i++) {
      document.getElementById('uploadNote').textContent = `Encrypting block ${i+1} of ${total} in your browser…`;
      const source = new Uint8Array(await file.slice(i*CHUNK, (i+1)*CHUNK).arrayBuffer());
      const cipher = await aesEncrypt(key, nonce(prefix, i), source);
      pct('encryptProgress','encryptText',(i+1)/total);
      document.getElementById('uploadNote').textContent = `Transferring and adding independent server encryption for block ${i+1}/${total}…`;
      await api(`/api/uploads/${upload.id}/chunks/${i}`, {
        method:'PUT', headers:{'Content-Type':'application/octet-stream'}, body:cipher
      });
      pct('uploadBar','uploadText',(i+1)/total);
      pct('serverProgress','serverText',(i+1)/total);
    }
    await api(`/api/uploads/${upload.id}/complete`, {method:'POST', body:'{}'});
    document.getElementById('uploadNote').textContent = 'All encrypted chunks safely stored.';
    message('File encrypted with both methods and stored successfully');
    await loadDashboard();
  } finally {
    password = '';
    passInput.value = '';
    confirmInput.value = '';
    busy = false;
    if (button.isConnected) button.disabled = false;
  }
}
async function showShare(fileId) {
  activeFile = fileId;
  document.getElementById('shareConfig').hidden = false;
  document.getElementById('shareResult').hidden = true;
  shareDialog.showModal();
  await refreshShares();
}
async function refreshShares() {
  if (!activeFile) return;
  const list = document.getElementById('shareList');
  const data = await api(`/api/files/${activeFile}/shares`);
  list.innerHTML = data.shares.length ? data.shares.map(s => `<div class="share-row"><div>Expires ${escapeHtml(formattedDate(s.expires))}<span>${s.used}/${s.maxDownloads} download sessions used · ${s.expires <= Date.now()/1000 ? 'Expired' : 'Limited link'}</span></div><button class="button danger tiny" data-action="revoke" data-id="${s.id}">Revoke</button></div>`).join('') : '<p class="micro">No links created for this file yet.</p>';
}
async function createShare(event) {
  event.preventDefault();
  if (!activeFile) return;
  const minutes = Number(document.getElementById('shareMinutes').value);
  const maxDownloads = Number(document.getElementById('shareDownloads').value);
  const response = await api(`/api/files/${activeFile}/shares`, {method:'POST',body:JSON.stringify({minutes,maxDownloads})});
  // Capability is in the fragment; the web server and HTTP access logs never receive it in GET /share.
  document.getElementById('shareUrl').value = `${location.origin}/share#${response.token}`;
  document.getElementById('shareConfig').hidden = true;
  document.getElementById('shareResult').hidden = false;
  await refreshShares();
  message('Time-limited encrypted sharing URL created');
}
async function copyLink() {
  const field = document.getElementById('shareUrl');
  if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(field.value);
  else { field.focus(); field.select(); document.execCommand('copy'); }
  message('Link copied — send the file password separately');
}
async function showDownload(mode, fileId) {
  const manifest = mode === 'share' ?
    await api('/api/share/manifest', {method:'POST', body:JSON.stringify({token:shareToken})}) :
    await api(`/api/files/${fileId}/manifest`);
  downloaded = {mode, fileId:manifest.id, manifest, key:null, name:null, mime:null};
  document.getElementById('unlockStage').hidden = false;
  document.getElementById('saveStage').hidden = true;
  document.getElementById('downloadProgress').hidden = true;
  document.getElementById('decryptPassword').value = '';
  downloadDialog.showModal();
  document.getElementById('decryptPassword').focus();
}
async function unlockFile(event) {
  event.preventDefault();
  if (busy) return;
  let password = document.getElementById('decryptPassword').value;
  if (!downloaded) throw new Error('No file selected');
  busy = true;
  try {
    const m = downloaded.manifest;
    const key = await browserKey(password, fromB64(m.salt));
    password = '';
    document.getElementById('decryptPassword').value = '';
    let data;
    try { data = await aesDecrypt(key, fromB64(m.metaIv), fromB64(m.metaCipher)); }
    catch (_) { throw new Error('Incorrect password or corrupted encrypted filename'); }
    const meta = JSON.parse(decoder.decode(data));
    downloaded.key = key;
    downloaded.name = String(meta.name || 'recovered-file').replace(/[\\/\x00-\x1f]/g,'_').slice(0,240) || 'recovered-file';
    downloaded.mime = (typeof meta.mime === 'string' && meta.mime.length < 250) ? meta.mime : 'application/octet-stream';
    document.getElementById('decryptedName').textContent = downloaded.name;
    document.getElementById('unlockStage').hidden = true;
    document.getElementById('saveStage').hidden = false;
    message('Password verified locally; filename recovered');
  } finally {
    password = '';
    document.getElementById('decryptPassword').value = '';
    busy = false;
  }
}
async function saveDownload() {
  if (busy || !downloaded || !downloaded.key) return;
  const target = downloaded;
  if (!window.showSaveFilePicker && target.manifest.size > FALLBACK_LIMIT) {
    throw new Error('This browser cannot stream this large file to disk. Use Chromium desktop or a file under 160 MiB.');
  }
  // File picker starts IMMEDIATELY in the click gesture, before the first await.
  const pickerPromise = window.showSaveFilePicker ? window.showSaveFilePicker({suggestedName:target.name}) : null;
  busy = true;
  let writer = null;
  let buffer = null;
  document.getElementById('saveStage').hidden = true;
  document.getElementById('downloadProgress').hidden = false;
  pct('outerProgress','outerText',0);
  pct('innerProgress','innerText',0);
  try {
    if (pickerPromise) {
      const handle = await pickerPromise;
      writer = await handle.createWritable();
    } else buffer = [];
    document.getElementById('downloadNote').textContent = 'Starting a restricted download session…';
    const ticket = target.mode === 'share' ?
      await api('/api/share/ticket', {method:'POST',body:JSON.stringify({token:shareToken})}) :
      await api(`/api/files/${target.fileId}/ticket`, {method:'POST',body:'{}'});
    const m = target.manifest;
    for (let i = 0; i < m.chunks; i++) {
      document.getElementById('downloadNote').textContent = `Server decrypting outer layer, block ${i+1} of ${m.chunks}…`;
      const cipher = await api('/api/download/chunk', {method:'POST',body:JSON.stringify({ticket:ticket.ticket,index:i}), binary:true});
      pct('outerProgress','outerText',(i+1)/m.chunks);
      document.getElementById('downloadNote').textContent = `Browser decrypting block ${i+1} of ${m.chunks}…`;
      let plain;
      try { plain = await aesDecrypt(target.key, nonce(fromB64(m.noncePrefix),i), cipher); }
      catch (_) { throw new Error('File chunk authentication failed. File or password may be corrupted.'); }
      if (writer) await writer.write(plain);
      else buffer.push(plain);
      pct('innerProgress','innerText',(i+1)/m.chunks);
    }
    if (writer) { await writer.close(); writer = null; }
    else {
      const blob = new Blob(buffer, {type:target.mime});
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.href = url;
      link.download = target.name;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      buffer = null;
    }
    document.getElementById('downloadNote').textContent = 'Completed. Both layers decrypted successfully; original content never reached the server.';
    message('Decrypted file saved successfully');
    downloaded = null;
  } catch (err) {
    if (writer) { try { await writer.abort(); } catch (_) { /* best effort */ } }
    document.getElementById('saveStage').hidden = false;
    document.getElementById('downloadProgress').hidden = true;
    throw err;
  } finally { busy = false; }
}
async function showPublicShare() {
  logoutBtn.hidden = true;
  csrf = '';
  app.innerHTML = `<section class="hero"><div class="hero-icon">◇</div><span class="eyebrow">ENCRYPTED FILE DELIVERY</span><h1>A file has been shared securely.</h1><p class="muted">This limited-access link delivers only encrypted data. The file's password must be provided to you separately.</p></section>
  <section class="panel auth-panel"><h2>Private shared download</h2><p id="publicStatus" class="muted">Checking sharing token…</p><div id="publicInfo" hidden><div class="server-blind-note"><strong>Double-encrypted storage</strong><p class="micro">First the server removes ChaCha20-Poly1305, then your browser uses your password to remove AES-256-GCM. Your password never leaves this device.</p></div><button class="button primary full" data-action="public-download">Unlock & download securely</button></div></section>`;
  if (!shareToken || !/^[A-Za-z0-9_-]{30,128}$/.test(shareToken)) {
    document.getElementById('publicStatus').textContent = 'This link is invalid or missing its sharing token.';
    return;
  }
  try {
    const m = await api('/api/share/manifest', {method:'POST',body:JSON.stringify({token:shareToken})});
    document.getElementById('publicStatus').textContent = `${bytes(m.size)} · Available until ${formattedDate(m.expires)} · ${m.remaining} remaining download(s)`;
    document.getElementById('publicInfo').hidden = false;
  } catch (err) {
    document.getElementById('publicStatus').textContent = formatError(err);
  }
}
async function launch() {
  if (!crypto || !crypto.subtle || !window.isSecureContext) {
    app.innerHTML = '<div class="panel auth-panel"><h2>HTTPS required</h2><p>Your browser must load this application over HTTPS (or localhost) to run client-side encryption.</p></div>';
    return;
  }
  if (location.pathname === '/share') { await showPublicShare(); return; }
  boot = await api('/api/bootstrap');
  if (!boot.initialized) { showAuth(true); return; }
  try {
    const me = await api('/api/me');
    csrf = me.csrf;
    await loadDashboard();
  } catch (_) { showAuth(false); }
}
app.addEventListener('submit', event => {
  const id = event.target.id;
  const func = ({authForm:submitAuth, uploadForm:uploadFile})[id];
  if (func) { event.preventDefault(); func(event).catch(e => message(formatError(e), true)); }
});
document.addEventListener('submit', event => {
  if (event.target.id === 'unlockForm') { event.preventDefault(); unlockFile(event).catch(e => message(formatError(e), true)); }
  if (event.target.id === 'shareForm') { event.preventDefault(); createShare(event).catch(e => message(formatError(e), true)); }
});
document.addEventListener('click', event => {
  const target = event.target.closest('[data-action]');
  if (!target) return;
  const a = target.dataset.action;
  const id = target.dataset.id;
  const actions = {
    'refresh':loadDashboard,
    'download':() => showDownload('admin',id),
    'public-download':() => showDownload('share',null),
    'share':() => showShare(id),
    'delete':async () => {if (window.confirm('Permanently delete this file and all its encrypted chunks and links?')) {await api(`/api/files/${id}`,{method:'DELETE'});message('File deleted');await loadDashboard();}},
    'revoke':async () => {await api(`/api/shares/${id}`,{method:'DELETE'});await refreshShares();message('Sharing link and its download sessions revoked');},
    'copy-link':copyLink,
    'save-download':saveDownload,
    'close-download':() => { if (!busy) { downloaded = null; downloadDialog.close(); } },
    'close-share':() => { shareDialog.close(); activeFile = null; },
  };
  if (actions[a]) actions[a]().catch(e => message(formatError(e),true));
});
logoutBtn.addEventListener('click',async () => {
  try {await api('/api/logout',{method:'POST',body:'{}'});csrf='';showAuth(false);message('Signed out');}
  catch (e) {message(formatError(e),true);}
});
downloadDialog.addEventListener('cancel', event => {if (busy) event.preventDefault();else downloaded = null;});
shareDialog.addEventListener('close', () => {activeFile = null;});
launch().catch(e => {app.textContent = 'Unable to start CipherVault: ' + formatError(e);});
