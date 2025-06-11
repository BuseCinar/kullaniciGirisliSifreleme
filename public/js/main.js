// ===== DEĞİŞKENLER =====
// Şifrelenmiş ve çözülmüş veriyi tutar
let encryptedData = null;
let decryptedData = null;
// Geçerli anahtar (hex string)
let currentKey = null;

// ===== DOSYA OKUMA PROGRESS HELPER'LARI =====
/**
 * Dosya okunurken progress olayını dinleyip yüzde döner
 * @param {File} file
 * @param {function(number):void} onProgress
 * @returns {Promise<ArrayBuffer>}
 */
function readFileWithProgress(file, onProgress) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = e => reject(e);
        reader.onprogress = e => {
            if (e.lengthComputable) {
                onProgress(Math.floor(e.loaded / e.total * 100));
            }
        };
        reader.readAsArrayBuffer(file);
    });
}

/**
 * Progress bar güncelleme
 * @param {string} prefix - 'encrypt' veya 'decrypt'
 * @param {number} p - %0-100
 */
function updateProgress(prefix, p) {
    document.getElementById(prefix + 'Progress').style.width = p + '%';
}

/**
 * Progress bar container göster/gizle
 * @param {string} prefix
 * @param {boolean} show
 */
function showProgress(prefix, show) {
    document.getElementById(prefix + 'ProgressContainer').style.display = show ? 'block' : 'none';
}

/**
 * ArrayBuffer → hex string
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function buf2hex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// ===== AES Şifreleme/Çözme =====
/**
 * AES-GCM veya AES-CBC ile şifreleme
 * @param {string} alg - 'aes-gcm' veya 'aes-cbc'
 * @param {ArrayBuffer} dataBuffer
 * @returns {Promise<{encryptedData:ArrayBuffer, keyHex:string}>}
 */
async function encryptAES(alg, dataBuffer) {
    const ivLen = (alg === 'aes-gcm' ? 12 : 16);
    const iv = crypto.getRandomValues(new Uint8Array(ivLen));
    const algoName = alg.toUpperCase();
    // Anahtar oluştur ve raw al
    const keyObj = await crypto.subtle.generateKey(
        { name: algoName, length: 256 },
        true,
        ['encrypt','decrypt']
    );
    const rawKey = await crypto.subtle.exportKey('raw', keyObj);
    const keyHex = buf2hex(rawKey);
    // Şifreleme
    const cipherBuffer = await crypto.subtle.encrypt(
        { name: algoName, iv },
        keyObj,
        dataBuffer
    );
    // iv + şifreli veriyi birleştir
    const out = new Uint8Array(ivLen + cipherBuffer.byteLength);
    out.set(iv, 0);
    out.set(new Uint8Array(cipherBuffer), ivLen);
    return { encryptedData: out.buffer, keyHex };
}

/**
 * AES-GCM veya AES-CBC ile çözme
 * @param {string} alg - 'aes-gcm' veya 'aes-cbc'
 * @param {ArrayBuffer} combinedBuffer - iv + ciphertext
 * @param {string} keyHex - Anahtar hex string
 * @returns {Promise<ArrayBuffer>} - Çözülmüş veri
 */
async function decryptAES(alg, combinedBuffer, keyHex) {
    const all = new Uint8Array(combinedBuffer);
    const ivLen = (alg === 'aes-gcm' ? 12 : 16);
    const iv = all.slice(0, ivLen);
    const ciphertext = all.slice(ivLen);
    const keyBytes = hexToBytes(keyHex);
    const keyObj = await crypto.subtle.importKey(
        'raw', keyBytes,
        { name: alg.toUpperCase() },
        false,
        ['encrypt','decrypt']
    );
    const plainBuffer = await crypto.subtle.decrypt(
        { name: alg.toUpperCase(), iv },
        keyObj,
        ciphertext
    );
    return plainBuffer;
}

// ===== SEKME GEÇİŞİ =====
function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(tab + '-tab').classList.add('active');
    hideAlerts();
}

// ===== DOSYA SEÇİMİ =====
function handleFileSelect(input, type) {
    const file = input.files[0];
    const display = document.getElementById(type + 'FileDisplay');
    const btn = document.getElementById(type + 'Btn');
    if (!file) return;
    display.classList.add('has-file');
    display.innerHTML = `
        <div class="file-icon">📄</div>
        <div><strong>${file.name}</strong></div>
        <div style="font-size:14px;color:#64748b;">${(file.size/1024).toFixed(1)} KB</div>
    `;
    btn.disabled = false;
}

document.getElementById('decryptKey').addEventListener('input', function() {
    const hasKey = this.value.trim() !== '';
    const hasFile = document.getElementById('decryptFile').files.length > 0;
    document.getElementById('decryptBtn').disabled = !(hasKey && hasFile);
});

// ===== ANAHTAR OLUŞTURMA =====
function generateKey() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ===== ŞİFRELEME =====
async function encryptFile() {
  const file = document.getElementById('encryptFile').files[0];
  const alg  = document.getElementById('algorithm').value;
  if (!file) return showError('Şifrelenecek dosya seçilmedi!');

  showProgress('encrypt', true);
  let buffer;
  try {
    buffer = await readFileWithProgress(file, p => updateProgress('encrypt', p));
  } catch {
    showError('Dosya okuma hatası');
    showProgress('encrypt', false);
    return;
  }

  let result;
  if (alg === 'xor') {
    currentKey     = generateKey();                // eski hex anahtar
    const dataArr  = xorCrypt(new Uint8Array(buffer), currentKey);
    result         = { encryptedData: dataArr.buffer, keyHex: currentKey };
  } else {
    // AES-GCM veya AES-CBC
    result = await encryptAES(alg, buffer);
    currentKey = result.keyHex;
  }

  encryptedData = new Uint8Array(result.encryptedData);
  document.getElementById('generatedKey').textContent = currentKey;
  document.getElementById('encryptResult').style.display = 'block';
  updateProgress('encrypt', 100);
  setTimeout(()=> showProgress('encrypt', false), 500);
  showSuccess('Dosya şifrelendi! Anahtarı saklayın.');
}

// ===== ÇÖZME =====
async function decryptFile() {
  const file = document.getElementById('decryptFile').files[0];
  const alg  = document.getElementById('algorithm').value;
  const key  = document.getElementById('decryptKey').value.trim();
  if (!file) return showError('Çözülecek dosya seçilmedi!');
  if (!key)  return showError('Anahtar girilmedi!');

  showProgress('decrypt', true);
  let buffer;
  try {
    buffer = await readFileWithProgress(file, p => updateProgress('decrypt', p));
  } catch {
    showError('Dosya okuma hatası');
    showProgress('decrypt', false);
    return;
  }

  let plainBuf;
  try {
    if (alg === 'xor') {
      plainBuf = xorCrypt(new Uint8Array(buffer), key).buffer;
    } else {
      plainBuf = await decryptAES(alg, buffer, key);
    }
  } catch {
    showProgress('decrypt', false);
    return showError('Çözme hatası: Anahtar yanlış veya dosya bozuk');
  }

  decryptedData = new Uint8Array(plainBuf);
  document.getElementById('decryptResult').style.display = 'block';
  updateProgress('decrypt', 100);
  setTimeout(()=> showProgress('decrypt', false), 500);
  showSuccess('Dosya çözüldü! Önizleme için tıklayın.');
}

// ===== XOR ŞİFRELEME FONKSİYONU =====
function xorCrypt(data, keyHex) {
    const key = hexToBytes(keyHex);
    return data.map((byte, idx) => byte ^ key[idx % key.length]);
}

// ===== HEX'DEN BYTE DİZİSİNE =====
function hexToBytes(hex) {
    const arr = [];
    for (let i = 0; i < hex.length; i += 2) {
        arr.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(arr);
}

// ===== İNDİRME FONKSİYONLARI =====
function downloadEncryptedFile() {
    if (!encryptedData) return;
    const blob = new Blob([encryptedData], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'sifrelenmis_dosya.bin'; a.click(); URL.revokeObjectURL(url);
}
function downloadDecryptedFile() {
    if (!decryptedData) return;
    const blob = new Blob([decryptedData], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'cozulmus_dosya.txt'; a.click(); URL.revokeObjectURL(url);
}

// ===== KOPYALA =====
function copyToClipboard(elId) {
    const text = document.getElementById(elId).textContent;
    navigator.clipboard.writeText(text)
        .then(() => showSuccess('Anahtar panoya kopyalandı!'))
        .catch(() => { document.execCommand('copy'); showSuccess('Anahtar panoya kopyalandı!'); });
}

// ===== UYARI ve BİLDİRİMLER =====
function showError(msg) { hideAlerts(); const e = document.getElementById('errorAlert'); e.textContent = msg; e.style.display = 'block'; setTimeout(hideAlerts, 5000); }
function showSuccess(msg) { hideAlerts(); const s = document.getElementById('successAlert'); s.textContent = msg; s.style.display = 'block'; setTimeout(hideAlerts, 3000); }
function hideAlerts() { document.getElementById('errorAlert').style.display = 'none'; document.getElementById('successAlert').style.display = 'none'; }

// ===== MODAL İŞLEMLERİ =====
function showPreviewModal() {
  const modal = document.getElementById('previewModal');
  const body  = modal.querySelector('.modal-body');
  const file  = document.getElementById('decryptFile').files[0];
  const mime  = file.type;
  body.innerHTML = '';  // önce temizle

  const blob  = new Blob([decryptedData], { type: mime });
  const url   = URL.createObjectURL(blob);

  if (mime === 'application/pdf') {
    const embed = document.createElement('embed');
    embed.src  = url; embed.type = mime;
    embed.style.width = '100%'; embed.style.height = '80vh';
    body.appendChild(embed);
  }
  else if (mime.startsWith('image/')) {
    const img = document.createElement('img');
    img.src = url;
    img.style.maxWidth  = '100%';
    img.style.maxHeight = '80vh';
    body.appendChild(img);
  }
  else if (mime.startsWith('video/')) {
    const vid = document.createElement('video');
    vid.src = url; vid.controls = true;
    vid.style.maxWidth  = '100%'; vid.style.maxHeight = '80vh';
    body.appendChild(vid);
  }
  else {
    // fallback: metin önizlemesi
    let txt;
    try {
      txt = new TextDecoder().decode(decryptedData);
    } catch {
      txt = 'Önizleme yapılamıyor';
    }
    const pre = document.createElement('pre');
    pre.textContent = txt.slice(0,2000) + (txt.length>2000?'…':'');
    body.appendChild(pre);
  }

  modal.style.display = 'block';
  document.body.style.overflow = 'hidden';
}

function closePreviewModal() { document.getElementById('previewModal').style.display = 'none'; document.body.style.overflow = 'auto'; }
window.onclick = e => { if (e.target === document.getElementById('previewModal')) closePreviewModal(); };
document.addEventListener('keydown', e => { if (e.key === 'Escape') closePreviewModal(); });
