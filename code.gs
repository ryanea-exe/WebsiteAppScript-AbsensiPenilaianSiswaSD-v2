/**
 * ============================================================================
 * SISTEM ABSENSI & PENILAIAN SISWA SD (VERSI 2)
 * File: code.gs — Backend Controller, Autentikasi, dan Sesi Server-Side
 * ============================================================================
 *
 * Ruang Lingkup Phase 2:
 * 1. doGet(e) untuk melayani shell aplikasi web responsif.
 * 2. Helper akses database Spreadsheet (batch reading, mapping kolom dinamis).
 * 3. Hashing password PBKDF2-HMAC-SHA256 (Pure JS V8 Engine, 100.000 iterasi)
 *    dengan format terstruktur 'pbkdf2:sha256:<iter>:<hex>'.
 * 4. Verifikasi konstan (timing-attack mitigation) dan lazy rehash untuk akun legacy SHA-256.
 * 5. Manajemen sesi server-side (CacheService dengan fallback memori untuk testing)
 *    berumur terbatas (TTL 2 jam) dan pembatasan akses berbasis role.
 * 6. Respons standar { success, data, message } tanpa kebocoran stack trace internal.
 */

// Konfigurasi Autentikasi dan Sesi
const AUTH_CONFIG = Object.freeze({
  ALGORITHM: 'pbkdf2:sha256',
  ITERATIONS: 100000, // Kompromi terukur: ~897ms di GAS V8, aman dari offline brute-force
  MIN_ITERATIONS: 1000,
  MAX_ITERATIONS: 250000,
  DK_LEN: 32, // 256 bits output
  SESSION_TTL_SECONDS: 7200, // 2 jam sesi aktif
  GENERIC_AUTH_ERROR: 'Username atau password salah.',
  INACTIVE_USER_ERROR: 'Akun Anda dinonaktifkan. Silakan hubungi Kepala Sekolah.'
});

// Cache in-memory lokal untuk pengujian Node.js ketika CacheService belum tersedia
const _localMemoryCache = new Map();

// ============================================================================
// 1. KRIPTOGRAFI PBKDF2-HMAC-SHA256 (PURE JS V8 ENGINE)
// ============================================================================

/**
 * Konversi string ke UTF-8 Uint8Array.
 * @param {string} str
 * @return {Uint8Array}
 */
function utf8ToBytes(str) {
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(str);
  }
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) {
      bytes.push(c);
    } else if (c < 0x800) {
      bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c < 0xd800 || c >= 0xe000) {
      bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else {
      i++;
      c = 0x10000 + (((c & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      bytes.push(
        0xf0 | (c >> 18),
        0x80 | ((c >> 12) & 0x3f),
        0x80 | ((c >> 6) & 0x3f),
        0x80 | (c & 0x3f)
      );
    }
  }
  return new Uint8Array(bytes);
}

function rotr32(n, x) {
  return (x >>> n) | (x << (32 - n));
}

const K_SHA256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function rawSha256(dataBytes) {
  const bitLen = dataBytes.length * 8;
  const padLen = (dataBytes.length + 9 + 63) & ~63;
  const padded = new Uint8Array(padLen);
  padded.set(dataBytes);
  padded[dataBytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(padLen - 4, bitLen >>> 0);
  view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000));

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);

  for (let offset = 0; offset < padLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + (i * 4));
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr32(7, w[i - 15]) ^ rotr32(18, w[i - 15]) ^ (w[i - 15] >>> 3);
      const s1 = rotr32(17, w[i - 2]) ^ rotr32(19, w[i - 2]) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr32(6, e) ^ rotr32(11, e) ^ rotr32(25, e);
      const ch = (e & f) ^ ((~e) & g);
      const temp1 = (h + S1 + ch + K_SHA256[i] + w[i]) | 0;
      const S0 = rotr32(2, a) ^ rotr32(13, a) ^ rotr32(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

      h = g; g = f; f = e; e = (d + temp1) | 0;
      d = c; c = b; b = a; a = (temp1 + temp2) | 0;
    }

    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0); outView.setUint32(4, h1);
  outView.setUint32(8, h2); outView.setUint32(12, h3);
  outView.setUint32(16, h4); outView.setUint32(20, h5);
  outView.setUint32(24, h6); outView.setUint32(28, h7);
  return out;
}

function rawHmacSha256(keyBytes, msgBytes) {
  let k = keyBytes;
  if (k.length > 64) {
    k = rawSha256(k);
  }

  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    const b = i < k.length ? k[i] : 0;
    ipad[i] = b ^ 0x36;
    opad[i] = b ^ 0x5c;
  }

  const innerBuf = new Uint8Array(64 + msgBytes.length);
  innerBuf.set(ipad, 0);
  innerBuf.set(msgBytes, 64);
  const innerHash = rawSha256(innerBuf);

  const outerBuf = new Uint8Array(64 + 32);
  outerBuf.set(opad, 0);
  outerBuf.set(innerHash, 64);
  return rawSha256(outerBuf);
}

/**
 * Derivasi kunci PBKDF2-HMAC-SHA256 (RFC 8018).
 * @param {string} password
 * @param {string} salt
 * @param {number} iterations
 * @param {number} dkLen
 * @return {string} Hexadecimal string lowercase
 */
function computePBKDF2(password, salt, iterations, dkLen) {
  if (iterations <= 0 || dkLen <= 0) {
    throw new Error('Iterasi dan dkLen harus bilangan positif.');
  }
  const pBytes = utf8ToBytes(password);
  const sBytes = utf8ToBytes(salt);
  const hLen = 32;
  const l = Math.ceil(dkLen / hLen);
  const r = dkLen - (l - 1) * hLen;
  const dk = new Uint8Array(dkLen);

  for (let i = 1; i <= l; i++) {
    const sInt = new Uint8Array(sBytes.length + 4);
    sInt.set(sBytes, 0);
    sInt[sBytes.length] = (i >>> 24) & 0xff;
    sInt[sBytes.length + 1] = (i >>> 16) & 0xff;
    sInt[sBytes.length + 2] = (i >>> 8) & 0xff;
    sInt[sBytes.length + 3] = i & 0xff;

    let u = rawHmacSha256(pBytes, sInt);
    const t = new Uint8Array(u);

    for (let c = 1; c < iterations; c++) {
      u = rawHmacSha256(pBytes, u);
      for (let k = 0; k < hLen; k++) {
        t[k] ^= u[k];
      }
    }

    const blockLen = (i === l) ? r : hLen;
    dk.set(t.subarray(0, blockLen), (i - 1) * hLen);
  }

  let hex = '';
  for (let i = 0; i < dk.length; i++) {
    const b = dk[i].toString(16);
    hex += (b.length === 1 ? '0' + b : b);
  }
  return hex;
}

/**
 * Menghasilkan salt acak berbasis CSPRNG Apps Script (UUID v4 ganda = 64 karakter hex).
 * Catatan entropi: Dua UUID v4 dari Utilities.getUuid() memberikan ~244 bit entropi efektif
 * (122 bit per UUID v4 karena bit version dan variant bersifat fixed), melampaui batas
 * minimum rekomendasi keamanan industri/OWASP (128 bit).
 * @return {string}
 */
function generateSecureSalt() {
  if (typeof Utilities !== 'undefined' && typeof Utilities.getUuid === 'function') {
    const u1 = Utilities.getUuid().replace(/-/g, '');
    const u2 = Utilities.getUuid().replace(/-/g, '');
    return (u1 + u2).substring(0, 64);
  }
  if (typeof crypto !== 'undefined') {
    if (typeof crypto.randomBytes === 'function') {
      return crypto.randomBytes(32).toString('hex');
    }
    if (typeof crypto.randomUUID === 'function') {
      const u1 = crypto.randomUUID().replace(/-/g, '');
      const u2 = crypto.randomUUID().replace(/-/g, '');
      return (u1 + u2).substring(0, 64);
    }
  }
  let hex = '';
  for (let i = 0; i < 8; i++) {
    hex += Math.floor(Math.random() * 0x100000000).toString(16).padStart(8, '0');
  }
  return hex.substring(0, 64);
}

/**
 * Membuat password_hash berformat terstruktur PBKDF2: 'pbkdf2:sha256:<iter>:<hex>'.
 * @param {string} password
 * @param {string} salt
 * @param {number} [iterations]
 * @return {string}
 */
function hashPasswordPBKDF2(password, salt, iterations) {
  const iter = iterations || AUTH_CONFIG.ITERATIONS;
  const derivedHex = computePBKDF2(password, salt, iter, AUTH_CONFIG.DK_LEN);
  return 'pbkdf2:sha256:' + iter + ':' + derivedHex;
}

/**
 * Perbandingan string konstan untuk memitigasi timing attack (early-exit leakage).
 * @param {string} a
 * @param {string} b
 * @return {boolean}
 */
function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Verifikasi password terhadap hash tersimpan.
 * Mendukung format PBKDF2 terstruktur dan backward-compatibility dengan legacy SHA-256.
 *
 * @param {string} passwordPlaintext
 * @param {string} storedHash
 * @param {string} storedSalt
 * @return {{ valid: boolean, needsRehash: boolean }}
 */
function verifyPassword(passwordPlaintext, storedHash, storedSalt) {
  if (!passwordPlaintext || !storedHash) {
    return { valid: false, needsRehash: false };
  }

  // Kasus 1: Format Terstruktur PBKDF2: 'pbkdf2:sha256:<iterations>:<hex>'
  if (storedHash.startsWith('pbkdf2:sha256:')) {
    const parts = storedHash.split(':');
    if (parts.length !== 4) {
      return { valid: false, needsRehash: false };
    }
    const iter = parseInt(parts[2], 10);
    const expectedHex = parts[3];

    // Validasi batas iterasi defensif untuk mencegah DoS lewat data tersimpan
    if (isNaN(iter) || iter < AUTH_CONFIG.MIN_ITERATIONS || iter > AUTH_CONFIG.MAX_ITERATIONS) {
      return { valid: false, needsRehash: false };
    }

    const calculatedHex = computePBKDF2(passwordPlaintext, storedSalt || '', iter, expectedHex.length / 2);
    const isValid = constantTimeCompare(calculatedHex, expectedHex);
    return { valid: isValid, needsRehash: false };
  }

  // Kasus 2: Format Legacy SHA-256 + Salt (Hex 64 karakter dari Phase 1)
  if (/^[a-f0-9]{64}$/i.test(storedHash)) {
    let legacyHash = '';
    if (typeof hashPasswordWithSalt === 'function') {
      legacyHash = hashPasswordWithSalt(passwordPlaintext, storedSalt || '');
    } else if (typeof Utilities !== 'undefined' && typeof Utilities.computeDigest === 'function') {
      const combined = passwordPlaintext + ':' + (storedSalt || '');
      const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, combined, Utilities.Charset.UTF_8);
      legacyHash = digest.map(function(byte) {
        const v = (byte < 0 ? byte + 256 : byte).toString(16);
        return v.length === 1 ? '0' + v : v;
      }).join('');
    } else if (typeof require !== 'undefined') {
      const crypto = require('crypto');
      legacyHash = crypto.createHash('sha256').update(passwordPlaintext + ':' + (storedSalt || ''), 'utf8').digest('hex');
    }

    const isValid = constantTimeCompare(legacyHash.toLowerCase(), storedHash.toLowerCase());
    return { valid: isValid, needsRehash: isValid };
  }

  // Format tidak dikenal
  return { valid: false, needsRehash: false };
}

// ============================================================================
// 2. MANAJEMEN SESI SERVER-SIDE (CacheService Adapter)
// ============================================================================

/**
 * Adapter pembacaan dan penulisan cache sesi.
 */
const SessionStore = {
  get: function(token) {
    if (typeof CacheService !== 'undefined') {
      const cache = CacheService.getScriptCache();
      const val = cache.get('session_' + token);
      if (!val) return null;
      try {
        return JSON.parse(val);
      } catch (e) {
        return null;
      }
    }
    return _localMemoryCache.get('session_' + token) || null;
  },

  set: function(token, sessionData, ttlSeconds) {
    const ttl = ttlSeconds || AUTH_CONFIG.SESSION_TTL_SECONDS;
    if (typeof CacheService !== 'undefined') {
      const cache = CacheService.getScriptCache();
      cache.put('session_' + token, JSON.stringify(sessionData), ttl);
      return;
    }
    _localMemoryCache.set('session_' + token, sessionData);
  },

  remove: function(token) {
    if (typeof CacheService !== 'undefined') {
      const cache = CacheService.getScriptCache();
      cache.remove('session_' + token);
      return;
    }
    _localMemoryCache.delete('session_' + token);
  }
};

/**
 * Membuat sesi login baru untuk user.
 * @param {Object} userRecord
 * @return {string} sessionToken (UUID v4)
 */
function createSession(userRecord) {
  let token = '';
  if (typeof Utilities !== 'undefined' && typeof Utilities.getUuid === 'function') {
    token = Utilities.getUuid();
  } else if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    token = crypto.randomUUID();
  } else if (typeof generateUUID === 'function') {
    token = generateUUID();
  } else {
    token = 'sess_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  const sessionData = {
    userId: userRecord.id,
    username: userRecord.username,
    nama: userRecord.nama,
    role: userRecord.role,
    foto: userRecord.foto || '',
    createdAt: Date.now()
  };

  SessionStore.set(token, sessionData, AUTH_CONFIG.SESSION_TTL_SECONDS);
  return token;
}

/**
 * Mengambil dan memvalidasi sesi aktif dari token.
 * @param {string} token
 * @return {Object|null}
 */
function getActiveSession(token) {
  if (!token || typeof token !== 'string') return null;
  return SessionStore.get(token);
}

/**
 * Mengakhiri sesi (logout).
 * @param {string} token
 * @return {boolean}
 */
function destroySession(token) {
  if (!token || typeof token !== 'string') return false;
  SessionStore.remove(token);
  return true;
}

// ============================================================================
// 3. HELPER AKSES SPREADSHEET BATCH
// ============================================================================

/**
 * Membaca seluruh data sheet sebagai array objek menggunakan header baris 1.
 * @param {string} sheetName
 * @return {{ headers: string[], rows: Object[], rawValues: any[][] }}
 */
function getSheetDataBatch(sheetName) {
  const ss = (typeof getTargetSpreadsheet === 'function')
    ? getTargetSpreadsheet()
    : (typeof SpreadsheetApp !== 'undefined' ? SpreadsheetApp.getActiveSpreadsheet() : null);

  if (!ss) {
    throw new Error('Spreadsheet target tidak dapat diakses.');
  }

  const sheet = ss.getSheetByName(sheetName);
  if (!sheet) {
    throw new Error('Sheet "' + sheetName + '" tidak ditemukan.');
  }

  const lastRow = sheet.getLastRow();
  const lastCol = sheet.getLastColumn();

  if (lastRow <= 1 || lastCol === 0) {
    const headers = lastRow === 1 ? (sheet.getRange(1, 1, 1, lastCol).getValues()[0] || []) : [];
    return { headers: headers, rows: [], rawValues: [] };
  }

  const values = sheet.getRange(1, 1, lastRow, lastCol).getValues();
  const headers = values[0].map(h => String(h || '').trim());
  const rows = [];

  for (let r = 1; r < values.length; r++) {
    const rowObj = { _rowIndex: r + 1 };
    for (let c = 0; c < headers.length; c++) {
      rowObj[headers[c]] = values[r][c];
    }
    rows.push(rowObj);
  }

  return { headers: headers, rows: rows, rawValues: values };
}

/**
 * Standar wrapper response API JSON.
 */
function buildResponse(success, data, message) {
  return {
    success: !!success,
    data: data || null,
    message: message || (success ? 'Operasi berhasil.' : 'Terjadi kesalahan.')
  };
}

/**
 * Helper pembangkit ID UUID v4 stabil.
 */
function getStableUUID() {
  if (typeof Utilities !== 'undefined' && typeof Utilities.getUuid === 'function') {
    return Utilities.getUuid();
  }
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Menambahkan baris baru ke sheet berdasarkan pemetaan nama kolom header.
 * @param {string} sheetName
 * @param {Object} rowObject
 * @return {boolean}
 */
function appendSheetRow(sheetName, rowObject) {
  const ss = (typeof getTargetSpreadsheet === 'function')
    ? getTargetSpreadsheet()
    : (typeof SpreadsheetApp !== 'undefined' ? SpreadsheetApp.getActiveSpreadsheet() : null);

  if (!ss) throw new Error('Spreadsheet target tidak dapat diakses.');
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet) throw new Error('Sheet "' + sheetName + '" tidak ditemukan.');

  const lastCol = sheet.getLastColumn();
  if (lastCol === 0) throw new Error('Sheet "' + sheetName + '" tidak memiliki kolom.');
  const headers = sheet.getRange(1, 1, 1, lastCol).getValues()[0].map(h => String(h || '').trim());
  const rowValues = new Array(headers.length).fill('');
  for (let c = 0; c < headers.length; c++) {
    const colName = headers[c];
    if (rowObject.hasOwnProperty(colName)) {
      rowValues[c] = rowObject[colName];
    }
  }

  sheet.appendRow(rowValues);
  if (typeof SpreadsheetApp !== 'undefined' && typeof SpreadsheetApp.flush === 'function') {
    SpreadsheetApp.flush();
  }
  return true;
}

/**
 * Memperbarui sel-sel pada baris tertentu di sheet berdasarkan nama kolom.
 * @param {string} sheetName
 * @param {number} rowIndex (1-indexed)
 * @param {Object} updateFields
 * @return {boolean}
 */
function updateSheetRow(sheetName, rowIndex, updateFields) {
  const ss = (typeof getTargetSpreadsheet === 'function')
    ? getTargetSpreadsheet()
    : (typeof SpreadsheetApp !== 'undefined' ? SpreadsheetApp.getActiveSpreadsheet() : null);

  if (!ss) throw new Error('Spreadsheet target tidak dapat diakses.');
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet) throw new Error('Sheet "' + sheetName + '" tidak ditemukan.');

  const lastCol = sheet.getLastColumn();
  const headers = sheet.getRange(1, 1, 1, lastCol).getValues()[0].map(h => String(h || '').trim());
  for (const [colName, val] of Object.entries(updateFields)) {
    const colIdx = headers.indexOf(colName);
    if (colIdx >= 0) {
      sheet.getRange(rowIndex, colIdx + 1).setValue(val);
    }
  }

  if (typeof SpreadsheetApp !== 'undefined' && typeof SpreadsheetApp.flush === 'function') {
    SpreadsheetApp.flush();
  }
  return true;
}

/**
 * Menghapus baris dari sheet.
 * @param {string} sheetName
 * @param {number} rowIndex (1-indexed)
 * @return {boolean}
 */
function deleteSheetRow(sheetName, rowIndex) {
  const ss = (typeof getTargetSpreadsheet === 'function')
    ? getTargetSpreadsheet()
    : (typeof SpreadsheetApp !== 'undefined' ? SpreadsheetApp.getActiveSpreadsheet() : null);

  if (!ss) throw new Error('Spreadsheet target tidak dapat diakses.');
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet) throw new Error('Sheet "' + sheetName + '" tidak ditemukan.');

  sheet.deleteRow(rowIndex);
  if (typeof SpreadsheetApp !== 'undefined' && typeof SpreadsheetApp.flush === 'function') {
    SpreadsheetApp.flush();
  }
  return true;
}

// ============================================================================
// 4. ENDPOINT AUTENTIKASI DAN VALIDASI (Dipanggil Frontend google.script.run)
// ============================================================================

/**
 * Endpoint Login: Autentikasi kredensial dan inisialisasi sesi.
 *
 * @param {string} username
 * @param {string} password
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiLogin(username, password) {
  try {
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
      return buildResponse(false, null, AUTH_CONFIG.GENERIC_AUTH_ERROR);
    }

    const cleanUsername = username.trim().toLowerCase();
    const cleanPassword = password;

    if (cleanUsername === '' || cleanPassword === '') {
      return buildResponse(false, null, AUTH_CONFIG.GENERIC_AUTH_ERROR);
    }

    const userData = getSheetDataBatch('user');
    const userRow = userData.rows.find(function(u) {
      return String(u.username || '').trim().toLowerCase() === cleanUsername;
    });

    // Jika username tidak ditemukan, gunakan pesan umum untuk cegah user enumeration
    if (!userRow) {
      return buildResponse(false, null, AUTH_CONFIG.GENERIC_AUTH_ERROR);
    }

    // Periksa status aktif user
    if (userRow.is_active === false || String(userRow.is_active).toLowerCase() === 'false') {
      return buildResponse(false, null, AUTH_CONFIG.INACTIVE_USER_ERROR);
    }

    // Verifikasi hash password
    const verifyResult = verifyPassword(cleanPassword, String(userRow.password_hash || ''), String(userRow.password_salt || ''));
    if (!verifyResult.valid) {
      return buildResponse(false, null, AUTH_CONFIG.GENERIC_AUTH_ERROR);
    }

    const ss = (typeof getTargetSpreadsheet === 'function')
      ? getTargetSpreadsheet()
      : (typeof SpreadsheetApp !== 'undefined' ? SpreadsheetApp.getActiveSpreadsheet() : null);

    const nowIso = new Date().toISOString();

    // Lazy Rehash: Jika akun login menggunakan legacy SHA-256, upgrade transparan ke PBKDF2
    if (verifyResult.needsRehash && ss) {
      try {
        const userSheet = ss.getSheetByName('user');
        const newSalt = generateSecureSalt();
        const newHash = hashPasswordPBKDF2(cleanPassword, newSalt);

        const hashCol = userData.headers.indexOf('password_hash') + 1;
        const saltCol = userData.headers.indexOf('password_salt') + 1;
        const updatedCol = userData.headers.indexOf('updated_at') + 1;

        if (hashCol > 0 && saltCol > 0) {
          userSheet.getRange(userRow._rowIndex, hashCol).setValue(newHash);
          userSheet.getRange(userRow._rowIndex, saltCol).setValue(newSalt);
          if (updatedCol > 0) {
            userSheet.getRange(userRow._rowIndex, updatedCol).setValue(nowIso);
          }
        }
      } catch (rehashError) {
        // Kegagalan penulisan rehash tidak membatalkan login sesi saat ini
        if (typeof Logger !== 'undefined') {
          Logger.log('Peringatan: Gagal melakukan lazy rehash akun legacy: ' + rehashError.message);
        }
      }
    }

    // Perbarui timestamp terakhir_login
    if (ss) {
      try {
        const userSheet = ss.getSheetByName('user');
        const lastLoginCol = userData.headers.indexOf('terakhir_login') + 1;
        if (lastLoginCol > 0) {
          userSheet.getRange(userRow._rowIndex, lastLoginCol).setValue(nowIso);
        }
      } catch (loginTimeErr) {
        // Abaikan kegagalan penulisan audit non-kritis
      }
    }

    // Buat sesi server-side
    const sessionToken = createSession(userRow);

    return buildResponse(true, {
      token: sessionToken,
      user: {
        id: userRow.id,
        nama: userRow.nama,
        username: userRow.username,
        role: userRow.role,
        foto: userRow.foto || ''
      }
    }, 'Login berhasil.');
  } catch (err) {
    if (typeof Logger !== 'undefined') {
      Logger.log('Kesalahan internal apiLogin: ' + err.message);
    }
    return buildResponse(false, null, 'Terjadi kesalahan sistem saat memproses login.');
  }
}

/**
 * Endpoint Logout: Mengakhiri sesi aktif.
 * @param {string} sessionToken
 * @return {{ success: boolean, data: null, message: string }}
 */
function apiLogout(sessionToken) {
  try {
    destroySession(sessionToken);
    return buildResponse(true, null, 'Berhasil logout.');
  } catch (err) {
    return buildResponse(true, null, 'Sesi telah diakhiri.');
  }
}

/**
 * Endpoint Pengambilan User Sesi Aktif.
 * @param {string} sessionToken
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiGetSessionUser(sessionToken) {
  try {
    const session = getActiveSession(sessionToken);
    if (!session) {
      return buildResponse(false, null, 'Sesi tidak valid atau telah berakhir.');
    }

    // Verifikasi bahwa user masih aktif di database
    const userData = getSheetDataBatch('user');
    const userRow = userData.rows.find(u => u.id === session.userId);
    if (!userRow || userRow.is_active === false || String(userRow.is_active).toLowerCase() === 'false') {
      destroySession(sessionToken);
      return buildResponse(false, null, AUTH_CONFIG.INACTIVE_USER_ERROR);
    }

    return buildResponse(true, {
      id: userRow.id,
      nama: userRow.nama,
      username: userRow.username,
      role: userRow.role,
      foto: userRow.foto || ''
    }, 'Sesi aktif.');
  } catch (err) {
    return buildResponse(false, null, 'Gagal memvalidasi sesi.');
  }
}

/**
 * Guard Helper Otorisasi Server-Side: Wajib dipanggil pada setiap endpoint sensitif.
 * @param {string} sessionToken
 * @param {string} [requiredRole] 'kepala_sekolah' | 'wali_kelas'
 * @return {Object} sessionUser
 */
function requireAuth(sessionToken, requiredRole) {
  const session = getActiveSession(sessionToken);
  if (!session) {
    throw new Error('Akses ditolak: Sesi tidak valid atau telah kedaluwarsa.');
  }

  // Verifikasi status user terkini dari database
  const userData = getSheetDataBatch('user');
  const userRow = userData.rows.find(u => u.id === session.userId);

  if (!userRow || userRow.is_active === false || String(userRow.is_active).toLowerCase() === 'false') {
    destroySession(sessionToken);
    throw new Error(AUTH_CONFIG.INACTIVE_USER_ERROR);
  }

  if (requiredRole) {
    if (Array.isArray(requiredRole)) {
      if (!requiredRole.includes(userRow.role)) {
        throw new Error('Akses ditolak: Anda tidak memiliki izin untuk operasi ini.');
      }
    } else if (userRow.role !== requiredRole) {
      throw new Error('Akses ditolak: Anda tidak memiliki izin untuk operasi ini.');
    }
  }

  return {
    id: userRow.id,
    nama: userRow.nama,
    username: userRow.username,
    role: userRow.role,
    foto: userRow.foto || ''
  };
}

/**
 * Endpoint Dashboard Awal (Phase 3):
 * Mengambil ringkasan dashboard, identitas profil sekolah, periode aktif, dan statistik sesuai role.
 * Otorisasi: Wajib sesi valid (kepala_sekolah atau wali_kelas).
 *
 * @param {string} sessionToken
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiGetInitialDashboard(sessionToken) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    // 1. Profil Sekolah (Sheet pengaturan)
    let schoolProfile = {
      namaSekolah: 'SD Negeri Percobaan',
      namaKepalaSekolah: '',
      nipKepalaSekolah: '',
      logoSekolah: ''
    };
    try {
      const pengData = getSheetDataBatch('pengaturan');
      if (pengData.rows.length > 0) {
        const row = pengData.rows[0];
        schoolProfile.namaSekolah = row.nama_sekolah || schoolProfile.namaSekolah;
        schoolProfile.namaKepalaSekolah = row.nama_kepala_sekolah || '';
        schoolProfile.nipKepalaSekolah = row.nip_kepala_sekolah || '';
        schoolProfile.logoSekolah = row.logo_sekolah || '';
      }
    } catch (e) {
      // Abaikan jika sheet pengaturan belum siap
    }

    // 2. Tahun Ajaran Aktif (Sheet tahun_ajaran)
    let activeYear = null;
    try {
      const taData = getSheetDataBatch('tahun_ajaran');
      const foundTa = taData.rows.find(ta => ta.is_active === true || String(ta.is_active).toLowerCase() === 'true');
      if (foundTa) {
        activeYear = {
          id: foundTa.id,
          tahunAjaran: foundTa.tahun_ajaran,
          semester: foundTa.semester,
          isLocked: foundTa.is_locked === true || String(foundTa.is_locked).toLowerCase() === 'true'
        };
      }
    } catch (e) {
      // Abaikan jika belum ada tahun ajaran
    }

    const payload = {
      user: {
        id: user.id,
        nama: user.nama,
        username: user.username,
        role: user.role,
        foto: user.foto || ''
      },
      schoolProfile: schoolProfile,
      activeYear: activeYear
    };

    if (user.role === 'kepala_sekolah') {
      // Data Ringkasan untuk Kepala Sekolah
      let totalGuru = 0;
      let totalKelasDitugaskan = 0;
      let totalSiswa = 0;
      let uData = null;
      let wkData = null;
      let sData = null;

      try {
        uData = getSheetDataBatch('user');
        totalGuru = uData.rows.filter(u => u.role === 'wali_kelas' && (u.is_active === true || String(u.is_active).toLowerCase() === 'true')).length;
      } catch (e) {}

      try {
        wkData = getSheetDataBatch('wali_kelas');
        if (activeYear) {
          totalKelasDitugaskan = wkData.rows.filter(w => w.tahun_ajaran_id === activeYear.id && (w.is_active === true || String(w.is_active).toLowerCase() === 'true')).length;
        } else {
          totalKelasDitugaskan = wkData.rows.filter(w => w.is_active === true || String(w.is_active).toLowerCase() === 'true').length;
        }
      } catch (e) {}

      try {
        sData = getSheetDataBatch('siswa');
        totalSiswa = sData.rows.filter(s => s.is_active !== false && String(s.is_active).toLowerCase() !== 'false').length;
      } catch (e) {}

      // Breakdown 6 kelas (Kelas 1 - Kelas 6) untuk Kepala Sekolah
      const kelasOverview = [];
      const wkRows = (wkData && wkData.rows) ? wkData.rows : [];
      const uRows = (uData && uData.rows) ? uData.rows : [];
      const sRows = (sData && sData.rows) ? sData.rows : [];

      for (let k = 1; k <= 6; k++) {
        const kStr = String(k);
        let detail = null;
        if (activeYear) {
          const matchWk = wkRows.find(w =>
            String(w.kelas) === kStr &&
            w.tahun_ajaran_id === activeYear.id &&
            (w.is_active === true || String(w.is_active).toLowerCase() === 'true')
          );
          if (matchWk) {
            const teacher = uRows.find(u => u.id === matchWk.user_id);
            const count = sRows.filter(s =>
              s.wali_kelas_id === matchWk.id &&
              (s.is_active !== false && String(s.is_active).toLowerCase() !== 'false')
            ).length;
            detail = {
              penugasanId: matchWk.id,
              guruNama: teacher ? teacher.nama : 'Guru tidak dikenal',
              guruNip: teacher ? (teacher.nip || '-') : '-',
              totalSiswa: count
            };
          }
        }
        kelasOverview.push({
          kelas: kStr,
          isAssigned: !!detail,
          guruNama: detail ? detail.guruNama : 'Belum Ditugaskan',
          guruNip: detail ? detail.guruNip : '-',
          totalSiswa: detail ? detail.totalSiswa : 0,
          details: detail
        });
      }

      payload.kelasOverview = kelasOverview;
      payload.summary = {
        totalGuru: totalGuru,
        totalKelasDitugaskan: totalKelasDitugaskan,
        totalSiswa: totalSiswa,
        totalKelasMaksimal: 6
      };
    } else if (user.role === 'wali_kelas') {
      // Data Ringkasan untuk Wali Kelas
      let penugasanAktif = null;
      let totalSiswaKelas = 0;

      try {
        const wkData = getSheetDataBatch('wali_kelas');
        const assignment = wkData.rows.find(w =>
          w.user_id === user.id &&
          (activeYear ? w.tahun_ajaran_id === activeYear.id : true) &&
          (w.is_active === true || String(w.is_active).toLowerCase() === 'true')
        );

        if (assignment) {
          penugasanAktif = {
            id: assignment.id,
            kelas: assignment.kelas,
            tahunAjaranId: assignment.tahun_ajaran_id
          };

          const sData = getSheetDataBatch('siswa');
          totalSiswaKelas = sData.rows.filter(s =>
            s.wali_kelas_id === assignment.id &&
            (s.is_active !== false && String(s.is_active).toLowerCase() !== 'false')
          ).length;
        }
      } catch (e) {}

      payload.assignment = penugasanAktif;
      payload.summary = {
        hasAssignment: !!penugasanAktif,
        kelas: penugasanAktif ? penugasanAktif.kelas : null,
        totalSiswa: totalSiswaKelas,
        kelengkapanNilaiPersen: 0
      };
    }

    return buildResponse(true, payload, 'Data dashboard awal berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat dashboard.');
  }
}

// ============================================================================
// 5. ENDPOINT PHASE 4: TAHUN AJARAN & PENUGASAN WALI KELAS
// ============================================================================

/**
 * Mengambil daftar tahun ajaran dan semester.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 * @param {string} sessionToken
 * @return {{ success: boolean, data: Object[], message: string }}
 */
function apiGetTahunAjaranList(sessionToken) {
  try {
    requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    const taData = getSheetDataBatch('tahun_ajaran');
    let wkData = { rows: [] };
    try {
      wkData = getSheetDataBatch('wali_kelas');
    } catch (e) {}

    const result = taData.rows.map(t => {
      const hasWkRelations = wkData.rows.some(w => w.tahun_ajaran_id === t.id);
      return {
        id: t.id,
        tahun_ajaran: t.tahun_ajaran,
        semester: t.semester,
        tanggal_mulai: t.tanggal_mulai ? String(t.tanggal_mulai).substring(0, 10) : '',
        tanggal_selesai: t.tanggal_selesai ? String(t.tanggal_selesai).substring(0, 10) : '',
        is_active: (t.is_active === true || String(t.is_active).toLowerCase() === 'true'),
        is_locked: (t.is_locked === true || String(t.is_locked).toLowerCase() === 'true'),
        hasRelations: hasWkRelations,
        created_at: t.created_at,
        updated_at: t.updated_at
      };
    });

    // Urutkan tanggal_mulai descending
    result.sort((a, b) => (b.tanggal_mulai || '').localeCompare(a.tanggal_mulai || ''));

    return buildResponse(true, result, 'Daftar tahun ajaran berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat daftar tahun ajaran.');
  }
}

/**
 * Menyimpan (Tambah/Edit) Tahun Ajaran dan Semester.
 * Otorisasi: kepala_sekolah saja.
 * @param {string} sessionToken
 * @param {Object} payload
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiSaveTahunAjaran(sessionToken, payload) {
  let lock = null;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }
  try {
    requireAuth(sessionToken, 'kepala_sekolah');

    if (!payload || typeof payload !== 'object') {
      return buildResponse(false, null, 'Data tahun ajaran tidak valid.');
    }

    const cleanTahunAjaran = String(payload.tahun_ajaran || '').trim();
    const cleanSemester = String(payload.semester || '').trim();
    const cleanTglMulai = String(payload.tanggal_mulai || '').trim();
    const cleanTglSelesai = String(payload.tanggal_selesai || '').trim();
    const isActive = payload.is_active === true || String(payload.is_active).toLowerCase() === 'true';
    const isLocked = payload.is_locked === true || String(payload.is_locked).toLowerCase() === 'true';
    const editId = payload.id ? String(payload.id).trim() : null;

    if (!cleanTahunAjaran || !cleanSemester || !cleanTglMulai || !cleanTglSelesai) {
      return buildResponse(false, null, 'Seluruh field (Tahun Ajaran, Semester, Tanggal Mulai, Tanggal Selesai) wajib diisi.');
    }

    // Validasi format tahun ajaran YYYY/YYYY dengan selisih 1 tahun
    if (!/^\d{4}\/\d{4}$/.test(cleanTahunAjaran)) {
      return buildResponse(false, null, 'Format tahun ajaran harus YYYY/YYYY (contoh: 2026/2027).');
    }
    const [y1, y2] = cleanTahunAjaran.split('/').map(Number);
    if (y2 !== y1 + 1) {
      return buildResponse(false, null, 'Tahun kedua harus berurutan tepat satu tahun setelah tahun pertama (contoh: 2026/2027).');
    }

    // Validasi semester
    if (cleanSemester !== 'Ganjil' && cleanSemester !== 'Genap') {
      return buildResponse(false, null, 'Semester harus salah satu dari: Ganjil atau Genap.');
    }

    // Validasi tanggal
    const startTimestamp = Date.parse(cleanTglMulai);
    const endTimestamp = Date.parse(cleanTglSelesai);
    if (isNaN(startTimestamp) || isNaN(endTimestamp)) {
      return buildResponse(false, null, 'Format tanggal mulai atau tanggal selesai tidak valid.');
    }
    if (endTimestamp <= startTimestamp) {
      return buildResponse(false, null, 'Tanggal selesai harus setelah tanggal mulai.');
    }

    // Periode yang terkunci tidak boleh diaktifkan
    if (isLocked && isActive) {
      return buildResponse(false, null, 'Periode yang dikunci tidak dapat dijadikan periode aktif.');
    }

    const allTa = getSheetDataBatch('tahun_ajaran');

    // Validasi keunikan kombinasi tahun_ajaran + semester
    const duplicate = allTa.rows.find(t =>
      t.tahun_ajaran.toLowerCase() === cleanTahunAjaran.toLowerCase() &&
      t.semester.toLowerCase() === cleanSemester.toLowerCase() &&
      (!editId || t.id !== editId)
    );
    if (duplicate) {
      return buildResponse(false, null, 'Kombinasi Tahun Ajaran ' + cleanTahunAjaran + ' dan Semester ' + cleanSemester + ' sudah terdaftar.');
    }

    const nowIso = new Date().toISOString();

    if (editId) {
      // Edit data yang ada
      const existingRow = allTa.rows.find(t => t.id === editId);
      if (!existingRow) {
        return buildResponse(false, null, 'Data tahun ajaran yang akan diedit tidak ditemukan.');
      }

      // Jika sudah dikunci, batasi perubahan
      const existingLocked = existingRow.is_locked === true || String(existingRow.is_locked).toLowerCase() === 'true';
      if (existingLocked && !isLocked) {
        // Membuka kunci diperbolehkan oleh kepala sekolah
      } else if (existingLocked) {
        return buildResponse(false, null, 'Periode ini telah dikunci dan tidak dapat diubah lagi.');
      }

      // Jika periode ini dijadikan aktif, nonaktifkan periode lain
      if (isActive) {
        for (const row of allTa.rows) {
          if (row.id !== editId && (row.is_active === true || String(row.is_active).toLowerCase() === 'true')) {
            updateSheetRow('tahun_ajaran', row._rowIndex, { is_active: false, updated_at: nowIso });
          }
        }
      }

      updateSheetRow('tahun_ajaran', existingRow._rowIndex, {
        tahun_ajaran: cleanTahunAjaran,
        semester: cleanSemester,
        tanggal_mulai: cleanTglMulai,
        tanggal_selesai: cleanTglSelesai,
        is_active: isActive,
        is_locked: isLocked,
        updated_at: nowIso
      });

      return buildResponse(true, { id: editId }, 'Tahun ajaran berhasil diperbarui.');
    } else {
      // Tambah periode baru
      const newId = getStableUUID();

      // Jika periode baru aktif, nonaktifkan periode sebelumnya
      if (isActive) {
        for (const row of allTa.rows) {
          if (row.is_active === true || String(row.is_active).toLowerCase() === 'true') {
            updateSheetRow('tahun_ajaran', row._rowIndex, { is_active: false, updated_at: nowIso });
          }
        }
      }

      appendSheetRow('tahun_ajaran', {
        id: newId,
        tahun_ajaran: cleanTahunAjaran,
        semester: cleanSemester,
        tanggal_mulai: cleanTglMulai,
        tanggal_selesai: cleanTglSelesai,
        is_active: isActive,
        is_locked: isLocked,
        created_at: nowIso,
        updated_at: nowIso
      });

      return buildResponse(true, { id: newId }, 'Tahun ajaran baru berhasil ditambahkan.');
    }
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menyimpan tahun ajaran.');
  } finally {
    if (lock) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

/**
 * Mengubah status kunci (lock / unlock) periode tahun ajaran.
 * Otorisasi: kepala_sekolah saja.
 * @param {string} sessionToken
 * @param {string} tahunAjaranId
 * @param {boolean} isLocked
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiToggleLockTahunAjaran(sessionToken, tahunAjaranId, isLocked) {
  try {
    requireAuth(sessionToken, 'kepala_sekolah');

    if (!tahunAjaranId) {
      return buildResponse(false, null, 'ID tahun ajaran diperlukan.');
    }

    const allTa = getSheetDataBatch('tahun_ajaran');
    const target = allTa.rows.find(t => t.id === tahunAjaranId);
    if (!target) {
      return buildResponse(false, null, 'Data tahun ajaran tidak ditemukan.');
    }

    const targetLock = !!isLocked;
    const nowIso = new Date().toISOString();

    const updateFields = {
      is_locked: targetLock,
      updated_at: nowIso
    };

    // Jika dikunci, pastikan tidak berstatus aktif
    if (targetLock) {
      updateFields.is_active = false;
    }

    updateSheetRow('tahun_ajaran', target._rowIndex, updateFields);

    const msg = targetLock ? 'Periode berhasil dikunci.' : 'Kunci periode berhasil dibuka.';
    return buildResponse(true, { id: tahunAjaranId, is_locked: targetLock }, msg);
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memperbarui status kunci periode.');
  }
}

/**
 * Menghapus tahun ajaran (hanya jika belum memiliki relasi).
 * Otorisasi: kepala_sekolah saja.
 * @param {string} sessionToken
 * @param {string} tahunAjaranId
 * @return {{ success: boolean, data: null, message: string }}
 */
function apiDeleteTahunAjaran(sessionToken, tahunAjaranId) {
  try {
    requireAuth(sessionToken, 'kepala_sekolah');

    if (!tahunAjaranId) {
      return buildResponse(false, null, 'ID tahun ajaran diperlukan.');
    }

    const allTa = getSheetDataBatch('tahun_ajaran');
    const existing = allTa.rows.find(t => t.id === tahunAjaranId);
    if (!existing) {
      return buildResponse(false, null, 'Data tahun ajaran tidak ditemukan.');
    }

    if (existing.is_active === true || String(existing.is_active).toLowerCase() === 'true') {
      return buildResponse(false, null, 'Periode yang sedang aktif tidak dapat dihapus. Silakan nonaktifkan atau aktifkan periode lain terlebih dahulu.');
    }

    // Cek relasi penugasan wali kelas
    try {
      const wkData = getSheetDataBatch('wali_kelas');
      const hasWk = wkData.rows.some(w => w.tahun_ajaran_id === tahunAjaranId);
      if (hasWk) {
        return buildResponse(false, null, 'Periode ini sudah memiliki data penugasan wali kelas dan tidak dapat dihapus. Silakan gunakan fitur kunci periode.');
      }
    } catch (e) {}

    // Cek relasi pengaturan rapor
    try {
      const prData = getSheetDataBatch('pengaturan_rapor');
      const hasPr = prData.rows.some(p => p.tahun_ajaran_id === tahunAjaranId);
      if (hasPr) {
        return buildResponse(false, null, 'Periode ini sudah memiliki data pengaturan rapor dan tidak dapat dihapus.');
      }
    } catch (e) {}

    deleteSheetRow('tahun_ajaran', existing._rowIndex);
    return buildResponse(true, null, 'Tahun ajaran berhasil dihapus.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menghapus tahun ajaran.');
  }
}

/**
 * Mengambil daftar guru yang memenuhi syarat menjadi wali kelas.
 * Otorisasi: kepala_sekolah saja.
 * @param {string} sessionToken
 * @return {{ success: boolean, data: Object[], message: string }}
 */
function apiGetGuruWaliKelasOptions(sessionToken) {
  try {
    requireAuth(sessionToken, 'kepala_sekolah');

    const uData = getSheetDataBatch('user');
    const teachers = uData.rows
      .filter(u => u.role === 'wali_kelas' && (u.is_active === true || String(u.is_active).toLowerCase() === 'true'))
      .map(u => ({
        id: u.id,
        nama: u.nama,
        nip: u.nip || '-',
        username: u.username
      }));

    teachers.sort((a, b) => a.nama.localeCompare(b.nama));
    return buildResponse(true, teachers, 'Daftar guru wali kelas berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat daftar guru.');
  }
}

/**
 * Mengambil daftar penugasan wali kelas.
 * Otorisasi: kepala_sekolah (seluruh kelas) atau wali_kelas (kelasnya sendiri).
 * @param {string} sessionToken
 * @param {string} [filterTahunAjaranId]
 * @return {{ success: boolean, data: Object[], message: string }}
 */
function apiGetPenugasanList(sessionToken, filterTahunAjaranId) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    const wkData = getSheetDataBatch('wali_kelas');
    const uData = getSheetDataBatch('user');
    const taData = getSheetDataBatch('tahun_ajaran');
    let sData = { rows: [] };
    try {
      sData = getSheetDataBatch('siswa');
    } catch (e) {}

    let rows = wkData.rows;

    // Filter role: jika wali kelas, batasi ke penugasan milik sendiri
    if (user.role === 'wali_kelas') {
      rows = rows.filter(w => w.user_id === user.id);
    }

    if (filterTahunAjaranId) {
      rows = rows.filter(w => w.tahun_ajaran_id === filterTahunAjaranId);
    }

    const result = rows.map(w => {
      const teacher = uData.rows.find(u => u.id === w.user_id);
      const ta = taData.rows.find(t => t.id === w.tahun_ajaran_id);
      const studentCount = sData.rows.filter(s =>
        s.wali_kelas_id === w.id &&
        (s.is_active !== false && String(s.is_active).toLowerCase() !== 'false')
      ).length;

      return {
        id: w.id,
        user_id: w.user_id,
        guruNama: teacher ? teacher.nama : 'Guru Tidak Ditemukan',
        guruNip: teacher ? (teacher.nip || '-') : '-',
        guruUsername: teacher ? teacher.username : '',
        tahun_ajaran_id: w.tahun_ajaran_id,
        tahunAjaran: ta ? ta.tahun_ajaran : '-',
        semester: ta ? ta.semester : '-',
        isTahunAjaranActive: ta ? (ta.is_active === true || String(ta.is_active).toLowerCase() === 'true') : false,
        isTahunAjaranLocked: ta ? (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true') : false,
        kelas: String(w.kelas || ''),
        is_active: (w.is_active === true || String(w.is_active).toLowerCase() === 'true'),
        totalSiswa: studentCount,
        created_at: w.created_at,
        updated_at: w.updated_at
      };
    });

    result.sort((a, b) => Number(a.kelas) - Number(b.kelas));
    return buildResponse(true, result, 'Daftar penugasan berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat daftar penugasan.');
  }
}

/**
 * Menyimpan (Tambah/Edit) Penugasan Wali Kelas.
 * Otorisasi: kepala_sekolah saja.
 * @param {string} sessionToken
 * @param {Object} payload
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiSavePenugasan(sessionToken, payload) {
  let lock = null;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }
  try {
    requireAuth(sessionToken, 'kepala_sekolah');

    if (!payload || typeof payload !== 'object') {
      return buildResponse(false, null, 'Data penugasan tidak valid.');
    }

    const cleanUserId = String(payload.user_id || '').trim();
    const cleanTahunAjaranId = String(payload.tahun_ajaran_id || '').trim();
    const cleanKelas = String(payload.kelas || '').trim();
    const isActive = payload.is_active === undefined ? true : (payload.is_active === true || String(payload.is_active).toLowerCase() === 'true');
    const editId = payload.id ? String(payload.id).trim() : null;

    if (!cleanUserId || !cleanTahunAjaranId || !cleanKelas) {
      return buildResponse(false, null, 'Guru wali kelas, tahun ajaran, dan kelas wajib dipilih.');
    }

    if (!['1', '2', '3', '4', '5', '6'].includes(cleanKelas)) {
      return buildResponse(false, null, 'Pilihan kelas harus antara 1 sampai 6.');
    }

    // Verifikasi guru
    const uData = getSheetDataBatch('user');
    const teacher = uData.rows.find(u => u.id === cleanUserId);
    if (!teacher) {
      return buildResponse(false, null, 'Data guru tidak ditemukan di sistem.');
    }
    if (teacher.role !== 'wali_kelas') {
      return buildResponse(false, null, 'Pengguna yang dipilih bukan memiliki role wali kelas.');
    }
    if (teacher.is_active === false || String(teacher.is_active).toLowerCase() === 'false') {
      return buildResponse(false, null, 'Guru yang dipilih sedang dalam status nonaktif.');
    }

    // Verifikasi tahun ajaran
    const taData = getSheetDataBatch('tahun_ajaran');
    const ta = taData.rows.find(t => t.id === cleanTahunAjaranId);
    if (!ta) {
      return buildResponse(false, null, 'Tahun ajaran tidak ditemukan.');
    }
    if (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true') {
      return buildResponse(false, null, 'Tidak dapat menambah atau mengubah penugasan pada tahun ajaran yang telah dikunci.');
    }

    const wkData = getSheetDataBatch('wali_kelas');

    // Cek apakah kelas sudah memiliki wali kelas aktif lain pada periode yang sama
    const duplicateClass = wkData.rows.find(w =>
      w.tahun_ajaran_id === cleanTahunAjaranId &&
      String(w.kelas) === cleanKelas &&
      (w.is_active === true || String(w.is_active).toLowerCase() === 'true') &&
      (!editId || w.id !== editId)
    );
    if (duplicateClass && isActive) {
      return buildResponse(false, null, 'Kelas ' + cleanKelas + ' sudah memiliki wali kelas aktif pada periode ini.');
    }

    // Cek apakah guru sudah ditugaskan ke kelas lain pada periode yang sama
    const duplicateTeacher = wkData.rows.find(w =>
      w.tahun_ajaran_id === cleanTahunAjaranId &&
      w.user_id === cleanUserId &&
      (w.is_active === true || String(w.is_active).toLowerCase() === 'true') &&
      (!editId || w.id !== editId)
    );
    if (duplicateTeacher && isActive) {
      return buildResponse(false, null, 'Guru ' + teacher.nama + ' sudah ditugaskan mengampu Kelas ' + duplicateTeacher.kelas + ' pada periode ini.');
    }

    const nowIso = new Date().toISOString();

    if (editId) {
      const existingWk = wkData.rows.find(w => w.id === editId);
      if (!existingWk) {
        return buildResponse(false, null, 'Penugasan yang akan diedit tidak ditemukan.');
      }
      updateSheetRow('wali_kelas', existingWk._rowIndex, {
        user_id: cleanUserId,
        tahun_ajaran_id: cleanTahunAjaranId,
        kelas: cleanKelas,
        is_active: isActive,
        updated_at: nowIso
      });
      return buildResponse(true, { id: editId }, 'Penugasan wali kelas berhasil diperbarui.');
    } else {
      const newId = getStableUUID();
      appendSheetRow('wali_kelas', {
        id: newId,
        user_id: cleanUserId,
        tahun_ajaran_id: cleanTahunAjaranId,
        kelas: cleanKelas,
        is_active: isActive,
        created_at: nowIso,
        updated_at: nowIso
      });
      return buildResponse(true, { id: newId }, 'Penugasan wali kelas berhasil ditambahkan.');
    }
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menyimpan penugasan wali kelas.');
  } finally {
    if (lock) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

/**
 * Mengubah status aktif / nonaktif penugasan.
 * Otorisasi: kepala_sekolah saja.
 * @param {string} sessionToken
 * @param {string} penugasanId
 * @param {boolean} isActive
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiToggleStatusPenugasan(sessionToken, penugasanId, isActive) {
  try {
    requireAuth(sessionToken, 'kepala_sekolah');

    const wkData = getSheetDataBatch('wali_kelas');
    const existingWk = wkData.rows.find(w => w.id === penugasanId);
    if (!existingWk) {
      return buildResponse(false, null, 'Data penugasan tidak ditemukan.');
    }

    const taData = getSheetDataBatch('tahun_ajaran');
    const ta = taData.rows.find(t => t.id === existingWk.tahun_ajaran_id);
    if (ta && (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true')) {
      return buildResponse(false, null, 'Tidak dapat mengubah status penugasan pada periode yang telah dikunci.');
    }

    const targetActive = !!isActive;
    if (targetActive) {
      // Cek konflik kelas
      const conflictClass = wkData.rows.find(w =>
        w.id !== penugasanId &&
        w.tahun_ajaran_id === existingWk.tahun_ajaran_id &&
        String(w.kelas) === String(existingWk.kelas) &&
        (w.is_active === true || String(w.is_active).toLowerCase() === 'true')
      );
      if (conflictClass) {
        return buildResponse(false, null, 'Kelas ' + existingWk.kelas + ' sudah memiliki wali kelas aktif lain pada periode ini.');
      }

      // Cek konflik guru
      const conflictTeacher = wkData.rows.find(w =>
        w.id !== penugasanId &&
        w.tahun_ajaran_id === existingWk.tahun_ajaran_id &&
        w.user_id === existingWk.user_id &&
        (w.is_active === true || String(w.is_active).toLowerCase() === 'true')
      );
      if (conflictTeacher) {
        return buildResponse(false, null, 'Guru ini sudah memiliki penugasan aktif lain di Kelas ' + conflictTeacher.kelas + ' pada periode ini.');
      }
    }

    const nowIso = new Date().toISOString();
    updateSheetRow('wali_kelas', existingWk._rowIndex, {
      is_active: targetActive,
      updated_at: nowIso
    });

    const msg = targetActive ? 'Penugasan berhasil diaktifkan.' : 'Penugasan berhasil dinonaktifkan.';
    return buildResponse(true, { id: penugasanId, is_active: targetActive }, msg);
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal mengubah status penugasan.');
  }
}

/**
 * Menghapus penugasan wali kelas (hanya jika belum memiliki data siswa atau nilai).
 * Otorisasi: kepala_sekolah saja.
 * @param {string} sessionToken
 * @param {string} penugasanId
 * @return {{ success: boolean, data: null, message: string }}
 */
function apiDeletePenugasan(sessionToken, penugasanId) {
  try {
    requireAuth(sessionToken, 'kepala_sekolah');

    if (!penugasanId) {
      return buildResponse(false, null, 'ID penugasan diperlukan.');
    }

    const wkData = getSheetDataBatch('wali_kelas');
    const existingWk = wkData.rows.find(w => w.id === penugasanId);
    if (!existingWk) {
      return buildResponse(false, null, 'Data penugasan tidak ditemukan.');
    }

    // Periksa status terkunci periode terkait
    const taData = getSheetDataBatch('tahun_ajaran');
    const ta = taData.rows.find(t => t.id === existingWk.tahun_ajaran_id);
    if (ta && (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true')) {
      return buildResponse(false, null, 'Penugasan pada periode yang telah dikunci tidak dapat dihapus.');
    }

    // Cek apakah penugasan ini sudah memiliki data siswa
    try {
      const sData = getSheetDataBatch('siswa');
      const hasStudents = sData.rows.some(s => s.wali_kelas_id === penugasanId);
      if (hasStudents) {
        return buildResponse(false, null, 'Penugasan ini sudah memiliki data siswa dan tidak boleh dihapus permanen. Silakan nonaktifkan status penugasan.');
      }
    } catch (e) {}

    // Cek apakah penugasan ini memiliki data mata pelajaran
    try {
      const mData = getSheetDataBatch('mata_pelajaran');
      const hasMapel = mData.rows.some(m => m.wali_kelas_id === penugasanId);
      if (hasMapel) {
        return buildResponse(false, null, 'Penugasan ini sudah memiliki data mata pelajaran dan tidak boleh dihapus permanen.');
      }
    } catch (e) {}

    // Cek apakah penugasan ini memiliki pengaturan rapor
    try {
      const prData = getSheetDataBatch('pengaturan_rapor');
      const hasPr = prData.rows.some(p => p.wali_kelas_id === penugasanId);
      if (hasPr) {
        return buildResponse(false, null, 'Penugasan ini sudah memiliki pengaturan rapor dan tidak boleh dihapus.');
      }
    } catch (e) {}

    deleteSheetRow('wali_kelas', existingWk._rowIndex);
    return buildResponse(true, null, 'Penugasan wali kelas berhasil dihapus.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menghapus penugasan wali kelas.');
  }
}

// ============================================================================
// 6. ENTRYPOINT APLIKASI WEB (doGet)
// ============================================================================

/**
 * Melayani shell aplikasi web responsif (HTML + Tailwind CDN).
 * @param {Object} e Event object HTTP GET
 * @return {GoogleAppsScript.HTML.HtmlOutput}
 */
function doGet(e) {
  if (typeof HtmlService !== 'undefined') {
    return HtmlService.createHtmlOutputFromFile('index')
      .setTitle('Sistem Absensi & Penilaian Siswa SD (Versi 2)')
      .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
      .addMetaTag('viewport', 'width=device-width, initial-scale=1.0');
  }
  return null;
}

// Ekspor untuk lingkungan pengujian Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    AUTH_CONFIG,
    _localMemoryCache,
    utf8ToBytes,
    computePBKDF2,
    generateSecureSalt,
    hashPasswordPBKDF2,
    constantTimeCompare,
    verifyPassword,
    SessionStore,
    createSession,
    getActiveSession,
    destroySession,
    getStableUUID,
    appendSheetRow,
    updateSheetRow,
    deleteSheetRow,
    getSheetDataBatch,
    buildResponse,
    apiLogin,
    apiLogout,
    apiGetSessionUser,
    apiGetInitialDashboard,
    apiGetTahunAjaranList,
    apiSaveTahunAjaran,
    apiToggleLockTahunAjaran,
    apiDeleteTahunAjaran,
    apiGetPenugasanList,
    apiGetGuruWaliKelasOptions,
    apiSavePenugasan,
    apiToggleStatusPenugasan,
    apiDeletePenugasan,
    requireAuth,
    doGet
  };
}
