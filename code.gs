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
      namaSekolah: '',
      namaKepalaSekolah: '',
      nipKepalaSekolah: '',
      logoSekolah: ''
    };
    try {
      const pengData = getSheetDataBatch('pengaturan');
      if (pengData.rows.length > 0) {
        const row = pengData.rows[0];
        schoolProfile.namaSekolah = row.nama_sekolah || '';
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
      let mData = null;
      let nData = { rows: [] };
      let skData = { rows: [] };
      let rkData = { rows: [] };

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

      try { mData = getSheetDataBatch('mata_pelajaran'); } catch (e) {}
      try { nData = getSheetDataBatch('nilai_mata_pelajaran'); } catch (e) {}
      try { skData = getSheetDataBatch('nilai_sikap'); } catch (e) {}
      try { rkData = getSheetDataBatch('rekap_kehadiran'); } catch (e) {}

      // Breakdown 6 kelas (Kelas 1 - Kelas 6) untuk Kepala Sekolah
      const kelasOverview = [];
      const wkRows = (wkData && wkData.rows) ? wkData.rows : [];
      const uRows = (uData && uData.rows) ? uData.rows : [];
      const sRows = (sData && sData.rows) ? sData.rows : [];
      const mRows = (mData && mData.rows) ? mData.rows : [];

      let kelasSiapRapor = 0;
      let kelasBelumSiap = 0;

      for (let k = 1; k <= 6; k++) {
        const kStr = String(k);
        let detail = null;
        let mapelCount = 0;
        let nilaiPct = 0;
        let sikapPct = 0;
        let kehadiranPct = 0;
        let statusLabel = 'Belum Ada Wali Kelas';
        let isRaporReady = false;
        let hasWarning = false;
        let warningMessage = '';

        if (activeYear) {
          const matchWk = wkRows.find(w =>
            String(w.kelas) === kStr &&
            w.tahun_ajaran_id === activeYear.id &&
            (w.is_active === true || String(w.is_active).toLowerCase() === 'true')
          );

          if (matchWk) {
            const teacher = uRows.find(u => u.id === matchWk.user_id);
            const activeSiswaClass = sRows.filter(s =>
              s.wali_kelas_id === matchWk.id &&
              (s.is_active !== false && String(s.is_active).toLowerCase() !== 'false')
            );
            const activeMapelsClass = mRows.filter(m =>
              m.wali_kelas_id === matchWk.id &&
              (m.is_active === true || String(m.is_active).toLowerCase() === 'true')
            );
            mapelCount = activeMapelsClass.length;

            const totalExpected = activeSiswaClass.length * activeMapelsClass.length;
            let countCompleteGrades = 0;
            activeSiswaClass.forEach(s => {
              activeMapelsClass.forEach(m => {
                const grade = nData.rows.find(n => n.siswa_id === s.id && n.mata_pelajaran_id === m.id);
                if (grade && (grade.is_complete === true || String(grade.is_complete).toLowerCase() === 'true')) {
                  countCompleteGrades++;
                }
              });
            });

            const countSikap = activeSiswaClass.filter(s => skData.rows.some(sk => sk.siswa_id === s.id && sk.predikat && String(sk.predikat).trim() !== '')).length;
            const countKehadiran = activeSiswaClass.filter(s => rkData.rows.some(rk => rk.siswa_id === s.id && (rk.jumlah_hadir !== '' || rk.jumlah_sakit !== '' || rk.jumlah_izin !== '' || rk.jumlah_alpha !== ''))).length;

            nilaiPct = totalExpected > 0 ? Math.round((countCompleteGrades / totalExpected) * 100) : 0;
            sikapPct = activeSiswaClass.length > 0 ? Math.round((countSikap / activeSiswaClass.length) * 100) : 0;
            kehadiranPct = activeSiswaClass.length > 0 ? Math.round((countKehadiran / activeSiswaClass.length) * 100) : 0;

            if (nilaiPct === 100 && sikapPct === 100 && kehadiranPct === 100 && activeSiswaClass.length > 0 && mapelCount > 0) {
              statusLabel = 'Lengkap';
              isRaporReady = true;
              kelasSiapRapor++;
            } else if (nilaiPct > 0 || sikapPct > 0 || kehadiranPct > 0) {
              statusLabel = 'Sebagian';
              kelasBelumSiap++;
            } else {
              statusLabel = 'Belum Mulai';
              kelasBelumSiap++;
            }

            if (mapelCount === 0) {
              hasWarning = true;
              warningMessage = 'Mata pelajaran belum ditambahkan';
            }

            detail = {
              penugasanId: matchWk.id,
              guruNama: teacher ? teacher.nama : 'Guru tidak dikenal',
              guruNip: teacher ? (teacher.nip || '-') : '-',
              totalSiswa: activeSiswaClass.length
            };
          } else {
            hasWarning = true;
            warningMessage = 'Wali kelas belum ditugaskan';
          }
        } else {
          hasWarning = true;
          warningMessage = 'Tahun ajaran belum diaktifkan';
        }

        kelasOverview.push({
          kelas: kStr,
          isAssigned: !!detail,
          guruNama: detail ? detail.guruNama : 'Belum Ditugaskan',
          guruNip: detail ? detail.guruNip : '-',
          totalSiswa: detail ? detail.totalSiswa : 0,
          mapelCount: mapelCount,
          nilaiPercent: nilaiPct,
          sikapPercent: sikapPct,
          kehadiranPercent: kehadiranPct,
          statusLabel: statusLabel,
          isRaporReady: isRaporReady,
          hasWarning: hasWarning,
          warningMessage: warningMessage,
          details: detail
        });
      }

      payload.kelasOverview = kelasOverview;
      payload.summary = {
        totalGuru: totalGuru,
        totalKelasDitugaskan: totalKelasDitugaskan,
        totalSiswa: totalSiswa,
        totalKelasMaksimal: 6,
        kelasSiapRapor: kelasSiapRapor,
        kelasBelumSiap: kelasBelumSiap
      };
    } else if (user.role === 'wali_kelas') {
      // Data Ringkasan untuk Wali Kelas
      let penugasanAktif = null;

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
          let mData = { rows: [] };
          let nData = { rows: [] };
          let skData = { rows: [] };
          let rkData = { rows: [] };
          let prData = { rows: [] };

          try { mData = getSheetDataBatch('mata_pelajaran'); } catch (e) {}
          try { nData = getSheetDataBatch('nilai_mata_pelajaran'); } catch (e) {}
          try { skData = getSheetDataBatch('nilai_sikap'); } catch (e) {}
          try { rkData = getSheetDataBatch('rekap_kehadiran'); } catch (e) {}
          try { prData = getSheetDataBatch('pengaturan_rapor'); } catch (e) {}

          const activeSiswa = sData.rows.filter(s =>
            s.wali_kelas_id === assignment.id &&
            (s.is_active !== false && String(s.is_active).toLowerCase() !== 'false')
          );
          const activeMapels = mData.rows.filter(m =>
            m.wali_kelas_id === assignment.id &&
            (m.is_active === true || String(m.is_active).toLowerCase() === 'true')
          );

          const totalExpected = activeSiswa.length * activeMapels.length;
          let countCompleteGrades = 0;
          activeSiswa.forEach(s => {
            activeMapels.forEach(m => {
              const grade = nData.rows.find(n => n.siswa_id === s.id && n.mata_pelajaran_id === m.id);
              if (grade && (grade.is_complete === true || String(grade.is_complete).toLowerCase() === 'true')) {
                countCompleteGrades++;
              }
            });
          });

          const countSikap = activeSiswa.filter(s => skData.rows.some(sk => sk.siswa_id === s.id && sk.predikat && String(sk.predikat).trim() !== '')).length;
          const countKehadiran = activeSiswa.filter(s => rkData.rows.some(rk => rk.siswa_id === s.id && (rk.jumlah_hadir !== '' || rk.jumlah_sakit !== '' || rk.jumlah_izin !== '' || rk.jumlah_alpha !== ''))).length;

          const nilaiPct = totalExpected > 0 ? Math.round((countCompleteGrades / totalExpected) * 100) : 0;
          const sikapPct = activeSiswa.length > 0 ? Math.round((countSikap / activeSiswa.length) * 100) : 0;
          const kehadiranPct = activeSiswa.length > 0 ? Math.round((countKehadiran / activeSiswa.length) * 100) : 0;
          const isRaporReady = (nilaiPct === 100 && sikapPct === 100 && kehadiranPct === 100 && activeSiswa.length > 0 && activeMapels.length > 0);

          // Hitung ranking kompetisi untuk top 3 ranking dashboard
          const rankingRes = calculateClassRanking(assignment.id, { sData, mData, nData, prData, wkData });
          const topRanking = (rankingRes.rankedStudents || []).slice(0, 3).map(st => ({
            rank: st.rank,
            nama: st.nama,
            no_absen: st.no_absen,
            rataNilai: st.avgScore !== null ? st.avgScore : '-',
            isComplete: st.isStudentComplete,
            rankingStatus: rankingRes.rankingStatus
          }));

          payload.assignment = penugasanAktif;
          payload.summary = {
            hasAssignment: true,
            kelas: penugasanAktif.kelas,
            totalSiswa: activeSiswa.length,
            totalMapel: activeMapels.length,
            kelengkapanNilaiPersen: nilaiPct,
            kelengkapanSikapPersen: sikapPct,
            kelengkapanKehadiranPersen: kehadiranPct,
            statusRapor: isRaporReady ? 'Siap Diterbitkan' : 'Belum Lengkap',
            isRankingFinal: rankingRes.isClassAllComplete,
            rankingStatus: rankingRes.rankingStatus,
            topRanking: topRanking
          };
        } else {
          payload.assignment = null;
          payload.summary = {
            hasAssignment: false,
            kelas: null,
            totalSiswa: 0,
            totalMapel: 0,
            kelengkapanNilaiPersen: 0,
            kelengkapanSikapPersen: 0,
            kelengkapanKehadiranPersen: 0,
            statusRapor: 'Belum Ada Penugasan',
            isRankingFinal: false,
            rankingStatus: 'Sementara',
            topRanking: []
          };
        }
      } catch (e) {
        payload.assignment = penugasanAktif;
        payload.summary = {
          hasAssignment: !!penugasanAktif,
          kelas: penugasanAktif ? penugasanAktif.kelas : null,
          totalSiswa: 0,
          kelengkapanNilaiPersen: 0,
          statusRapor: 'Belum Lengkap',
          topRanking: []
        };
      }
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
// 6. ENDPOINT PHASE 5: PENGELOLAAN USER, SISWA, DAN MATA PELAJARAN
// ============================================================================

/**
 * Mengambil daftar user untuk pengelolaan akun oleh Kepala Sekolah.
 * Otorisasi: kepala_sekolah saja.
 * Catatan Keamanan: password_hash dan password_salt TIDAK PERNAH dikembalikan ke frontend.
 *
 * @param {string} sessionToken
 * @param {string} [searchQuery]
 * @return {{ success: boolean, data: Object[], message: string }}
 */
function apiGetUsersList(sessionToken, searchQuery) {
  try {
    requireAuth(sessionToken, 'kepala_sekolah');

    const uData = getSheetDataBatch('user');
    let wkData = { rows: [] };
    try {
      wkData = getSheetDataBatch('wali_kelas');
    } catch (e) {}

    const cleanQuery = searchQuery ? String(searchQuery).trim().toLowerCase() : '';

    let users = uData.rows.map(u => {
      const hasPenugasan = wkData.rows.some(w => w.user_id === u.id);
      return {
        id: u.id,
        nama: u.nama,
        nip: u.nip || '-',
        username: u.username,
        role: u.role,
        foto: u.foto || '',
        terakhir_login: u.terakhir_login || '',
        is_active: (u.is_active === true || String(u.is_active).toLowerCase() === 'true'),
        hasPenugasan: hasPenugasan,
        created_at: u.created_at,
        updated_at: u.updated_at
      };
    });

    if (cleanQuery) {
      users = users.filter(u =>
        u.nama.toLowerCase().includes(cleanQuery) ||
        u.username.toLowerCase().includes(cleanQuery) ||
        (u.nip && u.nip.toLowerCase().includes(cleanQuery))
      );
    }

    // Urutkan: kepala sekolah di atas, lalu urutkan nama secara alfabetis
    users.sort((a, b) => {
      if (a.role === 'kepala_sekolah' && b.role !== 'kepala_sekolah') return -1;
      if (b.role === 'kepala_sekolah' && a.role !== 'kepala_sekolah') return 1;
      return a.nama.localeCompare(b.nama);
    });

    return buildResponse(true, users, 'Daftar pengguna berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat daftar pengguna.');
  }
}

/**
 * Menyimpan (Tambah/Edit) User oleh Kepala Sekolah.
 * Otorisasi: kepala_sekolah saja.
 * Password di-hash menggunakan PBKDF2-HMAC-SHA256 sebelum disimpan ke sheet.
 *
 * @param {string} sessionToken
 * @param {Object} payload
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiSaveUser(sessionToken, payload) {
  let lock = null;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }
  try {
    const adminUser = requireAuth(sessionToken, 'kepala_sekolah');

    if (!payload || typeof payload !== 'object') {
      return buildResponse(false, null, 'Data pengguna tidak valid.');
    }

    const editId = payload.id ? String(payload.id).trim() : null;
    const cleanNama = String(payload.nama || '').trim();
    const cleanNip = String(payload.nip || '').trim();
    const cleanUsername = String(payload.username || '').trim().toLowerCase();
    const cleanRole = String(payload.role || '').trim();
    const cleanPassword = payload.password ? String(payload.password) : '';
    const cleanFoto = payload.foto ? String(payload.foto).trim() : '';
    const isActive = payload.is_active === undefined ? true : (payload.is_active === true || String(payload.is_active).toLowerCase() === 'true');

    if (!cleanNama) {
      return buildResponse(false, null, 'Nama lengkap wajib diisi.');
    }
    if (!cleanUsername) {
      return buildResponse(false, null, 'Username wajib diisi.');
    }
    if (cleanUsername.length < 3) {
      return buildResponse(false, null, 'Username minimal 3 karakter.');
    }
    if (!/^[a-z0-9_.]+$/.test(cleanUsername)) {
      return buildResponse(false, null, 'Username hanya boleh berupa huruf kecil, angka, garis bawah (_), atau titik (.).');
    }

    if (!['kepala_sekolah', 'wali_kelas'].includes(cleanRole)) {
      return buildResponse(false, null, 'Role harus salah satu dari: kepala_sekolah atau wali_kelas.');
    }

    const uData = getSheetDataBatch('user');

    // Validasi keunikan username (case-insensitive)
    const duplicateUser = uData.rows.find(u =>
      String(u.username || '').toLowerCase() === cleanUsername &&
      (!editId || u.id !== editId)
    );
    if (duplicateUser) {
      return buildResponse(false, null, 'Username "' + cleanUsername + '" sudah digunakan oleh pengguna lain.');
    }

    // Validasi keunikan NIP jika diisi
    if (cleanNip && cleanNip !== '-') {
      const duplicateNip = uData.rows.find(u =>
        String(u.nip || '').trim() === cleanNip &&
        (!editId || u.id !== editId)
      );
      if (duplicateNip) {
        return buildResponse(false, null, 'NIP "' + cleanNip + '" sudah terdaftar pada pengguna lain.');
      }
    }

    const nowIso = new Date().toISOString();

    if (editId) {
      // Edit User yang Ada
      const existingUser = uData.rows.find(u => u.id === editId);
      if (!existingUser) {
        return buildResponse(false, null, 'Data pengguna tidak ditemukan.');
      }

      // Proteksi Admin Lockout: Kepala sekolah tidak boleh menonaktifkan dirinya sendiri atau menurunkan rolenya
      if (adminUser.id === editId) {
        if (!isActive) {
          return buildResponse(false, null, 'Anda tidak dapat menonaktifkan akun Anda sendiri.');
        }
        if (cleanRole !== 'kepala_sekolah') {
          return buildResponse(false, null, 'Anda tidak dapat mengubah role akun Anda sendiri.');
        }
      }

      const updateFields = {
        nama: cleanNama,
        nip: cleanNip,
        username: cleanUsername,
        role: cleanRole,
        foto: cleanFoto,
        is_active: isActive,
        updated_at: nowIso
      };

      // Jika password baru diisi, perbarui password_hash & password_salt
      if (cleanPassword) {
        if (cleanPassword.length < 6) {
          return buildResponse(false, null, 'Password baru minimal 6 karakter.');
        }
        const newSalt = generateSecureSalt();
        const newHash = hashPasswordPBKDF2(cleanPassword, newSalt);
        updateFields.password_salt = newSalt;
        updateFields.password_hash = newHash;
      }

      updateSheetRow('user', existingUser._rowIndex, updateFields);
      return buildResponse(true, { id: editId }, 'Data pengguna berhasil diperbarui.');
    } else {
      // Tambah User Baru
      if (!cleanPassword) {
        return buildResponse(false, null, 'Password wajib diisi untuk pengguna baru.');
      }
      if (cleanPassword.length < 6) {
        return buildResponse(false, null, 'Password minimal 6 karakter.');
      }

      const newId = getStableUUID();
      const salt = generateSecureSalt();
      const hash = hashPasswordPBKDF2(cleanPassword, salt);

      appendSheetRow('user', {
        id: newId,
        nama: cleanNama,
        nip: cleanNip,
        username: cleanUsername,
        password_hash: hash,
        password_salt: salt,
        role: cleanRole,
        foto: cleanFoto,
        terakhir_login: '',
        is_active: isActive,
        created_at: nowIso,
        updated_at: nowIso
      });

      return buildResponse(true, { id: newId }, 'Pengguna baru berhasil ditambahkan.');
    }
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menyimpan pengguna.');
  } finally {
    if (lock) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

/**
 * Mengubah status aktif / nonaktif user.
 * Otorisasi: kepala_sekolah saja.
 *
 * @param {string} sessionToken
 * @param {string} userId
 * @param {boolean} isActive
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiToggleUserStatus(sessionToken, userId, isActive) {
  try {
    const adminUser = requireAuth(sessionToken, 'kepala_sekolah');

    if (!userId) {
      return buildResponse(false, null, 'ID pengguna diperlukan.');
    }

    if (adminUser.id === userId && !isActive) {
      return buildResponse(false, null, 'Anda tidak dapat menonaktifkan akun Anda sendiri.');
    }

    const uData = getSheetDataBatch('user');
    const existing = uData.rows.find(u => u.id === userId);
    if (!existing) {
      return buildResponse(false, null, 'Data pengguna tidak ditemukan.');
    }

    const targetActive = !!isActive;
    const nowIso = new Date().toISOString();

    updateSheetRow('user', existing._rowIndex, {
      is_active: targetActive,
      updated_at: nowIso
    });

    const msg = targetActive ? 'Akun pengguna berhasil diaktifkan.' : 'Akun pengguna berhasil dinonaktifkan.';
    return buildResponse(true, { id: userId, is_active: targetActive }, msg);
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal mengubah status pengguna.');
  }
}

/**
 * Menghapus user (Hanya jika belum pernah memiliki penugasan atau relasi).
 * Otorisasi: kepala_sekolah saja.
 *
 * @param {string} sessionToken
 * @param {string} userId
 * @return {{ success: boolean, data: null, message: string }}
 */
function apiDeleteUser(sessionToken, userId) {
  try {
    const adminUser = requireAuth(sessionToken, 'kepala_sekolah');

    if (!userId) {
      return buildResponse(false, null, 'ID pengguna diperlukan.');
    }

    if (adminUser.id === userId) {
      return buildResponse(false, null, 'Anda tidak dapat menghapus akun Anda sendiri.');
    }

    const uData = getSheetDataBatch('user');
    const existing = uData.rows.find(u => u.id === userId);
    if (!existing) {
      return buildResponse(false, null, 'Data pengguna tidak ditemukan.');
    }

    // Proteksi relasi penugasan wali kelas
    try {
      const wkData = getSheetDataBatch('wali_kelas');
      const hasWk = wkData.rows.some(w => w.user_id === userId);
      if (hasWk) {
        return buildResponse(false, null, 'Pengguna ini memiliki riwayat penugasan kelas dan tidak dapat dihapus permanen demi menjaga keutuhan riwayat data. Silakan nonaktifkan akun sebagai gantinya.');
      }
    } catch (e) {}

    // Proteksi relasi pengaturan sekolah
    try {
      const pengData = getSheetDataBatch('pengaturan');
      const hasPeng = pengData.rows.some(p => p.user_id === userId);
      if (hasPeng) {
        return buildResponse(false, null, 'Pengguna ini terhubung dengan profil kepala sekolah pada pengaturan dan tidak dapat dihapus.');
      }
    } catch (e) {}

    deleteSheetRow('user', existing._rowIndex);
    return buildResponse(true, null, 'Pengguna berhasil dihapus.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menghapus pengguna.');
  }
}

/**
 * Helper Server-Side: Memverifikasi akses penugasan dan mencegah IDOR.
 * Mengembalikan objek penugasan beserta info tahun ajaran jika valid.
 *
 * @param {Object} sessionUser { id, role }
 * @param {string} [requestedWaliKelasId]
 * @return {{ assignment: Object, activeYear: Object }}
 */
function resolveWaliKelasScope(sessionUser, requestedWaliKelasId) {
  const wkData = getSheetDataBatch('wali_kelas');
  const taData = getSheetDataBatch('tahun_ajaran');

  const activeYear = taData.rows.find(t => t.is_active === true || String(t.is_active).toLowerCase() === 'true');

  if (sessionUser.role === 'wali_kelas') {
    // Wali kelas hanya boleh mengakses penugasan miliknya
    let assignment = null;
    if (requestedWaliKelasId) {
      assignment = wkData.rows.find(w => w.id === requestedWaliKelasId && w.user_id === sessionUser.id);
      if (!assignment) {
        throw new Error('Akses ditolak: Anda tidak memiliki akses ke penugasan kelas ini.');
      }
    } else {
      // Ambil penugasan aktif pada tahun ajaran aktif
      if (activeYear) {
        assignment = wkData.rows.find(w =>
          w.user_id === sessionUser.id &&
          w.tahun_ajaran_id === activeYear.id &&
          (w.is_active === true || String(w.is_active).toLowerCase() === 'true')
        );
      }
      if (!assignment) {
        // Fallback penugasan terakhir milik guru
        assignment = wkData.rows.find(w => w.user_id === sessionUser.id && (w.is_active === true || String(w.is_active).toLowerCase() === 'true'));
      }
    }

    if (!assignment) {
      throw new Error('Anda belum memiliki penugasan wali kelas yang aktif.');
    }

    const ta = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);
    return { assignment, activeYear: ta || activeYear };
  } else if (sessionUser.role === 'kepala_sekolah') {
    // Kepala sekolah boleh mengakses penugasan mana pun jika diminta
    let assignment = null;
    if (requestedWaliKelasId) {
      assignment = wkData.rows.find(w => w.id === requestedWaliKelasId);
      if (!assignment) {
        throw new Error('Data penugasan kelas tidak ditemukan.');
      }
    } else if (activeYear) {
      // Ambil penugasan pertama di tahun ajaran aktif jika ada
      assignment = wkData.rows.find(w => w.tahun_ajaran_id === activeYear.id) || wkData.rows[0] || null;
    }

    const ta = assignment ? taData.rows.find(t => t.id === assignment.tahun_ajaran_id) : activeYear;
    return { assignment, activeYear: ta || activeYear };
  }

  throw new Error('Akses ditolak: Role tidak valid.');
}

/**
 * Mengambil daftar siswa berdasarkan penugasan wali kelas.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 * Pencegahan IDOR: Wali kelas dibatasi hanya pada penugasan miliknya di server.
 *
 * @param {string} sessionToken
 * @param {string} [filterWaliKelasId]
 * @return {{ success: boolean, data: Object, message: string }}
 */
function apiGetSiswaList(sessionToken, filterWaliKelasId) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);
    const { assignment, activeYear } = resolveWaliKelasScope(user, filterWaliKelasId);

    const sData = getSheetDataBatch('siswa');
    const uData = getSheetDataBatch('user');
    const wkData = getSheetDataBatch('wali_kelas');
    const taData = getSheetDataBatch('tahun_ajaran');

    let rows = sData.rows;

    // Filter siswa sesuai penugasan
    if (assignment) {
      rows = rows.filter(s => s.wali_kelas_id === assignment.id);
    } else if (user.role === 'wali_kelas') {
      rows = [];
    }

    // Hitung riwayat nilai untuk flag proteksi
    let nData = { rows: [] };
    let skData = { rows: [] };
    let rkData = { rows: [] };
    try { nData = getSheetDataBatch('nilai_mata_pelajaran'); } catch (e) {}
    try { skData = getSheetDataBatch('nilai_sikap'); } catch (e) {}
    try { rkData = getSheetDataBatch('rekap_kehadiran'); } catch (e) {}

    const siswaList = rows.map(s => {
      const hasGrades = nData.rows.some(n => n.siswa_id === s.id) ||
                        skData.rows.some(sk => sk.siswa_id === s.id) ||
                        rkData.rows.some(rk => rk.siswa_id === s.id);
      return {
        id: s.id,
        wali_kelas_id: s.wali_kelas_id,
        no_absen: Number(s.no_absen) || 0,
        nisn: s.nisn || '-',
        nis: s.nis || '-',
        nama: s.nama,
        jenis_kelamin: s.jenis_kelamin,
        tempat_lahir: s.tempat_lahir || '',
        tanggal_lahir: s.tanggal_lahir ? String(s.tanggal_lahir).substring(0, 10) : '',
        wali_murid: s.wali_murid || '',
        nomor_telepon: s.nomor_telepon || '',
        is_active: (s.is_active === true || String(s.is_active).toLowerCase() === 'true'),
        hasGrades: hasGrades,
        created_at: s.created_at,
        updated_at: s.updated_at
      };
    });

    siswaList.sort((a, b) => a.no_absen - b.no_absen);

    // Detail penugasan terkait
    let penugasanInfo = null;
    if (assignment) {
      const teacher = uData.rows.find(u => u.id === assignment.user_id);
      const ta = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);
      penugasanInfo = {
        id: assignment.id,
        kelas: String(assignment.kelas),
        guruNama: teacher ? teacher.nama : '-',
        guruNip: teacher ? (teacher.nip || '-') : '-',
        tahunAjaran: ta ? ta.tahun_ajaran : '-',
        semester: ta ? ta.semester : '-',
        isLocked: ta ? (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true') : false,
        isActive: assignment.is_active === true || String(assignment.is_active).toLowerCase() === 'true'
      };
    }

    // Daftar opsi penugasan untuk filter (khusus Kepala Sekolah)
    let penugasanOptions = [];
    if (user.role === 'kepala_sekolah') {
      penugasanOptions = wkData.rows.map(w => {
        const teacher = uData.rows.find(u => u.id === w.user_id);
        const ta = taData.rows.find(t => t.id === w.tahun_ajaran_id);
        return {
          id: w.id,
          kelas: String(w.kelas),
          guruNama: teacher ? teacher.nama : '-',
          tahunAjaran: ta ? ta.tahun_ajaran : '-',
          semester: ta ? ta.semester : '-',
          isActive: w.is_active === true || String(w.is_active).toLowerCase() === 'true'
        };
      });
      penugasanOptions.sort((a, b) => Number(a.kelas) - Number(b.kelas));
    }

    return buildResponse(true, {
      siswa: siswaList,
      penugasan: penugasanInfo,
      penugasanOptions: penugasanOptions,
      isReadOnly: penugasanInfo ? penugasanInfo.isLocked : false
    }, 'Daftar siswa berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat daftar siswa.');
  }
}

/**
 * Menyimpan (Tambah/Edit) Data Siswa.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 * Validasi: NISN unik, NIS unik, No. Absen unik per kelas, dan pencegahan edit pada periode terkunci.
 *
 * @param {string} sessionToken
 * @param {Object} payload
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiSaveSiswa(sessionToken, payload) {
  let lock = null;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    if (!payload || typeof payload !== 'object') {
      return buildResponse(false, null, 'Data siswa tidak valid.');
    }

    const editId = payload.id ? String(payload.id).trim() : null;
    const requestedWkId = payload.wali_kelas_id ? String(payload.wali_kelas_id).trim() : null;

    // Verifikasi cakupan penugasan dan proteksi IDOR
    const { assignment, activeYear } = resolveWaliKelasScope(user, requestedWkId);
    if (!assignment) {
      return buildResponse(false, null, 'Penugasan kelas untuk siswa tidak ditemukan.');
    }

    // Proteksi periode terkunci
    const taData = getSheetDataBatch('tahun_ajaran');
    const ta = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);
    if (ta && (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true')) {
      return buildResponse(false, null, 'Periode akademik telah dikunci. Data siswa pada periode ini bersifat baca-saja.');
    }

    const cleanNama = String(payload.nama || '').trim();
    const rawNoAbsen = payload.no_absen;
    const noAbsen = parseInt(rawNoAbsen, 10);
    const cleanJk = String(payload.jenis_kelamin || '').trim().toUpperCase();
    const cleanNisn = payload.nisn ? String(payload.nisn).trim() : '';
    const cleanNis = payload.nis ? String(payload.nis).trim() : '';
    const cleanTempatLahir = payload.tempat_lahir ? String(payload.tempat_lahir).trim() : '';
    const cleanTanggalLahir = payload.tanggal_lahir ? String(payload.tanggal_lahir).trim() : '';
    const cleanWaliMurid = payload.wali_murid ? String(payload.wali_murid).trim() : '';
    const cleanTelepon = payload.nomor_telepon ? String(payload.nomor_telepon).trim() : '';
    const isActive = payload.is_active === undefined ? true : (payload.is_active === true || String(payload.is_active).toLowerCase() === 'true');

    if (!cleanNama) {
      return buildResponse(false, null, 'Nama lengkap siswa wajib diisi.');
    }
    if (isNaN(noAbsen) || noAbsen < 1) {
      return buildResponse(false, null, 'Nomor absen wajib berupa bilangan bulat positif (minimal 1).');
    }
    if (cleanJk !== 'L' && cleanJk !== 'P') {
      return buildResponse(false, null, 'Jenis kelamin harus salah satu dari: L (Laki-laki) atau P (Perempuan).');
    }

    // Validasi NISN jika diisi (harus numerik, 10 digit jika sesuai standar nasional)
    if (cleanNisn && cleanNisn !== '-') {
      if (!/^\d{8,12}$/.test(cleanNisn)) {
        return buildResponse(false, null, 'Format NISN harus berupa angka (standar 10 digit).');
      }
    }

    const sData = getSheetDataBatch('siswa');

    let existingSiswa = null;
    if (editId) {
      existingSiswa = sData.rows.find(s => s.id === editId);
      if (!existingSiswa) {
        return buildResponse(false, null, 'Data siswa yang akan diedit tidak ditemukan.');
      }

      // Pastikan wali kelas tidak mengedit siswa di luar kelasnya
      if (user.role === 'wali_kelas' && existingSiswa.wali_kelas_id !== assignment.id) {
        return buildResponse(false, null, 'Akses ditolak: Anda tidak memiliki izin untuk mengedit siswa ini.');
      }
    }

    // Validasi nomor absen unik per penugasan wali kelas
    const dupAbsen = sData.rows.find(s =>
      s.wali_kelas_id === assignment.id &&
      Number(s.no_absen) === noAbsen &&
      (!editId || s.id !== editId)
    );
    if (dupAbsen) {
      return buildResponse(false, null, 'Nomor absen ' + noAbsen + ' sudah digunakan oleh siswa ' + dupAbsen.nama + ' di kelas ini.');
    }

    // Validasi NISN unik di sekolah jika diisi
    if (cleanNisn && cleanNisn !== '-') {
      const dupNisn = sData.rows.find(s =>
        String(s.nisn || '').trim() === cleanNisn &&
        (!editId || s.id !== editId)
      );
      if (dupNisn) {
        return buildResponse(false, null, 'NISN "' + cleanNisn + '" sudah terdaftar untuk siswa ' + dupNisn.nama + '.');
      }
    }

    // Validasi NIS unik di sekolah jika diisi
    if (cleanNis && cleanNis !== '-') {
      const dupNis = sData.rows.find(s =>
        String(s.nis || '').trim() === cleanNis &&
        (!editId || s.id !== editId)
      );
      if (dupNis) {
        return buildResponse(false, null, 'NIS "' + cleanNis + '" sudah terdaftar untuk siswa ' + dupNis.nama + '.');
      }
    }

    const nowIso = new Date().toISOString();

    if (editId) {
      updateSheetRow('siswa', existingSiswa._rowIndex, {
        no_absen: noAbsen,
        nisn: cleanNisn,
        nis: cleanNis,
        nama: cleanNama,
        jenis_kelamin: cleanJk,
        tempat_lahir: cleanTempatLahir,
        tanggal_lahir: cleanTanggalLahir,
        wali_murid: cleanWaliMurid,
        nomor_telepon: cleanTelepon,
        is_active: isActive,
        updated_at: nowIso
      });

      return buildResponse(true, { id: editId }, 'Data siswa berhasil diperbarui.');
    } else {
      const newId = getStableUUID();
      appendSheetRow('siswa', {
        id: newId,
        wali_kelas_id: assignment.id,
        nisn: cleanNisn,
        nis: cleanNis,
        no_absen: noAbsen,
        nama: cleanNama,
        jenis_kelamin: cleanJk,
        tempat_lahir: cleanTempatLahir,
        tanggal_lahir: cleanTanggalLahir,
        wali_murid: cleanWaliMurid,
        nomor_telepon: cleanTelepon,
        is_active: isActive,
        created_at: nowIso,
        updated_at: nowIso
      });

      return buildResponse(true, { id: newId }, 'Data siswa baru berhasil ditambahkan.');
    }
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menyimpan data siswa.');
  } finally {
    if (lock) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

/**
 * Mengubah status aktif / nonaktif siswa.
 * Otorisasi: kepala_sekolah atau wali_kelas (penugasan sendiri).
 *
 * @param {string} sessionToken
 * @param {string} siswaId
 * @param {boolean} isActive
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiToggleSiswaStatus(sessionToken, siswaId, isActive) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    if (!siswaId) {
      return buildResponse(false, null, 'ID siswa diperlukan.');
    }

    const sData = getSheetDataBatch('siswa');
    const existingSiswa = sData.rows.find(s => s.id === siswaId);
    if (!existingSiswa) {
      return buildResponse(false, null, 'Data siswa tidak ditemukan.');
    }

    // Verifikasi hak akses wali kelas
    if (user.role === 'wali_kelas') {
      const wkData = getSheetDataBatch('wali_kelas');
      const assignment = wkData.rows.find(w => w.id === existingSiswa.wali_kelas_id && w.user_id === user.id);
      if (!assignment) {
        return buildResponse(false, null, 'Akses ditolak: Anda tidak memiliki wewenang untuk mengubah status siswa ini.');
      }
    }

    const targetActive = !!isActive;
    const nowIso = new Date().toISOString();

    updateSheetRow('siswa', existingSiswa._rowIndex, {
      is_active: targetActive,
      updated_at: nowIso
    });

    const msg = targetActive ? 'Siswa berhasil diaktifkan kembali.' : 'Siswa berhasil dinonaktifkan.';
    return buildResponse(true, { id: siswaId, is_active: targetActive }, msg);
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal mengubah status siswa.');
  }
}

/**
 * Menghapus siswa secara permanen (hanya jika belum memiliki data nilai/kehadiran).
 * Otorisasi: kepala_sekolah atau wali_kelas (penugasan sendiri).
 *
 * @param {string} sessionToken
 * @param {string} siswaId
 * @return {{ success: boolean, data: null, message: string }}
 */
function apiDeleteSiswa(sessionToken, siswaId) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    if (!siswaId) {
      return buildResponse(false, null, 'ID siswa diperlukan.');
    }

    const sData = getSheetDataBatch('siswa');
    const existingSiswa = sData.rows.find(s => s.id === siswaId);
    if (!existingSiswa) {
      return buildResponse(false, null, 'Data siswa tidak ditemukan.');
    }

    // Verifikasi hak akses wali kelas
    const wkData = getSheetDataBatch('wali_kelas');
    const assignment = wkData.rows.find(w => w.id === existingSiswa.wali_kelas_id);
    if (user.role === 'wali_kelas') {
      if (!assignment || assignment.user_id !== user.id) {
        return buildResponse(false, null, 'Akses ditolak: Anda tidak memiliki wewenang untuk menghapus siswa ini.');
      }
    }

    // Proteksi periode terkunci
    if (assignment) {
      const taData = getSheetDataBatch('tahun_ajaran');
      const ta = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);
      if (ta && (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true')) {
        return buildResponse(false, null, 'Periode akademik telah dikunci. Data siswa pada periode ini tidak dapat dihapus.');
      }
    }

    // Proteksi Integritas Relasi Historis: Nilai Mapel, Nilai Sikap, Rekap Kehadiran
    try {
      const nData = getSheetDataBatch('nilai_mata_pelajaran');
      if (nData.rows.some(n => n.siswa_id === siswaId)) {
        return buildResponse(false, null, 'Siswa ini sudah memiliki riwayat nilai mata pelajaran dan tidak boleh dihapus permanen. Silakan nonaktifkan status siswa.');
      }
    } catch (e) {}

    try {
      const skData = getSheetDataBatch('nilai_sikap');
      if (skData.rows.some(sk => sk.siswa_id === siswaId)) {
        return buildResponse(false, null, 'Siswa ini sudah memiliki riwayat penilaian sikap dan tidak boleh dihapus permanen. Silakan nonaktifkan status siswa.');
      }
    } catch (e) {}

    try {
      const rkData = getSheetDataBatch('rekap_kehadiran');
      if (rkData.rows.some(rk => rk.siswa_id === siswaId)) {
        return buildResponse(false, null, 'Siswa ini sudah memiliki riwayat kehadiran dan tidak boleh dihapus permanen. Silakan nonaktifkan status siswa.');
      }
    } catch (e) {}

    deleteSheetRow('siswa', existingSiswa._rowIndex);
    return buildResponse(true, null, 'Data siswa berhasil dihapus.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menghapus siswa.');
  }
}

/**
 * Mengambil daftar mata pelajaran berdasarkan penugasan wali kelas.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {string} [filterWaliKelasId]
 * @return {{ success: boolean, data: Object, message: string }}
 */
function apiGetMataPelajaranList(sessionToken, filterWaliKelasId) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);
    const { assignment } = resolveWaliKelasScope(user, filterWaliKelasId);

    const mapelData = getSheetDataBatch('mata_pelajaran');
    const uData = getSheetDataBatch('user');
    const wkData = getSheetDataBatch('wali_kelas');
    const taData = getSheetDataBatch('tahun_ajaran');

    let rows = mapelData.rows;

    if (assignment) {
      rows = rows.filter(m => m.wali_kelas_id === assignment.id);
    } else if (user.role === 'wali_kelas') {
      rows = [];
    }

    let nData = { rows: [] };
    try {
      nData = getSheetDataBatch('nilai_mata_pelajaran');
    } catch (e) {}

    const mapelList = rows.map(m => {
      const hasGrades = nData.rows.some(n => n.mata_pelajaran_id === m.id);
      return {
        id: m.id,
        wali_kelas_id: m.wali_kelas_id,
        kode_mata_pelajaran: m.kode_mata_pelajaran,
        mata_pelajaran: m.mata_pelajaran,
        is_active: (m.is_active === true || String(m.is_active).toLowerCase() === 'true'),
        hasGrades: hasGrades,
        created_at: m.created_at,
        updated_at: m.updated_at
      };
    });

    mapelList.sort((a, b) => a.kode_mata_pelajaran.localeCompare(b.kode_mata_pelajaran));

    let penugasanInfo = null;
    if (assignment) {
      const teacher = uData.rows.find(u => u.id === assignment.user_id);
      const ta = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);
      penugasanInfo = {
        id: assignment.id,
        kelas: String(assignment.kelas),
        guruNama: teacher ? teacher.nama : '-',
        guruNip: teacher ? (teacher.nip || '-') : '-',
        tahunAjaran: ta ? ta.tahun_ajaran : '-',
        semester: ta ? ta.semester : '-',
        isLocked: ta ? (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true') : false,
        isActive: assignment.is_active === true || String(assignment.is_active).toLowerCase() === 'true'
      };
    }

    return buildResponse(true, {
      mataPelajaran: mapelList,
      penugasan: penugasanInfo,
      isReadOnly: penugasanInfo ? penugasanInfo.isLocked : false
    }, 'Daftar mata pelajaran berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat daftar mata pelajaran.');
  }
}

/**
 * Menyimpan (Tambah/Edit) Mata Pelajaran.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {Object} payload
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiSaveMataPelajaran(sessionToken, payload) {
  let lock = null;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    if (!payload || typeof payload !== 'object') {
      return buildResponse(false, null, 'Data mata pelajaran tidak valid.');
    }

    const editId = payload.id ? String(payload.id).trim() : null;
    const requestedWkId = payload.wali_kelas_id ? String(payload.wali_kelas_id).trim() : null;

    // Verifikasi penugasan dan proteksi IDOR
    const { assignment } = resolveWaliKelasScope(user, requestedWkId);
    if (!assignment) {
      return buildResponse(false, null, 'Penugasan kelas untuk mata pelajaran tidak ditemukan.');
    }

    // Proteksi periode terkunci
    const taData = getSheetDataBatch('tahun_ajaran');
    const ta = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);
    if (ta && (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true')) {
      return buildResponse(false, null, 'Periode akademik telah dikunci. Mata pelajaran pada periode ini bersifat baca-saja.');
    }

    const cleanKode = String(payload.kode_mata_pelajaran || '').trim().toUpperCase();
    const cleanNama = String(payload.mata_pelajaran || '').trim();
    const isActive = payload.is_active === undefined ? true : (payload.is_active === true || String(payload.is_active).toLowerCase() === 'true');

    if (!cleanKode) {
      return buildResponse(false, null, 'Kode mata pelajaran wajib diisi.');
    }
    if (!cleanNama) {
      return buildResponse(false, null, 'Nama mata pelajaran wajib diisi.');
    }

    const mapelData = getSheetDataBatch('mata_pelajaran');

    let existingMapel = null;
    if (editId) {
      existingMapel = mapelData.rows.find(m => m.id === editId);
      if (!existingMapel) {
        return buildResponse(false, null, 'Data mata pelajaran yang akan diedit tidak ditemukan.');
      }

      if (user.role === 'wali_kelas' && existingMapel.wali_kelas_id !== assignment.id) {
        return buildResponse(false, null, 'Akses ditolak: Anda tidak memiliki wewenang untuk mengedit mata pelajaran ini.');
      }
    }

    // Validasi keunikan kode mapel dalam penugasan
    const dupKode = mapelData.rows.find(m =>
      m.wali_kelas_id === assignment.id &&
      m.kode_mata_pelajaran.toUpperCase() === cleanKode &&
      (!editId || m.id !== editId)
    );
    if (dupKode) {
      return buildResponse(false, null, 'Kode mata pelajaran "' + cleanKode + '" sudah digunakan pada kelas ini.');
    }

    // Validasi keunikan nama mapel dalam penugasan
    const dupNama = mapelData.rows.find(m =>
      m.wali_kelas_id === assignment.id &&
      m.mata_pelajaran.toLowerCase() === cleanNama.toLowerCase() &&
      (!editId || m.id !== editId)
    );
    if (dupNama) {
      return buildResponse(false, null, 'Mata pelajaran "' + cleanNama + '" sudah terdaftar pada kelas ini.');
    }

    const nowIso = new Date().toISOString();

    if (editId) {
      updateSheetRow('mata_pelajaran', existingMapel._rowIndex, {
        kode_mata_pelajaran: cleanKode,
        mata_pelajaran: cleanNama,
        is_active: isActive,
        updated_at: nowIso
      });

      return buildResponse(true, { id: editId }, 'Mata pelajaran berhasil diperbarui.');
    } else {
      const newId = getStableUUID();
      appendSheetRow('mata_pelajaran', {
        id: newId,
        wali_kelas_id: assignment.id,
        kode_mata_pelajaran: cleanKode,
        mata_pelajaran: cleanNama,
        is_active: isActive,
        created_at: nowIso,
        updated_at: nowIso
      });

      return buildResponse(true, { id: newId }, 'Mata pelajaran baru berhasil ditambahkan.');
    }
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menyimpan mata pelajaran.');
  } finally {
    if (lock) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

/**
 * Mengubah status aktif / nonaktif mata pelajaran.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {string} mapelId
 * @param {boolean} isActive
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiToggleMataPelajaranStatus(sessionToken, mapelId, isActive) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    if (!mapelId) {
      return buildResponse(false, null, 'ID mata pelajaran diperlukan.');
    }

    const mapelData = getSheetDataBatch('mata_pelajaran');
    const existingMapel = mapelData.rows.find(m => m.id === mapelId);
    if (!existingMapel) {
      return buildResponse(false, null, 'Data mata pelajaran tidak ditemukan.');
    }

    if (user.role === 'wali_kelas') {
      const wkData = getSheetDataBatch('wali_kelas');
      const assignment = wkData.rows.find(w => w.id === existingMapel.wali_kelas_id && w.user_id === user.id);
      if (!assignment) {
        return buildResponse(false, null, 'Akses ditolak: Anda tidak memiliki wewenang untuk mengubah status mata pelajaran ini.');
      }
    }

    const targetActive = !!isActive;
    const nowIso = new Date().toISOString();

    updateSheetRow('mata_pelajaran', existingMapel._rowIndex, {
      is_active: targetActive,
      updated_at: nowIso
    });

    const msg = targetActive ? 'Mata pelajaran berhasil diaktifkan.' : 'Mata pelajaran berhasil dinonaktifkan.';
    return buildResponse(true, { id: mapelId, is_active: targetActive }, msg);
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal mengubah status mata pelajaran.');
  }
}

/**
 * Menghapus mata pelajaran permanen (hanya jika belum memiliki data nilai).
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {string} mapelId
 * @return {{ success: boolean, data: null, message: string }}
 */
function apiDeleteMataPelajaran(sessionToken, mapelId) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    if (!mapelId) {
      return buildResponse(false, null, 'ID mata pelajaran diperlukan.');
    }

    const mapelData = getSheetDataBatch('mata_pelajaran');
    const existingMapel = mapelData.rows.find(m => m.id === mapelId);
    if (!existingMapel) {
      return buildResponse(false, null, 'Data mata pelajaran tidak ditemukan.');
    }

    const wkData = getSheetDataBatch('wali_kelas');
    const assignment = wkData.rows.find(w => w.id === existingMapel.wali_kelas_id);
    if (user.role === 'wali_kelas') {
      if (!assignment || assignment.user_id !== user.id) {
        return buildResponse(false, null, 'Akses ditolak: Anda tidak memiliki wewenang untuk menghapus mata pelajaran ini.');
      }
    }

    // Proteksi periode terkunci
    if (assignment) {
      const taData = getSheetDataBatch('tahun_ajaran');
      const ta = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);
      if (ta && (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true')) {
        return buildResponse(false, null, 'Periode akademik telah dikunci. Mata pelajaran pada periode ini tidak dapat dihapus.');
      }
    }

    // Proteksi integritas nilai
    try {
      const nData = getSheetDataBatch('nilai_mata_pelajaran');
      const hasGrades = nData.rows.some(n => n.mata_pelajaran_id === mapelId);
      if (hasGrades) {
        return buildResponse(false, null, 'Mata pelajaran ini sudah memiliki riwayat nilai siswa dan tidak dapat dihapus permanen. Silakan nonaktifkan status mata pelajaran.');
      }
    } catch (e) {}

    deleteSheetRow('mata_pelajaran', existingMapel._rowIndex);
    return buildResponse(true, null, 'Mata pelajaran berhasil dihapus.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menghapus mata pelajaran.');
  }
}

// ============================================================================
// 6. MODUL PHASE 6: PENGATURAN RAPOR, NILAI, SIKAP & REKAP KEHADIRAN
// ============================================================================

/**
 * Menentukan predikat dari nilai numerik berdasarkan rentang konfigurasi rapor.
 *
 * @param {number|string} score
 * @param {Array<Object>} predikatRanges
 * @return {string}
 */
function resolvePredikatScore(score, predikatRanges) {
  if (score === null || score === undefined || score === '' || isNaN(score)) {
    return '-';
  }
  const num = Number(score);
  if (!Array.isArray(predikatRanges) || predikatRanges.length === 0) {
    if (num >= 90) return 'A';
    if (num >= 80) return 'B';
    if (num >= 70) return 'C';
    return 'D';
  }
  for (let i = 0; i < predikatRanges.length; i++) {
    const r = predikatRanges[i];
    const min = Number(r.min);
    const max = Number(r.max);
    if (num >= min - 0.001 && num <= max + 0.001) {
      return r.label;
    }
  }
  const sorted = predikatRanges.slice().sort((a, b) => Number(a.min) - Number(b.min));
  if (num < Number(sorted[0].min)) return sorted[0].label;
  if (num > Number(sorted[sorted.length - 1].max)) return sorted[sorted.length - 1].label;
  return '-';
}

/**
 * Mengambil konfigurasi pengaturan rapor (bobot tugas, UTS, UAS, dan rentang predikat).
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {string} [requestedWaliKelasId]
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiGetPengaturanRapor(sessionToken, requestedWaliKelasId) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);
    const { assignment, activeYear } = resolveWaliKelasScope(user, requestedWaliKelasId);

    if (!assignment) {
      return buildResponse(false, null, 'Data penugasan kelas tidak ditemukan.');
    }

    const prData = getSheetDataBatch('pengaturan_rapor');
    const existing = prData.rows.find(p => p.tahun_ajaran_id === assignment.tahun_ajaran_id && p.wali_kelas_id === assignment.id);

    const defaultPredikat = [
      { label: 'A', min: 90, max: 100 },
      { label: 'B', min: 80, max: 89.99 },
      { label: 'C', min: 70, max: 79.99 },
      { label: 'D', min: 0, max: 69.99 }
    ];

    let config = {
      id: existing ? existing.id : '',
      tahun_ajaran_id: assignment.tahun_ajaran_id,
      wali_kelas_id: assignment.id,
      bobot_tugas: existing && existing.bobot_tugas !== '' ? Number(existing.bobot_tugas) : 40,
      bobot_uts: existing && existing.bobot_uts !== '' ? Number(existing.bobot_uts) : 30,
      bobot_uas: existing && existing.bobot_uas !== '' ? Number(existing.bobot_uas) : 30,
      predikat: defaultPredikat,
      isDefault: !existing
    };

    if (existing && existing.predikat) {
      try {
        const parsed = typeof existing.predikat === 'string' ? JSON.parse(existing.predikat) : existing.predikat;
        if (Array.isArray(parsed) && parsed.length > 0) {
          config.predikat = parsed;
        }
      } catch (e) {
        config.predikat = defaultPredikat;
      }
    }

    const isLocked = activeYear ? (activeYear.is_locked === true || String(activeYear.is_locked).toLowerCase() === 'true') : false;

    return buildResponse(true, {
      config: config,
      assignment: {
        id: assignment.id,
        kelas: String(assignment.kelas),
        tahunAjaran: activeYear ? activeYear.tahun_ajaran : '-',
        semester: activeYear ? activeYear.semester : '-',
        isLocked: isLocked
      },
      isReadOnly: isLocked
    }, 'Pengaturan rapor berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat pengaturan rapor.');
  }
}

/**
 * Menyimpan konfigurasi pengaturan rapor (bobot dan rentang predikat).
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {Object} payload
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiSavePengaturanRapor(sessionToken, payload) {
  let lock = null;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    if (!payload || typeof payload !== 'object') {
      return buildResponse(false, null, 'Data pengaturan rapor tidak valid.');
    }

    const requestedWkId = payload.wali_kelas_id ? String(payload.wali_kelas_id).trim() : null;
    const { assignment, activeYear } = resolveWaliKelasScope(user, requestedWkId);

    if (!assignment) {
      return buildResponse(false, null, 'Penugasan kelas tidak ditemukan.');
    }

    // Proteksi periode terkunci
    const taData = getSheetDataBatch('tahun_ajaran');
    const ta = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);
    if (ta && (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true')) {
      return buildResponse(false, null, 'Periode akademik telah dikunci. Pengaturan rapor bersifat baca-saja.');
    }

    // Validasi Bobot
    const bTugas = Number(payload.bobot_tugas);
    const bUts = Number(payload.bobot_uts);
    const bUas = Number(payload.bobot_uas);

    if (isNaN(bTugas) || bTugas < 0 || isNaN(bUts) || bUts < 0 || isNaN(bUas) || bUas < 0) {
      return buildResponse(false, null, 'Bobot tugas, UTS, dan UAS harus berupa angka tidak negatif (0–100).');
    }

    const totalBobot = bTugas + bUts + bUas;
    if (Math.abs(totalBobot - 100) > 0.01) {
      return buildResponse(false, null, 'Total bobot tugas, UTS, dan UAS harus tepat 100% (saat ini: ' + totalBobot + '%).');
    }

    // Validasi Predikat
    let predikatList = payload.predikat;
    if (typeof predikatList === 'string') {
      try {
        predikatList = JSON.parse(predikatList);
      } catch (e) {
        return buildResponse(false, null, 'Format data predikat tidak valid.');
      }
    }

    if (!Array.isArray(predikatList) || predikatList.length < 2) {
      return buildResponse(false, null, 'Pengaturan predikat minimal memiliki 2 rentang (contoh: A, B, C, D).');
    }

    for (let i = 0; i < predikatList.length; i++) {
      const p = predikatList[i];
      if (!p || typeof p !== 'object' || !p.label || typeof p.label !== 'string') {
        return buildResponse(false, null, 'Label predikat pada baris ke-' + (i + 1) + ' wajib diisi.');
      }
      const minVal = Number(p.min);
      const maxVal = Number(p.max);
      if (isNaN(minVal) || isNaN(maxVal) || minVal < 0 || maxVal > 100 || minVal >= maxVal) {
        return buildResponse(false, null, 'Rentang nilai predikat ' + p.label + ' harus dalam rentang 0–100 dan nilai minimum harus lebih kecil dari nilai maksimum.');
      }
    }

    // Periksa kontinuitas (tidak ada overlap dan tidak ada gap)
    const sortedPred = predikatList.slice().sort((a, b) => Number(a.min) - Number(b.min));
    if (Number(sortedPred[0].min) > 0.01) {
      return buildResponse(false, null, 'Rentang predikat terendah harus dimulai dari angka 0.');
    }
    if (Number(sortedPred[sortedPred.length - 1].max) < 99.99) {
      return buildResponse(false, null, 'Rentang predikat tertinggi harus mencapai angka 100.');
    }

    for (let i = 0; i < sortedPred.length - 1; i++) {
      const prev = sortedPred[i];
      const next = sortedPred[i + 1];
      const prevMax = Number(prev.max);
      const nextMin = Number(next.min);

      if (prevMax > nextMin + 0.001) {
        return buildResponse(false, null, 'Terdapat tumpang tindih (overlap) antara predikat ' + prev.label + ' dan ' + next.label + '.');
      }
      if (nextMin - prevMax > 0.02) {
        return buildResponse(false, null, 'Terdapat celah nilai (gap) antara predikat ' + prev.label + ' (maks: ' + prevMax + ') dan ' + next.label + ' (min: ' + nextMin + ').');
      }
    }

    const prData = getSheetDataBatch('pengaturan_rapor');
    const existing = prData.rows.find(p => p.tahun_ajaran_id === assignment.tahun_ajaran_id && p.wali_kelas_id === assignment.id);

    const nowIso = new Date().toISOString();
    const jsonPredikat = JSON.stringify(predikatList);

    if (existing) {
      updateSheetRow('pengaturan_rapor', existing._rowIndex, {
        bobot_tugas: bTugas,
        bobot_uts: bUts,
        bobot_uas: bUas,
        predikat: jsonPredikat,
        updated_at: nowIso
      });
      return buildResponse(true, { id: existing.id }, 'Pengaturan rapor berhasil diperbarui.');
    } else {
      const newId = getStableUUID();
      appendSheetRow('pengaturan_rapor', {
        id: newId,
        tahun_ajaran_id: assignment.tahun_ajaran_id,
        wali_kelas_id: assignment.id,
        bobot_tugas: bTugas,
        bobot_uts: bUts,
        bobot_uas: bUas,
        predikat: jsonPredikat,
        created_at: nowIso,
        updated_at: nowIso
      });
      return buildResponse(true, { id: newId }, 'Pengaturan rapor berhasil disimpan.');
    }
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menyimpan pengaturan rapor.');
  } finally {
    if (lock) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

/**
 * Mengambil daftar nilai mata pelajaran untuk seluruh siswa di kelas penugasan.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {string} [mataPelajaranId]
 * @param {string} [requestedWaliKelasId]
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiGetNilaiMataPelajaran(sessionToken, mataPelajaranId, requestedWaliKelasId) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);
    const { assignment, activeYear } = resolveWaliKelasScope(user, requestedWaliKelasId);

    if (!assignment) {
      return buildResponse(false, null, 'Data penugasan kelas tidak ditemukan.');
    }

    const mapelData = getSheetDataBatch('mata_pelajaran');
    const activeMapels = mapelData.rows.filter(m =>
      m.wali_kelas_id === assignment.id &&
      (m.is_active === true || String(m.is_active).toLowerCase() === 'true')
    );
    activeMapels.sort((a, b) => a.kode_mata_pelajaran.localeCompare(b.kode_mata_pelajaran));

    if (activeMapels.length === 0) {
      return buildResponse(true, {
        mapelCurrent: null,
        mapelList: [],
        siswaNilaiList: [],
        configRapor: null,
        summary: { totalSiswa: 0, jumlahLengkap: 0, persentase: 0 },
        isReadOnly: true
      }, 'Belum ada mata pelajaran aktif pada rombel ini.');
    }

    let targetMapel = null;
    if (mataPelajaranId) {
      targetMapel = activeMapels.find(m => m.id === mataPelajaranId);
      if (!targetMapel) {
        targetMapel = activeMapels[0];
      }
    } else {
      targetMapel = activeMapels[0];
    }

    // Ambil konfigurasi rapor untuk predikat
    const prData = getSheetDataBatch('pengaturan_rapor');
    const existingPr = prData.rows.find(p => p.tahun_ajaran_id === assignment.tahun_ajaran_id && p.wali_kelas_id === assignment.id);
    let predikatRanges = [
      { label: 'A', min: 90, max: 100 },
      { label: 'B', min: 80, max: 89.99 },
      { label: 'C', min: 70, max: 79.99 },
      { label: 'D', min: 0, max: 69.99 }
    ];
    if (existingPr && existingPr.predikat) {
      try {
        const parsed = typeof existingPr.predikat === 'string' ? JSON.parse(existingPr.predikat) : existingPr.predikat;
        if (Array.isArray(parsed) && parsed.length > 0) predikatRanges = parsed;
      } catch (e) {}
    }

    // Ambil siswa aktif
    const sData = getSheetDataBatch('siswa');
    const siswaList = sData.rows.filter(s =>
      s.wali_kelas_id === assignment.id &&
      (s.is_active === true || String(s.is_active).toLowerCase() === 'true')
    );
    siswaList.sort((a, b) => (Number(a.no_absen) || 0) - (Number(b.no_absen) || 0));

    // Ambil nilai tersimpan
    let nData = { rows: [] };
    try {
      nData = getSheetDataBatch('nilai_mata_pelajaran');
    } catch (e) {}

    let countLengkap = 0;

    const siswaNilaiList = siswaList.map(s => {
      const existingGrade = nData.rows.find(n => n.siswa_id === s.id && n.mata_pelajaran_id === targetMapel.id);
      const isComplete = existingGrade ? (existingGrade.is_complete === true || String(existingGrade.is_complete).toLowerCase() === 'true') : false;
      if (isComplete) {
        countLengkap++;
      }

      const nAkhir = existingGrade && existingGrade.nilai_akhir !== '' && existingGrade.nilai_akhir !== null ? Number(existingGrade.nilai_akhir) : '';
      const predikat = isComplete && nAkhir !== '' ? resolvePredikatScore(nAkhir, predikatRanges) : '-';

      return {
        id: existingGrade ? existingGrade.id : null,
        siswa_id: s.id,
        no_absen: Number(s.no_absen) || 0,
        nama: s.nama,
        nisn: s.nisn || '-',
        nis: s.nis || '-',
        nilai_tugas_1: existingGrade && existingGrade.nilai_tugas_1 !== '' && existingGrade.nilai_tugas_1 !== null ? Number(existingGrade.nilai_tugas_1) : '',
        nilai_tugas_2: existingGrade && existingGrade.nilai_tugas_2 !== '' && existingGrade.nilai_tugas_2 !== null ? Number(existingGrade.nilai_tugas_2) : '',
        nilai_tugas_3: existingGrade && existingGrade.nilai_tugas_3 !== '' && existingGrade.nilai_tugas_3 !== null ? Number(existingGrade.nilai_tugas_3) : '',
        nilai_tugas_4: existingGrade && existingGrade.nilai_tugas_4 !== '' && existingGrade.nilai_tugas_4 !== null ? Number(existingGrade.nilai_tugas_4) : '',
        nilai_uts: existingGrade && existingGrade.nilai_uts !== '' && existingGrade.nilai_uts !== null ? Number(existingGrade.nilai_uts) : '',
        nilai_uas: existingGrade && existingGrade.nilai_uas !== '' && existingGrade.nilai_uas !== null ? Number(existingGrade.nilai_uas) : '',
        nilai_akhir: nAkhir,
        is_complete: isComplete,
        predikat: predikat
      };
    });

    const isLocked = activeYear ? (activeYear.is_locked === true || String(activeYear.is_locked).toLowerCase() === 'true') : false;

    return buildResponse(true, {
      mapelCurrent: {
        id: targetMapel.id,
        kode: targetMapel.kode_mata_pelajaran,
        nama: targetMapel.mata_pelajaran
      },
      mapelList: activeMapels.map(m => ({ id: m.id, kode: m.kode_mata_pelajaran, nama: m.mata_pelajaran })),
      siswaNilaiList: siswaNilaiList,
      configRapor: {
        bobot_tugas: existingPr ? Number(existingPr.bobot_tugas) : 40,
        bobot_uts: existingPr ? Number(existingPr.bobot_uts) : 30,
        bobot_uas: existingPr ? Number(existingPr.bobot_uas) : 30,
        predikat: predikatRanges
      },
      summary: {
        totalSiswa: siswaList.length,
        jumlahLengkap: countLengkap,
        persentase: siswaList.length > 0 ? Math.round((countLengkap / siswaList.length) * 100) : 0
      },
      assignment: {
        id: assignment.id,
        kelas: String(assignment.kelas),
        tahunAjaran: activeYear ? activeYear.tahun_ajaran : '-',
        semester: activeYear ? activeYear.semester : '-'
      },
      isReadOnly: isLocked
    }, 'Daftar nilai berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat nilai mata pelajaran.');
  }
}

/**
 * Menyimpan batch nilai mata pelajaran untuk seluruh siswa kelas.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {Object} payload
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiSaveNilaiMataPelajaranBatch(sessionToken, payload) {
  let lock = null;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    if (!payload || typeof payload !== 'object') {
      return buildResponse(false, null, 'Data input nilai tidak valid.');
    }

    const targetMapelId = payload.mata_pelajaran_id ? String(payload.mata_pelajaran_id).trim() : null;
    if (!targetMapelId) {
      return buildResponse(false, null, 'ID mata pelajaran wajib ditentukan.');
    }

    const requestedWkId = payload.wali_kelas_id ? String(payload.wali_kelas_id).trim() : null;
    const { assignment, activeYear } = resolveWaliKelasScope(user, requestedWkId);

    if (!assignment) {
      return buildResponse(false, null, 'Penugasan kelas tidak ditemukan.');
    }

    // Proteksi periode terkunci
    const taData = getSheetDataBatch('tahun_ajaran');
    const ta = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);
    if (ta && (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true')) {
      return buildResponse(false, null, 'Periode akademik telah dikunci. Nilai mata pelajaran bersifat baca-saja.');
    }

    // Pastikan mata pelajaran memang milik penugasan ini
    const mapelData = getSheetDataBatch('mata_pelajaran');
    const mapelItem = mapelData.rows.find(m => m.id === targetMapelId && m.wali_kelas_id === assignment.id);
    if (!mapelItem) {
      return buildResponse(false, null, 'Akses ditolak: Mata pelajaran ini tidak terdaftar pada kelas yang Anda ampu.');
    }

    // Pastikan siswa yang dikirim memang siswa milik penugasan ini
    const sData = getSheetDataBatch('siswa');
    const validSiswaIds = new Set(sData.rows.filter(s => s.wali_kelas_id === assignment.id).map(s => s.id));

    const rows = Array.isArray(payload.rows) ? payload.rows : [];
    if (rows.length === 0) {
      return buildResponse(false, null, 'Tidak ada baris nilai yang dikirim untuk disimpan.');
    }

    // Ambil bobot penilaian untuk kalkulasi
    const prData = getSheetDataBatch('pengaturan_rapor');
    const existingPr = prData.rows.find(p => p.tahun_ajaran_id === assignment.tahun_ajaran_id && p.wali_kelas_id === assignment.id);
    const bobotTugas = existingPr && existingPr.bobot_tugas !== '' ? Number(existingPr.bobot_tugas) : 40;
    const bobotUts = existingPr && existingPr.bobot_uts !== '' ? Number(existingPr.bobot_uts) : 30;
    const bobotUas = existingPr && existingPr.bobot_uas !== '' ? Number(existingPr.bobot_uas) : 30;

    // Helper validasi nilai per sel
    function parseGradeVal(val, fieldName, siswaId) {
      if (val === null || val === undefined || val === '') {
        return '';
      }
      const num = Number(val);
      if (isNaN(num) || num < 0 || num > 100) {
        throw new Error('Nilai ' + fieldName + ' harus berada dalam rentang angka 0 sampai 100.');
      }
      return num;
    }

    const nData = getSheetDataBatch('nilai_mata_pelajaran');
    const nowIso = new Date().toISOString();
    let updatedCount = 0;

    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      if (!r || !r.siswa_id) continue;
      const sId = String(r.siswa_id).trim();

      if (!validSiswaIds.has(sId)) {
        return buildResponse(false, null, 'Akses ditolak: Terdapat siswa yang bukan anggota rombel penugasan ini.');
      }

      const t1 = parseGradeVal(r.nilai_tugas_1, 'Tugas 1', sId);
      const t2 = parseGradeVal(r.nilai_tugas_2, 'Tugas 2', sId);
      const t3 = parseGradeVal(r.nilai_tugas_3, 'Tugas 3', sId);
      const t4 = parseGradeVal(r.nilai_tugas_4, 'Tugas 4', sId);
      const uts = parseGradeVal(r.nilai_uts, 'UTS', sId);
      const uas = parseGradeVal(r.nilai_uas, 'UAS', sId);

      // Rule: Hanya jika seluruh komponen wajib lengkap (T1, T2, T3, T4, UTS, UAS), nilai akhir dihitung.
      // Komponen kosong tidak dianggap 0.
      const isComplete = (t1 !== '' && t2 !== '' && t3 !== '' && t4 !== '' && uts !== '' && uas !== '');
      let nilaiAkhir = '';

      if (isComplete) {
        const rataTugas = (t1 + t2 + t3 + t4) / 4;
        const rawAkhir = (rataTugas * bobotTugas + uts * bobotUts + uas * bobotUas) / 100;
        nilaiAkhir = Math.round(rawAkhir * 100) / 100;
      }

      const existingRecord = nData.rows.find(n => n.siswa_id === sId && n.mata_pelajaran_id === targetMapelId);

      const fieldsToSave = {
        siswa_id: sId,
        mata_pelajaran_id: targetMapelId,
        nilai_tugas_1: t1,
        nilai_tugas_2: t2,
        nilai_tugas_3: t3,
        nilai_tugas_4: t4,
        nilai_uts: uts,
        nilai_uas: uas,
        nilai_akhir: nilaiAkhir,
        is_complete: isComplete,
        updated_at: nowIso
      };

      if (existingRecord) {
        updateSheetRow('nilai_mata_pelajaran', existingRecord._rowIndex, fieldsToSave);
      } else {
        fieldsToSave.id = getStableUUID();
        fieldsToSave.created_at = nowIso;
        appendSheetRow('nilai_mata_pelajaran', fieldsToSave);
      }
      updatedCount++;
    }

    return buildResponse(true, { updatedCount: updatedCount }, 'Nilai mata pelajaran ' + mapelItem.mata_pelajaran + ' berhasil disimpan.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menyimpan nilai mata pelajaran.');
  } finally {
    if (lock) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

/**
 * Mengambil daftar penilaian sikap siswa di kelas penugasan.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {string} [requestedWaliKelasId]
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiGetNilaiSikapList(sessionToken, requestedWaliKelasId) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);
    const { assignment, activeYear } = resolveWaliKelasScope(user, requestedWaliKelasId);

    if (!assignment) {
      return buildResponse(false, null, 'Data penugasan kelas tidak ditemukan.');
    }

    const sData = getSheetDataBatch('siswa');
    const siswaList = sData.rows.filter(s =>
      s.wali_kelas_id === assignment.id &&
      (s.is_active === true || String(s.is_active).toLowerCase() === 'true')
    );
    siswaList.sort((a, b) => (Number(a.no_absen) || 0) - (Number(b.no_absen) || 0));

    let skData = { rows: [] };
    try {
      skData = getSheetDataBatch('nilai_sikap');
    } catch (e) {}

    let countLengkap = 0;

    const siswaSikapList = siswaList.map(s => {
      const existing = skData.rows.find(n => n.siswa_id === s.id);
      const hasPredikat = existing && existing.predikat && String(existing.predikat).trim() !== '';
      if (hasPredikat) {
        countLengkap++;
      }

      return {
        id: existing ? existing.id : null,
        siswa_id: s.id,
        no_absen: Number(s.no_absen) || 0,
        nama: s.nama,
        nisn: s.nisn || '-',
        predikat: existing ? existing.predikat : '',
        deskripsi: existing ? existing.deskripsi : ''
      };
    });

    const isLocked = activeYear ? (activeYear.is_locked === true || String(activeYear.is_locked).toLowerCase() === 'true') : false;

    return buildResponse(true, {
      siswaSikapList: siswaSikapList,
      summary: {
        totalSiswa: siswaList.length,
        jumlahLengkap: countLengkap,
        persentase: siswaList.length > 0 ? Math.round((countLengkap / siswaList.length) * 100) : 0
      },
      assignment: {
        id: assignment.id,
        kelas: String(assignment.kelas),
        tahunAjaran: activeYear ? activeYear.tahun_ajaran : '-',
        semester: activeYear ? activeYear.semester : '-'
      },
      isReadOnly: isLocked
    }, 'Daftar penilaian sikap berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat penilaian sikap.');
  }
}

/**
 * Menyimpan batch penilaian sikap siswa.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {Object} payload
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiSaveNilaiSikapBatch(sessionToken, payload) {
  let lock = null;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    if (!payload || typeof payload !== 'object') {
      return buildResponse(false, null, 'Data penilaian sikap tidak valid.');
    }

    const requestedWkId = payload.wali_kelas_id ? String(payload.wali_kelas_id).trim() : null;
    const { assignment, activeYear } = resolveWaliKelasScope(user, requestedWkId);

    if (!assignment) {
      return buildResponse(false, null, 'Penugasan kelas tidak ditemukan.');
    }

    // Proteksi periode terkunci
    const taData = getSheetDataBatch('tahun_ajaran');
    const ta = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);
    if (ta && (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true')) {
      return buildResponse(false, null, 'Periode akademik telah dikunci. Penilaian sikap bersifat baca-saja.');
    }

    const sData = getSheetDataBatch('siswa');
    const validSiswaIds = new Set(sData.rows.filter(s => s.wali_kelas_id === assignment.id).map(s => s.id));

    const rows = Array.isArray(payload.rows) ? payload.rows : [];
    if (rows.length === 0) {
      return buildResponse(false, null, 'Tidak ada baris nilai sikap yang dikirim untuk disimpan.');
    }

    const validPredikats = new Set(['Sangat Baik', 'Baik', 'Cukup', 'Kurang', 'A', 'B', 'C', 'D']);
    const skData = getSheetDataBatch('nilai_sikap');
    const nowIso = new Date().toISOString();
    let updatedCount = 0;

    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      if (!r || !r.siswa_id) continue;
      const sId = String(r.siswa_id).trim();

      if (!validSiswaIds.has(sId)) {
        return buildResponse(false, null, 'Akses ditolak: Terdapat siswa yang bukan anggota rombel penugasan ini.');
      }

      const cleanPredikat = r.predikat ? String(r.predikat).trim() : '';
      if (cleanPredikat && !validPredikats.has(cleanPredikat)) {
        return buildResponse(false, null, 'Predikat sikap "' + cleanPredikat + '" tidak valid. Pilihan yang diizinkan: Sangat Baik, Baik, Cukup, Kurang.');
      }

      const cleanDeskripsi = r.deskripsi ? String(r.deskripsi).trim() : '';

      const existingRecord = skData.rows.find(n => n.siswa_id === sId);

      const fieldsToSave = {
        siswa_id: sId,
        predikat: cleanPredikat,
        deskripsi: cleanDeskripsi,
        updated_at: nowIso
      };

      if (existingRecord) {
        updateSheetRow('nilai_sikap', existingRecord._rowIndex, fieldsToSave);
      } else {
        fieldsToSave.id = getStableUUID();
        fieldsToSave.created_at = nowIso;
        appendSheetRow('nilai_sikap', fieldsToSave);
      }
      updatedCount++;
    }

    return buildResponse(true, { updatedCount: updatedCount }, 'Penilaian sikap berhasil disimpan.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menyimpan penilaian sikap.');
  } finally {
    if (lock) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

/**
 * Mengambil rekap kehadiran siswa di kelas penugasan.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {string} [requestedWaliKelasId]
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiGetRekapKehadiranList(sessionToken, requestedWaliKelasId) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);
    const { assignment, activeYear } = resolveWaliKelasScope(user, requestedWaliKelasId);

    if (!assignment) {
      return buildResponse(false, null, 'Data penugasan kelas tidak ditemukan.');
    }

    const sData = getSheetDataBatch('siswa');
    const siswaList = sData.rows.filter(s =>
      s.wali_kelas_id === assignment.id &&
      (s.is_active === true || String(s.is_active).toLowerCase() === 'true')
    );
    siswaList.sort((a, b) => (Number(a.no_absen) || 0) - (Number(b.no_absen) || 0));

    let rkData = { rows: [] };
    try {
      rkData = getSheetDataBatch('rekap_kehadiran');
    } catch (e) {}

    let totalHadir = 0;
    let totalSakit = 0;
    let totalIzin = 0;
    let totalAlpha = 0;
    let countFilled = 0;

    const siswaKehadiranList = siswaList.map(s => {
      const existing = rkData.rows.find(r => r.siswa_id === s.id);
      const jHadir = existing && existing.jumlah_hadir !== '' && existing.jumlah_hadir !== null ? Number(existing.jumlah_hadir) : '';
      const jSakit = existing && existing.jumlah_sakit !== '' && existing.jumlah_sakit !== null ? Number(existing.jumlah_sakit) : '';
      const jIzin = existing && existing.jumlah_izin !== '' && existing.jumlah_izin !== null ? Number(existing.jumlah_izin) : '';
      const jAlpha = existing && existing.jumlah_alpha !== '' && existing.jumlah_alpha !== null ? Number(existing.jumlah_alpha) : '';

      if (jHadir !== '' || jSakit !== '' || jIzin !== '' || jAlpha !== '') {
        countFilled++;
      }

      if (jHadir !== '') totalHadir += jHadir;
      if (jSakit !== '') totalSakit += jSakit;
      if (jIzin !== '') totalIzin += jIzin;
      if (jAlpha !== '') totalAlpha += jAlpha;

      return {
        id: existing ? existing.id : null,
        siswa_id: s.id,
        no_absen: Number(s.no_absen) || 0,
        nama: s.nama,
        nisn: s.nisn || '-',
        jumlah_hadir: jHadir,
        jumlah_sakit: jSakit,
        jumlah_izin: jIzin,
        jumlah_alpha: jAlpha,
        keterangan: existing ? existing.keterangan : ''
      };
    });

    const isLocked = activeYear ? (activeYear.is_locked === true || String(activeYear.is_locked).toLowerCase() === 'true') : false;

    return buildResponse(true, {
      siswaKehadiranList: siswaKehadiranList,
      totals: {
        hadir: totalHadir,
        sakit: totalSakit,
        izin: totalIzin,
        alpha: totalAlpha
      },
      summary: {
        totalSiswa: siswaList.length,
        jumlahLengkap: countFilled,
        persentase: siswaList.length > 0 ? Math.round((countFilled / siswaList.length) * 100) : 0
      },
      assignment: {
        id: assignment.id,
        kelas: String(assignment.kelas),
        tahunAjaran: activeYear ? activeYear.tahun_ajaran : '-',
        semester: activeYear ? activeYear.semester : '-'
      },
      isReadOnly: isLocked
    }, 'Rekap kehadiran berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat rekap kehadiran.');
  }
}

/**
 * Menyimpan batch rekap kehadiran siswa.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {Object} payload
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiSaveRekapKehadiranBatch(sessionToken, payload) {
  let lock = null;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    if (!payload || typeof payload !== 'object') {
      return buildResponse(false, null, 'Data rekap kehadiran tidak valid.');
    }

    const requestedWkId = payload.wali_kelas_id ? String(payload.wali_kelas_id).trim() : null;
    const { assignment, activeYear } = resolveWaliKelasScope(user, requestedWkId);

    if (!assignment) {
      return buildResponse(false, null, 'Penugasan kelas tidak ditemukan.');
    }

    // Proteksi periode terkunci
    const taData = getSheetDataBatch('tahun_ajaran');
    const ta = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);
    if (ta && (ta.is_locked === true || String(ta.is_locked).toLowerCase() === 'true')) {
      return buildResponse(false, null, 'Periode akademik telah dikunci. Rekap kehadiran bersifat baca-saja.');
    }

    const sData = getSheetDataBatch('siswa');
    const validSiswaIds = new Set(sData.rows.filter(s => s.wali_kelas_id === assignment.id).map(s => s.id));

    const rows = Array.isArray(payload.rows) ? payload.rows : [];
    if (rows.length === 0) {
      return buildResponse(false, null, 'Tidak ada baris kehadiran yang dikirim untuk disimpan.');
    }

    function parseAttendanceVal(val, fieldName) {
      if (val === null || val === undefined || val === '') {
        return '';
      }
      const num = parseInt(val, 10);
      if (isNaN(num) || num < 0) {
        throw new Error('Jumlah ' + fieldName + ' harus berupa bilangan bulat tidak negatif (minimal 0).');
      }
      return num;
    }

    const rkData = getSheetDataBatch('rekap_kehadiran');
    const nowIso = new Date().toISOString();
    let updatedCount = 0;

    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      if (!r || !r.siswa_id) continue;
      const sId = String(r.siswa_id).trim();

      if (!validSiswaIds.has(sId)) {
        return buildResponse(false, null, 'Akses ditolak: Terdapat siswa yang bukan anggota rombel penugasan ini.');
      }

      const jHadir = parseAttendanceVal(r.jumlah_hadir, 'hadir');
      const jSakit = parseAttendanceVal(r.jumlah_sakit, 'sakit');
      const jIzin = parseAttendanceVal(r.jumlah_izin, 'izin');
      const jAlpha = parseAttendanceVal(r.jumlah_alpha, 'alpa');
      const cleanKet = r.keterangan ? String(r.keterangan).trim() : '';

      const existingRecord = rkData.rows.find(rec => rec.siswa_id === sId);

      const fieldsToSave = {
        siswa_id: sId,
        jumlah_hadir: jHadir,
        jumlah_sakit: jSakit,
        jumlah_izin: jIzin,
        jumlah_alpha: jAlpha,
        keterangan: cleanKet,
        updated_at: nowIso
      };

      if (existingRecord) {
        updateSheetRow('rekap_kehadiran', existingRecord._rowIndex, fieldsToSave);
      } else {
        fieldsToSave.id = getStableUUID();
        fieldsToSave.created_at = nowIso;
        appendSheetRow('rekap_kehadiran', fieldsToSave);
      }
      updatedCount++;
    }

    return buildResponse(true, { updatedCount: updatedCount }, 'Rekap kehadiran berhasil disimpan.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal menyimpan rekap kehadiran.');
  } finally {
    if (lock) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

/**
 * Mengambil ringkasan indikator kelengkapan penilaian kelas.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 *
 * @param {string} sessionToken
 * @param {string} [requestedWaliKelasId]
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiGetKelengkapanPenilaian(sessionToken, requestedWaliKelasId) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    const sData = getSheetDataBatch('siswa');
    const mData = getSheetDataBatch('mata_pelajaran');
    const wkData = getSheetDataBatch('wali_kelas');
    const taData = getSheetDataBatch('tahun_ajaran');
    const uData = getSheetDataBatch('user');

    let nData = { rows: [] };
    let skData = { rows: [] };
    let rkData = { rows: [] };
    try { nData = getSheetDataBatch('nilai_mata_pelajaran'); } catch (e) {}
    try { skData = getSheetDataBatch('nilai_sikap'); } catch (e) {}
    try { rkData = getSheetDataBatch('rekap_kehadiran'); } catch (e) {}

    const activeYear = taData.rows.find(t => t.is_active === true || String(t.is_active).toLowerCase() === 'true');

    // Jika kepala sekolah memanggil tanpa filter: sajikan ringkasan 6 kelas
    if (user.role === 'kepala_sekolah' && !requestedWaliKelasId) {
      const activeAssignments = wkData.rows.filter(w =>
        activeYear && w.tahun_ajaran_id === activeYear.id &&
        (w.is_active === true || String(w.is_active).toLowerCase() === 'true')
      );

      const classOverviews = [1, 2, 3, 4, 5, 6].map(kelasNum => {
        const assignment = activeAssignments.find(w => Number(w.kelas) === kelasNum);
        if (!assignment) {
          return {
            kelas: String(kelasNum),
            waliKelasNama: '-',
            hasPenugasan: false,
            siswaCount: 0,
            mapelCount: 0,
            nilaiPercent: 0,
            sikapPercent: 0,
            kehadiranPercent: 0,
            statusLabel: 'Belum Ada Wali Kelas'
          };
        }

        const teacher = uData.rows.find(u => u.id === assignment.user_id);
        const activeSiswa = sData.rows.filter(s => s.wali_kelas_id === assignment.id && (s.is_active === true || String(s.is_active).toLowerCase() === 'true'));
        const activeMapels = mData.rows.filter(m => m.wali_kelas_id === assignment.id && (m.is_active === true || String(m.is_active).toLowerCase() === 'true'));

        const totalExpectedGrades = activeSiswa.length * activeMapels.length;
        let countCompleteGrades = 0;
        activeSiswa.forEach(s => {
          activeMapels.forEach(m => {
            const grade = nData.rows.find(n => n.siswa_id === s.id && n.mata_pelajaran_id === m.id);
            if (grade && (grade.is_complete === true || String(grade.is_complete).toLowerCase() === 'true')) {
              countCompleteGrades++;
            }
          });
        });

        const countSikap = activeSiswa.filter(s => skData.rows.some(sk => sk.siswa_id === s.id && sk.predikat && String(sk.predikat).trim() !== '')).length;
        const countKehadiran = activeSiswa.filter(s => rkData.rows.some(rk => rk.siswa_id === s.id && (rk.jumlah_hadir !== '' || rk.jumlah_sakit !== '' || rk.jumlah_izin !== '' || rk.jumlah_alpha !== ''))).length;

        const nilaiPct = totalExpectedGrades > 0 ? Math.round((countCompleteGrades / totalExpectedGrades) * 100) : 0;
        const sikapPct = activeSiswa.length > 0 ? Math.round((countSikap / activeSiswa.length) * 100) : 0;
        const kehadiranPct = activeSiswa.length > 0 ? Math.round((countKehadiran / activeSiswa.length) * 100) : 0;

        let statusLabel = 'Belum Lengkap';
        if (nilaiPct === 100 && sikapPct === 100 && kehadiranPct === 100) {
          statusLabel = 'Lengkap';
        } else if (nilaiPct > 0 || sikapPct > 0 || kehadiranPct > 0) {
          statusLabel = 'Sebagian';
        }

        return {
          kelas: String(kelasNum),
          assignmentId: assignment.id,
          waliKelasNama: teacher ? teacher.nama : '-',
          hasPenugasan: true,
          siswaCount: activeSiswa.length,
          mapelCount: activeMapels.length,
          nilaiPercent: nilaiPct,
          sikapPercent: sikapPct,
          kehadiranPercent: kehadiranPct,
          statusLabel: statusLabel
        };
      });

      return buildResponse(true, {
        isMultiClass: true,
        classes: classOverviews,
        activeYear: activeYear ? activeYear.tahun_ajaran + ' ' + activeYear.semester : '-'
      }, 'Data pemantauan kelengkapan sekolah berhasil dimuat.');
    }

    // Detail kelas tunggal
    const { assignment } = resolveWaliKelasScope(user, requestedWaliKelasId);
    if (!assignment) {
      return buildResponse(false, null, 'Data penugasan kelas tidak ditemukan.');
    }

    const activeSiswa = sData.rows.filter(s => s.wali_kelas_id === assignment.id && (s.is_active === true || String(s.is_active).toLowerCase() === 'true'));
    const activeMapels = mData.rows.filter(m => m.wali_kelas_id === assignment.id && (m.is_active === true || String(m.is_active).toLowerCase() === 'true'));
    activeMapels.sort((a, b) => a.kode_mata_pelajaran.localeCompare(b.kode_mata_pelajaran));

    const mapelProgress = activeMapels.map(m => {
      let lengkap = 0;
      activeSiswa.forEach(s => {
        const grade = nData.rows.find(n => n.siswa_id === s.id && n.mata_pelajaran_id === m.id);
        if (grade && (grade.is_complete === true || String(grade.is_complete).toLowerCase() === 'true')) {
          lengkap++;
        }
      });
      return {
        id: m.id,
        kode: m.kode_mata_pelajaran,
        nama: m.mata_pelajaran,
        totalSiswa: activeSiswa.length,
        jumlahLengkap: lengkap,
        persentase: activeSiswa.length > 0 ? Math.round((lengkap / activeSiswa.length) * 100) : 0
      };
    });

    const countSikap = activeSiswa.filter(s => skData.rows.some(sk => sk.siswa_id === s.id && sk.predikat && String(sk.predikat).trim() !== '')).length;
    const countKehadiran = activeSiswa.filter(s => rkData.rows.some(rk => rk.siswa_id === s.id && (rk.jumlah_hadir !== '' || rk.jumlah_sakit !== '' || rk.jumlah_izin !== '' || rk.jumlah_alpha !== ''))).length;

    const totalExpectedGrades = activeSiswa.length * activeMapels.length;
    let totalLengkapGrades = 0;
    mapelProgress.forEach(mp => { totalLengkapGrades += mp.jumlahLengkap; });

    const totalNilaiPct = totalExpectedGrades > 0 ? Math.round((totalLengkapGrades / totalExpectedGrades) * 100) : 0;
    const totalSikapPct = activeSiswa.length > 0 ? Math.round((countSikap / activeSiswa.length) * 100) : 0;
    const totalKehadiranPct = activeSiswa.length > 0 ? Math.round((countKehadiran / activeSiswa.length) * 100) : 0;

    let overallStatus = 'Belum Lengkap';
    if (totalNilaiPct === 100 && totalSikapPct === 100 && totalKehadiranPct === 100) {
      overallStatus = 'Lengkap';
    } else if (totalNilaiPct > 0 || totalSikapPct > 0 || totalKehadiranPct > 0) {
      overallStatus = 'Sebagian';
    }

    return buildResponse(true, {
      isMultiClass: false,
      assignmentId: assignment.id,
      kelas: String(assignment.kelas),
      siswaCount: activeSiswa.length,
      mapelCount: activeMapels.length,
      mapelProgress: mapelProgress,
      sikapProgress: {
        totalSiswa: activeSiswa.length,
        jumlahLengkap: countSikap,
        persentase: totalSikapPct
      },
      kehadiranProgress: {
        totalSiswa: activeSiswa.length,
        jumlahLengkap: countKehadiran,
        persentase: totalKehadiranPct
      },
      overallStatus: overallStatus,
      totalNilaiPercent: totalNilaiPct,
      totalSikapPercent: totalSikapPct,
      totalKehadiranPercent: totalKehadiranPct
    }, 'Kelengkapan penilaian kelas berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat kelengkapan penilaian.');
  }
}

// ============================================================================
// 7. ENDPOINT PHASE 7: DASHBOARD, RANKING SISWA, & RAPOR DIGITAL
// ============================================================================

/**
 * Menghitung ranking kompetisi standar (Competition Ranking: 1, 2, 2, 4)
 * berdasarkan rata-rata nilai akhir seluruh mata pelajaran yang lengkap.
 *
 * Aturan:
 * - Nilai akhir kosong BUKAN nol.
 * - Rata-rata nilai agregat hanya dihitung dari mata pelajaran yang telah lengkap.
 * - Jika kelas belum 100% lengkap seluruh mapel dan siswanya, status berlabel "Sementara".
 * - Aturan tie: nilai rata-rata sama memperoleh ranking yang sama (1, 2, 2, 4).
 *
 * @param {string} assignmentId
 * @param {Object} [cachedData]
 * @return {{
 *   rankedStudents: Array<Object>,
 *   isClassAllComplete: boolean,
 *   rankingStatus: string,
 *   totalSiswa: number,
 *   activeMapels: Array<Object>,
 *   predikatRanges: Array<Object>
 * }}
 */
function calculateClassRanking(assignmentId, cachedData) {
  let sData = (cachedData && cachedData.sData);
  let mData = (cachedData && cachedData.mData);
  let nData = (cachedData && cachedData.nData);
  let prData = (cachedData && cachedData.prData);
  let wkData = (cachedData && cachedData.wkData);

  try { if (!sData) sData = getSheetDataBatch('siswa'); } catch (e) { sData = { rows: [] }; }
  try { if (!mData) mData = getSheetDataBatch('mata_pelajaran'); } catch (e) { mData = { rows: [] }; }
  try { if (!nData) nData = getSheetDataBatch('nilai_mata_pelajaran'); } catch (e) { nData = { rows: [] }; }
  try { if (!prData) prData = getSheetDataBatch('pengaturan_rapor'); } catch (e) { prData = { rows: [] }; }
  try { if (!wkData) wkData = getSheetDataBatch('wali_kelas'); } catch (e) { wkData = { rows: [] }; }

  const assignment = wkData.rows.find(w => w.id === assignmentId);
  const activeSiswa = sData.rows.filter(s =>
    s.wali_kelas_id === assignmentId &&
    (s.is_active === true || String(s.is_active).toLowerCase() === 'true')
  );
  activeSiswa.sort((a, b) => (Number(a.no_absen) || 0) - (Number(b.no_absen) || 0));

  const activeMapels = mData.rows.filter(m =>
    m.wali_kelas_id === assignmentId &&
    (m.is_active === true || String(m.is_active).toLowerCase() === 'true')
  );
  activeMapels.sort((a, b) => (a.kode_mata_pelajaran || a.kode || '').localeCompare(b.kode_mata_pelajaran || b.kode || ''));

  let predikatRanges = [
    { label: 'A', min: 90, max: 100 },
    { label: 'B', min: 80, max: 89.99 },
    { label: 'C', min: 70, max: 79.99 },
    { label: 'D', min: 0, max: 69.99 }
  ];
  if (assignment) {
    const prRow = prData.rows.find(p => p.wali_kelas_id === assignment.id && p.tahun_ajaran_id === assignment.tahun_ajaran_id);
    if (prRow && prRow.predikat) {
      try {
        const parsed = typeof prRow.predikat === 'string' ? JSON.parse(prRow.predikat) : prRow.predikat;
        if (Array.isArray(parsed) && parsed.length > 0) {
          predikatRanges = parsed;
        }
      } catch (e) {}
    }
  }

  // Evaluasi nilai tiap siswa
  const studentStats = activeSiswa.map(s => {
    const mapelScores = {};
    let completedCount = 0;
    let sumScore = 0;

    activeMapels.forEach(m => {
      const grade = nData.rows.find(n => n.siswa_id === s.id && n.mata_pelajaran_id === m.id);
      const isComplete = grade ? (grade.is_complete === true || String(grade.is_complete).toLowerCase() === 'true') : false;
      const hasFinal = grade && grade.nilai_akhir !== '' && grade.nilai_akhir !== null && !isNaN(grade.nilai_akhir);

      if (isComplete && hasFinal) {
        const score = Number(grade.nilai_akhir);
        completedCount++;
        sumScore += score;
        mapelScores[m.id] = {
          nilai_akhir: score,
          predikat: resolvePredikatScore(score, predikatRanges),
          is_complete: true
        };
      } else {
        mapelScores[m.id] = {
          nilai_akhir: '',
          predikat: '-',
          is_complete: false
        };
      }
    });

    const isStudentAllComplete = (activeMapels.length > 0 && completedCount === activeMapels.length);
    const avgScore = completedCount > 0 ? Math.round((sumScore / completedCount) * 100) / 100 : null;

    return {
      siswa_id: s.id,
      no_absen: Number(s.no_absen) || 0,
      nisn: s.nisn || '-',
      nis: s.nis || '-',
      nama: s.nama,
      jenis_kelamin: s.jenis_kelamin,
      mapel_scores: mapelScores,
      completedMapelCount: completedCount,
      totalMapelCount: activeMapels.length,
      isStudentComplete: isStudentAllComplete,
      sumScore: sumScore,
      avgScore: avgScore,
      rank: null
    };
  });

  // Apakah kelas 100% lengkap seluruh siswa dan mapel?
  const isClassAllComplete = (activeSiswa.length > 0 && activeMapels.length > 0 && studentStats.every(st => st.isStudentComplete));
  const rankingStatus = isClassAllComplete ? 'Final' : 'Sementara';

  // Urutkan siswa untuk Standard Competition Ranking (1, 2, 2, 4)
  // Siswa yang belum lengkap nilainya TIDAK layak diranking numerik (diberi rank '-')
  const completeStudents = studentStats.filter(st => st.isStudentComplete && st.avgScore !== null);
  const incompleteStudents = studentStats.filter(st => !st.isStudentComplete || st.avgScore === null);

  completeStudents.sort((a, b) => {
    if (b.avgScore !== a.avgScore) return b.avgScore - a.avgScore;
    return a.no_absen - b.no_absen;
  });

  incompleteStudents.sort((a, b) => a.no_absen - b.no_absen);

  for (let i = 0; i < completeStudents.length; i++) {
    const cur = completeStudents[i];
    if (i === 0) {
      cur.rank = 1;
    } else {
      const prev = completeStudents[i - 1];
      if (prev.avgScore === cur.avgScore) {
        cur.rank = prev.rank; // Tied rank
      } else {
        cur.rank = i + 1; // Competition rank skip
      }
    }
  }

  for (let j = 0; j < incompleteStudents.length; j++) {
    incompleteStudents[j].rank = '-';
  }

  const allRanked = [...completeStudents, ...incompleteStudents];

  return {
    rankedStudents: allRanked,
    isClassAllComplete: isClassAllComplete,
    rankingStatus: rankingStatus,
    totalSiswa: activeSiswa.length,
    activeMapels: activeMapels,
    predikatRanges: predikatRanges
  };
}

/**
 * Mengambil rekapitulasi rapor digital seluruh siswa pada satu kelas penugasan.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 * IDOR Guard: Wali kelas hanya boleh memuat rapor rombel yang diampunya.
 *
 * @param {string} sessionToken
 * @param {string} [requestedWaliKelasId]
 * @param {string} [sortBy] - 'no_absen', 'ranking', 'nama', 'nilai_agregat'
 * @param {string} [sortOrder] - 'asc', 'desc'
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiGetRaporDigitalKelas(sessionToken, requestedWaliKelasId, sortBy, sortOrder) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);
    const { assignment, activeYear } = resolveWaliKelasScope(user, requestedWaliKelasId);

    if (!assignment) {
      return buildResponse(false, null, 'Data penugasan kelas tidak ditemukan.');
    }

    const sData = getSheetDataBatch('siswa');
    const mData = getSheetDataBatch('mata_pelajaran');
    const uData = getSheetDataBatch('user');
    const wkData = getSheetDataBatch('wali_kelas');
    const taData = getSheetDataBatch('tahun_ajaran');
    const pengData = getSheetDataBatch('pengaturan');

    let nData = { rows: [] };
    let skData = { rows: [] };
    let rkData = { rows: [] };
    let prData = { rows: [] };
    try { nData = getSheetDataBatch('nilai_mata_pelajaran'); } catch (e) {}
    try { skData = getSheetDataBatch('nilai_sikap'); } catch (e) {}
    try { rkData = getSheetDataBatch('rekap_kehadiran'); } catch (e) {}
    try { prData = getSheetDataBatch('pengaturan_rapor'); } catch (e) {}

    // Profil Sekolah
    const schoolRow = pengData.rows[0] || {};
    const schoolProfile = {
      namaSekolah: schoolRow.nama_sekolah || '',
      namaKepalaSekolah: schoolRow.nama_kepala_sekolah || '',
      nipKepalaSekolah: schoolRow.nip_kepala_sekolah || '',
      logoSekolah: schoolRow.logo_sekolah || ''
    };

    // Identitas Guru Wali Kelas
    const teacher = uData.rows.find(u => u.id === assignment.user_id);
    const teacherInfo = {
      nama: teacher ? teacher.nama : '-',
      nip: teacher ? (teacher.nip || '-') : '-'
    };

    // Hitung ranking kompetisi
    const rankingRes = calculateClassRanking(assignment.id, { sData, mData, nData, prData, wkData });
    const rankedStudents = rankingRes.rankedStudents;

    let readyCount = 0;
    let notReadyCount = 0;

    // Pasangkan nilai sikap, kehadiran, dan kesiapan rapor per siswa
    const studentsWithRapor = rankedStudents.map(st => {
      const sikapRow = skData.rows.find(sk => sk.siswa_id === st.siswa_id);
      const sikapPredikat = sikapRow && sikapRow.predikat ? String(sikapRow.predikat).trim() : '';
      const sikapDeskripsi = sikapRow && sikapRow.deskripsi ? String(sikapRow.deskripsi).trim() : '';
      const hasSikap = sikapPredikat !== '';

      const attRow = rkData.rows.find(rk => rk.siswa_id === st.siswa_id);
      const jHadir = attRow && attRow.jumlah_hadir !== '' && attRow.jumlah_hadir !== null ? Number(attRow.jumlah_hadir) : '';
      const jSakit = attRow && attRow.jumlah_sakit !== '' && attRow.jumlah_sakit !== null ? Number(attRow.jumlah_sakit) : '';
      const jIzin = attRow && attRow.jumlah_izin !== '' && attRow.jumlah_izin !== null ? Number(attRow.jumlah_izin) : '';
      const jAlpha = attRow && attRow.jumlah_alpha !== '' && attRow.jumlah_alpha !== null ? Number(attRow.jumlah_alpha) : '';
      const hasKehadiran = (jHadir !== '' || jSakit !== '' || jIzin !== '' || jAlpha !== '');

      const isRaporSiap = st.isStudentComplete && hasSikap && hasKehadiran;
      if (isRaporSiap) {
        readyCount++;
      } else {
        notReadyCount++;
      }

      return {
        id: st.siswa_id,
        siswa_id: st.siswa_id,
        no_absen: st.no_absen,
        nisn: st.nisn,
        nis: st.nis,
        nama: st.nama,
        jenis_kelamin: st.jenis_kelamin,
        grades: st.mapel_scores,
        mapel_scores: st.mapel_scores,
        completedMapelCount: st.completedMapelCount,
        totalMapelCount: st.totalMapelCount,
        isStudentComplete: st.isStudentComplete,
        sumScore: st.sumScore,
        avgScore: st.avgScore,
        rank: st.rank,
        ranking_label: rankingRes.rankingStatus,
        sikap: {
          predikat: sikapPredikat || '-',
          deskripsi: sikapDeskripsi,
          isComplete: hasSikap
        },
        sikapSummary: {
          predikat: sikapPredikat || '-',
          deskripsi: sikapDeskripsi,
          isComplete: hasSikap
        },
        kehadiran: {
          hadir: jHadir !== '' ? jHadir : '-',
          sakit: jSakit !== '' ? jSakit : '-',
          izin: jIzin !== '' ? jIzin : '-',
          alpha: jAlpha !== '' ? jAlpha : '-',
          keterangan: attRow ? (attRow.keterangan || '') : '',
          isComplete: hasKehadiran
        },
        kehadiranSummary: {
          hadir: jHadir !== '' ? jHadir : '-',
          sakit: jSakit !== '' ? jSakit : '-',
          izin: jIzin !== '' ? jIzin : '-',
          alpha: jAlpha !== '' ? jAlpha : '-',
          keterangan: attRow ? (attRow.keterangan || '') : '',
          isComplete: hasKehadiran
        },
        isRaporSiap: isRaporSiap
      };
    });

    // Urutkan siswa sesuai permintaan
    const cleanSortBy = sortBy || 'no_absen';
    const cleanOrder = sortOrder === 'desc' ? -1 : 1;

    studentsWithRapor.sort((a, b) => {
      if (cleanSortBy === 'ranking') {
        if (a.rank !== '-' && b.rank !== '-') {
          return (Number(a.rank) - Number(b.rank)) * cleanOrder;
        }
        if (a.rank !== '-' && b.rank === '-') return -1;
        if (a.rank === '-' && b.rank !== '-') return 1;
        return a.no_absen - b.no_absen;
      }
      if (cleanSortBy === 'nilai_agregat') {
        if (a.avgScore !== null && b.avgScore !== null) {
          return (a.avgScore - b.avgScore) * cleanOrder;
        }
        if (a.avgScore !== null && b.avgScore === null) return -1;
        if (a.avgScore === null && b.avgScore !== null) return 1;
        return a.no_absen - b.no_absen;
      }
      if (cleanSortBy === 'nama') {
        return a.nama.localeCompare(b.nama) * cleanOrder;
      }
      // Default: no_absen
      return (a.no_absen - b.no_absen) * cleanOrder;
    });

    // Opsi penugasan kelas yang tersedia bagi Kepala Sekolah
    let availableAssignments = [];
    if (user.role === 'kepala_sekolah') {
      const activeTa = activeYear ? activeYear.id : (assignment ? assignment.tahun_ajaran_id : null);
      availableAssignments = wkData.rows
        .filter(w => !activeTa || w.tahun_ajaran_id === activeTa)
        .map(w => {
          const t = uData.rows.find(u => u.id === w.user_id);
          return {
            id: w.id,
            penugasanId: w.id,
            kelas: String(w.kelas),
            guruNama: t ? t.nama : '-',
            waliKelasNama: t ? t.nama : '-',
            isActive: (w.is_active === true || String(w.is_active).toLowerCase() === 'true')
          };
        })
        .sort((a, b) => Number(a.kelas) - Number(b.kelas));
    }

    const isLocked = activeYear ? (activeYear.is_locked === true || String(activeYear.is_locked).toLowerCase() === 'true') : false;

    const assignmentPayload = {
      id: assignment.id,
      kelas: String(assignment.kelas),
      tahunAjaran: activeYear ? activeYear.tahun_ajaran : '-',
      semester: activeYear ? activeYear.semester : '-',
      isLocked: isLocked,
      waliKelasNama: teacherInfo.nama,
      waliKelasNip: teacherInfo.nip
    };

    return buildResponse(true, {
      schoolProfile: schoolProfile,
      pengaturan: schoolProfile,
      assignment: assignmentPayload,
      waliKelas: assignmentPayload,
      tahunAjaran: {
        tahun_ajaran: activeYear ? activeYear.tahun_ajaran : '-',
        semester: activeYear ? activeYear.semester : '-'
      },
      mapelList: rankingRes.activeMapels.map(m => ({ id: m.id, kode: m.kode_mata_pelajaran, nama: m.mata_pelajaran })),
      predikatRanges: rankingRes.predikatRanges,
      students: studentsWithRapor,
      summary: {
        totalSiswa: rankingRes.totalSiswa,
        raporSiapCount: readyCount,
        raporBelumSiapCount: notReadyCount,
        isClassAllComplete: rankingRes.isClassAllComplete,
        rankingStatus: rankingRes.rankingStatus
      },
      raporSiapCount: readyCount,
      raporBelumSiapCount: notReadyCount,
      rankingStatus: rankingRes.rankingStatus,
      availableAssignments: availableAssignments,
      availableClasses: availableAssignments,
      isReadOnly: isLocked
    }, 'Data rapor digital kelas berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat rapor digital kelas.');
  }
}

/**
 * Mengambil dokumen rapor digital individual siswa untuk tampilan pratinjau dan cetak A4/F4.
 * Otorisasi: kepala_sekolah atau wali_kelas.
 * IDOR Guard: Wali kelas hanya boleh memuat rapor siswa di kelas binaannya.
 *
 * @param {string} sessionToken
 * @param {string} siswaId
 * @return {{ success: boolean, data: Object|null, message: string }}
 */
function apiGetRaporDigitalSiswa(sessionToken, siswaId) {
  try {
    const user = requireAuth(sessionToken, ['kepala_sekolah', 'wali_kelas']);

    if (!siswaId || typeof siswaId !== 'string') {
      return buildResponse(false, null, 'ID siswa wajib disertakan.');
    }

    const cleanSiswaId = String(siswaId).trim();
    const sData = getSheetDataBatch('siswa');
    // Siswa historis (misal di tahun ajaran lampau) tetap harus bisa diakses rapornya
    const student = sData.rows.find(s => s.id === cleanSiswaId);

    if (!student) {
      return buildResponse(false, null, 'Data siswa tidak ditemukan.');
    }

    const wkData = getSheetDataBatch('wali_kelas');
    const assignment = wkData.rows.find(w => w.id === student.wali_kelas_id);

    if (!assignment) {
      return buildResponse(false, null, 'Data penugasan kelas siswa tidak ditemukan.');
    }

    // Proteksi IDOR: Wali kelas hanya boleh melihat siswa di rombel kelas yang diampunya
    if (user.role === 'wali_kelas') {
      if (assignment.user_id !== user.id) {
        return buildResponse(false, null, 'Akses ditolak: Siswa ini bukan anggota rombel kelas yang Anda ampu.');
      }
    }

    const taData = getSheetDataBatch('tahun_ajaran');
    const activeYear = taData.rows.find(t => t.id === assignment.tahun_ajaran_id);

    const mData = getSheetDataBatch('mata_pelajaran');
    const uData = getSheetDataBatch('user');
    const pengData = getSheetDataBatch('pengaturan');

    let nData = { rows: [] };
    let skData = { rows: [] };
    let rkData = { rows: [] };
    let prData = { rows: [] };
    try { nData = getSheetDataBatch('nilai_mata_pelajaran'); } catch (e) {}
    try { skData = getSheetDataBatch('nilai_sikap'); } catch (e) {}
    try { rkData = getSheetDataBatch('rekap_kehadiran'); } catch (e) {}
    try { prData = getSheetDataBatch('pengaturan_rapor'); } catch (e) {}

    // Profil Sekolah
    const schoolRow = pengData.rows[0] || {};
    const schoolProfile = {
      namaSekolah: schoolRow.nama_sekolah || '',
      namaKepalaSekolah: schoolRow.nama_kepala_sekolah || '',
      nipKepalaSekolah: schoolRow.nip_kepala_sekolah || '',
      logoSekolah: schoolRow.logo_sekolah || ''
    };

    // Identitas Guru Wali Kelas
    const teacher = uData.rows.find(u => u.id === assignment.user_id);
    const teacherInfo = {
      nama: teacher ? teacher.nama : '-',
      nip: teacher ? (teacher.nip || '-') : '-'
    };

    // Hitung ranking kompetisi kelas
    const rankingRes = calculateClassRanking(assignment.id, { sData, mData, nData, prData, wkData });
    const thisStudentRank = rankingRes.rankedStudents.find(st => st.siswa_id === student.id);

    // Rincian Mata Pelajaran
    const activeMapels = rankingRes.activeMapels;
    let completedCount = 0;
    let sumScore = 0;

    const subjects = activeMapels.map((m, idx) => {
      const grade = nData.rows.find(n => n.siswa_id === student.id && n.mata_pelajaran_id === m.id);
      const isComplete = grade ? (grade.is_complete === true || String(grade.is_complete).toLowerCase() === 'true') : false;

      const t1 = grade && grade.nilai_tugas_1 !== '' && grade.nilai_tugas_1 !== null ? Number(grade.nilai_tugas_1) : '';
      const t2 = grade && grade.nilai_tugas_2 !== '' && grade.nilai_tugas_2 !== null ? Number(grade.nilai_tugas_2) : '';
      const t3 = grade && grade.nilai_tugas_3 !== '' && grade.nilai_tugas_3 !== null ? Number(grade.nilai_tugas_3) : '';
      const t4 = grade && grade.nilai_tugas_4 !== '' && grade.nilai_tugas_4 !== null ? Number(grade.nilai_tugas_4) : '';
      const uts = grade && grade.nilai_uts !== '' && grade.nilai_uts !== null ? Number(grade.nilai_uts) : '';
      const uas = grade && grade.nilai_uas !== '' && grade.nilai_uas !== null ? Number(grade.nilai_uas) : '';

      let rataTugas = '';
      if (t1 !== '' && t2 !== '' && t3 !== '' && t4 !== '') {
        rataTugas = Math.round(((t1 + t2 + t3 + t4) / 4) * 100) / 100;
      }

      let finalScore = '';
      let predikat = '-';
      let deskripsi = '';

      if (isComplete && grade.nilai_akhir !== '' && grade.nilai_akhir !== null && !isNaN(grade.nilai_akhir)) {
        finalScore = Number(grade.nilai_akhir);
        predikat = resolvePredikatScore(finalScore, rankingRes.predikatRanges);
        completedCount++;
        sumScore += finalScore;

        if (predikat === 'A') deskripsi = 'Sangat baik dalam menguasai seluruh kompetensi materi pembelajaran.';
        else if (predikat === 'B') deskripsi = 'Baik dalam memahami materi pembelajaran, mampu mengaplikasikan dengan benar.';
        else if (predikat === 'C') deskripsi = 'Cukup dalam penguasaan materi pembelajaran, perlu peningkatan ketelitian.';
        else if (predikat === 'D') deskripsi = 'Perlu bimbingan dan pendampingan lebih lanjut dalam kompetensi materi.';
      }

      return {
        no: idx + 1,
        id: m.id,
        kode: m.kode_mata_pelajaran,
        nama: m.mata_pelajaran,
        mata_pelajaran_nama: m.mata_pelajaran,
        nilai_tugas_1: t1,
        nilai_tugas_2: t2,
        nilai_tugas_3: t3,
        nilai_tugas_4: t4,
        rata_tugas: rataTugas,
        nilai_uts: uts,
        nilai_uas: uas,
        nilai_akhir: finalScore,
        predikat: predikat,
        deskripsi: deskripsi,
        is_complete: isComplete
      };
    });

    const isAcademicComplete = (activeMapels.length > 0 && completedCount === activeMapels.length);
    const avgScore = completedCount > 0 ? Math.round((sumScore / completedCount) * 100) / 100 : null;

    // Nilai Sikap
    const sikapRow = skData.rows.find(sk => sk.siswa_id === student.id);
    const sikapPredikat = sikapRow && sikapRow.predikat ? String(sikapRow.predikat).trim() : '';
    const sikapDeskripsi = sikapRow && sikapRow.deskripsi ? String(sikapRow.deskripsi).trim() : '';
    const hasSikap = sikapPredikat !== '';

    // Rekap Kehadiran
    const attRow = rkData.rows.find(rk => rk.siswa_id === student.id);
    const jHadir = attRow && attRow.jumlah_hadir !== '' && attRow.jumlah_hadir !== null ? Number(attRow.jumlah_hadir) : '';
    const jSakit = attRow && attRow.jumlah_sakit !== '' && attRow.jumlah_sakit !== null ? Number(attRow.jumlah_sakit) : '';
    const jIzin = attRow && attRow.jumlah_izin !== '' && attRow.jumlah_izin !== null ? Number(attRow.jumlah_izin) : '';
    const jAlpha = attRow && attRow.jumlah_alpha !== '' && attRow.jumlah_alpha !== null ? Number(attRow.jumlah_alpha) : '';
    const hasKehadiran = (jHadir !== '' || jSakit !== '' || jIzin !== '' || jAlpha !== '');

    const isReady = isAcademicComplete && hasSikap && hasKehadiran;

    const studentInfo = {
      id: student.id,
      nama: student.nama,
      nisn: student.nisn || '-',
      nis: student.nis || '-',
      no_absen: Number(student.no_absen) || 0,
      jenis_kelamin: student.jenis_kelamin,
      tempat_lahir: student.tempat_lahir || '-',
      tanggal_lahir: student.tanggal_lahir || '-',
      wali_murid: student.wali_murid || '-',
      nomor_telepon: student.nomor_telepon || '-'
    };

    const assignmentInfo = {
      id: assignment.id,
      kelas: String(assignment.kelas),
      tahunAjaran: activeYear ? activeYear.tahun_ajaran : '-',
      semester: activeYear ? activeYear.semester : '-',
      tanggal_selesai: activeYear ? (activeYear.tanggal_selesai || '') : '',
      waliKelasNama: teacherInfo.nama,
      waliKelasNip: teacherInfo.nip,
      guruNama: teacherInfo.nama,
      guruNip: teacherInfo.nip,
      kepalaSekolahNama: schoolProfile.namaKepalaSekolah,
      kepalaSekolahNip: schoolProfile.nipKepalaSekolah
    };

    const academicSummary = {
      totalNilai: sumScore,
      rataNilai: avgScore !== null ? avgScore : '-',
      totalMapel: activeMapels.length,
      mapelLengkapCount: completedCount,
      isAcademicComplete: isAcademicComplete,
      rank: thisStudentRank ? thisStudentRank.rank : '-',
      totalSiswaKelas: rankingRes.totalSiswa,
      rankingStatus: rankingRes.rankingStatus,
      avgScore: avgScore !== null ? avgScore : '-',
      totalSiswa: rankingRes.totalSiswa
    };

    return buildResponse(true, {
      schoolProfile: schoolProfile,
      pengaturan: schoolProfile,
      student: studentInfo,
      siswa: studentInfo,
      assignment: assignmentInfo,
      waliKelas: assignmentInfo,
      tahunAjaran: activeYear ? {
        id: activeYear.id,
        tahun_ajaran: activeYear.tahun_ajaran,
        semester: activeYear.semester,
        tanggal_selesai: activeYear.tanggal_selesai || ''
      } : {
        tahun_ajaran: '-',
        semester: '-'
      },
      academic: {
        subjects: subjects,
        summary: academicSummary
      },
      grades: subjects,
      ranking: academicSummary,
      sikap: {
        predikat: sikapPredikat || '-',
        deskripsi: sikapDeskripsi,
        isComplete: hasSikap
      },
      kehadiran: {
        hadir: jHadir !== '' ? jHadir : 0,
        sakit: jSakit !== '' ? jSakit : 0,
        izin: jIzin !== '' ? jIzin : 0,
        alpha: jAlpha !== '' ? jAlpha : 0,
        keterangan: attRow ? (attRow.keterangan || '') : '',
        isComplete: hasKehadiran
      },
      isReady: isReady,
      statusRapor: {
        isReady: isReady,
        statusLabel: isReady ? 'Siap Diterbitkan' : 'Belum Lengkap'
      }
    }, 'Rapor digital siswa berhasil dimuat.');
  } catch (err) {
    return buildResponse(false, null, err.message || 'Gagal memuat rapor digital siswa.');
  }
}

// ============================================================================
// 8. ENTRYPOINT APLIKASI WEB (doGet)
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
    apiGetUsersList,
    apiSaveUser,
    apiToggleUserStatus,
    apiDeleteUser,
    resolveWaliKelasScope,
    apiGetSiswaList,
    apiSaveSiswa,
    apiToggleSiswaStatus,
    apiDeleteSiswa,
    apiGetMataPelajaranList,
    apiSaveMataPelajaran,
    apiToggleMataPelajaranStatus,
    apiDeleteMataPelajaran,
    resolvePredikatScore,
    apiGetPengaturanRapor,
    apiSavePengaturanRapor,
    apiGetNilaiMataPelajaran,
    apiSaveNilaiMataPelajaranBatch,
    apiGetNilaiSikapList,
    apiSaveNilaiSikapBatch,
    apiGetRekapKehadiranList,
    apiSaveRekapKehadiranBatch,
    apiGetKelengkapanPenilaian,
    calculateClassRanking,
    apiGetRaporDigitalKelas,
    apiGetRaporDigitalSiswa,
    requireAuth,
    doGet
  };
}
