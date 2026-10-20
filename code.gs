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

      try {
        const uData = getSheetDataBatch('user');
        totalGuru = uData.rows.filter(u => u.role === 'wali_kelas' && (u.is_active === true || String(u.is_active).toLowerCase() === 'true')).length;
      } catch (e) {}

      try {
        const wkData = getSheetDataBatch('wali_kelas');
        if (activeYear) {
          totalKelasDitugaskan = wkData.rows.filter(w => w.tahun_ajaran_id === activeYear.id && (w.is_active === true || String(w.is_active).toLowerCase() === 'true')).length;
        } else {
          totalKelasDitugaskan = wkData.rows.filter(w => w.is_active === true || String(w.is_active).toLowerCase() === 'true').length;
        }
      } catch (e) {}

      try {
        const sData = getSheetDataBatch('siswa');
        totalSiswa = sData.rows.filter(s => s.is_active !== false && String(s.is_active).toLowerCase() !== 'false').length;
      } catch (e) {}

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
// 5. ENTRYPOINT APLIKASI WEB (doGet)
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
    getSheetDataBatch,
    buildResponse,
    apiLogin,
    apiLogout,
    apiGetSessionUser,
    apiGetInitialDashboard,
    requireAuth,
    doGet
  };
}
