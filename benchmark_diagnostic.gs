/**
 * ============================================================================
 * SISTEM ABSENSI & PENILAIAN SISWA SD (VERSI 2)
 * File: benchmark_diagnostic.gs
 * ============================================================================
 *
 * TUJUAN:
 * File diagnostik mandiri untuk memvalidasi algoritma PBKDF2-HMAC-SHA256
 * terhadap test vector standar resmi dan mengukur profil performa empiris
 * pada runtime Google Apps Script V8 sebelum keputusan Phase 2.
 *
 * KARAKTERISTIK KESELAMATAN:
 * 1. 100% BEBAS EFEK SAMPING: Tidak membaca atau menulis Spreadsheet, Drive,
 *    PropertiesService, atau layanan Google lainnya.
 * 2. PRE-FLIGHT VALIDATION WAJIB: Benchmark hanya berjalan jika implementasi
 *    terbukti lolos seluruh test vector resmi secara identik.
 * 3. PENGHENTIAN ADAPTIF: Pengujian iterasi tinggi otomatis dihentikan/dilewati
 *    jika waktu median iterasi sebelumnya melampaui ambang batas aman.
 */

/**
 * Daftar Test Vector Resmi Standar PBKDF2-HMAC-SHA256
 * Sumber:
 * - RFC 7914 Section 11 (The scrypt Password-Based Key Derivation Function)
 * - IETF PBKDF2-HMAC-SHA256 Test Vectors
 */
const PBKDF2_TEST_VECTORS = Object.freeze([
  {
    id: 'TV1_RFC7914_SEC11',
    source: 'RFC 7914 Section 11',
    password: 'passwd',
    salt: 'salt',
    iterations: 1,
    dkLen: 64,
    expectedHex:
      '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc' +
      '49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783'
  },
  {
    id: 'TV2_IETF_32',
    source: 'IETF SHA-256 Test Vector (c=1, dkLen=32)',
    password: 'password',
    salt: 'salt',
    iterations: 1,
    dkLen: 32,
    expectedHex:
      '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
  },
  {
    id: 'TV3_IETF_40',
    source: 'IETF SHA-256 Long Inputs (c=4096, dkLen=40)',
    password: 'passwordPASSWORDpassword',
    salt: 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
    iterations: 4096,
    dkLen: 40,
    expectedHex:
      '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1' +
      'c635518c7dac47e9'
  },
  {
    id: 'TV4_RFC7914_HIGH',
    source: 'RFC 7914 Section 11 High Iterations (c=80000, dkLen=64)',
    password: 'Password',
    salt: 'NaCl',
    iterations: 80000,
    dkLen: 64,
    expectedHex:
      '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56' +
      'a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d'
  }
]);

// ============================================================================
// IMPLEMENTASI 1: Pure JavaScript V8 PBKDF2-HMAC-SHA256 (RFC 8018 Compliant)
// ============================================================================

/**
 * Konversi string ke UTF-8 Uint8Array (kompatibel ASCII, Unicode, dan Surrogate Pairs).
 * @param {string} str
 * @return {Uint8Array}
 */
function pureJsUtf8ToBytes(str) {
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

/**
 * Bitwise right rotate 32-bit.
 */
function pureJsRotr(n, x) {
  return (x >>> n) | (x << (32 - n));
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

/**
 * Komputasi hash SHA-256 murni pada Uint8Array.
 * @param {Uint8Array} dataBytes
 * @return {Uint8Array} 32 bytes digest
 */
function pureJsSha256(dataBytes) {
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
      const s0 = pureJsRotr(7, w[i - 15]) ^ pureJsRotr(18, w[i - 15]) ^ (w[i - 15] >>> 3);
      const s1 = pureJsRotr(17, w[i - 2]) ^ pureJsRotr(19, w[i - 2]) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = pureJsRotr(6, e) ^ pureJsRotr(11, e) ^ pureJsRotr(25, e);
      const ch = (e & f) ^ ((~e) & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) | 0;
      const S0 = pureJsRotr(2, a) ^ pureJsRotr(13, a) ^ pureJsRotr(22, a);
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

/**
 * Komputasi HMAC-SHA-256 (RFC 2104).
 * @param {Uint8Array} keyBytes
 * @param {Uint8Array} msgBytes
 * @return {Uint8Array} 32 bytes MAC
 */
function pureJsHmacSha256(keyBytes, msgBytes) {
  let k = keyBytes;
  if (k.length > 64) {
    k = pureJsSha256(k);
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
  const innerHash = pureJsSha256(innerBuf);

  const outerBuf = new Uint8Array(64 + 32);
  outerBuf.set(opad, 0);
  outerBuf.set(innerHash, 64);
  return pureJsSha256(outerBuf);
}

/**
 * Implementasi PBKDF2-HMAC-SHA256 Murni (RFC 8018).
 * Mendukung panjang kunci derived berapapun (multi-blok dkLen > 32).
 *
 * @param {string} password
 * @param {string} salt
 * @param {number} iterations
 * @param {number} dkLen Panjang output dalam bytes
 * @return {string} Hexadecimal string lowercase
 */
function pureJsPbkdf2HmacSha256(password, salt, iterations, dkLen) {
  if (iterations <= 0 || dkLen <= 0) {
    throw new Error('Iterasi dan dkLen harus bilangan positif.');
  }
  const pBytes = pureJsUtf8ToBytes(password);
  const sBytes = pureJsUtf8ToBytes(salt);
  const hLen = 32;
  const l = Math.ceil(dkLen / hLen);
  const r = dkLen - (l - 1) * hLen;
  const dk = new Uint8Array(dkLen);

  for (let i = 1; i <= l; i++) {
    // S || INT_32_BE(i)
    const sInt = new Uint8Array(sBytes.length + 4);
    sInt.set(sBytes, 0);
    sInt[sBytes.length] = (i >>> 24) & 0xff;
    sInt[sBytes.length + 1] = (i >>> 16) & 0xff;
    sInt[sBytes.length + 2] = (i >>> 8) & 0xff;
    sInt[sBytes.length + 3] = i & 0xff;

    let u = pureJsHmacSha256(pBytes, sInt);
    const t = new Uint8Array(u);

    for (let c = 1; c < iterations; c++) {
      u = pureJsHmacSha256(pBytes, u);
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

// ============================================================================
// IMPLEMENTASI 2: Native Google Apps Script Utilities PBKDF2
// ============================================================================

/**
 * Helper konversi Uint8Array ke Base64 murni tanpa dependensi native.
 * Digunakan untuk menjembatani pembuatan Java Byte[] di Google Apps Script via Utilities.base64Decode().
 * @param {Uint8Array} bytes
 * @return {string}
 */
function uint8ArrayToBase64(bytes) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let b64 = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    b64 += chars[b0 >> 2];
    b64 += chars[((b0 & 3) << 4) | (b1 >> 4)];
    b64 += (i + 1 < bytes.length) ? chars[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    b64 += (i + 2 < bytes.length) ? chars[b2 & 63] : '=';
  }
  return b64;
}

/**
 * Implementasi PBKDF2-HMAC-SHA256 menggunakan API Native Apps Script (Utilities.computeHmacSha256Signature).
 * Menjamin kompatibilitas tanda tangan metode Java: kedua parameter (value dan key) bertipe Byte[].
 * Mendukung panjang kunci derived berapapun (multi-blok dkLen > 32).
 *
 * @param {string} password
 * @param {string} salt
 * @param {number} iterations
 * @param {number} dkLen Panjang output dalam bytes
 * @return {string} Hexadecimal string lowercase
 */
function gasNativePbkdf2HmacSha256(password, salt, iterations, dkLen) {
  if (iterations <= 0 || dkLen <= 0) {
    throw new Error('Iterasi dan dkLen harus bilangan positif.');
  }

  // 1. Dapatkan keyBytes (Java Byte[]) dari password
  let keyBytes;
  if (typeof Utilities !== 'undefined' && typeof Utilities.newBlob === 'function') {
    keyBytes = Utilities.newBlob(password).getBytes();
  } else if (typeof Buffer !== 'undefined') {
    keyBytes = Array.from(Buffer.from(password, 'utf8'));
  } else {
    keyBytes = Array.from(pureJsUtf8ToBytes(password));
  }

  // 2. Helper konversi Uint8Array ke Java Byte[] di Apps Script
  function toGasBytes(uint8Arr) {
    if (typeof Utilities !== 'undefined' && typeof Utilities.base64Decode === 'function') {
      return Utilities.base64Decode(uint8ArrayToBase64(uint8Arr));
    }
    return Array.from(uint8Arr);
  }

  // 3. Adapter pemanggilan HMAC-SHA256 native (memastikan kedua argumen Byte[])
  function computeHmac(valBytes, kBytes) {
    if (typeof Utilities !== 'undefined') {
      if (typeof Utilities.computeHmacSha256Signature === 'function') {
        return Utilities.computeHmacSha256Signature(valBytes, kBytes);
      }
      if (typeof Utilities.computeHmacSignature === 'function') {
        return Utilities.computeHmacSignature(Utilities.MacAlgorithm.HMAC_SHA_256, valBytes, kBytes);
      }
    }
    // Fallback Node.js untuk pengujian lokal
    if (typeof require !== 'undefined') {
      const crypto = require('crypto');
      const hmac = crypto.createHmac('sha256', Buffer.from(kBytes));
      hmac.update(Buffer.from(valBytes));
      const digest = hmac.digest();
      const signed = [];
      for (let i = 0; i < digest.length; i++) {
        const b = digest[i];
        signed.push(b > 127 ? b - 256 : b);
      }
      return signed;
    }
    throw new Error('Layanan kriptografi native tidak tersedia pada runtime ini.');
  }

  const sBytes = pureJsUtf8ToBytes(salt);
  const hLen = 32;
  const l = Math.ceil(dkLen / hLen);
  const r = dkLen - (l - 1) * hLen;
  const dk = [];

  for (let i = 1; i <= l; i++) {
    // S || INT_32_BE(i)
    const sInt = new Uint8Array(sBytes.length + 4);
    sInt.set(sBytes, 0);
    sInt[sBytes.length] = (i >>> 24) & 0xff;
    sInt[sBytes.length + 1] = (i >>> 16) & 0xff;
    sInt[sBytes.length + 2] = (i >>> 8) & 0xff;
    sInt[sBytes.length + 3] = i & 0xff;

    // Pastikan initialBytes adalah Java Byte[]
    const initialBytes = toGasBytes(sInt);
    let u = computeHmac(initialBytes, keyBytes);
    const t = u.slice(0);

    for (let c = 1; c < iterations; c++) {
      u = computeHmac(u, keyBytes);
      for (let k = 0; k < hLen; k++) {
        t[k] ^= u[k];
      }
    }

    const blockLen = (i === l) ? r : hLen;
    for (let k = 0; k < blockLen; k++) {
      dk.push(t[k]);
    }
  }

  let hex = '';
  for (let i = 0; i < dk.length; i++) {
    const unsignedByte = dk[i] < 0 ? dk[i] + 256 : dk[i];
    const s = unsignedByte.toString(16);
    hex += (s.length === 1 ? '0' + s : s);
  }
  return hex;
}

// ============================================================================
// SUITE VALIDASI & BENCHMARK
// ============================================================================

/**
 * Memvalidasi implementasi terhadap seluruh test vector resmi.
 * Melempar Error jika ada output yang tidak cocok.
 * @return {Object} Laporan hasil validasi
 */
function validatePBKDF2TestVectors() {
  const report = {
    allPassed: true,
    pureJsResults: [],
    nativeResults: []
  };

  const logger = (typeof Logger !== 'undefined' && typeof Logger.log === 'function')
    ? Logger
    : { log: console.log };

  logger.log('--- MEMULAI PRE-FLIGHT VALIDASI TEST VECTORS ---');

  for (let i = 0; i < PBKDF2_TEST_VECTORS.length; i++) {
    const tv = PBKDF2_TEST_VECTORS[i];

    // 1. Validasi Pure JS
    const outPureJs = pureJsPbkdf2HmacSha256(tv.password, tv.salt, tv.iterations, tv.dkLen);
    const matchPureJs = (outPureJs.toLowerCase() === tv.expectedHex.toLowerCase());
    report.pureJsResults.push({ id: tv.id, match: matchPureJs });

    if (!matchPureJs) {
      report.allPassed = false;
      const msg = '[FAIL] Pure JS gagal pada ' + tv.id + ' (' + tv.source + ')';
      logger.log(msg);
      throw new Error(msg);
    }
    logger.log('[PASS] Pure JS  : ' + tv.id + ' (' + tv.source + ')');

    // 2. Validasi Native GAS
    const outNative = gasNativePbkdf2HmacSha256(tv.password, tv.salt, tv.iterations, tv.dkLen);
    const matchNative = (outNative.toLowerCase() === tv.expectedHex.toLowerCase());
    report.nativeResults.push({ id: tv.id, match: matchNative });

    if (!matchNative) {
      report.allPassed = false;
      const msg = '[FAIL] Native GAS gagal pada ' + tv.id + ' (' + tv.source + ')';
      logger.log(msg);
      throw new Error(msg);
    }
    logger.log('[PASS] Native GAS: ' + tv.id + ' (' + tv.source + ')');
  }

  logger.log('--- PRE-FLIGHT VALIDATION: 100% LOLOS PADA SEMUA METODE ---\n');
  return report;
}

/**
 * Menghitung metrik durasi: min, max, median, mean.
 * @param {number[]} times
 * @return {Object}
 */
function calculateMetrics(times) {
  const sorted = times.slice(0).sort((a, b) => a - b);
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  const median = sorted[Math.floor(sorted.length / 2)];
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  const mean = Math.round((sum / sorted.length) * 100) / 100;
  return { min, max, median, mean, runs: sorted };
}

/**
 * FUNGSI UTAMA: Menjalankan benchmark diagnostik lengkap.
 * Jalankan fungsi ini dari Apps Script Editor.
 */
function runPBKDF2BenchmarkSuite() {
  const logger = (typeof Logger !== 'undefined' && typeof Logger.log === 'function')
    ? Logger
    : { log: console.log };

  logger.log('================================================================');
  logger.log('BENCHMARK DIAGNOSTIK PBKDF2-HMAC-SHA256 (RUNTIME V8)');
  logger.log('================================================================');

  // TAHAP 1: Pre-flight Test Vector Validation
  validatePBKDF2TestVectors();

  // TAHAP 2: Pengukuran Performa Empiris
  const samplePassword = 'PasswordKepalaSekolah2026!';
  const sampleSalt = 'a1b2c3d4-e5f6-47a8-b9c0-123456789abc';
  const repetitions = 5;
  const SAFE_MEDIAN_THRESHOLD_MS = 10000; // Ambang batas henti otomatis disesuaikan ke 10 detik agar 600.000 iterasi dapat terukur

  logger.log('Parameter Uji: Password 26 char, Salt 36 char, dkLen 32 bytes.');
  logger.log('Setiap kandidat diulang ' + repetitions + ' kali setelah pemanasan (warm-up).\n');

  // Warm-up phase
  pureJsPbkdf2HmacSha256('warmup', 'warmup', 100, 32);
  gasNativePbkdf2HmacSha256('warmup', 'warmup', 100, 32);

  const results = {
    pureJs: {},
    native: {}
  };

  // A. Uji Metode Pure JS (Ditambahkan kandidat 300.000, 400.000, dan 600.000)
  logger.log('--- METODE A: Pure JavaScript V8 (In-Engine Bitwise Math) ---');
  const pureJsCandidates = [1000, 10000, 50000, 100000, 210000, 300000, 400000, 600000];

  for (let idx = 0; idx < pureJsCandidates.length; idx++) {
    const iter = pureJsCandidates[idx];
    const times = [];

    for (let r = 0; r < repetitions; r++) {
      const t0 = new Date().getTime();
      pureJsPbkdf2HmacSha256(samplePassword, sampleSalt, iter, 32);
      times.push(new Date().getTime() - t0);
    }

    const metrics = calculateMetrics(times);
    results.pureJs[iter] = metrics;

    logger.log(
      '[Pure JS] Iterasi: ' + String(iter).padStart(6, ' ') +
      ' | Min: ' + String(metrics.min).padStart(5, ' ') + 'ms' +
      ' | Max: ' + String(metrics.max).padStart(5, ' ') + 'ms' +
      ' | Median: ' + String(metrics.median).padStart(5, ' ') + 'ms' +
      ' | Mean: ' + String(metrics.mean).padStart(6, ' ') + 'ms'
    );

    if (metrics.median > SAFE_MEDIAN_THRESHOLD_MS) {
      logger.log('[Pure JS] Menghentikan kandidat lebih tinggi: median melampaui ambang batas ' + SAFE_MEDIAN_THRESHOLD_MS + 'ms.');
      break;
    }
  }

  // B. Uji Metode Native Apps Script (Kandidat mahal dilewati pada pengujian lanjutan)
  logger.log('\n--- METODE B: Native Utilities.computeHmacSha256Signature (Context-Bridge) ---');
  logger.log('[Native] Kandidat mahal (>1.000 iterasi) dilewati pada pengujian lanjutan ini karena terbukti melampaui batas toleransi latensi (>5.000ms pada 20.000 iterasi).');
  const nativeCandidates = [1000]; // Hanya kandidat 1000 sebagai acuan baseline ringan

  for (let idx = 0; idx < nativeCandidates.length; idx++) {
    const iter = nativeCandidates[idx];
    const times = [];

    for (let r = 0; r < repetitions; r++) {
      const t0 = new Date().getTime();
      gasNativePbkdf2HmacSha256(samplePassword, sampleSalt, iter, 32);
      times.push(new Date().getTime() - t0);
    }

    const metrics = calculateMetrics(times);
    results.native[iter] = metrics;

    logger.log(
      '[Native]  Iterasi: ' + String(iter).padStart(6, ' ') +
      ' | Min: ' + String(metrics.min).padStart(5, ' ') + 'ms' +
      ' | Max: ' + String(metrics.max).padStart(5, ' ') + 'ms' +
      ' | Median: ' + String(metrics.median).padStart(5, ' ') + 'ms' +
      ' | Mean: ' + String(metrics.mean).padStart(6, ' ') + 'ms'
    );
  }

  logger.log('\n================================================================');
  logger.log('BENCHMARK SELESAI');
  logger.log('================================================================');

  return results;
}

// Ekspor untuk lingkungan pengujian otomatis Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    PBKDF2_TEST_VECTORS,
    pureJsUtf8ToBytes,
    pureJsSha256,
    pureJsHmacSha256,
    pureJsPbkdf2HmacSha256,
    gasNativePbkdf2HmacSha256,
    validatePBKDF2TestVectors,
    calculateMetrics,
    runPBKDF2BenchmarkSuite
  };
}
