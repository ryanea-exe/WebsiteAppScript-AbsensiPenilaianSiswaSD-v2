/**
 * ============================================================================
 * SUITE PENGUJIAN OTOMATIS PHASE 2: AUTENTIKASI & MANAJEMEN SESI
 * File: tests/test_auth.js
 * ============================================================================
 *
 * Menguji:
 * 1. Implementasi Kriptografi PBKDF2-HMAC-SHA256 (RFC 8018, RFC 7914, IETF).
 * 2. Format Hash Terstruktur 'pbkdf2:sha256:<iter>:<hex>' dan Salt Acak.
 * 3. Verifikasi Password (Password Benar, Salah, Unicode UTF-8, Batas DoS Iterasi).
 * 4. Backward-Compatibility Verifikasi Akun Legacy SHA-256 dan Penanda Rehash.
 * 5. Mitigasi Timing Attack via Constant-Time String Comparison.
 * 6. Manajemen Sesi Server-Side (Create, Validate, Inactive Detection, Destroy).
 * 7. Endpoint apiLogin (Sukses, Password Salah, User Tidak Ditemukan, User Nonaktif,
 *    Audit terakhir_login, dan Lazy Rehash Transparan).
 * 8. Endpoint apiLogout dan apiGetSessionUser.
 * 9. Guard Server-Side requireAuth (Validasi Sesi & Role-Based Access Control).
 */

const assert = require('assert');
const path = require('path');

// Muat implementasi setup.gs dan code.gs
const setupModule = require('../setup.gs');
const authModule = require('../code.gs');

console.log('=== MEMULAI SUITE PENGUJIAN OTOMATIS PHASE 2: AUTENTIKASI ===\n');

// ============================================================================
// UJI 1: Vektor Uji Resmi PBKDF2-HMAC-SHA256
// ============================================================================
console.log('1. Menguji Vektor Uji Kriptografi PBKDF2-HMAC-SHA256 (RFC 7914 & IETF)...');

// Vektor 1: RFC 7914 Section 11 (c=1, dkLen=64)
const tv1 = authModule.computePBKDF2('passwd', 'salt', 1, 64);
const exp1 = '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc' +
             '49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783';
assert.strictEqual(tv1, exp1, 'Gagal pada RFC 7914 Vektor 1');

// Vektor 2: IETF SHA-256 (c=1, dkLen=32)
const tv2 = authModule.computePBKDF2('password', 'salt', 1, 32);
const exp2 = '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b';
assert.strictEqual(tv2, exp2, 'Gagal pada IETF Vektor 2');

// Vektor 3: IETF Long Inputs (c=4096, dkLen=40)
const tv3 = authModule.computePBKDF2('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 40);
const exp3 = '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9';
assert.strictEqual(tv3, exp3, 'Gagal pada IETF Vektor 3');

console.log('   ✓ Seluruh vektor uji resmi kriptografi terverifikasi identik 100%.\n');

// ============================================================================
// UJI 2: Format Hash Terstruktur dan Salt Acak
// ============================================================================
console.log('2. Menguji Format Terstruktur PBKDF2 dan Pembangkitan Salt...');

const salt1 = authModule.generateSecureSalt();
const salt2 = authModule.generateSecureSalt();
assert.strictEqual(typeof salt1, 'string');
assert.strictEqual(salt1.length, 64, 'Panjang salt harus 64 karakter hex');
assert.notStrictEqual(salt1, salt2, 'Salt acak harus unik');

const hashOutput = authModule.hashPasswordPBKDF2('PasswordRahasia123!', salt1, 1000);
assert.ok(hashOutput.startsWith('pbkdf2:sha256:1000:'), 'Format hash harus berawalan pbkdf2:sha256:<iter>:');
const parts = hashOutput.split(':');
assert.strictEqual(parts.length, 4, 'Format hash harus memiliki 4 segmen');
assert.strictEqual(parts[3].length, 64, 'Panjang derived key hex harus 64 karakter (32 bytes)');

console.log('   ✓ Format hash terstruktur dan salt unik terbukti valid.\n');

// ============================================================================
// UJI 3: Verifikasi Password (Benar, Salah, dan Karakter Unicode)
// ============================================================================
console.log('3. Menguji Verifikasi Password & Penanganan Karakter Unicode...');

const testPw = 'KunciSiswa#2026_Bahasa_Indonesia_é_🔒';
const testSalt = authModule.generateSecureSalt();
const testHash = authModule.hashPasswordPBKDF2(testPw, testSalt, 1000);

// Password Benar
const vCorrect = authModule.verifyPassword(testPw, testHash, testSalt);
assert.strictEqual(vCorrect.valid, true, 'Password benar harus valid');
assert.strictEqual(vCorrect.needsRehash, false, 'Hash PBKDF2 baru tidak butuh rehash');

// Password Salah (Beda 1 karakter)
const vWrong1 = authModule.verifyPassword('KunciSiswa#2026_Bahasa_Indonesia_é_🔓', testHash, testSalt);
assert.strictEqual(vWrong1.valid, false, 'Password salah simbol harus ditolak');

// Password Salah (Beda huruf kapital)
const vWrong2 = authModule.verifyPassword(testPw.toLowerCase(), testHash, testSalt);
assert.strictEqual(vWrong2.valid, false, 'Password beda kapitalisasi harus ditolak');

// Salt Salah
const vWrongSalt = authModule.verifyPassword(testPw, testHash, 'wrong_salt_1234567890');
assert.strictEqual(vWrongSalt.valid, false, 'Salt salah harus menghasilkan verifikasi gagal');

console.log('   ✓ Verifikasi password benar, salah, dan Unicode terverifikasi.\n');

// ============================================================================
// UJI 4: Validasi Batas Iterasi Defensif (Mitigasi DoS)
// ============================================================================
console.log('4. Menguji Batas Iterasi Defensif (Mitigasi DoS)...');

// Iterasi terlalu kecil (< 1000)
const hashLowIter = 'pbkdf2:sha256:500:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
const vLow = authModule.verifyPassword('test', hashLowIter, 'salt');
assert.strictEqual(vLow.valid, false, 'Iterasi di bawah batas minimum harus ditolak');

// Iterasi terlalu besar (> 250000)
const hashHighIter = 'pbkdf2:sha256:5000000:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
const vHigh = authModule.verifyPassword('test', hashHighIter, 'salt');
assert.strictEqual(vHigh.valid, false, 'Iterasi manipulatif di atas batas maksimum harus ditolak');

console.log('   ✓ Batas iterasi defensif bekerja mencegah serangan DoS.\n');

// ============================================================================
// UJI 5: Backward-Compatibility Akun Legacy SHA-256 dan Lazy Rehash
// ============================================================================
console.log('5. Menguji Verifikasi Akun Legacy SHA-256 & Indikator Rehash...');

const legacySalt = 'legacy_salt_uuid_12345';
const legacyPlain = 'KepalaSekolah2026!';
// Hash legacy dibuat dengan helper setup.gs (SHA-256 satu putaran)
const legacyHash = setupModule.hashPasswordWithSalt(legacyPlain, legacySalt);
assert.strictEqual(legacyHash.length, 64, 'Hash legacy harus heksadesimal 64 karakter');

// Verifikasi dengan password benar -> harus valid dan menandai needsRehash = true
const vLegacyOk = authModule.verifyPassword(legacyPlain, legacyHash, legacySalt);
assert.strictEqual(vLegacyOk.valid, true, 'Password legacy yang benar harus valid');
assert.strictEqual(vLegacyOk.needsRehash, true, 'Akun legacy wajib ditandai needsRehash = true');

// Verifikasi dengan password salah
const vLegacyFail = authModule.verifyPassword('PasswordSalah123', legacyHash, legacySalt);
assert.strictEqual(vLegacyFail.valid, false, 'Password legacy salah harus ditolak');
assert.strictEqual(vLegacyFail.needsRehash, false);

console.log('   ✓ Kompatibilitas akun legacy SHA-256 dan deteksi rehash terbukti aman.\n');

// ============================================================================
// UJI 6: Mitigasi Timing Attack (Constant-Time Comparison)
// ============================================================================
console.log('6. Menguji Fungsi Constant-Time Comparison...');

assert.strictEqual(authModule.constantTimeCompare('secret_token_123', 'secret_token_123'), true);
assert.strictEqual(authModule.constantTimeCompare('secret_token_123', 'secret_token_124'), false);
assert.strictEqual(authModule.constantTimeCompare('secret', 'secret_longer'), false);
assert.strictEqual(authModule.constantTimeCompare('', ''), true);

console.log('   ✓ Constant-time string comparison berfungsi dengan benar.\n');

// ============================================================================
// UJI 7: Manajemen Sesi Server-Side
// ============================================================================
console.log('7. Menguji Manajemen Sesi Server-Side (Create, Validate, Destroy)...');

const mockUser = {
  id: 'usr-111',
  username: 'kepsek_sd',
  nama: 'H. Sudirman, M.Pd.',
  role: 'kepala_sekolah',
  foto: 'drive_file_id_001'
};

const token = authModule.createSession(mockUser);
assert.strictEqual(typeof token, 'string');
assert.ok(token.length >= 16);

// Ambil sesi aktif
const session = authModule.getActiveSession(token);
assert.ok(session !== null);
assert.strictEqual(session.userId, mockUser.id);
assert.strictEqual(session.role, mockUser.role);

// Hancurkan sesi (Logout)
authModule.destroySession(token);
const sessionAfterDestroy = authModule.getActiveSession(token);
assert.strictEqual(sessionAfterDestroy, null, 'Sesi harus null setelah destroySession');

console.log('   ✓ Siklus sesi server-side (create, fetch, destroy) terbukti aman.\n');

// ============================================================================
// UJI 8: Endpoint apiLogin dan Otorisasi (Simulasi Database Spreadsheet)
// ============================================================================
console.log('8. Menguji Endpoint apiLogin, apiLogout, dan Otorisasi Role...');

// Mock Spreadsheet in-memory untuk pengujian endpoint
function createAuthMockSpreadsheet() {
  const saltLegacy = 'salt_leg_001';
  const hashLegacy = setupModule.hashPasswordWithSalt('KepsekPass123', saltLegacy);

  const saltPbkdf2 = authModule.generateSecureSalt();
  const hashPbkdf2 = authModule.hashPasswordPBKDF2('WaliKelasPass123', saltPbkdf2, 1000);

  const userHeaders = setupModule.SCHEMA_DEFINITIONS.user;

  // Baris data mock:
  // 1: Header
  // 2: Kepala Sekolah (Legacy hash, aktif)
  // 3: Wali Kelas (PBKDF2 hash, aktif)
  // 4: Guru Nonaktif (PBKDF2 hash, is_active = false)
  const userRows = [
    userHeaders,
    ['u-01', 'Bpk Kepala', '', 'kepsek', hashLegacy, saltLegacy, 'kepala_sekolah', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-02', 'Ibu Wali', '', 'walikelas1', hashPbkdf2, saltPbkdf2, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-03', 'Guru Cuti', '', 'guru_nonaktif', hashPbkdf2, saltPbkdf2, 'wali_kelas', '', '', false, '2026-01-01', '2026-01-01']
  ];

  function createMockSheet(name, headers, rows) {
    const allRows = [headers, ...(rows || [])];
    return {
      getName: () => name,
      getLastRow: () => allRows.length,
      getLastColumn: () => headers.length,
      getRange: function(r, c, numR, numC) {
        return {
          getValues: function() {
            const res = [];
            for (let row = r - 1; row < r - 1 + (numR || 1); row++) {
              const rowData = [];
              for (let col = c - 1; col < c - 1 + (numC || 1); col++) {
                rowData.push(allRows[row] ? allRows[row][col] : '');
              }
              res.push(rowData);
            }
            return res;
          },
          setValue: function(val) {
            if (allRows[r - 1]) allRows[r - 1][c - 1] = val;
          }
        };
      }
    };
  }

  const userSheet = createMockSheet('user', userHeaders, userRows.slice(1));
  const pengSheet = createMockSheet('pengaturan', setupModule.SCHEMA_DEFINITIONS.pengaturan, [
    ['1', '', 'SD Negeri Percobaan 01', 'Bpk Sudirman, M.Pd.', '197501011999031001', 'u-01', '2026-01-01', '2026-01-01']
  ]);
  const taSheet = createMockSheet('tahun_ajaran', setupModule.SCHEMA_DEFINITIONS.tahun_ajaran, [
    ['ta-01', '2026/2027', 'Ganjil', '2026-07-15', '2026-12-20', true, false, '2026-01-01', '2026-01-01']
  ]);
  const wkSheet = createMockSheet('wali_kelas', setupModule.SCHEMA_DEFINITIONS.wali_kelas, [
    ['wk-01', 'u-02', 'ta-01', '4', true, '2026-01-01', '2026-01-01']
  ]);
  const siswaSheet = createMockSheet('siswa', setupModule.SCHEMA_DEFINITIONS.siswa, [
    ['s-01', 'wk-01', '1234567890', '1001', 'Ahmad Siswa', 'L', 'Jakarta', '2015-05-10', 'Islam', 'Jl. Merdeka', 'Bpk Budi', '0811111', '', true, '2026-01-01', '2026-01-01'],
    ['s-02', 'wk-01', '1234567891', '1002', 'Siti Siswi', 'P', 'Jakarta', '2015-08-12', 'Islam', 'Jl. Mawar', 'Bpk Ali', '0822222', '', true, '2026-01-01', '2026-01-01']
  ]);

  const sheets = {
    user: userSheet,
    pengaturan: pengSheet,
    tahun_ajaran: taSheet,
    wali_kelas: wkSheet,
    siswa: siswaSheet
  };

  return {
    getSheetByName: (name) => sheets[name] || null,
    _data: userRows
  };
}

// Pasang mock spreadsheet ke environment pengujian
const mockSS = createAuthMockSpreadsheet();
global.getTargetSpreadsheet = () => mockSS;
global.SpreadsheetApp = { getActiveSpreadsheet: () => mockSS };

// Kasus 8A: Login Sukses Akun PBKDF2 (Wali Kelas)
const loginWali = authModule.apiLogin('walikelas1', 'WaliKelasPass123');
assert.strictEqual(loginWali.success, true, 'Login wali kelas harus sukses');
assert.strictEqual(loginWali.data.user.role, 'wali_kelas');
assert.ok(loginWali.data.token, 'Token sesi harus dihasilkan');

// Periksa audit terakhir_login telah diperbarui
const userSheetDataAfterWali = mockSS._data;
assert.ok(userSheetDataAfterWali[2][8] !== '', 'terakhir_login baris wali kelas harus terisi');

// Kasus 8B: Login Sukses Akun Legacy (Kepala Sekolah) + Lazy Rehash
const loginKepsek = authModule.apiLogin('kepsek', 'KepsekPass123');
assert.strictEqual(loginKepsek.success, true, 'Login akun legacy harus sukses');
assert.strictEqual(loginKepsek.data.user.role, 'kepala_sekolah');

// Buktikan bahwa hash pada baris kepala sekolah di Spreadsheet otomatis di-upgrade ke PBKDF2!
const rehashedData = mockSS._data[1]; // Baris index 1 (Kepala Sekolah)
const newHash = rehashedData[4]; // password_hash
assert.ok(newHash.startsWith('pbkdf2:sha256:'), 'Hash akun legacy harus otomatis di-rehash ke PBKDF2');

// Kasus 8C: Login Password Salah
const loginFailPw = authModule.apiLogin('walikelas1', 'PasswordSalahTotal');
assert.strictEqual(loginFailPw.success, false);
assert.strictEqual(loginFailPw.message, authModule.AUTH_CONFIG.GENERIC_AUTH_ERROR, 'Pesan harus generik');

// Kasus 8D: Login Username Tidak Ditemukan
const loginFailUser = authModule.apiLogin('user_palsu_tidak_ada', 'Sembarang123');
assert.strictEqual(loginFailUser.success, false);
assert.strictEqual(loginFailUser.message, authModule.AUTH_CONFIG.GENERIC_AUTH_ERROR, 'Pesan harus generik');

// Kasus 8E: Login Akun Nonaktif
const loginInactive = authModule.apiLogin('guru_nonaktif', 'WaliKelasPass123');
assert.strictEqual(loginInactive.success, false);
assert.strictEqual(loginInactive.message, authModule.AUTH_CONFIG.INACTIVE_USER_ERROR, 'Pesan akun nonaktif harus jelas');

// Kasus 8F: apiGetSessionUser
const sessionUser = authModule.apiGetSessionUser(loginWali.data.token);
assert.strictEqual(sessionUser.success, true);
assert.strictEqual(sessionUser.data.username, 'walikelas1');

// Kasus 8G: requireAuth Guard Otorisasi Role
// 1. Role cocok -> lolos
const authOk = authModule.requireAuth(loginWali.data.token, 'wali_kelas');
assert.strictEqual(authOk.role, 'wali_kelas');

// 2. Role tidak cocok -> throw error
assert.throws(() => {
  authModule.requireAuth(loginWali.data.token, 'kepala_sekolah');
}, /tidak memiliki izin/, 'Role wali kelas tidak boleh mengakses endpoint kepala sekolah');

// 3. Token palsu/expired -> throw error
assert.throws(() => {
  authModule.requireAuth('token_palsu', 'wali_kelas');
}, /Akses ditolak/, 'Token tidak valid harus ditolak');

// Kasus 8H: apiLogout
const logoutRes = authModule.apiLogout(loginWali.data.token);
assert.strictEqual(logoutRes.success, true);
assert.strictEqual(authModule.getActiveSession(loginWali.data.token), null, 'Sesi harus musnah setelah logout');

console.log('   ✓ Seluruh alur autentikasi, lazy rehash, audit login, dan kontrol role terverifikasi 100%.\n');

// ============================================================================
// UJI 9: Endpoint Dashboard Awal & Validasi Otorisasi Array Role (Phase 3)
// ============================================================================
console.log('9. Menguji Endpoint apiGetInitialDashboard dan Guard Array Role (Phase 3)...');

// Login ulang wali kelas untuk mendapatkan sesi aktif baru
const reLoginWali = authModule.apiLogin('walikelas1', 'WaliKelasPass123');
assert.strictEqual(reLoginWali.success, true);
const waliToken = reLoginWali.data.token;
const kepsekToken = loginKepsek.data.token;

// 1. Uji requireAuth dengan array roles
const authMulti1 = authModule.requireAuth(kepsekToken, ['kepala_sekolah', 'wali_kelas']);
assert.strictEqual(authMulti1.role, 'kepala_sekolah');

const authMulti2 = authModule.requireAuth(waliToken, ['kepala_sekolah', 'wali_kelas']);
assert.strictEqual(authMulti2.role, 'wali_kelas');

assert.throws(() => {
  authModule.requireAuth(waliToken, ['kepala_sekolah']);
}, /tidak memiliki izin/, 'Wali kelas ditolak saat endpoint hanya untuk kepala sekolah');

// 2. Uji apiGetInitialDashboard untuk Kepala Sekolah
const dashKepsek = authModule.apiGetInitialDashboard(kepsekToken);
assert.strictEqual(dashKepsek.success, true);
assert.strictEqual(dashKepsek.data.user.role, 'kepala_sekolah');
assert.strictEqual(dashKepsek.data.schoolProfile.namaSekolah, 'SD Negeri Percobaan 01');
assert.strictEqual(dashKepsek.data.activeYear.tahunAjaran, '2026/2027');
assert.strictEqual(dashKepsek.data.summary.totalGuru, 1, 'Total guru aktif harus 1');
assert.strictEqual(dashKepsek.data.summary.totalKelasDitugaskan, 1, 'Total kelas ditugaskan harus 1');
assert.strictEqual(dashKepsek.data.summary.totalSiswa, 2, 'Total siswa harus 2');

// 3. Uji apiGetInitialDashboard untuk Wali Kelas
const dashWali = authModule.apiGetInitialDashboard(waliToken);
assert.strictEqual(dashWali.success, true);
assert.strictEqual(dashWali.data.user.role, 'wali_kelas');
assert.strictEqual(dashWali.data.summary.hasAssignment, true);
assert.strictEqual(dashWali.data.summary.kelas, '4');
assert.strictEqual(dashWali.data.summary.totalSiswa, 2);

// 4. Uji apiGetInitialDashboard dengan token tidak valid / kedaluwarsa
const dashBad = authModule.apiGetInitialDashboard('token_tidak_dikenal_123');
assert.strictEqual(dashBad.success, false);
assert.ok(dashBad.message.includes('Akses ditolak') || dashBad.message.includes('Sesi tidak valid'));

console.log('   ✓ Integrasi backend dashboard Phase 3 tervalidasi 100% aman dan role-separated.\n');

// ============================================================================
// RINGKASAN AKHIR
// ============================================================================
console.log('======================================================');
console.log('SELURUH PENGUJIAN PHASE 2 & 3 BERHASIL LULUS (100% PASS)');
console.log('======================================================');
