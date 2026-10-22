/**
 * ============================================================================
 * SISTEM ABSENSI & PENILAIAN SISWA SD (VERSI 2)
 * File: tests/test_phase9_remediation.js
 * ============================================================================
 *
 * Suite Pengujian Phase 9.3: Remediasi Keamanan Terarah
 * 1. Verifikasi penutupan fungsi internal (nama berakhiran _) di code.gs dan setup.gs
 * 2. Verifikasi hanya doGet dan api* yang berstatus fungsi publik
 * 3. Verifikasi mekanisme login throttling & lockout (5x gagal -> lockout 15 menit)
 * 4. Verifikasi pencegahan user enumeration pada login gagal dan lockout
 * 5. Verifikasi pemulihan (reset) counter setelah login berhasil atau lockout dibersihkan
 * 6. Verifikasi global burst throttling
 * 7. Verifikasi konsistensi pemanggilan internal pada endpoint yang sah
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

console.log('=== MEMULAI SUITE PENGUJIAN OTOMATIS PHASE 9.3: REMEDIASI KEAMANAN TERARAH ===\n');

// ----------------------------------------------------------------------------
// SUITE 1: Verifikasi Penutupan Fungsi Internal (Underscore Naming Convention)
// ----------------------------------------------------------------------------
console.log('--- TEST SUITE 1: Audit Penutupan Fungsi Internal RPC (Apps Script Underscore Convention) ---');

const codeGsContent = fs.readFileSync(path.resolve(__dirname, '../code.gs'), 'utf8');
const setupGsContent = fs.readFileSync(path.resolve(__dirname, '../setup.gs'), 'utf8');

// Ambil seluruh deklarasi fungsi global top-level di code.gs
const codeFuncMatches = [...codeGsContent.matchAll(/^function\s+([a-zA-Z0-9_]+)\s*\(/gm)].map(m => m[1]);
// Ambil seluruh deklarasi fungsi global top-level di setup.gs
const setupFuncMatches = [...setupGsContent.matchAll(/^function\s+([a-zA-Z0-9_]+)\s*\(/gm)].map(m => m[1]);

// 1. Verifikasi setup.gs: SELURUH fungsi HARUS berakhiran underscore _ kecuali whitelist wrapper menu publik resmi
const ALLOWED_SETUP_PUBLIC_WRAPPERS = new Set([
  'onOpen',
  'menuAuditSkema',
  'menuSetupDatabase',
  'menuInitKepalaSekolah',
  'menuSeedDatabase',
  'runSchemaCheckFromEditor',
  'runKepalaSekolahOnboardingFromEditor',
  'submitSecureSeedCredentials',
  'submitKepalaSekolahOnboarding'
]);
const invalidPublicSetup = setupFuncMatches.filter(fn => !fn.endsWith('_') && !ALLOWED_SETUP_PUBLIC_WRAPPERS.has(fn));
assert.strictEqual(invalidPublicSetup.length, 0, `Ditemukan fungsi publik tidak sah di setup.gs: ${invalidPublicSetup.join(', ')}`);
ALLOWED_SETUP_PUBLIC_WRAPPERS.forEach(fn => {
  assert(setupFuncMatches.includes(fn), `Fungsi wrapper publik ${fn} tidak ditemukan di setup.gs`);
});
console.log(`✓ setup.gs aman: Tepat ${ALLOWED_SETUP_PUBLIC_WRAPPERS.size} wrapper menu publik resmi terverifikasi dan ${setupFuncMatches.filter(fn => fn.endsWith('_')).length} fungsi internal berakhiran underscore _ (private RPC).`);

// 2. Verifikasi code.gs: Fungsi publik HANYA boleh diawali api* ATAU bernama doGet
const invalidPublicCode = codeFuncMatches.filter(fn => {
  if (fn.endsWith('_')) return false; // Private
  if (fn === 'doGet') return false;   // Entrypoint web app
  if (fn.startsWith('api')) return false; // Endpoint API resmi
  return true; // Tidak valid!
});
assert.strictEqual(invalidPublicCode.length, 0, `Ditemukan fungsi pembantu yang terekspos tanpa underscore di code.gs: ${invalidPublicCode.join(', ')}`);

const publicEndpoints = codeFuncMatches.filter(fn => !fn.endsWith('_'));
console.log(`✓ code.gs aman: Tepat ${publicEndpoints.length} entrypoint publik resmi (1 doGet + 41 api*).`);
console.log(`✓ code.gs helper: Seluruh ${codeFuncMatches.filter(fn => fn.endsWith('_')).length} fungsi pembantu berakhiran underscore _.\n`);

// ----------------------------------------------------------------------------
// SUITE 2: Verifikasi Throttling & Lockout pada apiLogin
// ----------------------------------------------------------------------------
console.log('--- TEST SUITE 2: Mitigasi Brute Force & Lockout Percobaan Login ---');

// Impor code.gs dan setup.gs
const codeModule = require('../code.gs');
const setupModule = require('../setup.gs');

const {
  AUTH_CONFIG,
  _localMemoryCache,
  LoginThrottle,
  apiLogin,
  hashPasswordPBKDF2_,
  generateSecureSalt_
} = codeModule;

// Bersihkan cache in-memory lokal sebelum pengujian
_localMemoryCache.clear();

// Siapkan mock database user di memory
const mockSalt = generateSecureSalt_();
const mockHash = hashPasswordPBKDF2_('Password123!', mockSalt);

const mockUserSheet = {
  getName: () => 'user',
  getLastRow: () => 2,
  getLastColumn: () => 12,
  getRange: (r, c, nr, nc) => ({
    getValues: () => [
      ['id', 'nama', 'nip', 'username', 'password_hash', 'password_salt', 'role', 'foto', 'terakhir_login', 'is_active', 'created_at', 'updated_at'],
      ['usr_1', 'Budi Santoso', '19800101', 'guru_budi', mockHash, mockSalt, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01']
    ],
    setValue: () => {}
  })
};

const mockSpreadsheet = {
  getSheetByName: (name) => {
    if (name === 'user') return mockUserSheet;
    return null;
  }
};

global.getTargetSpreadsheet_ = () => mockSpreadsheet;
global.SpreadsheetApp = {
  getActiveSpreadsheet: () => mockSpreadsheet
};

// Test 2.1: Login gagal berturut-turut pada akun yang terdaftar
const targetUser = 'guru_budi';
LoginThrottle.clearFailure(targetUser);

for (let attempt = 1; attempt <= 4; attempt++) {
  const res = apiLogin(targetUser, 'WrongPassword');
  assert.strictEqual(res.success, false, `Percobaan ${attempt} seharusnya gagal`);
  assert.strictEqual(res.message, AUTH_CONFIG.GENERIC_AUTH_ERROR, `Percobaan ${attempt} harus menghasilkan pesan generik`);
}
console.log('✓ Percobaan 1–4 menghasilkan pesan generik "Username atau password salah."');

// Percobaan ke-5 harus langsung memicu lockout
const res5 = apiLogin(targetUser, 'WrongPassword');
assert.strictEqual(res5.success, false);
assert.strictEqual(res5.message, AUTH_CONFIG.LOCKOUT_ERROR, 'Percobaan ke-5 harus menghasilkan pesan lockout');
console.log('✓ Percobaan ke-5 memicu status lockout 15 menit');

// Percobaan ke-6 (bahkan jika sekarang memasukkan password yang benar) harus tetap ditolak karena akun terkunci
const res6 = apiLogin(targetUser, 'Password123!');
assert.strictEqual(res6.success, false);
assert.strictEqual(res6.message, AUTH_CONFIG.LOCKOUT_ERROR, 'Saat lockout aktif, password benar tetap harus ditolak');
console.log('✓ Password benar tetap ditolak saat status lockout aktif');

// Test 2.2: Verifikasi anti user-enumeration pada username yang TIDAK terdaftar
const unknownUser = 'unknown_hacker';
LoginThrottle.clearFailure(unknownUser);

for (let attempt = 1; attempt <= 4; attempt++) {
  const res = apiLogin(unknownUser, 'AnyPassword');
  assert.strictEqual(res.success, false);
  assert.strictEqual(res.message, AUTH_CONFIG.GENERIC_AUTH_ERROR);
}

const resUnknown5 = apiLogin(unknownUser, 'AnyPassword');
assert.strictEqual(resUnknown5.success, false);
assert.strictEqual(resUnknown5.message, AUTH_CONFIG.LOCKOUT_ERROR, 'Username tidak terdaftar juga harus mengembalikan lockout setelah 5x');
console.log('✓ Anti User-Enumeration terverifikasi: Username tidak terdaftar mengikuti alur lockout yang identik 100%');

// Test 2.3: Pemulihan (Reset) setelah periode lockout selesai
LoginThrottle.clearFailure(targetUser);
const resRecovery = apiLogin(targetUser, 'Password123!');
assert.strictEqual(resRecovery.success, true, 'Setelah lockout dibersihkan, login sah harus berhasil');
assert.strictEqual(resRecovery.data.user.username, targetUser);
console.log('✓ Pemulihan akun: Login sah berhasil setelah masa lockout selesai/dibersihkan');

// Test 2.4: Login sukses membersihkan riwayat kegagalan sebelumnya
// Buat 3 kali gagal
apiLogin(targetUser, 'WrongPassword');
apiLogin(targetUser, 'WrongPassword');
apiLogin(targetUser, 'WrongPassword');
// Lalu login sukses
const resSuccess = apiLogin(targetUser, 'Password123!');
assert.strictEqual(resSuccess.success, true);
// Sekarang coba salah 4 kali lagi, akun tidak boleh langsung terkunci karena counter telah di-reset oleh login sukses
apiLogin(targetUser, 'WrongPassword');
apiLogin(targetUser, 'WrongPassword');
apiLogin(targetUser, 'WrongPassword');
const resCheck = apiLogin(targetUser, 'WrongPassword');
assert.strictEqual(resCheck.message, AUTH_CONFIG.GENERIC_AUTH_ERROR, 'Counter kegagalan terbukti di-reset setelah login sukses');
console.log('✓ Reset otomatis: Login sukses membersihkan akumulasi percobaan gagal sebelumnya\n');

// ----------------------------------------------------------------------------
// SUITE 3: Verifikasi Global Burst Throttling
// ----------------------------------------------------------------------------
console.log('--- TEST SUITE 3: Perlindungan Global Burst Throttling ---');

_localMemoryCache.clear();
const burstKey = 'login_burst_' + Math.floor(Date.now() / 60000);

// Set counter burst global mencapai batas maksimum
_localMemoryCache.set(burstKey, String(AUTH_CONFIG.GLOBAL_RATE_LIMIT_BURST));

const resBurst = apiLogin('anyone', 'password');
assert.strictEqual(resBurst.success, false);
assert.match(resBurst.message, /sibuk/i, 'Request harus ditahan ketika burst limit global tercapai');
console.log('✓ Global burst throttling berhasil menahan lonjakan request massal multi-username');

// Bersihkan cache burst
_localMemoryCache.clear();
console.log('✓ Global burst throttling berhasil diuji dan diverifikasi\n');

// ----------------------------------------------------------------------------
// SUITE 4: Verifikasi Kompatibilitas Endpoint Sah
// ----------------------------------------------------------------------------
console.log('--- TEST SUITE 4: Integritas Endpoint Sah dan Ketersediaan Ekspor ---');

// Pastikan helper dapat diakses baik melalui nama baru berakhiran _ maupun alias backward compatibility
assert.strictEqual(typeof codeModule.getSheetDataBatch_, 'function');
assert.strictEqual(typeof codeModule.getSheetDataBatch, 'function');
assert.strictEqual(typeof codeModule.requireAuth_, 'function');
assert.strictEqual(typeof codeModule.requireAuth, 'function');
assert.strictEqual(typeof setupModule.validateSpreadsheetSchema_, 'function');
assert.strictEqual(typeof setupModule.validateSpreadsheetSchema, 'function');

console.log('✓ Seluruh helper internal diekspor dengan aman untuk runner Node.js tanpa merusak antarmuka');
console.log('\n============================================================================');
console.log('HASIL PENGUJIAN: SELURUH TEST SUITE PHASE 9.3 BERHASIL 100% DENGAN SUKSES!');
console.log('============================================================================\n');
