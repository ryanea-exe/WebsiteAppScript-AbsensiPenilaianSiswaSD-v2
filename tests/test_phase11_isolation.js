/**
 * ============================================================================
 * SISTEM ABSENSI & PENILAIAN SISWA SD (VERSI 2)
 * File: tests/test_phase11_isolation.js
 * ============================================================================
 *
 * SUITE PENGUJIAN REGRESI PHASE 11.1: REMEDIASI ISOLASI PRODUKSI & TARGET DATABASE
 *
 * Cakupan Pengujian:
 * 1. SPREADSHEET_ID valid pada ScriptProperties.
 * 2. SPREADSHEET_ID kosong atau hilang.
 * 3. Penolakan fallback diam-diam ke spreadsheet container-bound.
 * 4. Penolakan ID target yang tidak sesuai kebijakan konfigurasi.
 * 5. Target test tetap berjalan menggunakan konfigurasi eksplisit.
 * 6. Seed/Setup tidak lagi bergantung pada ID test yang di-hardcode (Mendukung ID Produksi).
 * 7. Inisialisasi akun Kepala Sekolah tidak membuat akun dummy dan menggunakan hash aman.
 * 8. Inisialisasi ditolak jika akun Kepala Sekolah sudah terdaftar (Singleton Role Guard).
 * 9. Tidak ada mutasi/penulisan jika validasi preflight gagal (Zero-side-effects).
 * 10. Integritas pemisahan clasp (.clasp.test.json, .clasp.prod.json.template, .gitignore, scripts/check_target.js).
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const setupModule = require('../setup.gs');
const codeModule = require('../code.gs');

const {
  SCHEMA_DEFINITIONS,
  getTargetSpreadsheet_,
  validateSpreadsheetSchema_,
  runControlledSetupAndSeed_,
  initKepalaSekolahUser_,
  submitKepalaSekolahOnboarding
} = setupModule;

const {
  getDatabaseSpreadsheet_,
  apiLogin,
  verifyPassword_
} = codeModule;

console.log('=== MEMULAI SUITE PENGUJIAN REGRESI PHASE 11.1: ISOLASI TARGET & ONBOARDING PRODUKSI ===\n');

// 1. Inisialisasi Environment Mock Global
global.Session = {
  getActiveUser: () => ({ getEmail: () => 'ryanhillfree23@gmail.com' }),
  getEffectiveUser: () => ({ getEmail: () => 'ryanhillfree23@gmail.com' })
};

function createMockSS(id, name, initialSheets = {}) {
  const sheets = {};

  function makeMockSheet(sheetName, headers = [], dataRows = []) {
    const grid = [];
    if (headers && headers.length > 0) {
      grid.push([...headers]);
    }
    dataRows.forEach(r => grid.push([...r]));

    return {
      getName: () => sheetName,
      getLastRow: () => grid.length,
      getLastColumn: () => {
        let maxCol = 0;
        grid.forEach(row => { if (row.length > maxCol) maxCol = row.length; });
        return maxCol;
      },
      getRange: (row, col, numRows = 1, numCols = 1) => {
        return {
          getValues: () => {
            const result = [];
            for (let r = 0; r < numRows; r++) {
              const rowIdx = row - 1 + r;
              const rowArr = [];
              for (let c = 0; c < numCols; c++) {
                const colIdx = col - 1 + c;
                rowArr.push((grid[rowIdx] && grid[rowIdx][colIdx] !== undefined) ? grid[rowIdx][colIdx] : '');
              }
              result.push(rowArr);
            }
            return result;
          },
          setValues: (values) => {
            for (let r = 0; r < values.length; r++) {
              const rowIdx = row - 1 + r;
              while (grid.length <= rowIdx) {
                grid.push([]);
              }
              for (let c = 0; c < values[r].length; c++) {
                const colIdx = col - 1 + c;
                grid[rowIdx][colIdx] = values[r][c];
              }
            }
          },
          setFontWeight: () => {},
          setNumberFormat: () => {}
        };
      },
      appendRow: (rowArr) => {
        grid.push([...rowArr]);
      },
      deleteRow: (rowIdx) => {
        grid.splice(rowIdx - 1, 1);
      },
      _grid: grid
    };
  }

  // Siapkan sheet sesuai definisi skema
  Object.keys(SCHEMA_DEFINITIONS).forEach(sName => {
    const sData = initialSheets[sName];
    const headers = SCHEMA_DEFINITIONS[sName];
    const dataRows = (sData && sData.dataRows) ? sData.dataRows : [];
    sheets[sName] = makeMockSheet(sName, headers, dataRows);
  });

  return {
    getId: () => id,
    getName: () => name,
    getSheetByName: (sName) => sheets[sName] || null,
    insertSheet: (sName) => {
      if (sheets[sName]) throw new Error('Sheet ' + sName + ' sudah ada');
      sheets[sName] = makeMockSheet(sName);
      return sheets[sName];
    },
    getSheets: () => Object.values(sheets),
    _sheets: sheets
  };
}

// ----------------------------------------------------------------------------
// TEST 1: SPREADSHEET_ID Valid pada ScriptProperties
// ----------------------------------------------------------------------------
console.log('1. Menguji Akses Database dengan SPREADSHEET_ID Valid pada ScriptProperties...');

const validProdId = 'PROD_SPREADSHEET_ID_ALPHA_123456';
const mockProdSS = createMockSS(validProdId, 'PROD - Absensi SD v2 - Database');

const openedStore = {};
openedStore[validProdId] = mockProdSS;

let scriptProps = { SPREADSHEET_ID: validProdId };
global.PropertiesService = {
  getScriptProperties: () => ({
    getProperty: (key) => scriptProps[key] || null,
    setProperty: (key, val) => { scriptProps[key] = val; }
  })
};

global.SpreadsheetApp = {
  openById: (id) => {
    if (openedStore[id]) return openedStore[id];
    throw new Error('Spreadsheet dengan ID ' + id + ' tidak ditemukan');
  },
  getActiveSpreadsheet: () => null,
  flush: () => {}
};

const resolvedSS = getDatabaseSpreadsheet_();
assert.strictEqual(resolvedSS.getId(), validProdId, 'ID Spreadsheet harus cocok dengan konfigurasi SPREADSHEET_ID');
console.log('   ✓ Lolos: SPREADSHEET_ID valid berhasil membuka spreadsheet target yang benar.\n');

// ----------------------------------------------------------------------------
// TEST 2: SPREADSHEET_ID Kosong atau Hilang
// ----------------------------------------------------------------------------
console.log('2. Menguji Penolakan Akses jika SPREADSHEET_ID Kosong atau Hilang...');

scriptProps = { SPREADSHEET_ID: '' }; // Kosong
global.MOCK_DISABLE_NODE_FALLBACK = true; // Nonaktifkan fallback mock Node.js untuk menguji perilaku strict

let errorCaught2a = false;
try {
  getDatabaseSpreadsheet_();
} catch (err) {
  errorCaught2a = true;
  assert.ok(err.message.includes('Target SPREADSHEET_ID belum dikonfigurasi') || err.message.includes('Target Spreadsheet belum ditentukan'), 'Harus menolak dengan pesan error yang jelas');
}
assert.strictEqual(errorCaught2a, true, 'SPREADSHEET_ID kosong wajib ditolak.');

scriptProps = {}; // Hilang/undefined
let errorCaught2b = false;
try {
  getDatabaseSpreadsheet_();
} catch (err) {
  errorCaught2b = true;
  assert.ok(err.message.includes('Target SPREADSHEET_ID belum dikonfigurasi') || err.message.includes('Target Spreadsheet belum ditentukan'), 'Harus menolak dengan pesan error yang jelas');
}
assert.strictEqual(errorCaught2b, true, 'SPREADSHEET_ID tidak disetel wajib ditolak.');
console.log('   ✓ Lolos: SPREADSHEET_ID kosong/hilang berhasil ditolak secara fail-closed.\n');

// ----------------------------------------------------------------------------
// TEST 3: Penolakan Fallback Diam-diam ke Container-Bound Spreadsheet
// ----------------------------------------------------------------------------
console.log('3. Menguji Penolakan Fallback Diam-diam ke Spreadsheet Container-Bound...');

const testContainerSS = createMockSS('TEST_CONTAINER_BOUND_ID_999', 'TEST - Container Bound Sheet');
// Meskipun SpreadsheetApp.getActiveSpreadsheet mengembalikan spreadsheet container-bound:
global.SpreadsheetApp.getActiveSpreadsheet = () => testContainerSS;

let errorCaught3 = false;
try {
  // getDatabaseSpreadsheet_ (jalur Web App) TIDAK BOLEH mengambil active container sheet jika SPREADSHEET_ID tidak disetel
  getDatabaseSpreadsheet_();
} catch (err) {
  errorCaught3 = true;
  assert.ok(!err.message.includes('TEST_CONTAINER_BOUND_ID_999'), 'Tidak boleh membuka spreadsheet test secara diam-diam');
}
assert.strictEqual(errorCaught3, true, 'Fallback diam-diam ke active container-bound wajib diblokir pada Web App.');
console.log('   ✓ Lolos: Fallback diam-diam ke active container-bound spreadsheet terbukti diblokir 100%.\n');

// Pulihkan flag fallback testing
global.MOCK_DISABLE_NODE_FALLBACK = false;

// ----------------------------------------------------------------------------
// TEST 4: Penolakan ID Target yang Tidak Sesuai Kebijakan Konfigurasi
// ----------------------------------------------------------------------------
console.log('4. Menguji Penolakan ID Target yang Tidak Sesuai Kebijakan Konfigurasi...');

const officialTargetId = 'OFFICIAL_TARGET_ID_777';
scriptProps = { SPREADSHEET_ID: officialTargetId };

const foreignSS = createMockSS('UNAUTHORIZED_EXTERNAL_SHEET_ID', 'Foreign Spreadsheet');
let errorCaught4 = false;
try {
  runControlledSetupAndSeed_(foreignSS, { skipSeed: true });
} catch (err) {
  errorCaught4 = true;
  assert.ok(err.message.includes('Target Spreadsheet ID tidak valid'), 'Harus melaporkan ID tidak valid');
  assert.ok(err.message.includes(officialTargetId), 'Harus memuat ID resmi yang diharapkan');
}
assert.strictEqual(errorCaught4, true, 'Mutasi pada spreadsheet asing yang tidak sesuai target resmi wajib ditolak.');
console.log('   ✓ Lolos: Target spreadsheet ID asing berhasil digagalkan sebelum mutasi.\n');

// ----------------------------------------------------------------------------
// TEST 5: Target Test Tetap Berjalan Menggunakan Konfigurasi Eksplisit
// ----------------------------------------------------------------------------
console.log('5. Menguji Target Test Tetap Berjalan Melalui Konfigurasi Eksplisit...');

const testExplicitId = '1tVY7hHpZNTHQ0c_9GEaM2-Gz4fOh8qccsCP0afRLBd8';
const testMockSS = createMockSS(testExplicitId, 'TEST - Absensi SD v2 - Database Setup');
scriptProps = { SPREADSHEET_ID: testExplicitId };

const testReport = runControlledSetupAndSeed_(testMockSS, {
  skipSeed: true,
  expectedSpreadsheetId: testExplicitId
});
assert.strictEqual(testReport.success, true, 'Target test harus berhasil dijalankan secara eksplisit');
console.log('   ✓ Lolos: Lingkungan test berjalan stabil menggunakan konfigurasi eksplisit.\n');

// ----------------------------------------------------------------------------
// TEST 6: Seed/Setup Tidak Lagi Bergantung pada ID Test yang Di-hardcode
// ----------------------------------------------------------------------------
console.log('6. Menguji Seed/Setup Berhasil pada Target Produksi Baru (Bebas Hardcoded ID)...');

const newProdDbId = 'PROD_NEW_SPREADSHEET_ST_PETER_999888';
const newProdSS = createMockSS(newProdDbId, 'PROD - Database SD Negeri 01');
scriptProps = { SPREADSHEET_ID: newProdDbId };

const prodPass1 = 'ProdKepsekP@ssw0rd2026!';
const prodPass2 = 'ProdWaliP@ssw0rd2026!';

const prodSeedReport = runControlledSetupAndSeed_(newProdSS, {
  skipSeed: false,
  expectedSpreadsheetId: newProdDbId,
  credentials: {
    kepsekPassword: prodPass1,
    waliPassword: prodPass2
  }
});
assert.strictEqual(prodSeedReport.success, true, 'Seed harus berhasil pada ID produksi baru');
assert.strictEqual(newProdSS.getId(), newProdDbId, 'Target operasi adalah ID produksi baru');
console.log('   ✓ Lolos: Ketergantungan hardcoded ID test terbukti dihilangkan; setup/seed berjalan mulus pada ID produksi baru.\n');

// ----------------------------------------------------------------------------
// TEST 7: Inisialisasi Akun Kepala Sekolah Resmi (Bukan Akun Dummy & Hash Aman)
// ----------------------------------------------------------------------------
console.log('7. Menguji Inisialisasi Akun Kepala Sekolah Resmi (Tanpa Akun Dummy & Menggunakan Hash Aman)...');

const cleanProdSS = createMockSS('PROD_CLEAN_DB_001', 'PROD - Fresh DB');
scriptProps = { SPREADSHEET_ID: 'PROD_CLEAN_DB_001' };

// Setup skema kosong tanpa seed dummy
runControlledSetupAndSeed_(cleanProdSS, { skipSeed: true, expectedSpreadsheetId: 'PROD_CLEAN_DB_001' });

// A. Uji penolakan akun dummy saat inisialisasi resmi
let dummyRejectKepsek = false;
try {
  initKepalaSekolahUser_(cleanProdSS, {
    username: 'kepsek_test',
    password: 'OfficialPassword123!',
    nama: 'Kepsek Dummy'
  }, { expectedSpreadsheetId: 'PROD_CLEAN_DB_001' });
} catch (e) {
  dummyRejectKepsek = true;
  assert.ok(e.message.includes('Username pengujian'), 'Harus menolak username dummy kepsek_test');
}
assert.strictEqual(dummyRejectKepsek, true, 'Username dummy kepsek_test wajib ditolak untuk inisialisasi resmi.');

let dummyRejectGuru = false;
try {
  initKepalaSekolahUser_(cleanProdSS, {
    username: 'guru_test',
    password: 'OfficialPassword123!',
    nama: 'Guru Dummy'
  }, { expectedSpreadsheetId: 'PROD_CLEAN_DB_001' });
} catch (e) {
  dummyRejectGuru = true;
  assert.ok(e.message.includes('Username pengujian'), 'Harus menolak username dummy guru_test');
}
assert.strictEqual(dummyRejectGuru, true, 'Username dummy guru_test wajib ditolak untuk inisialisasi resmi.');

// B. Inisialisasi akun resmi Kepala Sekolah
const officialPass = 'K3ps3k_Resmi_2026!#Strong';
const initResult = initKepalaSekolahUser_(cleanProdSS, {
  username: 'kepsek_resmi',
  password: officialPass,
  nama: 'Drs. H. Mulyadi, M.Pd.',
  nip: '197001011995031001'
}, {
  expectedSpreadsheetId: 'PROD_CLEAN_DB_001',
  usePBKDF2: true
});

assert.strictEqual(initResult.success, true, 'Inisialisasi akun resmi harus sukses');
assert.strictEqual(initResult.username, 'kepsek_resmi');
assert.strictEqual(initResult.role, 'kepala_sekolah');
assert.strictEqual(initResult.password, undefined, 'Respons tidak boleh memuat password');

// Verifikasi isi sheet user
const uSheet = cleanProdSS.getSheetByName('user');
assert.strictEqual(uSheet.getLastRow(), 2, 'Sheet user harus berisi tepat 1 akun Kepala Sekolah (2 baris total)');
const userValues = uSheet.getRange(2, 1, 1, uSheet.getLastColumn()).getValues()[0];
const uHeaders = SCHEMA_DEFINITIONS.user;

const storedUsername = userValues[uHeaders.indexOf('username')];
const storedHash = userValues[uHeaders.indexOf('password_hash')];
const storedSalt = userValues[uHeaders.indexOf('password_salt')];
const storedRole = userValues[uHeaders.indexOf('role')];

assert.strictEqual(storedUsername, 'kepsek_resmi');
assert.strictEqual(storedRole, 'kepala_sekolah');
assert.ok(storedHash.startsWith('pbkdf2:sha256:100000:'), 'Password harus di-hash menggunakan PBKDF2 100.000 iterasi');
assert.strictEqual(storedSalt.length, 64, 'Salt harus memiliki panjang 64 karakter hex');

// Verifikasi kompatibilitas verifikasi password terhadap backend code.gs
const verifyRes = verifyPassword_(officialPass, storedHash, storedSalt);
assert.strictEqual(verifyRes.valid, true, 'Hash akun Kepala Sekolah harus terverifikasi valid 100% oleh verifyPassword_');
console.log('   ✓ Lolos: Inisialisasi akun Kepala Sekolah resmi menolak dummy, memakai PBKDF2 terstruktur, dan valid 100%.\n');

// ----------------------------------------------------------------------------
// TEST 8: Inisialisasi Ditolak jika Akun Kepala Sekolah Sudah Terdaftar
// ----------------------------------------------------------------------------
console.log('8. Menguji Singleton Guard: Penolakan Inisialisasi Akun Kepala Sekolah Kedua...');

let errorDuplicateKepsek = false;
try {
  initKepalaSekolahUser_(cleanProdSS, {
    username: 'kepsek_kedua',
    password: 'PasswordLain999!#',
    nama: 'Dr. Bambang, M.Pd.'
  }, { expectedSpreadsheetId: 'PROD_CLEAN_DB_001' });
} catch (e) {
  errorDuplicateKepsek = true;
  assert.ok(e.message.includes('Akun Kepala Sekolah sudah terdaftar'), 'Harus menolak akun Kepala Sekolah kedua');
}
assert.strictEqual(errorDuplicateKepsek, true, 'Inisialisasi akun Kepala Sekolah kedua wajib ditolak demi integritas singleton role.');

// Pastikan sheet user tetap tepat 2 baris
assert.strictEqual(cleanProdSS.getSheetByName('user').getLastRow(), 2, 'Sheet user tidak boleh bertambah setelah penolakan duplikat');
console.log('   ✓ Lolos: Singleton guard terbukti menolak pembentukan akun Kepala Sekolah ganda.\n');

// ----------------------------------------------------------------------------
// TEST 9: Tidak Ada Mutasi / Penulisan jika Validasi Preflight Gagal
// ----------------------------------------------------------------------------
console.log('9. Menguji Zero-Side-Effects: Tidak Ada Penulisan jika Preflight Gagal...');

const preflightSS = createMockSS('PROD_PREFLIGHT_002', 'PROD - Preflight DB');
scriptProps = { SPREADSHEET_ID: 'PROD_PREFLIGHT_002' };
runControlledSetupAndSeed_(preflightSS, { skipSeed: true, expectedSpreadsheetId: 'PROD_PREFLIGHT_002' });

const initialUserRows = preflightSS.getSheetByName('user').getLastRow(); // Tepat 1 baris (header)

// A. Password terlalu pendek (< 8 karakter)
let passShortErr = false;
try {
  initKepalaSekolahUser_(preflightSS, {
    username: 'kepsek_baru',
    password: 'short', // 5 chars
    nama: 'Pak Guru'
  }, { expectedSpreadsheetId: 'PROD_PREFLIGHT_002' });
} catch (e) {
  passShortErr = true;
}
assert.strictEqual(passShortErr, true, 'Password pendek wajib ditolak');
assert.strictEqual(preflightSS.getSheetByName('user').getLastRow(), initialUserRows, 'Sheet user tidak boleh berubah saat password tidak valid');

// B. Username terlalu pendek (< 3 karakter)
let userShortErr = false;
try {
  initKepalaSekolahUser_(preflightSS, {
    username: 'ab',
    password: 'PasswordPanjang123!',
    nama: 'Pak Guru'
  }, { expectedSpreadsheetId: 'PROD_PREFLIGHT_002' });
} catch (e) {
  userShortErr = true;
}
assert.strictEqual(userShortErr, true, 'Username pendek wajib ditolak');
assert.strictEqual(preflightSS.getSheetByName('user').getLastRow(), initialUserRows, 'Sheet user tidak boleh berubah saat username tidak valid');

// C. Mismatch target ID
let targetMismatchErr = false;
try {
  initKepalaSekolahUser_(preflightSS, {
    username: 'kepsek_valid',
    password: 'PasswordPanjang123!',
    nama: 'Pak Guru'
  }, { expectedSpreadsheetId: 'WRONG_UNAUTHORIZED_TARGET_ID' });
} catch (e) {
  targetMismatchErr = true;
}
assert.strictEqual(targetMismatchErr, true, 'Target mismatch wajib ditolak');
assert.strictEqual(preflightSS.getSheetByName('user').getLastRow(), initialUserRows, 'Sheet user tidak boleh berubah saat target mismatch');
console.log('   ✓ Lolos: Seluruh kegagalan preflight terbukti 100% aman tanpa mutasi atau efek samping.\n');

// ----------------------------------------------------------------------------
// TEST 10: Integritas Pemisahan Clasp (.clasp.test.json, .clasp.prod.json.template, .gitignore)
// ----------------------------------------------------------------------------
console.log('10. Menguji Ketersediaan & Validitas File Pemisahan Lingkungan Clasp...');

const rootDir = path.resolve(__dirname, '..');
const claspActiveFile = path.join(rootDir, '.clasp.json');
const claspTestFile = path.join(rootDir, '.clasp.test.json');
const claspProdTemplate = path.join(rootDir, '.clasp.prod.json.template');
const gitignoreFile = path.join(rootDir, '.gitignore');
const claspignoreFile = path.join(rootDir, '.claspignore');
const checkTargetScript = path.join(rootDir, 'scripts/check_target.js');

// 10.1 File wajib ada
assert.ok(fs.existsSync(claspActiveFile), '.clasp.json aktif wajib ada');
assert.ok(fs.existsSync(claspTestFile), '.clasp.test.json wajib ada');
assert.ok(fs.existsSync(claspProdTemplate), '.clasp.prod.json.template wajib ada');
assert.ok(fs.existsSync(gitignoreFile), '.gitignore wajib ada');
assert.ok(fs.existsSync(claspignoreFile), '.claspignore wajib ada');
assert.ok(fs.existsSync(checkTargetScript), 'scripts/check_target.js wajib ada');

// 10.2 Konten .clasp.test.json harus memuat test scriptId & test parentId
const testConfig = JSON.parse(fs.readFileSync(claspTestFile, 'utf8'));
assert.strictEqual(testConfig.scriptId, '17r8cFSyJY0M1EAZwBcsKDhjJq9wRE1hehz3GeU9OWIyYhF7n9GUA5pE3');
assert.strictEqual(testConfig.parentId, '1tVY7hHpZNTHQ0c_9GEaM2-Gz4fOh8qccsCP0afRLBd8');

// 10.3 Konten .clasp.prod.json.template tidak boleh memuat secret nyata
const prodTemplateContent = fs.readFileSync(claspProdTemplate, 'utf8');
assert.ok(prodTemplateContent.includes('REPLACE_WITH_PRODUCTION_APPS_SCRIPT_ID'));
assert.ok(!prodTemplateContent.includes('ryanhillfree23'));

// 10.4 .gitignore wajib mengecualikan .clasp.prod.json
const gitignoreContent = fs.readFileSync(gitignoreFile, 'utf8');
assert.ok(gitignoreContent.includes('.clasp.prod.json'));

// 10.5 .claspignore wajib mengecualikan profil clasp dan scripts
const claspignoreContent = fs.readFileSync(claspignoreFile, 'utf8');
assert.ok(claspignoreContent.includes('scripts/**'));
assert.ok(claspignoreContent.includes('.clasp.test.json'));
assert.ok(claspignoreContent.includes('.clasp.prod.json*'));
assert.ok(claspignoreContent.includes('.gitignore'));

// 10.6 Verifikasi file konfigurasi produksi lokal (.clasp.prod.json)
const claspProdFile = path.join(rootDir, '.clasp.prod.json');
assert.ok(fs.existsSync(claspProdFile), '.clasp.prod.json wajib tersedia secara lokal');
const prodConfigData = JSON.parse(fs.readFileSync(claspProdFile, 'utf8'));
assert.strictEqual(prodConfigData.scriptId, '1Pr_NMaCNjNaC-GHIrC4mWLg6zHg-4YgvE7W2aG4ntHDmUy-da-pLFQHs', 'Script ID produksi harus cocok');
assert.strictEqual(prodConfigData.parentId, '1nMOUhC8sIoJBQBWZ_Muhkoo1dQnIhylSnfQGg9qgqxk', 'Parent ID produksi harus cocok');

console.log('   ✓ Lolos: Seluruh file pemisahan clasp tervalidasi lengkap, bebas secret, dan terisolasi.\n');

// ----------------------------------------------------------------------------
// TEST 11: Verifikasi Handler Onboarding Kepala Sekolah & Modal Dialog
// ----------------------------------------------------------------------------
console.log('11. Menguji Handler Onboarding Kepala Sekolah (submitKepalaSekolahOnboarding)...');

// 11.1 Dialog HTML wajib ada
const kepsekDialogFile = path.join(rootDir, 'SecureKepsekDialog.html');
assert.ok(fs.existsSync(kepsekDialogFile), 'SecureKepsekDialog.html wajib tersedia');
const dialogHtml = fs.readFileSync(kepsekDialogFile, 'utf8');
assert.ok(dialogHtml.includes('submitKepalaSekolahOnboarding'), 'Dialog HTML wajib memanggil submitKepalaSekolahOnboarding');
assert.ok(dialogHtml.includes('type="password"'), 'Dialog HTML wajib menggunakan field password');

// 11.2 Penolakan password mismatch
let mismatchErr = false;
try {
  submitKepalaSekolahOnboarding({
    nama: 'H. Sudirman, M.Pd.',
    username: 'kepsek_prod',
    password: 'PasswordSuper123!',
    confirmPassword: 'PasswordBeda123!'
  });
} catch (e) {
  mismatchErr = true;
  assert.ok(e.message.includes('Konfirmasi kata sandi tidak cocok'));
}
assert.strictEqual(mismatchErr, true, 'Mismatch konfirmasi password wajib ditolak');

// 11.3 Penolakan jika bukan authorized owner
const originalSession = global.Session;
let unauthErr = false;
try {
  global.Session = {
    getActiveUser: () => ({ getEmail: () => 'attacker@gmail.com' }),
    getEffectiveUser: () => ({ getEmail: () => 'attacker@gmail.com' })
  };
  submitKepalaSekolahOnboarding({
    nama: 'H. Sudirman, M.Pd.',
    username: 'kepsek_prod',
    password: 'PasswordSuper123!',
    confirmPassword: 'PasswordSuper123!'
  });
} catch (e) {
  unauthErr = true;
  assert.ok(e.message.includes('Akses ditolak'));
} finally {
  global.Session = originalSession;
}
assert.strictEqual(unauthErr, true, 'Pengguna tidak terotorisasi wajib ditolak');

// 11.4 Eksekusi sukses onboarding pada mock spreadsheet baru
const onboardingSS = createMockSS('1nMOUhC8sIoJBQBWZ_Muhkoo1dQnIhylSnfQGg9qgqxk', 'PROD - Absensi Penilaian SD v2');
const userSheetMock = onboardingSS.getSheetByName('user');

const originalSpreadsheetApp = global.SpreadsheetApp;
global.SpreadsheetApp = {
  getActiveSpreadsheet: () => onboardingSS,
  openById: (id) => onboardingSS,
  flush: () => {}
};

let onboardResult = null;
try {
  onboardResult = submitKepalaSekolahOnboarding({
    nama: 'Drs. H. Ahmad Subagja, M.Pd.',
    nip: '197205101998031002',
    username: 'kepsek_resmi',
    password: 'PasswordKuatProd2026!',
    confirmPassword: 'PasswordKuatProd2026!'
  });
} finally {
  global.SpreadsheetApp = originalSpreadsheetApp;
}

assert.strictEqual(onboardResult.success, true);
assert.strictEqual(onboardResult.username, 'kepsek_resmi');
assert.strictEqual(onboardResult.role, 'kepala_sekolah');
assert.strictEqual(onboardResult.password, undefined, 'Password plaintext tidak boleh ada di return');
assert.strictEqual(onboardResult.passwordHash, undefined, 'Hash password tidak boleh bocor di return');

// Verifikasi baris tersimpan di sheet
const userRows = userSheetMock.getRange(2, 1, 1, SCHEMA_DEFINITIONS.user.length).getValues()[0];
const onboardStoredUsername = userRows[SCHEMA_DEFINITIONS.user.indexOf('username')];
const onboardStoredHash = userRows[SCHEMA_DEFINITIONS.user.indexOf('password_hash')];
const onboardStoredSalt = userRows[SCHEMA_DEFINITIONS.user.indexOf('password_salt')];

assert.strictEqual(onboardStoredUsername, 'kepsek_resmi');
assert.ok(onboardStoredHash.startsWith('pbkdf2:sha256:100000:'), 'Hash password wajib format PBKDF2');
assert.strictEqual(onboardStoredSalt.length, 64, 'Salt CSPRNG wajib 64 karakter');

console.log('   ✓ Lolos: Handler onboarding tervalidasi aman, owner-only, PBKDF2, dan bebas secret leak.\n');

console.log('============================================================================');
console.log('SELURUH 11 PENGUJIAN REGRESI PHASE 11 LULUS DENGAN SUKSES 100% (PASS)!');
console.log('============================================================================\n');
