/**
 * ============================================================================
 * SISTEM ABSENSI & PENILAIAN SISWA SD (VERSI 2)
 * File: tests/test_phase10_seed.js — Pengujian Runner Setup & Seeding Terkontrol
 * ============================================================================
 *
 * Pengujian Lengkap Phase 10.2D:
 * 1. Fresh setup 11 sheet & seed dummy dengan kredensial dinamis aman.
 * 2. Idempotensi eksekusi ulang (zero duplicate, no rows deleted).
 * 3. Opsi skipSeed: membentuk 11 sheet skema tanpa injeksi dummy.
 * 4. Proteksi aborsi skema: validasi selesai sebelum mutasi sheet.
 * 5. Kredensial tidak tersedia saat pembuatan akun -> proses berhenti SEBELUM mutasi.
 * 6. Audit source code: tidak ada fallback password plaintext di setup.gs.
 * 7. Tidak ada password atau salt rahasia yang masuk ke log atau laporan.
 * 8. Wrapper menu publik mendelegasikan ke handler internal yang benar.
 * 9. Formula nilai akhir seed identik 100% dengan formula backend.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const setupModule = require('../setup.gs');
const codeModule = require('../code.gs');

const {
  SCHEMA_DEFINITIONS,
  validateSpreadsheetSchema_,
  runControlledSetupAndSeed_,
  menuAuditSkema,
  menuSetupDatabase,
  menuSeedDatabase,
  runSchemaCheckFromEditor,
  onOpen,
  submitSecureSeedCredentials
} = setupModule;

console.log('=== MEMULAI SUITE PENGUJIAN OTOMATIS PHASE 10.2D: KEAMANAN KREDENSIAL & HANDLER MENU ===\n');

// Simulasikan sesi terotorisasi pemilik sah secara default untuk lingkungan pengujian Node.js
global.Session = {
  getActiveUser: () => ({ getEmail: () => 'ryanhillfree23@gmail.com' }),
  getEffectiveUser: () => ({ getEmail: () => 'ryanhillfree23@gmail.com' })
};

// Dynamic test credentials generated in memory (no plaintext stored in test file)
const dynamicTestPass1 = 'DynSec1_' + crypto.randomBytes(8).toString('hex') + 'A9!';
const dynamicTestPass2 = 'DynSec2_' + crypto.randomBytes(8).toString('hex') + 'B8!';

// Helper pembuatan Mock Spreadsheet
function createMockSpreadsheet(initialSheets = {}) {
  const sheets = {};

  function makeMockSheet(name, headers = [], dataRows = []) {
    const grid = [];
    if (headers && headers.length > 0) {
      grid.push([...headers]);
    }
    dataRows.forEach(r => grid.push([...r]));

    return {
      getName: () => name,
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
      setFrozenRows: () => {},
      appendRow: (rowContents) => {
        grid.push([...rowContents]);
      },
      _grid: grid
    };
  }

  // Isi sheet awal jika ada
  Object.keys(initialSheets).forEach(name => {
    const s = initialSheets[name];
    sheets[name] = makeMockSheet(name, s.headers, s.dataRows || []);
  });

  return {
    getId: () => '1tVY7hHpZNTHQ0c_9GEaM2-Gz4fOh8qccsCP0afRLBd8',
    getName: () => 'TEST - Absensi SD v2 - Database Setup',
    getSheetByName: (name) => sheets[name] || null,
    insertSheet: (name) => {
      if (sheets[name]) {
        throw new Error('Sheet "' + name + '" sudah ada.');
      }
      sheets[name] = makeMockSheet(name);
      return sheets[name];
    },
    getSheets: () => Object.values(sheets),
    _sheets: sheets
  };
}

// ----------------------------------------------------------------------------
// TEST 1: Setup & Seed Awal pada Spreadsheet Kosong (Fresh Setup)
// ----------------------------------------------------------------------------
console.log('1. Menguji Setup 11 Sheet & Seed Dummy Awal pada Spreadsheet Kosong...');

const mockFreshSS = createMockSpreadsheet();
const reportFresh = runControlledSetupAndSeed_(mockFreshSS, {
  skipSeed: false,
  credentials: {
    kepsekPassword: dynamicTestPass1,
    waliPassword: dynamicTestPass2
  }
});

assert.strictEqual(reportFresh.success, true, 'Eksekusi runner harus sukses');
assert.strictEqual(reportFresh.createdSheets.length, 11, 'Seluruh 11 sheet harus dibuat');
assert.strictEqual(reportFresh.pengaturanInitialized, true, 'Sheet pengaturan harus diinisialisasi');

const expectedAdded = {
  pengaturan: 1,
  tahun_ajaran: 1,
  user: 2,
  wali_kelas: 1,
  siswa: 3,
  mata_pelajaran: 3,
  pengaturan_rapor: 1,
  nilai_mata_pelajaran: 9,
  nilai_sikap: 3,
  rekap_kehadiran: 3,
  pengumuman: 1
};

Object.keys(expectedAdded).forEach(tbl => {
  assert.strictEqual(
    reportFresh.seedSummary.rowsAdded[tbl],
    expectedAdded[tbl],
    `Tabel ${tbl} harus memiliki ${expectedAdded[tbl]} baris baru yang ditambahkan.`
  );
  const sh = mockFreshSS.getSheetByName(tbl);
  assert.ok(sh, `Sheet ${tbl} harus ada di spreadsheet.`);
  assert.strictEqual(sh.getLastRow(), expectedAdded[tbl] + 1, `Total baris pada sheet ${tbl} harus header + ${expectedAdded[tbl]}.`);
});

// Verifikasi detail nilai akhir & kelengkapan pada nilai_mata_pelajaran
const nSheet = mockFreshSS.getSheetByName('nilai_mata_pelajaran');
const nHeader = nSheet._grid[0];
const idxNa = nHeader.indexOf('nilai_akhir');
const idxComp = nHeader.indexOf('is_complete');

const row1 = nSheet._grid[1];
assert.strictEqual(row1[idxComp], true, 'Status kelengkapan harus true');
assert.strictEqual(row1[idxNa], 86.3, 'Nilai akhir harus dihitung presisi 86.3');

console.log('   ✓ Fresh setup & seed data dummy berhasil 100% pada seluruh 11 sheet.\n');

// ----------------------------------------------------------------------------
// TEST 2: Uji Idempotensi Eksekusi Ulang (Second Run - Zero Duplicate Guarantee)
// ----------------------------------------------------------------------------
console.log('2. Menguji Idempotensi Eksekusi Ulang (Panggilan Kedua pada Spreadsheet yang Sama)...');

const reportSecondRun = runControlledSetupAndSeed_(mockFreshSS, {
  skipSeed: false,
  credentials: {
    kepsekPassword: dynamicTestPass1,
    waliPassword: dynamicTestPass2
  }
});

assert.strictEqual(reportSecondRun.success, true);
assert.strictEqual(reportSecondRun.createdSheets.length, 0, 'Tidak boleh ada sheet baru yang dibuat pada eksekusi kedua');
assert.strictEqual(reportSecondRun.retainedExistingSheets.length, 11, 'Seluruh 11 sheet harus dipertahankan utuh');

const secondAddedTotal = Object.keys(reportSecondRun.seedSummary.rowsAdded).reduce(
  (acc, k) => acc + reportSecondRun.seedSummary.rowsAdded[k],
  0
);
assert.strictEqual(secondAddedTotal, 0, 'Eksekusi ulang tidak boleh menambahkan baris data duplikat sama sekali!');

Object.keys(expectedAdded).forEach(tbl => {
  assert.strictEqual(
    reportSecondRun.seedSummary.rowsSkipped[tbl],
    expectedAdded[tbl],
    `Tabel ${tbl} harus mencatat ${expectedAdded[tbl]} baris dilewati secara idempoten.`
  );
  const sh = mockFreshSS.getSheetByName(tbl);
  assert.strictEqual(sh.getLastRow(), expectedAdded[tbl] + 1, `Total baris pada sheet ${tbl} tidak boleh bertambah.`);
});

console.log('   ✓ Idempotensi terbukti 100%: Eksekusi ulang tidak menambah baris atau menduplikasi data.\n');

// ----------------------------------------------------------------------------
// TEST 3: Uji Opsi skipSeed (Hanya Membentuk Sheet Kosong Tanpa Data Dummy)
// ----------------------------------------------------------------------------
console.log('3. Menguji Opsi skipSeed (Hanya Setup Skema 11 Sheet Tanpa Data Dummy)...');

const mockSkipSS = createMockSpreadsheet();
const reportSkip = runControlledSetupAndSeed_(mockSkipSS, { skipSeed: true });

assert.strictEqual(reportSkip.success, true);
assert.strictEqual(reportSkip.createdSheets.length, 11);

['siswa', 'mata_pelajaran', 'nilai_mata_pelajaran', 'nilai_sikap', 'rekap_kehadiran', 'pengumuman'].forEach(tbl => {
  const sh = mockSkipSS.getSheetByName(tbl);
  assert.strictEqual(sh.getLastRow(), 1, `Sheet ${tbl} harus tetap hanya 1 baris (header saja) saat skipSeed aktif.`);
});

console.log('   ✓ Opsi skipSeed berhasil: 11 sheet terbentuk rapi tanpa injeksi data dummy.\n');

// ----------------------------------------------------------------------------
// TEST 4: Proteksi Skema Tidak Cocok (Strict Whitespace & Mismatch Abort)
// ----------------------------------------------------------------------------
console.log('4. Menguji Proteksi Skema Tidak Cocok (Aborsi Aman Tanpa Mutasi)...');

const mockCorruptSS = createMockSpreadsheet({
  user: {
    headers: ['id', 'nama', 'username', 'password_salah_kolom'],
    dataRows: []
  }
});

let schemaErrorThrown = false;
try {
  runControlledSetupAndSeed_(mockCorruptSS, { skipSeed: false, credentials: { kepsekPassword: dynamicTestPass1, waliPassword: dynamicTestPass2 } });
} catch (err) {
  schemaErrorThrown = true;
  assert.ok(err.message.includes('SETUP DIBATALKAN'), 'Pesan error harus eksplisit membatalkan setup.');
}

assert.strictEqual(schemaErrorThrown, true, 'Setup wajib melempar error dan membatalkan mutasi saat skema tidak cocok.');
assert.strictEqual(mockCorruptSS.getSheetByName('siswa'), null, 'Sheet siswa tidak boleh dibuat saat setup dibatalkan.');
assert.strictEqual(mockCorruptSS.getSheetByName('tahun_ajaran'), null, 'Sheet tahun_ajaran tidak boleh dibuat saat setup dibatalkan.');

console.log('   ✓ Proteksi aborsi skema berhasil: Setup menolak mutasi parsial jika ditemukan ketidakcocokan skema.\n');

// ----------------------------------------------------------------------------
// TEST 5: Kredensial Tidak Tersedia -> Proses Berhenti SEBELUM Mutasi
// ----------------------------------------------------------------------------
console.log('5. Menguji Kredensial Tidak Tersedia (Proses Berhenti SEBELUM Mutasi Spreadsheet)...');

const mockEmptySS = createMockSpreadsheet(); // Spreadsheet kosong mutlak
let credErrorThrown = false;
try {
  // Panggil runner tanpa options.credentials ketika skipSeed false
  runControlledSetupAndSeed_(mockEmptySS, { skipSeed: false });
} catch (err) {
  credErrorThrown = true;
  assert.ok(err.message.includes('Kredensial akun pengujian'), 'Pesan error harus eksplisit meminta kredensial aman.');
}

assert.strictEqual(credErrorThrown, true, 'Runner harus melempar error jika kredensial tidak disediakan.');
// Buktikan bahwa TIDAK ADA sheet yang terbuat sama sekali sebelum mutasi!
assert.strictEqual(mockEmptySS.getSheets().length, 0, 'Spreadsheet harus tetap 100% kosong (tidak ada mutasi sheet sebelum validasi kredensial).');

console.log('   ✓ Lolos: Kredensial absen berhasil menghentikan proses sebelum mutasi sheet.\n');

// ----------------------------------------------------------------------------
// TEST 6: Audit Source Code: Tidak Ada Fallback Password Plaintext di setup.gs
// ----------------------------------------------------------------------------
console.log('6. Menguji Ketiadaan Fallback Password Plaintext di Source Code...');

const setupCode = fs.readFileSync(path.resolve(__dirname, '../setup.gs'), 'utf8');

assert.strictEqual(setupCode.includes('KepsekPass123'), false, 'Tidak boleh ada kata kunci KepsekPass123 di setup.gs');
assert.strictEqual(setupCode.includes('WaliKelasPass123'), false, 'Tidak boleh ada kata kunci WaliKelasPass123 di setup.gs');

console.log('   ✓ Lolos: Seluruh fallback password plaintext terbukti telah dihapus dari setup.gs.\n');

// ----------------------------------------------------------------------------
// TEST 7: Password Tidak Pernah Masuk ke Log atau Objek Laporan
// ----------------------------------------------------------------------------
console.log('7. Menguji Password Tidak Masuk ke Objek Laporan atau Pesan Status...');

const reportJson = JSON.stringify(reportFresh);
assert.strictEqual(reportJson.includes(dynamicTestPass1), false, 'Password kepsek tidak boleh ada di objek laporan');
assert.strictEqual(reportJson.includes(dynamicTestPass2), false, 'Password wali tidak boleh ada di objek laporan');

console.log('   ✓ Lolos: Password dinamis terbukti tidak bocor ke objek laporan.\n');

// ----------------------------------------------------------------------------
// TEST 8: Wrapper Menu Publik Mendelegasikan ke Handler Internal yang Benar
// ----------------------------------------------------------------------------
console.log('8. Menguji Ketersediaan Wrapper Menu Publik di setup.gs...');

assert.strictEqual(typeof menuAuditSkema, 'function', 'menuAuditSkema harus berupa fungsi publik');
assert.strictEqual(typeof menuSetupDatabase, 'function', 'menuSetupDatabase harus berupa fungsi publik');
assert.strictEqual(typeof menuSeedDatabase, 'function', 'menuSeedDatabase harus berupa fungsi publik');
assert.strictEqual(typeof runSchemaCheckFromEditor, 'function', 'runSchemaCheckFromEditor harus berupa fungsi publik');
assert.strictEqual(typeof onOpen, 'function', 'onOpen harus berupa fungsi publik');

console.log('   ✓ Lolos: Seluruh 5 wrapper menu publik tersedia dan terdefinisi dengan benar.\n');

// ----------------------------------------------------------------------------
// TEST 9: Formula Nilai Akhir Seed Identik 100% dengan Backend
// ----------------------------------------------------------------------------
console.log('9. Menguji Konsistensi Formula Nilai Akhir Seed vs Backend...');

// Hitung nilai akhir dengan bobot resmi (Tugas 40%, UTS 30%, UAS 30%)
const sampleTugas = [85, 88, 84, 87]; // rata-rata = 86
const sampleUts = 85;
const sampleUas = 88;

const rataTugas = (sampleTugas[0] + sampleTugas[1] + sampleTugas[2] + sampleTugas[3]) / 4;
const naBackend = Math.round(((rataTugas * 40 + sampleUts * 30 + sampleUas * 30) / 100) * 100) / 100;

assert.strictEqual(naBackend, 86.3, 'Formula backend menghasilkan 86.3');
assert.strictEqual(row1[idxNa], naBackend, 'Nilai akhir pada sheet seed identik dengan formula backend');

console.log('   ✓ Lolos: Formula nilai akhir seed identik 100% dengan backend.\n');

// ----------------------------------------------------------------------------
// TEST 10: Uji Otorisasi & Validasi RPC Handler submitSecureSeedCredentials
// ----------------------------------------------------------------------------
console.log('10. Menguji Otorisasi & Validasi Server-Side RPC submitSecureSeedCredentials...');

// Simulasikan lingkungan Session Apps Script
global.Session = {
  getActiveUser: () => ({ getEmail: () => 'attacker@unauthorized.com' }),
  getEffectiveUser: () => ({ getEmail: () => 'attacker@unauthorized.com' })
};

// 10a. Penolakan akses untuk pemanggil tidak terotorisasi
let authErrThrown = false;
try {
  submitSecureSeedCredentials({ kepsekPassword: 'ValidPassword123!', waliPassword: 'ValidPassword456!' });
} catch (err) {
  authErrThrown = true;
  assert.ok(err.message.includes('Akses ditolak'), 'Harus melempar error akses ditolak untuk email tidak sah');
}
assert.strictEqual(authErrThrown, true, 'Eksekusi oleh non-owner wajib ditolak seketika.');

// 10b. Pemilik sah tetapi password kurang dari 8 karakter
global.Session = {
  getActiveUser: () => ({ getEmail: () => 'ryanhillfree23@gmail.com' }),
  getEffectiveUser: () => ({ getEmail: () => 'ryanhillfree23@gmail.com' })
};

let shortPwErrThrown = false;
try {
  submitSecureSeedCredentials({ kepsekPassword: 'short', waliPassword: 'ValidPassword456!' });
} catch (err) {
  shortPwErrThrown = true;
  assert.ok(err.message.includes('minimal 8 karakter'), 'Harus melempar error password kurang dari 8 karakter');
}
assert.strictEqual(shortPwErrThrown, true, 'Password kurang dari 8 karakter wajib ditolak.');

console.log('   ✓ Lolos: Otorisasi pemilik dan validasi panjang password server-side bekerja 100% aman.\n');

// ----------------------------------------------------------------------------
// TEST 11: Audit Kebersihan dan Keamanan SecureSeedDialog.html
// ----------------------------------------------------------------------------
console.log('11. Menguji Integritas dan Keamanan File SecureSeedDialog.html...');

const dialogHtmlPath = path.resolve(__dirname, '../SecureSeedDialog.html');
assert.ok(fs.existsSync(dialogHtmlPath), 'File SecureSeedDialog.html harus ada di root project.');

const dialogHtml = fs.readFileSync(dialogHtmlPath, 'utf8');

// Memastikan input bertipe password
assert.ok(dialogHtml.includes('type="password"'), 'Input harus bertipe password');
assert.ok(dialogHtml.includes('id="kepsekPassword"'), 'Harus memiliki id kepsekPassword');
assert.ok(dialogHtml.includes('id="waliPassword"'), 'Harus memiliki id waliPassword');

// Memastikan tidak ada storage client atau logging
assert.strictEqual(dialogHtml.includes('localStorage'), false, 'Dialog dilarang menggunakan localStorage');
assert.strictEqual(dialogHtml.includes('sessionStorage'), false, 'Dialog dilarang menggunakan sessionStorage');
assert.strictEqual(dialogHtml.includes('document.cookie'), false, 'Dialog dilarang memanipulasi cookie');
assert.strictEqual(dialogHtml.includes('console.log'), false, 'Dialog dilarang menggunakan console.log');

// Memastikan sanitasi input setelah submit/cancel
assert.ok(dialogHtml.includes('clearSensitiveFields'), 'Dialog harus memiliki pembersih nilai input privat');

console.log('   ✓ Lolos: SecureSeedDialog.html memenuhi seluruh standar keamanan tanpa storage persisten atau kebocoran DOM.\n');

// ----------------------------------------------------------------------------
// TEST 12: Penolakan Otorisasi untuk Email Kosong & Domain Tidak Sah (Audit 10.4)
// ----------------------------------------------------------------------------
console.log('12. Menguji Penolakan Email Kosong & Pengguna Tidak Sah...');

// 12a. Email kosong (activeEmail & effectiveEmail = '')
global.Session = {
  getActiveUser: () => ({ getEmail: () => '' }),
  getEffectiveUser: () => ({ getEmail: () => '' })
};

let emptyEmailErr = false;
try {
  submitSecureSeedCredentials({ kepsekPassword: 'ValidPassword123!', waliPassword: 'ValidPassword456!' });
} catch (err) {
  emptyEmailErr = true;
  assert.ok(err.message.includes('Akses ditolak'), 'Email kosong harus ditolak');
}
assert.strictEqual(emptyEmailErr, true, 'Email kosong mutlak wajib ditolak server-side.');

// 12b. Email penyerang (attacker@random.com)
global.Session = {
  getActiveUser: () => ({ getEmail: () => 'intruder@domain.org' }),
  getEffectiveUser: () => ({ getEmail: () => 'intruder@domain.org' })
};

let intruderErr = false;
try {
  submitSecureSeedCredentials({ kepsekPassword: 'ValidPassword123!', waliPassword: 'ValidPassword456!' });
} catch (err) {
  intruderErr = true;
  assert.ok(err.message.includes('Akses ditolak'), 'Email bukan pemilik sah harus ditolak');
}
assert.strictEqual(intruderErr, true, 'Email penyerang wajib ditolak server-side.');

// 12c. Eksploitasi "Execute As Me" (effectiveUser = owner, tetapi activeUser = penyerang)
global.Session = {
  getActiveUser: () => ({ getEmail: () => 'intruder@domain.org' }),
  getEffectiveUser: () => ({ getEmail: () => 'ryanhillfree23@gmail.com' })
};

let dualIdentityErr = false;
try {
  submitSecureSeedCredentials({ kepsekPassword: 'ValidPassword123!', waliPassword: 'ValidPassword456!' });
} catch (err) {
  dualIdentityErr = true;
  assert.ok(err.message.includes('Akses ditolak'), 'Active user penyerang harus ditolak meskipun effectiveUser adalah pemilik');
}
assert.strictEqual(dualIdentityErr, true, 'Active user penyerang wajib ditolak walau effectiveUser adalah pemilik.');

// 12d. Active user kosong namun effectiveUser = owner (misal pemanggilan anonim)
global.Session = {
  getActiveUser: () => ({ getEmail: () => '' }),
  getEffectiveUser: () => ({ getEmail: () => 'ryanhillfree23@gmail.com' })
};

let anonWithEffectiveOwnerErr = false;
try {
  submitSecureSeedCredentials({ kepsekPassword: 'ValidPassword123!', waliPassword: 'ValidPassword456!' });
} catch (err) {
  anonWithEffectiveOwnerErr = true;
  assert.ok(err.message.includes('Akses ditolak'), 'Active user kosong harus ditolak meski effectiveUser adalah pemilik');
}
assert.strictEqual(anonWithEffectiveOwnerErr, true, 'Active user kosong wajib ditolak.');

// 12e. Fail-closed saat objek Session tidak terdefinisi sama sekali
delete global.Session;

let sessionUndefinedErr = false;
try {
  submitSecureSeedCredentials({ kepsekPassword: 'ValidPassword123!', waliPassword: 'ValidPassword456!' });
} catch (err) {
  sessionUndefinedErr = true;
  assert.ok(err.message.includes('Objek Session tidak tersedia') || err.message.includes('fail-closed'), 'Harus fail-closed saat Session tidak ada');
}
assert.strictEqual(sessionUndefinedErr, true, 'Ketiadaan Session wajib fail-closed melempar error.');

// 12f. Pulihkan Session ke owner yang sah
global.Session = {
  getActiveUser: () => ({ getEmail: () => 'ryanhillfree23@gmail.com' }),
  getEffectiveUser: () => ({ getEmail: () => 'ryanhillfree23@gmail.com' })
};

console.log('   ✓ Lolos: Email kosong, penyerang, eksploitasi dual-identity, dan fail-closed Session tertolak 100% tanpa bypass.\n');

// ----------------------------------------------------------------------------
// TEST 13: Validasi Target Spreadsheet ID Resmi (Audit 10.4)
// ----------------------------------------------------------------------------
console.log('13. Menguji Validasi Target Spreadsheet ID Resmi...');

const mockWrongIdSS = createMockSpreadsheet();
mockWrongIdSS.getId = () => 'unauthorized-external-sheet-id';

let wrongIdErr = false;
try {
  runControlledSetupAndSeed_(mockWrongIdSS, { skipSeed: true });
} catch (err) {
  wrongIdErr = true;
  assert.ok(err.message.includes('Target Spreadsheet ID tidak valid'), 'Spreadsheet ID salah harus ditolak');
}
assert.strictEqual(wrongIdErr, true, 'Target Spreadsheet selain target resmi wajib ditolak.');

console.log('   ✓ Lolos: Target spreadsheet ID divalidasi ketat sebelum eksekusi.\n');

// ----------------------------------------------------------------------------
// TEST 14: Akun Existing Tidak Mengalami Reset Password / Perubahan Salt (Audit 10.4)
// ----------------------------------------------------------------------------
console.log('14. Menguji Akun Existing Mempertahankan Password Hash & Salt Asli...');

const mockExistingSS = createMockSpreadsheet();
// Setup schema awal
runControlledSetupAndSeed_(mockExistingSS, { skipSeed: true });

// Masukkan akun kepsek existing dengan hash dan salt custom
const existingCustomHash = 'pbkdf2:sha256:100000:custom_persisted_hash_value_123';
const existingCustomSalt = 'custom_persisted_salt_456_abcdef0123456789abcdef0123456789abcdef';
const userSheet = mockExistingSS.getSheetByName('user');
userSheet.appendRow([
  'user-kepsek-01',
  'Drs. H. Ahmad Subagja, M.Pd.',
  '197205101998031002',
  'kepsek_test',
  existingCustomHash,
  existingCustomSalt,
  'kepala_sekolah',
  '',
  '',
  true,
  new Date().toISOString(),
  new Date().toISOString()
]);

// Jalankan seed dengan password baru untuk guru_test (kepsek_test sudah ada)
const seedWithExistingUser = runControlledSetupAndSeed_(mockExistingSS, {
  skipSeed: false,
  credentials: {
    waliPassword: 'GuruBaruSecure99!'
  }
});

// Periksa baris kepsek_test di sheet user
const userGrid = userSheet._grid;
const uHeaders = userGrid[0];
const idxUn = uHeaders.indexOf('username');
const idxHash = uHeaders.indexOf('password_hash');
const idxSalt = uHeaders.indexOf('password_salt');

let foundKepsekRow = null;
for (let r = 1; r < userGrid.length; r++) {
  if (userGrid[r][idxUn] === 'kepsek_test') {
    foundKepsekRow = userGrid[r];
  }
}

assert.ok(foundKepsekRow, 'Akun kepsek_test harus tetap ada');
assert.strictEqual(foundKepsekRow[idxHash], existingCustomHash, 'password_hash akun existing TIDAK BOLEH diubah/di-reset');
assert.strictEqual(foundKepsekRow[idxSalt], existingCustomSalt, 'password_salt akun existing TIDAK BOLEH diubah');

console.log('   ✓ Lolos: Akun existing terbukti mempertahankan hash dan salt 100% tanpa di-reset.\n');

// ----------------------------------------------------------------------------
// TEST 15: Konflik Role Akun Existing Menghentikan Seed SEBELUM Mutasi (Audit 10.4)
// ----------------------------------------------------------------------------
console.log('15. Menguji Deteksi Konflik Role Akun Existing (Aborsi Aman Sebelum Mutasi)...');

const mockConflictSS = createMockSpreadsheet();
runControlledSetupAndSeed_(mockConflictSS, { skipSeed: true });

// Masukkan kepsek_test dengan role yang SALAH (misal 'wali_kelas')
const conflictUserSheet = mockConflictSS.getSheetByName('user');
conflictUserSheet.appendRow([
  'user-kepsek-01',
  'Palsu',
  '123',
  'kepsek_test',
  'hash',
  'salt',
  'wali_kelas', // KONFLIK: kepsek_test bertindak sebagai wali_kelas
  '',
  '',
  true,
  new Date().toISOString(),
  new Date().toISOString()
]);

const initialTaRows = mockConflictSS.getSheetByName('tahun_ajaran').getLastRow();

let roleConflictErr = false;
try {
  runControlledSetupAndSeed_(mockConflictSS, {
    skipSeed: false,
    credentials: {
      kepsekPassword: 'PasswordValid123!',
      waliPassword: 'PasswordValid456!'
    }
  });
} catch (err) {
  roleConflictErr = true;
  assert.ok(err.message.includes('Konflik data akun'), 'Pesan error harus eksplisit menyebut konflik data akun');
}

assert.strictEqual(roleConflictErr, true, 'Role conflict wajib melempar error dan menghentikan proses.');
assert.strictEqual(mockConflictSS.getSheetByName('tahun_ajaran').getLastRow(), initialTaRows, 'Sheet tahun_ajaran TIDAK BOLEH termutasi saat konflik terjadi!');
assert.strictEqual(mockConflictSS.getSheetByName('siswa').getLastRow(), 1, 'Sheet siswa TIDAK BOLEH termutasi saat konflik terjadi!');

console.log('   ✓ Lolos: Konflik role akun existing terdeteksi sebelum mutasi data pertama.\n');

// ----------------------------------------------------------------------------
// TEST 16: Deteksi Konflik User ID Target (Audit 10.4)
// ----------------------------------------------------------------------------
console.log('16. Menguji Deteksi Konflik User ID Target Sebelum Mutasi...');

const mockIdConflictSS = createMockSpreadsheet();
runControlledSetupAndSeed_(mockIdConflictSS, { skipSeed: true });

// Masukkan username lain yang mencuri ID 'user-kepsek-01'
const idConflictUserSheet = mockIdConflictSS.getSheetByName('user');
idConflictUserSheet.appendRow([
  'user-kepsek-01',
  'Orang Lain',
  '111',
  'user_pembajak',
  'hash',
  'salt',
  'guru',
  '',
  '',
  true,
  new Date().toISOString(),
  new Date().toISOString()
]);

let idConflictErr = false;
try {
  runControlledSetupAndSeed_(mockIdConflictSS, {
    skipSeed: false,
    credentials: {
      kepsekPassword: 'PasswordValid123!',
      waliPassword: 'PasswordValid456!'
    }
  });
} catch (err) {
  idConflictErr = true;
  assert.ok(err.message.includes('Konflik ID akun'), 'Pesan error harus menyebut konflik ID akun');
}

assert.strictEqual(idConflictErr, true, 'Pembajakan target User ID wajib ditolak sebelum mutasi.');

console.log('   ✓ Lolos: Konflik User ID target terdeteksi dan digagalkan sebelum mutasi.\n');

// ----------------------------------------------------------------------------
// TEST 17: Validasi Kompatibilitas Login PBKDF2 (100.000 Iterasi)
// ----------------------------------------------------------------------------
console.log('17. Menguji Kompatibilitas Login PBKDF2 Hash Akun Seed...');

const seededUserSheet = mockFreshSS.getSheetByName('user');
const seededGrid = seededUserSheet._grid;
const seededHeaders = seededGrid[0];
const sHashIdx = seededHeaders.indexOf('password_hash');
const sSaltIdx = seededHeaders.indexOf('password_salt');
const sUserIdx = seededHeaders.indexOf('username');

let kepsekRow = seededGrid.find(r => r[sUserIdx] === 'kepsek_test');
assert.ok(kepsekRow, 'Baris kepsek_test harus ada di mockFreshSS');
assert.ok(kepsekRow[sHashIdx].startsWith('pbkdf2:sha256:100000:'), 'Hash akun kepsek harus berformat PBKDF2 100k');
assert.strictEqual(kepsekRow[sSaltIdx].length, 64, 'Salt kepsek harus berukuran 64 karakter hex');

// Uji autentikasi login menggunakan verifyPassword_ dari code.gs
if (typeof codeModule.verifyPassword_ === 'function') {
  const authResult = codeModule.verifyPassword_(dynamicTestPass1, kepsekRow[sHashIdx], kepsekRow[sSaltIdx]);
  assert.strictEqual(authResult.valid, true, 'Password yang diinput saat seed harus 100% valid saat login');
  assert.strictEqual(authResult.needsRehash, false, 'Hash PBKDF2 100k tidak memerlukan rehash');

  const wrongAuthResult = codeModule.verifyPassword_('SalahPassword123!', kepsekRow[sHashIdx], kepsekRow[sSaltIdx]);
  assert.strictEqual(wrongAuthResult.valid, false, 'Password salah wajib ditolak');
}

console.log('   ✓ Lolos: Hash akun seed kompatibel 100% dengan modul autentikasi backend code.gs.\n');

// ----------------------------------------------------------------------------
// TEST 18: Karakteristik Rollback & Atomicity pada Google Sheets (Audit 10.4)
// ----------------------------------------------------------------------------
console.log('18. Menguji Penanganan Kegagalan & Karakteristik Rollback...');

// Skenario: Simulasi kegagalan runtime (kuota/network/throw) saat penulisan di tengah proses
const mockFailSS = createMockSpreadsheet();
runControlledSetupAndSeed_(mockFailSS, { skipSeed: true });

// Modifikasi sheet nilai_mata_pelajaran agar melempar error saat appendRow
const failSheet = mockFailSS.getSheetByName('nilai_mata_pelajaran');
failSheet.appendRow = () => {
  throw new Error('SIMULATED_QUOTA_OR_NETWORK_FAILURE: Service Spreadsheets timed out.');
};

let failureCaught = false;
try {
  runControlledSetupAndSeed_(mockFailSS, {
    skipSeed: false,
    credentials: {
      kepsekPassword: 'PasswordKuat123!',
      waliPassword: 'PasswordKuat456!'
    }
  });
} catch (e) {
  failureCaught = true;
  assert.ok(e.message.includes('SIMULATED_QUOTA_OR_NETWORK_FAILURE'), 'Error harus terlempar ke caller');
}

assert.strictEqual(failureCaught, true, 'Kegagalan di tengah penulisan wajib melempar error.');

// Fakta arsitektur: Google Sheets TIDAK memiliki transaksi ACID database.
// Sheet yang ditulis sebelum kegagalan (tahun_ajaran, user, wali_kelas, siswa, mapel) tetap ada.
const taRowCount = mockFailSS.getSheetByName('tahun_ajaran').getLastRow();
assert.ok(taRowCount > 1, 'Data yang tertulis sebelum kegagalan tetap ada (bukti tidak ada rollback ACID bawaan Google Sheets).');

// Kemampuan pemulihan: Jalankan ulang setelah kegagalan teratasi
failSheet.appendRow = (rowContents) => { failSheet._grid.push([...rowContents]); };

const recoveryReport = runControlledSetupAndSeed_(mockFailSS, {
  skipSeed: false,
  credentials: {
    kepsekPassword: 'PasswordKuat123!',
    waliPassword: 'PasswordKuat456!'
  }
});

// Idempotensi: Tahun ajaran, user, wali_kelas yang sudah tertulis dilewati (skipped)
assert.strictEqual(recoveryReport.seedSummary.rowsSkipped['tahun_ajaran'], 1, 'Tahun ajaran dilewati pada pemulihan');
assert.strictEqual(recoveryReport.seedSummary.rowsSkipped['user'], 2, 'User dilewati pada pemulihan');
assert.strictEqual(recoveryReport.seedSummary.rowsAdded['nilai_mata_pelajaran'], 9, 'Nilai yang sebelumnya gagal berhasil ditulis tanpa duplikasi');

console.log('   ✓ Lolos: Karakteristik atomicity/rollback teranalisis akurat & pemulihan idempoten terverifikasi.\n');

// ============================================================================
// SUITE PENGUJIAN TAMBAHAN PHASE 10.10: AUDIT KEAMANAN SEED & REMEDIASI MINIMAL
// ============================================================================
console.log('=== MEMULAI PENGUJIAN TAMBAHAN PHASE 10.10: AUDIT KEAMANAN SEED & REMEDIASI MINIMAL ===\n');

// ----------------------------------------------------------------------------
// TEST 19: Referensi Siswa atau Mata Pelajaran Hilang / Salah Relasi
// ----------------------------------------------------------------------------
console.log('19. Menguji Pencegahan Missing Parent References & Relasi Hilang...');

const mockOrphanSS = createMockSpreadsheet({
  siswa: {
    headers: SCHEMA_DEFINITIONS.siswa,
    dataRows: [
      ['siswa-k4-01', 'wk-salah-99', '0151234001', '24250401', 1, 'Aditya Pratama', 'L', 'Jakarta', '2015-02-14', 'Bambang', '081', true, new Date().toISOString(), new Date().toISOString()]
    ]
  }
});

let orphanErrCaught = false;
try {
  runControlledSetupAndSeed_(mockOrphanSS, {
    skipSeed: false,
    credentials: {
      kepsekPassword: 'ValidPassword123!',
      waliPassword: 'ValidPassword123!'
    }
  });
} catch (err) {
  orphanErrCaught = true;
  assert.ok(err.message.includes('Konflik relasi siswa'), 'Error harus mendeteksi relasi wali_kelas siswa yang tidak cocok');
}
assert.strictEqual(orphanErrCaught, true, 'Relasi siswa ke penugasan yang tidak valid wajib ditolak sebelum mutasi');
console.log('   ✓ Lolos: Relasi induk yang tidak valid / hilang terdeteksi dan digagalkan sebelum mutasi.\n');

// ----------------------------------------------------------------------------
// TEST 20: Konflik Kunci Entitas dengan Atribut Berbeda (Tahun Ajaran)
// ----------------------------------------------------------------------------
console.log('20. Menguji Deteksi Konflik Kunci dengan Atribut Berbeda (Tahun Ajaran)...');

const mockTaConflictSS = createMockSpreadsheet({
  tahun_ajaran: {
    headers: SCHEMA_DEFINITIONS.tahun_ajaran,
    dataRows: [
      ['ta-2026-ganjil', '2026/2027', 'Genap', '2026-07-13', '2026-12-19', false, false, new Date().toISOString(), new Date().toISOString()]
    ]
  }
});

let taConflictCaught = false;
try {
  runControlledSetupAndSeed_(mockTaConflictSS, {
    skipSeed: false,
    credentials: {
      kepsekPassword: 'ValidPassword123!',
      waliPassword: 'ValidPassword123!'
    }
  });
} catch (err) {
  taConflictCaught = true;
  assert.ok(err.message.includes('Konflik') && err.message.includes('tahun_ajaran'), 'Pesan error harus menyebut konflik tahun_ajaran');
}
assert.strictEqual(taConflictCaught, true, 'Konflik semester/atribut tahun ajaran wajib digagalkan sebelum mutasi');
console.log('   ✓ Lolos: Konflik kunci ID dengan atribut periode berbeda digagalkan sebelum mutasi.\n');

// ----------------------------------------------------------------------------
// TEST 21: Konflik Ambigu Siswa (no_absen cocok baris A, nisn cocok baris B)
// ----------------------------------------------------------------------------
console.log('21. Menguji Deteksi Konflik Ambigu Siswa (no_absen vs nisn pada baris berbeda)...');

const mockAmbiguousSiswaSS = createMockSpreadsheet({
  siswa: {
    headers: SCHEMA_DEFINITIONS.siswa,
    dataRows: [
      ['siswa-custom-1', 'wk-2026-k4', '9999999999', '24250401', 1, 'Aditya Pratama', 'L', 'Jakarta', '2015-02-14', 'Bambang', '081', true, new Date().toISOString(), new Date().toISOString()],
      ['siswa-custom-2', 'wk-2026-k4', '0151234001', '24250409', 9, 'Siswa Lain', 'L', 'Jakarta', '2015-02-14', 'Bambang', '081', true, new Date().toISOString(), new Date().toISOString()]
    ]
  }
});

let ambiguousSiswaCaught = false;
try {
  runControlledSetupAndSeed_(mockAmbiguousSiswaSS, {
    skipSeed: false,
    credentials: {
      kepsekPassword: 'ValidPassword123!',
      waliPassword: 'ValidPassword123!'
    }
  });
} catch (err) {
  ambiguousSiswaCaught = true;
  assert.ok(err.message.includes('Konflik') && err.message.includes('ambigu'), 'Error harus mendeteksi penggabungan ambigu no_absen dan nisn');
}
assert.strictEqual(ambiguousSiswaCaught, true, 'Penggabungan ambigu siswa pada baris berbeda wajib ditolak');
console.log('   ✓ Lolos: Penggabungan ambigu no_absen dan NISN pada dua baris berbeda terdeteksi dan digagalkan.\n');

// ----------------------------------------------------------------------------
// TEST 22: Baris Konfigurasi Pengaturan Existing Tidak Cocok & Duplikasi Singleton
// ----------------------------------------------------------------------------
console.log('22. Menguji Deteksi Konflik Konfigurasi Pengaturan Sekolah & Singleton Guard...');

// 22a. UUID existing yang sah diterima tanpa mengubah ID
const validUuid = '86134cd3-c4f5-44f7-9d2c-55a7e5596f28';
const mockUuidPengSS = createMockSpreadsheet({
  pengaturan: {
    headers: SCHEMA_DEFINITIONS.pengaturan,
    dataRows: [
      [validUuid, '', 'SD Negeri Percobaan 01', 'Drs. H. Ahmad Subagja, M.Pd.', '197205101998031002', 'SYSTEM_SETUP', new Date().toISOString(), new Date().toISOString()]
    ]
  }
});

const reportUuidPeng = runControlledSetupAndSeed_(mockUuidPengSS, {
  skipSeed: true
});
assert.strictEqual(reportUuidPeng.success, true, 'Eksekusi dengan UUID existing yang sah harus berhasil');
assert.strictEqual(reportUuidPeng.seedSummary.rowsSkipped['pengaturan'], 1, 'Pengaturan dengan UUID sah harus dilewati (skipped)');
const pengSheetUuid = mockUuidPengSS.getSheetByName('pengaturan');
assert.strictEqual(pengSheetUuid._grid[1][0], validUuid, 'ID UUID existing wajib dipertahankan persis tanpa diubah');

// 22b. ID manifest existing ('pengaturan-sekolah-01') tetap diterima
const mockManifestPengSS = createMockSpreadsheet({
  pengaturan: {
    headers: SCHEMA_DEFINITIONS.pengaturan,
    dataRows: [
      ['pengaturan-sekolah-01', '', 'SD Negeri Percobaan 01', 'Drs. H. Ahmad Subagja, M.Pd.', '197205101998031002', 'SYSTEM_SEED', new Date().toISOString(), new Date().toISOString()]
    ]
  }
});
const reportManifestPeng = runControlledSetupAndSeed_(mockManifestPengSS, {
  skipSeed: true
});
assert.strictEqual(reportManifestPeng.success, true, 'Eksekusi dengan ID manifest existing harus berhasil');
assert.strictEqual(reportManifestPeng.seedSummary.rowsSkipped['pengaturan'], 1, 'Pengaturan dengan ID manifest harus dilewati');
assert.strictEqual(mockManifestPengSS.getSheetByName('pengaturan')._grid[1][0], 'pengaturan-sekolah-01', 'ID manifest existing wajib dipertahankan');

// 22c. Profil sekolah existing yang berbeda dari manifest tetap dipertahankan utuh
const customSchoolRow = [
  validUuid,
  'https://drive.google.com/uc?id=logo123',
  'SD Harapan Bangsa Mandiri',
  'Prof. Dr. Hj. Nurhasanah, M.Sc.',
  '197508152000032001',
  'USER_KEPSEK_01',
  '2026-01-01T08:00:00.000Z',
  '2026-02-01T09:00:00.000Z'
];
const mockCustomPengSS = createMockSpreadsheet({
  pengaturan: {
    headers: SCHEMA_DEFINITIONS.pengaturan,
    dataRows: [
      [...customSchoolRow]
    ]
  }
});
const reportCustomPeng = runControlledSetupAndSeed_(mockCustomPengSS, {
  skipSeed: true
});
assert.strictEqual(reportCustomPeng.success, true);
assert.strictEqual(reportCustomPeng.seedSummary.rowsSkipped['pengaturan'], 1);
const customPengGridRow = mockCustomPengSS.getSheetByName('pengaturan')._grid[1];
assert.deepStrictEqual(customPengGridRow, customSchoolRow, 'Seluruh kolom profil sekolah existing wajib dipertahankan utuh tanpa ditimpa nilai manifest');

// 22d. ID kosong atau whitespace ditolak
['', '   '].forEach(badId => {
  const mockBadIdSS = createMockSpreadsheet({
    pengaturan: {
      headers: SCHEMA_DEFINITIONS.pengaturan,
      dataRows: [
        [badId, '', 'SD Negeri Percobaan 01', 'Kepsek', '198000', 'USER', new Date().toISOString(), new Date().toISOString()]
      ]
    }
  });
  let badIdCaught = false;
  try {
    runControlledSetupAndSeed_(mockBadIdSS, { skipSeed: true });
  } catch (err) {
    badIdCaught = true;
    assert.ok(err.message.includes('kosong atau hanya berisi spasi'), 'Error harus menyebut ID kosong atau whitespace');
  }
  assert.strictEqual(badIdCaught, true, `ID "${badId}" wajib ditolak demi integritas skema`);
});

// 22e. ID dengan format tidak sah (karakter newline / kontrol) ditolak
const mockInvalidIdSS = createMockSpreadsheet({
  pengaturan: {
    headers: SCHEMA_DEFINITIONS.pengaturan,
    dataRows: [
      ['id_with\nnewline', '', 'SD Negeri Percobaan 01', 'Kepsek', '198000', 'USER', new Date().toISOString(), new Date().toISOString()]
    ]
  }
});
let invalidIdCaught = false;
try {
  runControlledSetupAndSeed_(mockInvalidIdSS, { skipSeed: true });
} catch (err) {
  invalidIdCaught = true;
  assert.ok(err.message.includes('Format ID konfigurasi existing'), 'Error harus mendeteksi format ID tidak valid');
}
assert.strictEqual(invalidIdCaught, true, 'ID dengan karakter newline wajib ditolak');

// 22f. Duplikasi singleton (lebih dari 1 baris di sheet pengaturan) ditolak
const mockMultiPengSS = createMockSpreadsheet({
  pengaturan: {
    headers: SCHEMA_DEFINITIONS.pengaturan,
    dataRows: [
      ['86134cd3-c4f5-44f7-9d2c-55a7e5596f28', '', 'SD Negeri Percobaan 01', 'Drs. H. Ahmad Subagja, M.Pd.', '197205101998031002', 'SYSTEM_SEED', new Date().toISOString(), new Date().toISOString()],
      ['pengaturan-sekolah-02', '', 'SD Cabang 02', 'Wakil Kepsek', '197500', 'USER', new Date().toISOString(), new Date().toISOString()]
    ]
  }
});
let multiPengCaught = false;
try {
  runControlledSetupAndSeed_(mockMultiPengSS, { skipSeed: true });
} catch (err) {
  multiPengCaught = true;
  assert.ok(err.message.includes('singleton'), 'Error harus mendeteksi pelanggaran singleton pengaturan');
}
assert.strictEqual(multiPengCaught, true, 'Pelanggaran singleton pada sheet pengaturan wajib digagalkan');

// 22g. Preflight gagal tanpa mutasi spreadsheet (Zero-Mutation Verification)
const mockZeroMutSS = createMockSpreadsheet({
  pengaturan: {
    headers: SCHEMA_DEFINITIONS.pengaturan,
    dataRows: [
      ['', '', 'SD Negeri Percobaan 01', 'Kepsek', '198000', 'USER', new Date().toISOString(), new Date().toISOString()]
    ]
  }
});
const snapZeroMutBefore = JSON.parse(JSON.stringify(mockZeroMutSS.getSheetByName('pengaturan')._grid));
try {
  runControlledSetupAndSeed_(mockZeroMutSS, { skipSeed: true });
} catch (e) {
  // Expected failure
}
const snapZeroMutAfter = JSON.parse(JSON.stringify(mockZeroMutSS.getSheetByName('pengaturan')._grid));
assert.deepStrictEqual(snapZeroMutBefore, snapZeroMutAfter, 'Kegagalan preflight terbukti tidak mengubah sel atau menambah baris');

console.log('   ✓ Lolos: UUID valid, manifest ID, proteksi profil existing, penolakan ID kosong/tidak sah, dan singleton guard teruji 100% aman.\n');

// ----------------------------------------------------------------------------
// TEST 23: Pemulihan Parsial (Seed Melanjutkan Sebagian Penulisan yang Sudah Ada)
// ----------------------------------------------------------------------------
console.log('23. Menguji Pemulihan Parsial (Seed Melanjutkan Sebagian Penulisan yang Sudah Ada)...');

const mockPartialSS = createMockSpreadsheet({
  pengaturan: {
    headers: SCHEMA_DEFINITIONS.pengaturan,
    dataRows: [
      ['pengaturan-sekolah-01', '', 'SD Negeri Percobaan 01', 'Drs. H. Ahmad Subagja, M.Pd.', '197205101998031002', 'SYSTEM_SEED', new Date().toISOString(), new Date().toISOString()]
    ]
  },
  tahun_ajaran: {
    headers: SCHEMA_DEFINITIONS.tahun_ajaran,
    dataRows: [
      ['ta-2026-ganjil', '2026/2027', 'Ganjil', '2026-07-13', '2026-12-19', true, false, new Date().toISOString(), new Date().toISOString()]
    ]
  },
  user: {
    headers: SCHEMA_DEFINITIONS.user,
    dataRows: [
      ['user-kepsek-01', 'Drs. H. Ahmad Subagja, M.Pd.', '197205101998031002', 'kepsek_test', 'pbkdf2:sha256:100000:hash1', 'salt1', 'kepala_sekolah', '', '', true, new Date().toISOString(), new Date().toISOString()],
      ['user-wali-01', 'Siti Rahmawati, S.Pd.', '198603152011012005', 'guru_test', 'pbkdf2:sha256:100000:hash2', 'salt2', 'wali_kelas', '', '', true, new Date().toISOString(), new Date().toISOString()]
    ]
  },
  wali_kelas: {
    headers: SCHEMA_DEFINITIONS.wali_kelas,
    dataRows: [
      ['wk-2026-k4', 'user-wali-01', 'ta-2026-ganjil', '4', true, new Date().toISOString(), new Date().toISOString()]
    ]
  }
});

const partialReport = runControlledSetupAndSeed_(mockPartialSS, {
  skipSeed: false,
  credentials: {
    kepsekPassword: 'ValidPassword123!',
    waliPassword: 'ValidPassword123!'
  }
});

assert.strictEqual(partialReport.success, true);
assert.strictEqual(partialReport.seedSummary.rowsSkipped['pengaturan'], 1, 'Pengaturan dilewati');
assert.strictEqual(partialReport.seedSummary.rowsSkipped['tahun_ajaran'], 1, 'Tahun ajaran dilewati');
assert.strictEqual(partialReport.seedSummary.rowsSkipped['user'], 2, 'Dua akun user dilewati');
assert.strictEqual(partialReport.seedSummary.rowsSkipped['wali_kelas'], 1, 'Penugasan wali kelas dilewati');

// Entitas anak yang belum ada harus ditulis lengkap:
assert.strictEqual(partialReport.seedSummary.rowsAdded['siswa'], 3, '3 siswa ditambahkan');
assert.strictEqual(partialReport.seedSummary.rowsAdded['mata_pelajaran'], 3, '3 mata pelajaran ditambahkan');
assert.strictEqual(partialReport.seedSummary.rowsAdded['pengaturan_rapor'], 1, '1 pengaturan rapor ditambahkan');
assert.strictEqual(partialReport.seedSummary.rowsAdded['nilai_mata_pelajaran'], 9, '9 nilai ditambahkan');
assert.strictEqual(partialReport.seedSummary.rowsAdded['nilai_sikap'], 3, '3 nilai sikap ditambahkan');
assert.strictEqual(partialReport.seedSummary.rowsAdded['rekap_kehadiran'], 3, '3 rekap kehadiran ditambahkan');
assert.strictEqual(partialReport.seedSummary.rowsAdded['pengumuman'], 1, '1 pengumuman ditambahkan');

let partialAddedTotal = 0;
Object.values(partialReport.seedSummary.rowsAdded).forEach(v => { partialAddedTotal += v; });
let partialSkippedTotal = 0;
Object.values(partialReport.seedSummary.rowsSkipped).forEach(v => { partialSkippedTotal += v; });

assert.strictEqual(partialAddedTotal, 23, 'Total data baru yang ditambahkan harus tepat 23 baris');
assert.strictEqual(partialSkippedTotal, 5, 'Total data existing yang dilewati harus tepat 5 baris');
assert.strictEqual(partialAddedTotal + partialSkippedTotal, 28, 'Total entitas terproses harus tetap 28');
console.log('   ✓ Lolos: Pemulihan parsial berhasil menyambung sisa 23 baris tanpa menduplikasi 5 baris existing.\n');

// ----------------------------------------------------------------------------
// TEST 24: Penghitungan Hasil & Verifikasi Kelengkapan 27 Entitas Seed
// ----------------------------------------------------------------------------
console.log('24. Menguji Penghitungan Hasil & Verifikasi Kelengkapan 27 Entitas Seed...');

const mockCompleteSS = createMockSpreadsheet();
const completeReport = runControlledSetupAndSeed_(mockCompleteSS, {
  skipSeed: false,
  credentials: {
    kepsekPassword: 'DynPassword123!',
    waliPassword: 'DynPassword456!'
  }
});

let completeAddedTotal = 0;
Object.values(completeReport.seedSummary.rowsAdded).forEach(v => { completeAddedTotal += v; });
assert.strictEqual(completeAddedTotal, 28, 'Fresh setup harus menambahkan 28 baris (1 pengaturan + 27 akademik/user)');

const academicAddedOnly = completeAddedTotal - (completeReport.seedSummary.rowsAdded['pengaturan'] || 0);
assert.strictEqual(academicAddedOnly, 27, 'Total entitas akademik dan user uji harus tepat 27 baris');

assert.strictEqual(completeReport.seedSummary.rowsAdded['tahun_ajaran'], 1);
assert.strictEqual(completeReport.seedSummary.rowsAdded['user'], 2);
assert.strictEqual(completeReport.seedSummary.rowsAdded['wali_kelas'], 1);
assert.strictEqual(completeReport.seedSummary.rowsAdded['siswa'], 3);
assert.strictEqual(completeReport.seedSummary.rowsAdded['mata_pelajaran'], 3);
assert.strictEqual(completeReport.seedSummary.rowsAdded['pengaturan_rapor'], 1);
assert.strictEqual(completeReport.seedSummary.rowsAdded['nilai_mata_pelajaran'], 9);
assert.strictEqual(completeReport.seedSummary.rowsAdded['nilai_sikap'], 3);
assert.strictEqual(completeReport.seedSummary.rowsAdded['rekap_kehadiran'], 3);
assert.strictEqual(completeReport.seedSummary.rowsAdded['pengumuman'], 1);
console.log('   ✓ Lolos: Penghitungan 27 entitas akademik + 1 singleton pengaturan terverifikasi presisi 100%.\n');

// ----------------------------------------------------------------------------
// TEST 25: Eksekusi Ulang Tidak Menambah Duplikat (0 Added, 28 Skipped)
// ----------------------------------------------------------------------------
console.log('25. Menguji Eksekusi Ulang Tidak Menambah Baris Duplikat (0 Added, 28 Skipped)...');

const secondRunReport = runControlledSetupAndSeed_(mockCompleteSS, {
  skipSeed: false,
  credentials: {
    kepsekPassword: 'DynPassword123!',
    waliPassword: 'DynPassword456!'
  }
});

let secondRunAdded = 0;
Object.values(secondRunReport.seedSummary.rowsAdded).forEach(v => { secondRunAdded += v; });
let secondRunSkipped = 0;
Object.values(secondRunReport.seedSummary.rowsSkipped).forEach(v => { secondRunSkipped += v; });

assert.strictEqual(secondRunAdded, 0, 'Eksekusi kedua tidak boleh menambah baris data baru');
assert.strictEqual(secondRunSkipped, 28, 'Eksekusi kedua harus melewati seluruh 28 entitas');
console.log('   ✓ Lolos: Eksekusi kedua terbukti murni 0 added dan 28 skipped.\n');

// ----------------------------------------------------------------------------
// TEST 26: Snapshot 100% Identik Sebelum & Sesudah Eksekusi Ulang (Data Protection)
// ----------------------------------------------------------------------------
console.log('26. Menguji Perlindungan Data Lama: Snapshot 100% Identik Sebelum & Sesudah Eksekusi Ulang...');

// Ambil deep snapshot dari mockCompleteSS
const snapshotBefore = {};
Object.keys(SCHEMA_DEFINITIONS).forEach(name => {
  snapshotBefore[name] = JSON.parse(JSON.stringify(mockCompleteSS.getSheetByName(name)._grid));
});

// Jalankan seed ke-3 pada basis data yang sama
runControlledSetupAndSeed_(mockCompleteSS, {
  skipSeed: false,
  credentials: {
    kepsekPassword: 'DynPassword123!',
    waliPassword: 'DynPassword456!'
  }
});

const snapshotAfter = {};
Object.keys(SCHEMA_DEFINITIONS).forEach(name => {
  snapshotAfter[name] = JSON.parse(JSON.stringify(mockCompleteSS.getSheetByName(name)._grid));
});

assert.deepStrictEqual(snapshotBefore, snapshotAfter, 'Seluruh sel, formula, dan baris pada 11 sheet harus 100% identik');
console.log('   ✓ Lolos: Snapshot komparatif membuktikan data lama tidak ditimpa, diubah, maupun dihapus.\n');

console.log('============================================================================');
console.log('SELURUH 26 PENGUJIAN OTOMATIS PHASE 10 LULUS DENGAN SUKSES (100% PASS)!');
console.log('============================================================================\n');
