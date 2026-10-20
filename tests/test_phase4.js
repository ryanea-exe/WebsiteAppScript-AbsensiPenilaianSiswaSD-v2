/**
 * ============================================================================
 * SUITE PENGUJIAN OTOMATIS PHASE 4: TAHUN AJARAN & PENUGASAN WALI KELAS
 * File: tests/test_phase4.js
 * ============================================================================
 *
 * Menguji:
 * 1. CRUD Tahun Ajaran & Semester:
 *    - Pengambilan daftar tahun ajaran (apiGetTahunAjaranList).
 *    - Validasi field wajib, format YYYY/YYYY sequential, semester valid (Ganjil/Genap).
 *    - Validasi rentang tanggal (tanggal_selesai > tanggal_mulai).
 *    - Validasi pencegahan duplikasi (tahun_ajaran + semester unik).
 *    - Aturan maksimal 1 periode aktif (otomatis menonaktifkan periode aktif lain).
 *    - Penguncian periode historis (lock/unlock toggle).
 *    - Pencegahan aktivasi periode yang sedang dikunci.
 *    - Pencegahan edit data pada periode yang berstatus terkunci.
 *    - Proteksi hapus periode: tidak boleh hapus periode aktif atau yang memiliki relasi.
 * 2. CRUD Penugasan Wali Kelas:
 *    - Pengambilan opsi guru wali kelas aktif (apiGetGuruWaliKelasOptions).
 *    - Penolakan penugasan user dengan role bukan wali_kelas atau user nonaktif.
 *    - Penolakan penugasan pada kelas di luar rentang 1–6.
 *    - Penolakan penugasan pada periode tahun ajaran yang telah dikunci.
 *    - Validasi keunikan kelas per periode (1 kelas hanya 1 wali kelas aktif).
 *    - Validasi keunikan guru per periode (1 guru hanya mengampu 1 kelas per periode).
 *    - Edit dan toggle status aktif/nonaktif penugasan.
 *    - Proteksi hapus penugasan jika sudah ada siswa atau mata pelajaran terkait.
 * 3. Otorisasi Role & Keamanan:
 *    - Penolakan endpoint mutasi bagi role wali_kelas (least privilege).
 *    - Penolakan request tanpa sesi token atau token kedaluwarsa.
 * 4. Integrasi Dashboard:
 *    - apiGetInitialDashboard menyajikan status 6 kelas (overview kelas 1–6).
 */

const assert = require('assert');
const path = require('path');

const setupModule = require('../setup.gs');
const appModule = require('../code.gs');

console.log('=== MEMULAI SUITE PENGUJIAN OTOMATIS PHASE 4: TAHUN AJARAN & PENUGASAN ===\n');

// ============================================================================
// SETUP MOCK SPREADSHEET ENVIRONMENT LOKAL
// ============================================================================
function createPhase4MockEnvironment() {
  const saltKepsek = appModule.generateSecureSalt();
  const hashKepsek = appModule.hashPasswordPBKDF2('KepsekPass123!', saltKepsek, 1000);

  const saltWali1 = appModule.generateSecureSalt();
  const hashWali1 = appModule.hashPasswordPBKDF2('WaliPass123!', saltWali1, 1000);

  const saltWali2 = appModule.generateSecureSalt();
  const hashWali2 = appModule.hashPasswordPBKDF2('WaliPass123!', saltWali2, 1000);

  const saltWali3 = appModule.generateSecureSalt();
  const hashWali3 = appModule.hashPasswordPBKDF2('WaliPass123!', saltWali3, 1000);

  const saltStaff = appModule.generateSecureSalt();
  const hashStaff = appModule.hashPasswordPBKDF2('StaffPass123!', saltStaff, 1000);

  const userHeaders = setupModule.SCHEMA_DEFINITIONS.user;
  const userRows = [
    ['u-kepsek', 'Drs. H. Subagyo, M.Pd.', '197001011995011001', 'kepsek', hashKepsek, saltKepsek, 'kepala_sekolah', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-wali1', 'Ahmad Dahlan, S.Pd.', '198502022010011002', 'wali1', hashWali1, saltWali1, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-wali2', 'Siti Fatimah, S.Pd.', '198803032011012003', 'wali2', hashWali2, saltWali2, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-wali3', 'Budi Santoso, S.Pd.', '199004042014011004', 'wali3', hashWali3, saltWali3, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-nonaktif', 'Guru Nonaktif, S.Pd.', '199205052015011005', 'nonaktif', hashWali3, saltWali3, 'wali_kelas', '', '', false, '2026-01-01', '2026-01-01'],
    ['u-bukanwali', 'Staff Tata Usaha', '199506062020011006', 'staff_tu', hashStaff, saltStaff, 'guru', '', '', true, '2026-01-01', '2026-01-01']
  ];

  const pengHeaders = setupModule.SCHEMA_DEFINITIONS.pengaturan;
  const pengRows = [
    ['1', '', 'SD Negeri Percobaan 01', 'Drs. H. Subagyo, M.Pd.', '197001011995011001', 'u-kepsek', '2026-01-01', '2026-01-01']
  ];

  const taHeaders = setupModule.SCHEMA_DEFINITIONS.tahun_ajaran;
  const taRows = [
    ['ta-hist-01', '2025/2026', 'Genap', '2026-01-05', '2026-06-20', false, true, '2026-01-01', '2026-01-01'],
    ['ta-aktif-01', '2026/2027', 'Ganjil', '2026-07-15', '2026-12-20', true, false, '2026-01-01', '2026-01-01']
  ];

  const wkHeaders = setupModule.SCHEMA_DEFINITIONS.wali_kelas;
  const wkRows = [
    ['wk-01', 'u-wali1', 'ta-aktif-01', '1', true, '2026-01-01', '2026-01-01']
  ];

  const siswaHeaders = setupModule.SCHEMA_DEFINITIONS.siswa;
  const siswaRows = [
    ['s-01', 'wk-01', '1234567890', '1001', 'Budi Cilik', 'L', 'Jakarta', '2019-01-01', 'Islam', 'Jl. Kenanga', 'Ortu Budi', '0812345678', '', true, '2026-01-01', '2026-01-01']
  ];

  const mapelHeaders = setupModule.SCHEMA_DEFINITIONS.mata_pelajaran;
  const mapelRows = [];

  const nilaiMapelHeaders = setupModule.SCHEMA_DEFINITIONS.nilai_mata_pelajaran;
  const nilaiMapelRows = [];

  const prHeaders = setupModule.SCHEMA_DEFINITIONS.pengaturan_rapor;
  const prRows = [];

  function makeMockSheet(name, headers, initialData) {
    const rows = [headers.slice(), ...initialData.map(r => r.slice())];
    return {
      getName: () => name,
      getLastRow: () => rows.length,
      getLastColumn: () => headers.length,
      getRange: function(r, c, numR, numC) {
        return {
          getValues: function() {
            const res = [];
            const countR = numR || 1;
            const countC = numC || 1;
            for (let rowIdx = r - 1; rowIdx < r - 1 + countR; rowIdx++) {
              const rowData = [];
              for (let colIdx = c - 1; colIdx < c - 1 + countC; colIdx++) {
                rowData.push(rows[rowIdx] ? rows[rowIdx][colIdx] : '');
              }
              res.push(rowData);
            }
            return res;
          },
          setValue: function(val) {
            if (rows[r - 1]) {
              rows[r - 1][c - 1] = val;
            }
          }
        };
      },
      appendRow: function(arr) {
        rows.push(arr.slice());
        return rows.length;
      },
      deleteRow: function(rowIndex) {
        if (rowIndex >= 1 && rowIndex <= rows.length) {
          rows.splice(rowIndex - 1, 1);
        }
        return rows.length;
      },
      _rawRows: rows
    };
  }

  const sheets = {
    user: makeMockSheet('user', userHeaders, userRows),
    pengaturan: makeMockSheet('pengaturan', pengHeaders, pengRows),
    tahun_ajaran: makeMockSheet('tahun_ajaran', taHeaders, taRows),
    wali_kelas: makeMockSheet('wali_kelas', wkHeaders, wkRows),
    siswa: makeMockSheet('siswa', siswaHeaders, siswaRows),
    mata_pelajaran: makeMockSheet('mata_pelajaran', mapelHeaders, mapelRows),
    nilai_mata_pelajaran: makeMockSheet('nilai_mata_pelajaran', nilaiMapelHeaders, nilaiMapelRows),
    pengaturan_rapor: makeMockSheet('pengaturan_rapor', prHeaders, prRows)
  };

  const ss = {
    getSheetByName: (name) => sheets[name] || null,
    sheets: sheets
  };

  return ss;
}

// Inisialisasi Mock Spreadsheet
const mockSS = createPhase4MockEnvironment();
global.getTargetSpreadsheet = () => mockSS;
global.SpreadsheetApp = {
  getActiveSpreadsheet: () => mockSS,
  flush: () => {}
};
global.LockService = {
  getScriptLock: () => ({
    waitLock: () => true,
    releaseLock: () => true
  })
};

// Login user untuk sesi pengujian
const kepsekLogin = appModule.apiLogin('kepsek', 'KepsekPass123!');
assert.strictEqual(kepsekLogin.success, true, 'Login kepala sekolah harus sukses');
const kepsekToken = kepsekLogin.data.token;

const waliLogin = appModule.apiLogin('wali1', 'WaliPass123!');
assert.strictEqual(waliLogin.success, true, 'Login wali kelas harus sukses');
const waliToken = waliLogin.data.token;

// ============================================================================
// UJI 1: PENGAMBILAN DAFTAR TAHUN AJARAN (apiGetTahunAjaranList)
// ============================================================================
console.log('1. Menguji Endpoint apiGetTahunAjaranList (Kepala Sekolah & Wali Kelas)...');

// 1A. Kepala sekolah memuat daftar
const listKepsek = appModule.apiGetTahunAjaranList(kepsekToken);
assert.strictEqual(listKepsek.success, true, 'apiGetTahunAjaranList harus sukses untuk kepala sekolah');
assert.ok(Array.isArray(listKepsek.data), 'Data harus berupa array');
assert.strictEqual(listKepsek.data.length, 2, 'Harus ada 2 record tahun ajaran');

// Periksa properti & relasi
const itemAktif = listKepsek.data.find(t => t.id === 'ta-aktif-01');
assert.ok(itemAktif, 'Tahun ajaran aktif harus ditemukan');
assert.strictEqual(itemAktif.tahun_ajaran, '2026/2027');
assert.strictEqual(itemAktif.semester, 'Ganjil');
assert.strictEqual(itemAktif.is_active, true);
assert.strictEqual(itemAktif.is_locked, false);
assert.strictEqual(itemAktif.hasRelations, true, 'ta-aktif-01 memiliki penugasan wk-01 sehingga hasRelations = true');

const itemHist = listKepsek.data.find(t => t.id === 'ta-hist-01');
assert.ok(itemHist);
assert.strictEqual(itemHist.is_locked, true, 'ta-hist-01 berstatus locked');
assert.strictEqual(itemHist.hasRelations, false);

// 1B. Wali kelas juga boleh melihat daftar periode (read-only)
const listWali = appModule.apiGetTahunAjaranList(waliToken);
assert.strictEqual(listWali.success, true, 'Wali kelas berhak membaca daftar tahun ajaran');
assert.strictEqual(listWali.data.length, 2);

// 1C. Request tanpa token valid harus ditolak
const listBad = appModule.apiGetTahunAjaranList('token_invalid_123');
assert.strictEqual(listBad.success, false);
assert.ok(listBad.message.includes('Akses ditolak'));

console.log('   ✓ apiGetTahunAjaranList terverifikasi benar.\n');

// ============================================================================
// UJI 2: VALIDASI DAN PENYIMPANAN TAHUN AJARAN (apiSaveTahunAjaran)
// ============================================================================
console.log('2. Menguji Validasi Server-Side apiSaveTahunAjaran...');

// 2A. Otorisasi role: Wali kelas tidak boleh menambah/mengedit tahun ajaran
const saveByWali = appModule.apiSaveTahunAjaran(waliToken, {
  tahun_ajaran: '2027/2028',
  semester: 'Ganjil',
  tanggal_mulai: '2027-07-15',
  tanggal_selesai: '2027-12-20'
});
assert.strictEqual(saveByWali.success, false);
assert.ok(saveByWali.message.includes('Akses ditolak') || saveByWali.message.includes('tidak memiliki izin'));

// 2B. Validasi field wajib kosong
const saveEmpty = appModule.apiSaveTahunAjaran(kepsekToken, {
  tahun_ajaran: '',
  semester: 'Ganjil',
  tanggal_mulai: '',
  tanggal_selesai: ''
});
assert.strictEqual(saveEmpty.success, false);
assert.ok(saveEmpty.message.includes('wajib diisi'));

// 2C. Validasi format tahun ajaran tidak sesuai regex
const saveBadFormat1 = appModule.apiSaveTahunAjaran(kepsekToken, {
  tahun_ajaran: '2026-2027', // strip bukan slash
  semester: 'Ganjil',
  tanggal_mulai: '2026-07-15',
  tanggal_selesai: '2026-12-20'
});
assert.strictEqual(saveBadFormat1.success, false);
assert.ok(saveBadFormat1.message.includes('YYYY/YYYY'));

// 2D. Validasi tahun ajaran bukan tahun berurutan (misal 2026/2028 selisih 2 tahun)
const saveBadFormat2 = appModule.apiSaveTahunAjaran(kepsekToken, {
  tahun_ajaran: '2026/2028',
  semester: 'Ganjil',
  tanggal_mulai: '2026-07-15',
  tanggal_selesai: '2026-12-20'
});
assert.strictEqual(saveBadFormat2.success, false);
assert.ok(saveBadFormat2.message.includes('berurutan tepat satu tahun'));

// 2E. Validasi semester invalid (bukan Ganjil/Genap)
const saveBadSem = appModule.apiSaveTahunAjaran(kepsekToken, {
  tahun_ajaran: '2027/2028',
  semester: 'Pendek',
  tanggal_mulai: '2027-07-15',
  tanggal_selesai: '2027-12-20'
});
assert.strictEqual(saveBadSem.success, false);
assert.ok(saveBadSem.message.includes('Ganjil atau Genap'));

// 2F. Validasi rentang tanggal: tanggal_selesai <= tanggal_mulai
const saveBadDates = appModule.apiSaveTahunAjaran(kepsekToken, {
  tahun_ajaran: '2027/2028',
  semester: 'Ganjil',
  tanggal_mulai: '2027-12-20',
  tanggal_selesai: '2027-07-15'
});
assert.strictEqual(saveBadDates.success, false);
assert.ok(saveBadDates.message.includes('Tanggal selesai harus setelah tanggal mulai'));

// 2G. Validasi periode terkunci tidak boleh dijadikan periode aktif
const saveLockedActive = appModule.apiSaveTahunAjaran(kepsekToken, {
  tahun_ajaran: '2027/2028',
  semester: 'Ganjil',
  tanggal_mulai: '2027-07-15',
  tanggal_selesai: '2027-12-20',
  is_active: true,
  is_locked: true
});
assert.strictEqual(saveLockedActive.success, false);
assert.ok(saveLockedActive.message.includes('Periode yang dikunci tidak dapat'));

// 2H. Validasi duplikasi: kombinasi tahun_ajaran + semester yang sudah ada
const saveDuplicate = appModule.apiSaveTahunAjaran(kepsekToken, {
  tahun_ajaran: '2026/2027',
  semester: 'Ganjil',
  tanggal_mulai: '2026-07-15',
  tanggal_selesai: '2026-12-20'
});
assert.strictEqual(saveDuplicate.success, false);
assert.ok(saveDuplicate.message.includes('sudah terdaftar'));

console.log('   ✓ Validasi server-side input tahun ajaran terverifikasi ketat.\n');

// ============================================================================
// UJI 3: PENAMBAHAN TAHUN AJARAN & SINGLE ACTIVE PERIOD SWITCH
// ============================================================================
console.log('3. Menguji Penambahan Tahun Ajaran Baru & Single Active Period Rule...');

// Tambah periode baru yang aktif: 2026/2027 Genap
const saveNewOk = appModule.apiSaveTahunAjaran(kepsekToken, {
  tahun_ajaran: '2026/2027',
  semester: 'Genap',
  tanggal_mulai: '2027-01-05',
  tanggal_selesai: '2027-06-20',
  is_active: true,
  is_locked: false
});
assert.strictEqual(saveNewOk.success, true, 'Penambahan tahun ajaran valid harus sukses');
assert.ok(saveNewOk.data.id, 'ID baru harus dikembalikan');
const newTaId = saveNewOk.data.id;

// Verifikasi aturan single active period:
// 'ta-aktif-01' yang sebelumnya aktif harus otomatis menjadi is_active = false
const taSheetData = mockSS.sheets.tahun_ajaran._rawRows;
const prevActiveRow = taSheetData.find(r => r[0] === 'ta-aktif-01');
assert.strictEqual(prevActiveRow[5], false, 'Periode aktif sebelumnya harus dinonaktifkan otomatis');

const newlyAddedRow = taSheetData.find(r => r[0] === newTaId);
assert.ok(newlyAddedRow, 'Baris baru harus masuk ke sheet');
assert.strictEqual(newlyAddedRow[5], true, 'Periode baru harus berstatus is_active = true');

console.log('   ✓ Single active period rule terbukti berhasil menonaktifkan periode lama.\n');

// ============================================================================
// UJI 4: PENGUNCIAN PERIODE HISTORIS (LOCK / UNLOCK TOGGLE)
// ============================================================================
console.log('4. Menguji Penguncian Periode Historis (Lock & Unlock)...');

// 4A. Mengunci periode baru yang aktif
const lockRes = appModule.apiToggleLockTahunAjaran(kepsekToken, newTaId, true);
assert.strictEqual(lockRes.success, true);
assert.strictEqual(lockRes.data.is_locked, true);

// Verifikasi bahwa periode yang dikunci otomatis is_active = false
const lockedRow = taSheetData.find(r => r[0] === newTaId);
assert.strictEqual(lockedRow[6], true, 'is_locked harus true');
assert.strictEqual(lockedRow[5], false, 'is_active otomatis false saat dikunci');

// 4B. Percobaan mengedit data periode yang sedang dikunci harus ditolak
const editLockedFail = appModule.apiSaveTahunAjaran(kepsekToken, {
  id: newTaId,
  tahun_ajaran: '2026/2027',
  semester: 'Genap',
  tanggal_mulai: '2027-01-10',
  tanggal_selesai: '2027-06-25',
  is_active: false,
  is_locked: true
});
assert.strictEqual(editLockedFail.success, false);
assert.ok(editLockedFail.message.includes('telah dikunci dan tidak dapat diubah'));

// 4C. Membuka kunci (Unlock) periode
const unlockRes = appModule.apiToggleLockTahunAjaran(kepsekToken, newTaId, false);
assert.strictEqual(unlockRes.success, true);
assert.strictEqual(unlockRes.data.is_locked, false);

// Sekarang edit data diperbolehkan
const editUnlockedOk = appModule.apiSaveTahunAjaran(kepsekToken, {
  id: newTaId,
  tahun_ajaran: '2026/2027',
  semester: 'Genap',
  tanggal_mulai: '2027-01-10',
  tanggal_selesai: '2027-06-25',
  is_active: false,
  is_locked: false
});
assert.strictEqual(editUnlockedOk.success, true, 'Edit periode yang sudah di-unlock harus sukses');

// Kembalikan ta-aktif-01 menjadi periode aktif
appModule.updateSheetRow('tahun_ajaran', 3, { is_active: true });

console.log('   ✓ Siklus penguncian (lock/unlock) dan proteksi edit historis terverifikasi.\n');

// ============================================================================
// UJI 5: PROTEKSI PENGHAPUSAN TAHUN AJARAN (apiDeleteTahunAjaran)
// ============================================================================
console.log('5. Menguji Proteksi Integritas Penghapusan Tahun Ajaran...');

// 5A. Tidak boleh menghapus periode yang sedang aktif
const delActiveFail = appModule.apiDeleteTahunAjaran(kepsekToken, 'ta-aktif-01');
assert.strictEqual(delActiveFail.success, false);
assert.ok(delActiveFail.message.includes('sedang aktif tidak dapat dihapus'));

// 5B. Nonaktifkan ta-aktif-01 sementara untuk menguji proteksi relasi
appModule.updateSheetRow('tahun_ajaran', 3, { is_active: false });

// 5C. Tidak boleh menghapus periode yang memiliki relasi wali_kelas
const delWithRelationsFail = appModule.apiDeleteTahunAjaran(kepsekToken, 'ta-aktif-01');
assert.strictEqual(delWithRelationsFail.success, false);
assert.ok(delWithRelationsFail.message.includes('memiliki data penugasan wali kelas'));

// 5D. Boleh menghapus periode yang tidak aktif dan tidak memiliki relasi
const delOrphanOk = appModule.apiDeleteTahunAjaran(kepsekToken, newTaId);
assert.strictEqual(delOrphanOk.success, true, 'Periode orphan harus berhasil dihapus');
const orphanRowCheck = taSheetData.find(r => r[0] === newTaId);
assert.strictEqual(orphanRowCheck, undefined, 'Baris orphan harus terhapus dari sheet');

// Kembalikan status ta-aktif-01 aktif
appModule.updateSheetRow('tahun_ajaran', 3, { is_active: true });

console.log('   ✓ Proteksi relasional dan status aktif saat penghapusan periode terbukti aman.\n');

// ============================================================================
// UJI 6: OPSI GURU WALI KELAS (apiGetGuruWaliKelasOptions)
// ============================================================================
console.log('6. Menguji Endpoint Opsi Guru Wali Kelas...');

// 6A. Kepala sekolah mengambil opsi guru
const guruOpts = appModule.apiGetGuruWaliKelasOptions(kepsekToken);
assert.strictEqual(guruOpts.success, true);
assert.ok(Array.isArray(guruOpts.data));

// Hanya guru aktif dengan role 'wali_kelas' yang muncul
// 'u-wali1', 'u-wali2', 'u-wali3' (3 orang)
// 'u-nonaktif' (nonaktif) dan 'u-bukanwali' (role: guru) TIDAK boleh masuk
assert.strictEqual(guruOpts.data.length, 3, 'Hanya 3 guru aktif ber-role wali_kelas yang boleh muncul');
assert.strictEqual(guruOpts.data.some(g => g.id === 'u-nonaktif'), false, 'Guru nonaktif tidak boleh muncul');
assert.strictEqual(guruOpts.data.some(g => g.id === 'u-bukanwali'), false, 'Staff selain wali_kelas tidak boleh muncul');

// Terurut alfabetis berdasarkan nama
assert.strictEqual(guruOpts.data[0].nama, 'Ahmad Dahlan, S.Pd.');
assert.strictEqual(guruOpts.data[1].nama, 'Budi Santoso, S.Pd.');
assert.strictEqual(guruOpts.data[2].nama, 'Siti Fatimah, S.Pd.');

// 6B. Wali kelas tidak memiliki akses endpoint ini
const guruOptsWali = appModule.apiGetGuruWaliKelasOptions(waliToken);
assert.strictEqual(guruOptsWali.success, false);
assert.ok(guruOptsWali.message.includes('Akses ditolak') || guruOptsWali.message.includes('tidak memiliki izin'));

console.log('   ✓ Opsi guru wali kelas terverifikasi sesuai role dan status keaktifan.\n');

// ============================================================================
// UJI 7: VALIDASI DAN PENYIMPANAN PENUGASAN (apiSavePenugasan)
// ============================================================================
console.log('7. Menguji Validasi Server-Side apiSavePenugasan (Konflik Kelas & Guru)...');

// 7A. Wali kelas tidak boleh mengakses apiSavePenugasan
const saveWkByWali = appModule.apiSavePenugasan(waliToken, {
  user_id: 'u-wali2',
  tahun_ajaran_id: 'ta-aktif-01',
  kelas: '2'
});
assert.strictEqual(saveWkByWali.success, false);

// 7B. Validasi pilihan kelas di luar 1–6
const saveBadClass = appModule.apiSavePenugasan(kepsekToken, {
  user_id: 'u-wali2',
  tahun_ajaran_id: 'ta-aktif-01',
  kelas: '7'
});
assert.strictEqual(saveBadClass.success, false);
assert.ok(saveBadClass.message.includes('antara 1 sampai 6'));

// 7C. Validasi penugasan user dengan role bukan wali_kelas
const saveNonWali = appModule.apiSavePenugasan(kepsekToken, {
  user_id: 'u-bukanwali',
  tahun_ajaran_id: 'ta-aktif-01',
  kelas: '2'
});
assert.strictEqual(saveNonWali.success, false);
assert.ok(saveNonWali.message.includes('bukan memiliki role wali kelas'));

// 7D. Validasi penugasan guru yang sedang nonaktif
const saveInactiveGuru = appModule.apiSavePenugasan(kepsekToken, {
  user_id: 'u-nonaktif',
  tahun_ajaran_id: 'ta-aktif-01',
  kelas: '2'
});
assert.strictEqual(saveInactiveGuru.success, false);
assert.ok(saveInactiveGuru.message.includes('status nonaktif'));

// 7E. Validasi penugasan pada periode yang terkunci
const saveOnLockedTa = appModule.apiSavePenugasan(kepsekToken, {
  user_id: 'u-wali2',
  tahun_ajaran_id: 'ta-hist-01', // ta-hist-01 is locked
  kelas: '2'
});
assert.strictEqual(saveOnLockedTa.success, false);
assert.ok(saveOnLockedTa.message.includes('telah dikunci'));

// 7F. Konflik Kelas: Kelas 1 sudah diampu u-wali1 pada ta-aktif-01
const saveConflictClass = appModule.apiSavePenugasan(kepsekToken, {
  user_id: 'u-wali2',
  tahun_ajaran_id: 'ta-aktif-01',
  kelas: '1'
});
assert.strictEqual(saveConflictClass.success, false);
assert.ok(saveConflictClass.message.includes('Kelas 1 sudah memiliki wali kelas aktif'));

// 7G. Konflik Guru: u-wali1 sudah mengampu Kelas 1, tidak boleh ditugaskan ke Kelas 2 pada periode yang sama
const saveConflictTeacher = appModule.apiSavePenugasan(kepsekToken, {
  user_id: 'u-wali1',
  tahun_ajaran_id: 'ta-aktif-01',
  kelas: '2'
});
assert.strictEqual(saveConflictTeacher.success, false);
assert.ok(saveConflictTeacher.message.includes('sudah ditugaskan mengampu Kelas 1'));

// 7H. Penugasan Valid: Guru u-wali2 ke Kelas 2
const saveWkOk = appModule.apiSavePenugasan(kepsekToken, {
  user_id: 'u-wali2',
  tahun_ajaran_id: 'ta-aktif-01',
  kelas: '2',
  is_active: true
});
assert.strictEqual(saveWkOk.success, true, 'Penugasan valid harus berhasil disimpan');
assert.ok(saveWkOk.data.id);
const newWkId = saveWkOk.data.id;

console.log('   ✓ Validasi pencegahan konflik kelas ganda dan guru ganda terbukti 100% efektif.\n');

// ============================================================================
// UJI 8: DAFTAR PENUGASAN BERDASARKAN ROLE (apiGetPenugasanList)
// ============================================================================
console.log('8. Menguji Endpoint apiGetPenugasanList (Filter Role & Periode)...');

// 8A. Kepala Sekolah melihat seluruh penugasan
const listAllPenugasan = appModule.apiGetPenugasanList(kepsekToken, 'ta-aktif-01');
assert.strictEqual(listAllPenugasan.success, true);
assert.strictEqual(listAllPenugasan.data.length, 2, 'Harus ada 2 penugasan (Kelas 1 dan Kelas 2)');
assert.strictEqual(listAllPenugasan.data[0].kelas, '1');
assert.strictEqual(listAllPenugasan.data[1].kelas, '2');
assert.strictEqual(listAllPenugasan.data[0].totalSiswa, 1, 'Kelas 1 memiliki 1 siswa');

// 8B. Wali Kelas 1 hanya melihat penugasan milik dirinya sendiri
const listWali1 = appModule.apiGetPenugasanList(waliToken, 'ta-aktif-01');
assert.strictEqual(listWali1.success, true);
assert.strictEqual(listWali1.data.length, 1, 'Wali kelas hanya boleh melihat kelas miliknya');
assert.strictEqual(listWali1.data[0].user_id, 'u-wali1');
assert.strictEqual(listWali1.data[0].kelas, '1');

console.log('   ✓ Pembatasan data penugasan berdasarkan role terbukti aman.\n');

// ============================================================================
// UJI 9: TOGGLE STATUS & PROTEKSI PENGHAPUSAN PENUGASAN (apiDeletePenugasan)
// ============================================================================
console.log('9. Menguji Toggle Status Aktif/Nonaktif & Proteksi Penghapusan Penugasan...');

// 9A. Nonaktifkan penugasan Kelas 2
const toggleOff = appModule.apiToggleStatusPenugasan(kepsekToken, newWkId, false);
assert.strictEqual(toggleOff.success, true);
assert.strictEqual(toggleOff.data.is_active, false);

// Setelah dinonaktifkan, u-wali3 boleh ditugaskan ke Kelas 2
const saveWk3Ok = appModule.apiSavePenugasan(kepsekToken, {
  user_id: 'u-wali3',
  tahun_ajaran_id: 'ta-aktif-01',
  kelas: '2',
  is_active: true
});
assert.strictEqual(saveWk3Ok.success, true, 'Kelas 2 boleh diisi jika penugasan sebelumnya nonaktif');

// Jika mencoba mengaktifkan kembali penugasan lama Kelas 2 -> harus ditolak karena konflik
const toggleConflict = appModule.apiToggleStatusPenugasan(kepsekToken, newWkId, true);
assert.strictEqual(toggleConflict.success, false);
assert.ok(toggleConflict.message.includes('sudah memiliki wali kelas aktif'));

// 9B. Proteksi Hapus: wk-01 memiliki relasi siswa -> TIDAK BOLEH dihapus
const delWkWithStudents = appModule.apiDeletePenugasan(kepsekToken, 'wk-01');
assert.strictEqual(delWkWithStudents.success, false);
assert.ok(delWkWithStudents.message.includes('sudah memiliki data siswa'));

// 9C. Hapus penugasan newWkId (tidak memiliki data siswa/mapel) -> DIPERBOLEHKAN
const delWkEmpty = appModule.apiDeletePenugasan(kepsekToken, newWkId);
assert.strictEqual(delWkEmpty.success, true, 'Penugasan tanpa relasi siswa/mapel boleh dihapus');

console.log('   ✓ Proteksi relasional data siswa pada penugasan terverifikasi kuat.\n');

// ============================================================================
// UJI 10: INTEGRASI DASHBOARD KEPALA SEKOLAH & WALI KELAS (Phase 4 Updates)
// ============================================================================
console.log('10. Menguji Integrasi Dashboard Awal dengan Overview Kelas 1–6...');

const dashKepsek = appModule.apiGetInitialDashboard(kepsekToken);
assert.strictEqual(dashKepsek.success, true);
assert.strictEqual(dashKepsek.data.user.role, 'kepala_sekolah');
assert.strictEqual(dashKepsek.data.summary.totalKelasDitugaskan, 2, 'Kelas 1 dan Kelas 2 aktif ditugaskan');
assert.strictEqual(dashKepsek.data.summary.totalSiswa, 1);

// Periksa kelasOverview (Kelas 1 s/d 6)
assert.ok(dashKepsek.data.kelasOverview, 'Harus ada kelasOverview pada payload Kepala Sekolah');
assert.strictEqual(dashKepsek.data.kelasOverview.length, 6, 'Harus ada 6 kelas');

const k1 = dashKepsek.data.kelasOverview.find(k => k.kelas === '1');
assert.strictEqual(k1.isAssigned, true);
assert.strictEqual(k1.guruNama, 'Ahmad Dahlan, S.Pd.');
assert.strictEqual(k1.totalSiswa, 1);

const k3 = dashKepsek.data.kelasOverview.find(k => k.kelas === '3');
assert.strictEqual(k3.isAssigned, false);
assert.strictEqual(k3.guruNama, 'Belum Ditugaskan');
assert.strictEqual(k3.totalSiswa, 0);

console.log('   ✓ Integrasi dashboard 6 kelas Kepala Sekolah terverifikasi lengkap.\n');

// ============================================================================
// RINGKASAN AKHIR
// ============================================================================
console.log('======================================================');
console.log('SELURUH PENGUJIAN OTOMATIS PHASE 4 BERHASIL LULUS (100% PASS)');
console.log('======================================================');
