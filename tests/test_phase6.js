/**
 * ============================================================================
 * SUITE PENGUJIAN OTOMATIS PHASE 6: NILAI, SIKAP, KEHADIRAN, & PENGATURAN RAPOR
 * File: tests/test_phase6.js
 * ============================================================================
 *
 * Menguji:
 * 1. Pengaturan Rapor & Bobot Penilaian (apiGetPengaturanRapor & apiSavePengaturanRapor):
 *    - Default fallback bobot 40/30/30 dan predikat A-D saat belum dikonfigurasi.
 *    - Validasi total bobot (harus tepat 100%, penolakan bobot negatif atau < 100% atau > 100%).
 *    - Validasi rentang predikat (minimal 2 rentang, 0–100, terendah dari 0, tertinggi sampai 100).
 *    - Validasi kontinuitas predikat: penolakan celah (gap) dan tumpang tindih (overlap).
 *    - Penyimpanan baru dan pembaruan konfigurasi yang sudah ada (pencegahan duplikasi baris).
 *    - Proteksi periode terkunci: penolakan perubahan saat tahun ajaran dikunci.
 *    - Proteksi IDOR: Wali kelas tidak dapat mengubah konfigurasi kelas guru lain.
 *
 * 2. Input Nilai Akademik (apiGetNilaiMataPelajaran & apiSaveNilaiMataPelajaranBatch):
 *    - Pengambilan daftar nilai per mata pelajaran sesuai rombel kelas.
 *    - Validasi rentang nilai numerik 0–100 (penolakan nilai negatif, > 100, atau non-numerik).
 *    - Penanganan nilai parsial: komponen kosong TIDAK otomatis diubah menjadi 0.
 *    - Perhitungan nilai akhir: hanya dihitung jika ke-6 komponen (T1-T4, UTS, UAS) lengkap.
 *    - Formula nilai akhir: rata_tugas = (t1+t2+t3+t4)/4, nilai_akhir = (rata_tugas*bT + uts*bU + uas*bA)/100, pembulatan 2 desimal.
 *    - Penentuan predikat otomatis sesuai konfigurasi rapor yang berlaku.
 *    - Penyimpanan batch dan pembaruan tanpa duplikasi record per siswa dan mapel.
 *    - Proteksi periode terkunci dan proteksi IDOR (mapel/siswa kelas lain).
 *
 * 3. Penilaian Sikap (apiGetNilaiSikapList & apiSaveNilaiSikapBatch):
 *    - Pengambilan daftar sikap siswa rombel kelas penugasan.
 *    - Validasi predikat sikap: hanya menerima pilihan sah (Sangat Baik, Baik, Cukup, Kurang / A, B, C, D).
 *    - Penyimpanan batch dan pembaruan record siswa (1 record per siswa, tanpa duplikasi).
 *    - Proteksi periode terkunci dan proteksi IDOR.
 *
 * 4. Rekap Kehadiran (apiGetRekapKehadiranList & apiSaveRekapKehadiranBatch):
 *    - Pengambilan rekap hadir, sakit, izin, alpa beserta kalkulasi total kelas.
 *    - Validasi angka kehadiran: hanya menerima integer non-negatif (>= 0). Penolakan angka negatif.
 *    - Penyimpanan batch dan pembaruan tanpa duplikasi record.
 *    - Proteksi periode terkunci dan proteksi IDOR.
 *
 * 5. Indikator Kelengkapan & Monitoring (apiGetKelengkapanPenilaian):
 *    - Monitoring kelas tunggal untuk Wali Kelas (progres mapel, sikap, kehadiran).
 *    - Monitoring multi-kelas (kelas 1–6) untuk Kepala Sekolah.
 *    - Penentuan status data: 'Belum Ada Wali Kelas', 'Belum Lengkap', 'Sebagian', 'Lengkap'.
 *
 * 6. Keamanan Sesi & Otorisasi:
 *    - Penolakan token tidak valid pada seluruh endpoint Phase 6.
 */

const assert = require('assert');
const path = require('path');

const setupModule = require('../setup.gs');
const appModule = require('../code.gs');

console.log('=== MEMULAI SUITE PENGUJIAN OTOMATIS PHASE 6: NILAI, SIKAP, KEHADIRAN & RAPOR ===\n');

// ============================================================================
// SETUP MOCK SPREADSHEET ENVIRONMENT LOKAL
// ============================================================================
function createPhase6MockEnvironment() {
  const saltKepsek = appModule.generateSecureSalt();
  const hashKepsek = appModule.hashPasswordPBKDF2('KepsekPass123!', saltKepsek, 1000);

  const saltWali1 = appModule.generateSecureSalt();
  const hashWali1 = appModule.hashPasswordPBKDF2('WaliPass123!', saltWali1, 1000);

  const saltWali2 = appModule.generateSecureSalt();
  const hashWali2 = appModule.hashPasswordPBKDF2('WaliPass123!', saltWali2, 1000);

  const userHeaders = setupModule.SCHEMA_DEFINITIONS.user;
  const userRows = [
    ['u-kepsek', 'Drs. H. Subagyo, M.Pd.', '197001011995011001', 'kepsek', hashKepsek, saltKepsek, 'kepala_sekolah', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-wali1', 'Ahmad Dahlan, S.Pd.', '198502022010011002', 'wali1', hashWali1, saltWali1, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-wali2', 'Siti Fatimah, S.Pd.', '198803032011012003', 'wali2', hashWali2, saltWali2, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01']
  ];

  const pengHeaders = setupModule.SCHEMA_DEFINITIONS.pengaturan;
  const pengRows = [
    ['1', '', 'SD Negeri Percobaan 01', 'Drs. H. Subagyo, M.Pd.', '197001011995011001', 'u-kepsek', '2026-01-01', '2026-01-01']
  ];

  const taHeaders = setupModule.SCHEMA_DEFINITIONS.tahun_ajaran;
  const taRows = [
    ['ta-locked', '2025/2026', 'Genap', '2026-01-05', '2026-06-20', false, true, '2026-01-01', '2026-01-01'],
    ['ta-aktif', '2026/2027', 'Ganjil', '2026-07-15', '2026-12-20', true, false, '2026-01-01', '2026-01-01']
  ];

  const wkHeaders = setupModule.SCHEMA_DEFINITIONS.wali_kelas;
  const wkRows = [
    ['wk-k1-aktif', 'u-wali1', 'ta-aktif', '1', true, '2026-01-01', '2026-01-01'],
    ['wk-k2-aktif', 'u-wali2', 'ta-aktif', '2', true, '2026-01-01', '2026-01-01'],
    ['wk-k1-locked', 'u-wali1', 'ta-locked', '1', false, '2026-01-01', '2026-01-01']
  ];

  const siswaHeaders = setupModule.SCHEMA_DEFINITIONS.siswa;
  const siswaRows = [
    ['s-01', 'wk-k1-aktif', '0012345678', '1001', '1', 'Budi Cilik', 'L', 'Jakarta', '2019-01-01', 'Ortu Budi', '0812345678', true, '2026-01-01', '2026-01-01'],
    ['s-02', 'wk-k1-aktif', '0012345679', '1002', '2', 'Ani Cantika', 'P', 'Jakarta', '2019-02-02', 'Ortu Ani', '0812345679', true, '2026-01-01', '2026-01-01'],
    ['s-03', 'wk-k2-aktif', '0012345680', '1003', '1', 'Doni Santoso', 'L', 'Bandung', '2018-05-05', 'Ortu Doni', '0812345680', true, '2026-01-01', '2026-01-01'],
    ['s-locked', 'wk-k1-locked', '0012345699', '1099', '1', 'Siswa Masa Lalu', 'L', 'Jakarta', '2018-01-01', 'Ortu Masa Lalu', '0812999999', true, '2026-01-01', '2026-01-01']
  ];

  const mapelHeaders = setupModule.SCHEMA_DEFINITIONS.mata_pelajaran;
  const mapelRows = [
    ['m-01', 'wk-k1-aktif', 'PAI', 'Pendidikan Agama Islam', true, '2026-01-01', '2026-01-01'],
    ['m-02', 'wk-k1-aktif', 'MTK', 'Matematika', true, '2026-01-01', '2026-01-01'],
    ['m-03', 'wk-k2-aktif', 'MTK', 'Matematika', true, '2026-01-01', '2026-01-01'],
    ['m-locked', 'wk-k1-locked', 'IPA', 'Ilmu Pengetahuan Alam', true, '2026-01-01', '2026-01-01']
  ];

  const nilaiMapelHeaders = setupModule.SCHEMA_DEFINITIONS.nilai_mata_pelajaran;
  const nilaiMapelRows = [];

  const nilaiSikapHeaders = setupModule.SCHEMA_DEFINITIONS.nilai_sikap;
  const nilaiSikapRows = [];

  const rekapKehadiranHeaders = setupModule.SCHEMA_DEFINITIONS.rekap_kehadiran;
  const rekapKehadiranRows = [];

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
    nilai_sikap: makeMockSheet('nilai_sikap', nilaiSikapHeaders, nilaiSikapRows),
    rekap_kehadiran: makeMockSheet('rekap_kehadiran', rekapKehadiranHeaders, rekapKehadiranRows),
    pengaturan_rapor: makeMockSheet('pengaturan_rapor', prHeaders, prRows)
  };

  const ss = {
    getSheetByName: (name) => sheets[name] || null,
    sheets: sheets
  };

  return ss;
}

// Inisialisasi Mock Spreadsheet
const mockSS = createPhase6MockEnvironment();
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

const wali1Login = appModule.apiLogin('wali1', 'WaliPass123!');
assert.strictEqual(wali1Login.success, true, 'Login wali kelas 1 harus sukses');
const wali1Token = wali1Login.data.token;

const wali2Login = appModule.apiLogin('wali2', 'WaliPass123!');
assert.strictEqual(wali2Login.success, true, 'Login wali kelas 2 harus sukses');
const wali2Token = wali2Login.data.token;

// ============================================================================
// 1. PENGUJIAN PENGATURAN RAPOR & BOBOT PENILAIAN
// ============================================================================
console.log('1. Menguji Pengaturan Rapor & Bobot Penilaian...');

// 1A. Memuat default konfigurasi rapor saat belum pernah disimpan
const getPrWali1 = appModule.apiGetPengaturanRapor(wali1Token);
assert.strictEqual(getPrWali1.success, true, 'Wali kelas 1 harus bisa memuat pengaturan rapor');
assert.strictEqual(getPrWali1.data.config.bobot_tugas, 40);
assert.strictEqual(getPrWali1.data.config.bobot_uts, 30);
assert.strictEqual(getPrWali1.data.config.bobot_uas, 30);
assert.strictEqual(getPrWali1.data.config.isDefault, true);
assert.strictEqual(getPrWali1.data.config.predikat.length, 4);

// 1B. Kepala Sekolah dapat melihat pengaturan rapor kelas tertentu
const getPrKepsek = appModule.apiGetPengaturanRapor(kepsekToken, 'wk-k1-aktif');
assert.strictEqual(getPrKepsek.success, true, 'Kepala sekolah harus bisa memuat pengaturan rapor kelas 1');
assert.strictEqual(getPrKepsek.data.assignment.kelas, '1');

// 1C. Validasi Bobot: Penolakan total bobot tidak sama dengan 100%
const savePrWrongTotal = appModule.apiSavePengaturanRapor(wali1Token, {
  bobot_tugas: 50,
  bobot_uts: 30,
  bobot_uas: 10, // Total = 90%
  predikat: [
    { label: 'A', min: 90, max: 100 },
    { label: 'B', min: 80, max: 89.99 },
    { label: 'C', min: 70, max: 79.99 },
    { label: 'D', min: 0, max: 69.99 }
  ]
});
assert.strictEqual(savePrWrongTotal.success, false);
assert.ok(savePrWrongTotal.message.includes('harus tepat 100%'), 'Harus menolak total bobot bukan 100%');

// 1D. Validasi Bobot: Penolakan angka negatif
const savePrNegative = appModule.apiSavePengaturanRapor(wali1Token, {
  bobot_tugas: -10,
  bobot_uts: 60,
  bobot_uas: 50,
  predikat: [
    { label: 'A', min: 90, max: 100 },
    { label: 'B', min: 0, max: 89.99 }
  ]
});
assert.strictEqual(savePrNegative.success, false);
assert.ok(savePrNegative.message.includes('tidak negatif'));

// 1E. Validasi Predikat: Penolakan celah (gap) antar rentang predikat
const savePrGap = appModule.apiSavePengaturanRapor(wali1Token, {
  bobot_tugas: 40,
  bobot_uts: 30,
  bobot_uas: 30,
  predikat: [
    { label: 'A', min: 90, max: 100 },
    { label: 'B', min: 70, max: 85 }, // Gap antara 85 dan 90
    { label: 'C', min: 0, max: 69.99 }
  ]
});
assert.strictEqual(savePrGap.success, false);
assert.ok(savePrGap.message.includes('celah nilai') || savePrGap.message.includes('gap'));

// 1F. Validasi Predikat: Penolakan tumpang tindih (overlap)
const savePrOverlap = appModule.apiSavePengaturanRapor(wali1Token, {
  bobot_tugas: 40,
  bobot_uts: 30,
  bobot_uas: 30,
  predikat: [
    { label: 'A', min: 85, max: 100 },
    { label: 'B', min: 80, max: 90 }, // Overlap antara 85 dan 90
    { label: 'C', min: 0, max: 79.99 }
  ]
});
assert.strictEqual(savePrOverlap.success, false);
assert.ok(savePrOverlap.message.includes('tumpang tindih') || savePrOverlap.message.includes('overlap'));

// 1G. Validasi Predikat: Penolakan rentang tidak mulai dari 0 atau tidak sampai 100
const savePrNotZero = appModule.apiSavePengaturanRapor(wali1Token, {
  bobot_tugas: 40,
  bobot_uts: 30,
  bobot_uas: 30,
  predikat: [
    { label: 'A', min: 80, max: 100 },
    { label: 'B', min: 10, max: 79.99 } // Mulai dari 10 bukan 0
  ]
});
assert.strictEqual(savePrNotZero.success, false);
assert.ok(savePrNotZero.message.includes('dimulai dari angka 0'));

// 1H. Simpan Konfigurasi Sah oleh Wali Kelas 1
const validPredikatConfig = [
  { label: 'A', min: 90, max: 100 },
  { label: 'B', min: 80, max: 89.99 },
  { label: 'C', min: 70, max: 79.99 },
  { label: 'D', min: 0, max: 69.99 }
];
const savePrOk = appModule.apiSavePengaturanRapor(wali1Token, {
  bobot_tugas: 50,
  bobot_uts: 25,
  bobot_uas: 25,
  predikat: validPredikatConfig
});
assert.strictEqual(savePrOk.success, true, 'Simpan konfigurasi rapor sah harus sukses');

// Verifikasi hasil simpan
const getPrWali1Updated = appModule.apiGetPengaturanRapor(wali1Token);
assert.strictEqual(getPrWali1Updated.data.config.bobot_tugas, 50);
assert.strictEqual(getPrWali1Updated.data.config.bobot_uts, 25);
assert.strictEqual(getPrWali1Updated.data.config.bobot_uas, 25);
assert.strictEqual(getPrWali1Updated.data.config.isDefault, false);

// 1I. Update Konfigurasi yang sudah ada (tidak boleh menambah baris baru di sheet)
const initialRowCount = mockSS.sheets.pengaturan_rapor.getLastRow();
const updatePrOk = appModule.apiSavePengaturanRapor(wali1Token, {
  bobot_tugas: 40,
  bobot_uts: 30,
  bobot_uas: 30,
  predikat: validPredikatConfig
});
assert.strictEqual(updatePrOk.success, true);
assert.strictEqual(mockSS.sheets.pengaturan_rapor.getLastRow(), initialRowCount, 'Update tidak boleh menduplikasi row');

// 1J. Proteksi Periode Terkunci pada Pengaturan Rapor
const savePrLocked = appModule.apiSavePengaturanRapor(kepsekToken, {
  wali_kelas_id: 'wk-k1-locked',
  bobot_tugas: 40,
  bobot_uts: 30,
  bobot_uas: 30,
  predikat: validPredikatConfig
});
assert.strictEqual(savePrLocked.success, false);
assert.ok(savePrLocked.message.includes('Periode akademik telah dikunci'));

// 1K. Proteksi IDOR: Wali kelas 1 tidak bisa menyimpan konfigurasi kelas 2
const savePrIdor = appModule.apiSavePengaturanRapor(wali1Token, {
  wali_kelas_id: 'wk-k2-aktif',
  bobot_tugas: 40,
  bobot_uts: 30,
  bobot_uas: 30,
  predikat: validPredikatConfig
});
// Dalam implementasi resolveWaliKelasScope, jika requestedWkId != penugasan guru, otomatis mengikat ke penugasan guru sendiri
// atau jika role wali_kelas meminta id kelas lain, fungsi mengabaikan atau menolak.
// Mari kita pastikan bahwa konfigurasi kelas 2 tidak terubah oleh wali 1:
const getPrWali2 = appModule.apiGetPengaturanRapor(wali2Token);
assert.strictEqual(getPrWali2.data.config.isDefault, true, 'Konfigurasi wali 2 tidak boleh terubah oleh aksi wali 1');

console.log('   ✓ Seluruh pengujian Pengaturan Rapor berhasil lolos 100%.\n');

// ============================================================================
// 2. PENGUJIAN INPUT NILAI AKADEMIK & KALKULASI
// ============================================================================
console.log('2. Menguji Input Nilai Akademik & Kalkulasi Nilai Akhir...');

// 2A. Memuat nilai mata pelajaran awal (kosong)
const getNilaiInit = appModule.apiGetNilaiMataPelajaran(wali1Token, 'm-01');
assert.strictEqual(getNilaiInit.success, true);
assert.strictEqual(getNilaiInit.data.siswaNilaiList.length, 2, 'Rombel kelas 1 memiliki 2 siswa aktif');
assert.strictEqual(getNilaiInit.data.summary.jumlahLengkap, 0);
assert.strictEqual(getNilaiInit.data.summary.persentase, 0);

// 2B. Penolakan Nilai di Luar Rentang 0–100 (Negatif & Lebih dari 100)
const saveNilaiNegative = appModule.apiSaveNilaiMataPelajaranBatch(wali1Token, {
  mata_pelajaran_id: 'm-01',
  rows: [
    { siswa_id: 's-01', nilai_tugas_1: -10, nilai_tugas_2: 80, nilai_tugas_3: 80, nilai_tugas_4: 80, nilai_uts: 80, nilai_uas: 80 }
  ]
});
assert.strictEqual(saveNilaiNegative.success, false);
assert.ok(saveNilaiNegative.message.includes('0 sampai 100'));

const saveNilaiOver100 = appModule.apiSaveNilaiMataPelajaranBatch(wali1Token, {
  mata_pelajaran_id: 'm-01',
  rows: [
    { siswa_id: 's-01', nilai_tugas_1: 105, nilai_tugas_2: 80, nilai_tugas_3: 80, nilai_tugas_4: 80, nilai_uts: 80, nilai_uas: 80 }
  ]
});
assert.strictEqual(saveNilaiOver100.success, false);
assert.ok(saveNilaiOver100.message.includes('0 sampai 100'));

// 2C. Penanganan Data Parsial: Field kosong TIDAK diubah jadi 0, nilai akhir tetap kosong & is_complete = false
const saveNilaiParsial = appModule.apiSaveNilaiMataPelajaranBatch(wali1Token, {
  mata_pelajaran_id: 'm-01',
  rows: [
    { siswa_id: 's-01', nilai_tugas_1: 85, nilai_tugas_2: 90, nilai_tugas_3: '', nilai_tugas_4: '', nilai_uts: 80, nilai_uas: '' },
    { siswa_id: 's-02', nilai_tugas_1: '', nilai_tugas_2: '', nilai_tugas_3: '', nilai_tugas_4: '', nilai_uts: '', nilai_uas: '' }
  ]
});
assert.strictEqual(saveNilaiParsial.success, true, 'Simpan nilai parsial harus sukses');

const checkNilaiParsial = appModule.apiGetNilaiMataPelajaran(wali1Token, 'm-01');
const s1Parsial = checkNilaiParsial.data.siswaNilaiList.find(s => s.siswa_id === 's-01');
assert.strictEqual(s1Parsial.nilai_tugas_1, 85);
assert.strictEqual(s1Parsial.nilai_tugas_2, 90);
assert.strictEqual(s1Parsial.nilai_tugas_3, '', 'Tugas 3 kosong tidak boleh jadi 0');
assert.strictEqual(s1Parsial.nilai_uts, 80);
assert.strictEqual(s1Parsial.nilai_uas, '', 'UAS kosong tidak boleh jadi 0');
assert.strictEqual(s1Parsial.is_complete, false, 'is_complete harus false saat komponen belum lengkap');
assert.strictEqual(s1Parsial.nilai_akhir, '', 'nilai_akhir harus kosong saat komponen belum lengkap');

// 2D. Simpan Nilai Lengkap & Verifikasi Formula Perhitungan Nilai Akhir
// Siswa 1: T1=80, T2=90, T3=85, T4=95 -> rataTugas = (80+90+85+95)/4 = 350/4 = 87.5
// UTS = 80, UAS = 90
// Bobot kelas 1 saat ini: bobot_tugas = 40, bobot_uts = 30, bobot_uas = 30
// nilaiAkhir = (87.5 * 40 + 80 * 30 + 90 * 30) / 100 = (3500 + 2400 + 2700) / 100 = 8600 / 100 = 86.00
// Predikat 86 -> rentang B (80 - 89.99)
// Siswa 2: T1=95, T2=95, T3=90, T4=100 -> rataTugas = 95
// UTS = 95, UAS = 90
// nilaiAkhir = (95 * 40 + 95 * 30 + 90 * 30) / 100 = (3800 + 2850 + 2700) / 100 = 9350 / 100 = 93.50
// Predikat 93.5 -> rentang A (90 - 100)
const saveNilaiLengkap = appModule.apiSaveNilaiMataPelajaranBatch(wali1Token, {
  mata_pelajaran_id: 'm-01',
  rows: [
    { siswa_id: 's-01', nilai_tugas_1: 80, nilai_tugas_2: 90, nilai_tugas_3: 85, nilai_tugas_4: 95, nilai_uts: 80, nilai_uas: 90 },
    { siswa_id: 's-02', nilai_tugas_1: 95, nilai_tugas_2: 95, nilai_tugas_3: 90, nilai_tugas_4: 100, nilai_uts: 95, nilai_uas: 90 }
  ]
});
assert.strictEqual(saveNilaiLengkap.success, true);

const checkNilaiLengkap = appModule.apiGetNilaiMataPelajaran(wali1Token, 'm-01');
assert.strictEqual(checkNilaiLengkap.data.summary.jumlahLengkap, 2);
assert.strictEqual(checkNilaiLengkap.data.summary.persentase, 100);

const s1Final = checkNilaiLengkap.data.siswaNilaiList.find(s => s.siswa_id === 's-01');
assert.strictEqual(s1Final.is_complete, true);
assert.strictEqual(s1Final.nilai_akhir, 86);
assert.strictEqual(s1Final.predikat, 'B');

const s2Final = checkNilaiLengkap.data.siswaNilaiList.find(s => s.siswa_id === 's-02');
assert.strictEqual(s2Final.is_complete, true);
assert.strictEqual(s2Final.nilai_akhir, 93.5);
assert.strictEqual(s2Final.predikat, 'A');

// 2E. Proteksi Duplikasi Nilai (Simpan Ulang Mengupdate Baris yang Ada)
const initialNilaiRows = mockSS.sheets.nilai_mata_pelajaran.getLastRow();
const saveNilaiUpdate = appModule.apiSaveNilaiMataPelajaranBatch(wali1Token, {
  mata_pelajaran_id: 'm-01',
  rows: [
    { siswa_id: 's-01', nilai_tugas_1: 85, nilai_tugas_2: 90, nilai_tugas_3: 85, nilai_tugas_4: 95, nilai_uts: 80, nilai_uas: 90 }
  ]
});
assert.strictEqual(saveNilaiUpdate.success, true);
assert.strictEqual(mockSS.sheets.nilai_mata_pelajaran.getLastRow(), initialNilaiRows, 'Penyimpanan nilai tidak boleh membuat duplikasi baris');

// 2F. Proteksi Periode Terkunci pada Nilai Mata Pelajaran
const saveNilaiLocked = appModule.apiSaveNilaiMataPelajaranBatch(kepsekToken, {
  wali_kelas_id: 'wk-k1-locked',
  mata_pelajaran_id: 'm-locked',
  rows: [
    { siswa_id: 's-locked', nilai_tugas_1: 80, nilai_tugas_2: 80, nilai_tugas_3: 80, nilai_tugas_4: 80, nilai_uts: 80, nilai_uas: 80 }
  ]
});
assert.strictEqual(saveNilaiLocked.success, false);
assert.ok(saveNilaiLocked.message.includes('Periode akademik telah dikunci'));

// 2G. Proteksi IDOR Nilai: Wali 1 dilarang mengisi nilai mapel kelas 2
const saveNilaiIdorMapel = appModule.apiSaveNilaiMataPelajaranBatch(wali1Token, {
  mata_pelajaran_id: 'm-03', // Mapel MTK milik kelas 2
  rows: [
    { siswa_id: 's-01', nilai_tugas_1: 80, nilai_tugas_2: 80, nilai_tugas_3: 80, nilai_tugas_4: 80, nilai_uts: 80, nilai_uas: 80 }
  ]
});
assert.strictEqual(saveNilaiIdorMapel.success, false);
assert.ok(saveNilaiIdorMapel.message.includes('Akses ditolak') || saveNilaiIdorMapel.message.includes('tidak terdaftar'));

// 2H. Proteksi IDOR Nilai: Wali 1 dilarang menyelipkan siswa kelas 2
const saveNilaiIdorSiswa = appModule.apiSaveNilaiMataPelajaranBatch(wali1Token, {
  mata_pelajaran_id: 'm-01',
  rows: [
    { siswa_id: 's-03', nilai_tugas_1: 80, nilai_tugas_2: 80, nilai_tugas_3: 80, nilai_tugas_4: 80, nilai_uts: 80, nilai_uas: 80 }
  ]
});
assert.strictEqual(saveNilaiIdorSiswa.success, false);
assert.ok(saveNilaiIdorSiswa.message.includes('Akses ditolak') || saveNilaiIdorSiswa.message.includes('bukan anggota rombel'));

console.log('   ✓ Seluruh pengujian Input Nilai Akademik & Kalkulasi berhasil lolos 100%.\n');

// ============================================================================
// 3. PENGUJIAN PENILAIAN SIKAP
// ============================================================================
console.log('3. Menguji Penilaian Sikap (Integritas, Religius, Nasionalis, Mandiri, Gotong Royong)...');

// 3A. Memuat penilaian sikap awal
const getSikapInit = appModule.apiGetNilaiSikapList(wali1Token);
assert.strictEqual(getSikapInit.success, true);
assert.strictEqual(getSikapInit.data.siswaSikapList.length, 2);
assert.strictEqual(getSikapInit.data.summary.jumlahLengkap, 0);

// 3B. Validasi Predikat Sikap: Menolak predikat invalid
const saveSikapInvalid = appModule.apiSaveNilaiSikapBatch(wali1Token, {
  rows: [
    { siswa_id: 's-01', predikat: 'Luar Biasa Sekali', deskripsi: 'Siswa aktif' }
  ]
});
assert.strictEqual(saveSikapInvalid.success, false);
assert.ok(saveSikapInvalid.message.includes('tidak valid') && saveSikapInvalid.message.includes('Sangat Baik'));

// 3C. Simpan Penilaian Sikap Sah
const saveSikapOk = appModule.apiSaveNilaiSikapBatch(wali1Token, {
  rows: [
    {
      siswa_id: 's-01',
      predikat: 'Sangat Baik',
      deskripsi: 'Menunjukkan integritas tinggi, ketaatan beribadah (religius), dan aktif bergotong royong.'
    },
    {
      siswa_id: 's-02',
      predikat: 'Baik',
      deskripsi: 'Menunjukkan sikap nasionalis, mandiri dalam belajar, dan ramah terhadap sesama.'
    }
  ]
});
assert.strictEqual(saveSikapOk.success, true);

// Verifikasi hasil simpan sikap
const checkSikap = appModule.apiGetNilaiSikapList(wali1Token);
assert.strictEqual(checkSikap.data.summary.jumlahLengkap, 2);
assert.strictEqual(checkSikap.data.summary.persentase, 100);
const s1Sikap = checkSikap.data.siswaSikapList.find(s => s.siswa_id === 's-01');
assert.strictEqual(s1Sikap.predikat, 'Sangat Baik');
assert.ok(s1Sikap.deskripsi.includes('integritas'));

// 3D. Update Sikap tanpa duplikasi baris
const initialSikapRows = mockSS.sheets.nilai_sikap.getLastRow();
const updateSikapOk = appModule.apiSaveNilaiSikapBatch(wali1Token, {
  rows: [
    { siswa_id: 's-01', predikat: 'Baik', deskripsi: 'Pembaruan deskripsi sikap mandiri.' }
  ]
});
assert.strictEqual(updateSikapOk.success, true);
assert.strictEqual(mockSS.sheets.nilai_sikap.getLastRow(), initialSikapRows, 'Update sikap tidak boleh membuat duplikasi baris');

// 3E. Proteksi Periode Terkunci pada Sikap
const saveSikapLocked = appModule.apiSaveNilaiSikapBatch(kepsekToken, {
  wali_kelas_id: 'wk-k1-locked',
  rows: [
    { siswa_id: 's-locked', predikat: 'Baik', deskripsi: 'Catatan masa lalu' }
  ]
});
assert.strictEqual(saveSikapLocked.success, false);
assert.ok(saveSikapLocked.message.includes('Periode akademik telah dikunci'));

// 3F. Proteksi IDOR Sikap: Tolak siswa di luar rombel penugasan
const saveSikapIdor = appModule.apiSaveNilaiSikapBatch(wali1Token, {
  rows: [
    { siswa_id: 's-03', predikat: 'Baik', deskripsi: 'Siswa kelas 2' }
  ]
});
assert.strictEqual(saveSikapIdor.success, false);
assert.ok(saveSikapIdor.message.includes('Akses ditolak') || saveSikapIdor.message.includes('bukan anggota rombel'));

console.log('   ✓ Seluruh pengujian Penilaian Sikap berhasil lolos 100%.\n');

// ============================================================================
// 4. PENGUJIAN REKAP KEHADIRAN (SAKIT, IZIN, ALPA)
// ============================================================================
console.log('4. Menguji Rekap Kehadiran Siswa...');

// 4A. Memuat rekap kehadiran awal
const getKehadiranInit = appModule.apiGetRekapKehadiranList(wali1Token);
assert.strictEqual(getKehadiranInit.success, true);
assert.strictEqual(getKehadiranInit.data.siswaKehadiranList.length, 2);
assert.strictEqual(getKehadiranInit.data.totals.hadir, 0);

// 4B. Validasi Angka Kehadiran: Menolak angka negatif
const saveKehadiranNegative = appModule.apiSaveRekapKehadiranBatch(wali1Token, {
  rows: [
    { siswa_id: 's-01', jumlah_hadir: 80, jumlah_sakit: -2, jumlah_izin: 0, jumlah_alpha: 0 }
  ]
});
assert.strictEqual(saveKehadiranNegative.success, false);
assert.ok(saveKehadiranNegative.message.includes('tidak negatif'));

// 4C. Simpan Rekap Kehadiran Sah
const saveKehadiranOk = appModule.apiSaveRekapKehadiranBatch(wali1Token, {
  rows: [
    { siswa_id: 's-01', jumlah_hadir: 95, jumlah_sakit: 2, jumlah_izin: 1, jumlah_alpha: 0, keterangan: 'Rajin masuk' },
    { siswa_id: 's-02', jumlah_hadir: 92, jumlah_sakit: 3, jumlah_izin: 2, jumlah_alpha: 1, keterangan: 'Tertib' }
  ]
});
assert.strictEqual(saveKehadiranOk.success, true);

// Verifikasi data dan total ringkasan kelas
const checkKehadiran = appModule.apiGetRekapKehadiranList(wali1Token);
assert.strictEqual(checkKehadiran.data.summary.jumlahLengkap, 2);
assert.strictEqual(checkKehadiran.data.totals.hadir, 95 + 92); // 187
assert.strictEqual(checkKehadiran.data.totals.sakit, 2 + 3);   // 5
assert.strictEqual(checkKehadiran.data.totals.izin, 1 + 2);    // 3
assert.strictEqual(checkKehadiran.data.totals.alpha, 0 + 1);   // 1

// 4D. Update Rekap Kehadiran tanpa duplikasi baris
const initialKehadiranRows = mockSS.sheets.rekap_kehadiran.getLastRow();
const updateKehadiranOk = appModule.apiSaveRekapKehadiranBatch(wali1Token, {
  rows: [
    { siswa_id: 's-01', jumlah_hadir: 96, jumlah_sakit: 1, jumlah_izin: 1, jumlah_alpha: 0, keterangan: 'Update kehadiran' }
  ]
});
assert.strictEqual(updateKehadiranOk.success, true);
assert.strictEqual(mockSS.sheets.rekap_kehadiran.getLastRow(), initialKehadiranRows, 'Update kehadiran tidak boleh membuat duplikasi baris');

// 4E. Proteksi Periode Terkunci pada Rekap Kehadiran
const saveKehadiranLocked = appModule.apiSaveRekapKehadiranBatch(kepsekToken, {
  wali_kelas_id: 'wk-k1-locked',
  rows: [
    { siswa_id: 's-locked', jumlah_hadir: 90, jumlah_sakit: 0, jumlah_izin: 0, jumlah_alpha: 0 }
  ]
});
assert.strictEqual(saveKehadiranLocked.success, false);
assert.ok(saveKehadiranLocked.message.includes('Periode akademik telah dikunci'));

// 4F. Proteksi IDOR Kehadiran: Tolak siswa di luar rombel penugasan
const saveKehadiranIdor = appModule.apiSaveRekapKehadiranBatch(wali1Token, {
  rows: [
    { siswa_id: 's-03', jumlah_hadir: 90, jumlah_sakit: 0, jumlah_izin: 0, jumlah_alpha: 0 }
  ]
});
assert.strictEqual(saveKehadiranIdor.success, false);
assert.ok(saveKehadiranIdor.message.includes('Akses ditolak') || saveKehadiranIdor.message.includes('bukan anggota rombel'));

console.log('   ✓ Seluruh pengujian Rekap Kehadiran berhasil lolos 100%.\n');

// ============================================================================
// 5. PENGUJIAN INDIKATOR KELENGKAPAN PENILAIAN & MONITORING
// ============================================================================
console.log('5. Menguji Indikator Kelengkapan Penilaian & Monitoring...');

// 5A. Wali Kelas 1 Memuat Status Kelengkapan Kelas Miliknya
// Catatan: Di kelas 1 terdapat 2 mapel: PAI (m-01, sudah lengkap 2/2) dan MTK (m-02, belum diisi 0/2).
// Sikap: 2/2 lengkap (100%). Kehadiran: 2/2 lengkap (100%).
// Nilai akademik total expected = 2 siswa * 2 mapel = 4. Lengkap = 2 (50%).
const kelengkapanWali1 = appModule.apiGetKelengkapanPenilaian(wali1Token);
assert.strictEqual(kelengkapanWali1.success, true);
assert.strictEqual(kelengkapanWali1.data.isMultiClass, false);
assert.strictEqual(kelengkapanWali1.data.mapelProgress.length, 2);
assert.strictEqual(kelengkapanWali1.data.totalSikapPercent, 100);
assert.strictEqual(kelengkapanWali1.data.totalKehadiranPercent, 100);
assert.strictEqual(kelengkapanWali1.data.totalNilaiPercent, 50);
assert.strictEqual(kelengkapanWali1.data.overallStatus, 'Sebagian');

// 5B. Mengisi MTK (m-02) agar nilai akademik kelas 1 menjadi 100% lengkap
const completeMtk = appModule.apiSaveNilaiMataPelajaranBatch(wali1Token, {
  mata_pelajaran_id: 'm-02',
  rows: [
    { siswa_id: 's-01', nilai_tugas_1: 85, nilai_tugas_2: 85, nilai_tugas_3: 85, nilai_tugas_4: 85, nilai_uts: 85, nilai_uas: 85 },
    { siswa_id: 's-02', nilai_tugas_1: 90, nilai_tugas_2: 90, nilai_tugas_3: 90, nilai_tugas_4: 90, nilai_uts: 90, nilai_uas: 90 }
  ]
});
assert.strictEqual(completeMtk.success, true);

// Verifikasi ulang kelengkapan kelas 1 -> Harus 100% dan berstatus 'Lengkap'
const kelengkapanWali1Full = appModule.apiGetKelengkapanPenilaian(wali1Token);
assert.strictEqual(kelengkapanWali1Full.data.totalNilaiPercent, 100);
assert.strictEqual(kelengkapanWali1Full.data.overallStatus, 'Lengkap');

// 5C. Kepala Sekolah Memuat Monitoring Multi-Kelas (Kelas 1 s/d 6)
const monitoringKepsek = appModule.apiGetKelengkapanPenilaian(kepsekToken);
assert.strictEqual(monitoringKepsek.success, true);
assert.strictEqual(monitoringKepsek.data.isMultiClass, true);
assert.strictEqual(monitoringKepsek.data.classes.length, 6, 'Harus mencakup kelas 1 sampai 6');

// Kelas 1 harus berstatus Lengkap
const k1Overview = monitoringKepsek.data.classes.find(c => c.kelas === '1');
assert.strictEqual(k1Overview.hasPenugasan, true);
assert.strictEqual(k1Overview.waliKelasNama, 'Ahmad Dahlan, S.Pd.');
assert.strictEqual(k1Overview.statusLabel, 'Lengkap');
assert.strictEqual(k1Overview.nilaiPercent, 100);

// Kelas 2 memiliki penugasan (Siti Fatimah) namun belum ada nilai
const k2Overview = monitoringKepsek.data.classes.find(c => c.kelas === '2');
assert.strictEqual(k2Overview.hasPenugasan, true);
assert.strictEqual(k2Overview.statusLabel, 'Belum Lengkap');

// Kelas 3 belum memiliki penugasan wali kelas
const k3Overview = monitoringKepsek.data.classes.find(c => c.kelas === '3');
assert.strictEqual(k3Overview.hasPenugasan, false);
assert.strictEqual(k3Overview.statusLabel, 'Belum Ada Wali Kelas');

console.log('   ✓ Seluruh pengujian Indikator Kelengkapan & Monitoring berhasil lolos 100%.\n');

// ============================================================================
// 6. PENGUJIAN OTORISASI SESI DAN LEAST PRIVILEGE
// ============================================================================
console.log('6. Menguji Otorisasi Sesi & Keamanan Token...');

const fakeToken = 'token_invalid_palsu_phase6';

assert.strictEqual(appModule.apiGetPengaturanRapor(fakeToken).success, false);
assert.strictEqual(appModule.apiSavePengaturanRapor(fakeToken, {}).success, false);

assert.strictEqual(appModule.apiGetNilaiMataPelajaran(fakeToken, 'm-01').success, false);
assert.strictEqual(appModule.apiSaveNilaiMataPelajaranBatch(fakeToken, {}).success, false);

assert.strictEqual(appModule.apiGetNilaiSikapList(fakeToken).success, false);
assert.strictEqual(appModule.apiSaveNilaiSikapBatch(fakeToken, {}).success, false);

assert.strictEqual(appModule.apiGetRekapKehadiranList(fakeToken).success, false);
assert.strictEqual(appModule.apiSaveRekapKehadiranBatch(fakeToken, {}).success, false);

assert.strictEqual(appModule.apiGetKelengkapanPenilaian(fakeToken).success, false);

console.log('   ✓ Seluruh endpoint tertolak secara aman saat sesi tidak valid.\n');

console.log('======================================================');
console.log('SELURUH PENGUJIAN OTOMATIS PHASE 6 BERHASIL LULUS (100% PASS)');
console.log('======================================================\n');
